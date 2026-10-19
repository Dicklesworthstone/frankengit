// Real files, child ownership and CLI; native-schema peers are NOT the Rust node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, readdir, unlink, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { once as execute, configuration as watchConfiguration } from '../../scripts/operator/workflow_watch.mjs';
import { configuration, once, status, serve } from '../../scripts/operator/workflow_check_publish.mjs';
import { sha256, encode, conclusion, journalConclusion, jobKey } from '../../scripts/operator/workflow_check_protocol.mjs';
import { main } from '../../scripts/fg_workflow_checks.mjs';

const publisherPeer = new URL('./fixtures/workflow_check_native.mjs', import.meta.url).href;
const watcherPeer = new URL('./fixtures/workflow_watch_native.mjs', import.meta.url).href;
const cli = new URL('../../scripts/fg_workflow_checks.mjs', import.meta.url).pathname;
const hex = value => Buffer.from(value).toString('hex');
const json = async path => JSON.parse(await readFile(path, 'utf8'));
const save = (path, value) => writeFile(path, encode(value), { mode: 0o600 });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFor(check) { for (let i = 0; i < 400; i++) { if (await check()) return; await sleep(10); } throw new Error('fixture wait failed'); }
async function fixture(t, format = 'sha1', patch = {}, artifactPipeline = false) {
  const root = await mkdtemp(join(tmpdir(), 'fg-check-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const dir of ['store', 'watch', 'runs', 'publication']) await mkdir(join(root, dir), { mode: 0o700 });
  if (artifactPipeline) await mkdir(join(root, 'artifacts'), { mode: 0o700 });
  const fg = join(root, 'fg');
  await writeFile(fg, `#!${process.execPath}\nimport { handle } from ${JSON.stringify(publisherPeer)};\nif (!await handle(process.argv.slice(2))) await import(${JSON.stringify(watcherPeer)});\n`, { mode: 0o700 });
  const watch = watchConfiguration({ schema: 'frankengit-workflow-watch-v1', fg, storage_root: join(root, 'store'),
    tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format,
    ref_hex: hex('refs/heads/main'), workflow_directory_hex: hex('.github/workflows'), input_prefixes_hex: [hex('.github')],
    event: 'push', state_directory: join(root, 'watch'), run_parent: join(root, 'runs'), max_runs: 16, trust: 'selected-branch-host-execution',
    ...(artifactPipeline ? { artifacts: { root: join(root, 'artifacts'),
      selections: [{ workflow_path_hex: hex('.github/workflows/ci.yml'), job_id: 'build', output_path_hex: hex('dist/result') }],
      inputs: [{ workflow_path_hex: hex('.github/workflows/ci.yml'), consumer_job_id: 'test', producer_job_id: 'build',
        output_path_hex: hex('dist/result'), destination_hex: hex('build/result') }] } } : {}) });
  let control = { tenant: watch.tenant_id, repository: watch.repository_id, incarnation: watch.repository_incarnation,
    format, ref_hex: watch.ref_hex, commit: 'a'.repeat(format === 'sha1' ? 40 : 64),
    source_head: 'fixture-head', snapshot: `alg:2:${'4'.repeat(64)}`, ...patch };
  const set = async patch => { control = { ...control, ...patch }; await save(join(root, 'store/control.json'), control); };
  await set({});
  const config = configuration({ schema: 'frankengit-workflow-check-publisher-v1', watch, state_directory: join(root, 'publication'), principal_id: '5'.repeat(32) });
  const watchFile = join(root, 'watch.json'); await save(watchFile, watch);
  const lines = async file => { try { return (await readFile(join(root, 'store', file), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); } catch (e) { if (e.code === 'ENOENT') return []; throw e; } };
  async function run() {
    const observation = await execute(watch);
    assert.equal(observation.type, 'workflow_watch_result');
    const report = await json(join(observation.native_directory, 'report.json'));
    for (const run of report.runs) {
      const directory = Buffer.from(run.run_directory_hex, 'hex').toString();
      const marker = Object.fromEntries(Object.entries(run).filter(([key]) => !['type', 'succeeded', 'workspaces_closed', 'request_interrupted', 'execution', 'artifacts', 'artifact_inputs'].includes(key)));
      const markerBytes = Buffer.from(JSON.stringify({ type: 'trusted_workflow_attempt', ...marker, state: 'started', execution_plan: { ...run.execution, succeeded: false, jobs: [] } }));
      await writeFile(join(directory, 'attempt.json'), markerBytes, { mode: 0o600 });
      const entries = run.execution.jobs.map((job, index) => ({ batch_sha256: sha256(encode([run.run_id, index])), body_bytes: 256, ordinal: index,
        delivery: 'pending', delivery_receipt_sha256: null, run_sha256: sha256(Buffer.from(run.run_id)), attempt_sha256: '6'.repeat(64),
        authority_basis_sha256: control.snapshot.slice(6), object_format: format, source_commit: run.executed_commit,
        workflow_graph_sha256: 'c'.repeat(64), trust_domain: 'trusted-local-owner', profile: { name: 'trusted-local-foreground-v1',
          source_sha256: 'b'.repeat(64), step_timeout_nanos: run.execution.step_timeout_millis * 1000000,
          run_timeout_nanos: run.execution.run_timeout_millis * 1000000, stream_bytes: run.execution.stream_bytes, total_output_bytes: run.execution.total_output_bytes },
        facts: [{ job: job.id, status: 'completed', conclusion: journalConclusion(job.outcome), evidence_sha256: sha256(encode(job)), logical_millis: 0 }] }));
      await save(join(directory, 'custody.json'), { store: watch.storage_root, incarnation: watch.repository_incarnation, ref_hex: watch.ref_hex,
        conclusions: Object.fromEntries(run.execution.jobs.map(job => [job.id, conclusion(job.outcome)])), history: {
          type: 'workflow_custody_history', schema_version: 1, authoritative_check: false, execution_retried: false,
          execution_completion: 'not_asserted', evidence_payloads_included: false,
          scope: { tenant: watch.tenant_id, repository: watch.repository_id, journal_id: sha256(markerBytes) },
          snapshot: `1024:${'7'.repeat(64)}`, retained_batches: entries.length, pending_batches: entries.length, next_after: null, entries } });
    }
    return { observation, report, directory: report.runs.length ? Buffer.from(report.runs[0].run_directory_hex, 'hex').toString() : null };
  }
  return { root, config, watch, watchFile, set, lines, run, get control() { return control; } };
}
function child(f, operation, extras = []) {
  const p = spawn(process.execPath, [cli, operation, '--watch-config', f.watchFile, '--state', f.config.state_directory,
    '--principal-id', f.config.principal_id, '--trusted-local', ...extras], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', errors = ''; p.stdout.on('data', b => { output += b; }); p.stderr.on('data', b => { errors += b; });
  const done = new Promise((resolve, reject) => { p.once('error', reject); p.once('close', (code, signal) => resolve({ code, signal, output, errors })); });
  return { p, done, get output() { return output; } };
}
const multiple = { execution_patch: { jobs: [
  { id: 'first', outcome: 'succeeded', steps: [], failure: null },
  { id: 'second', outcome: 'succeeded', steps: [], failure: null },
] } };
for (const format of ['sha1', 'sha256']) {
  test(`${format}: artifact pipeline publication matches the immutable contract without treating output receipts as marker fields`, async t => {
    const f = await fixture(t, format, { execution_patch: { jobs: [
      { id: 'build', outcome: 'succeeded', steps: [], failure: null },
      { id: 'test', outcome: 'succeeded', steps: [], failure: null },
    ] } }, true);
    const run = await f.run(), markerPath = join(run.directory, 'attempt.json'), marker = await readFile(markerPath);
    const value = JSON.parse(marker);
    assert.deepEqual(value.artifact_contract, run.report.runs[0].artifact_contract);
    assert.equal(Object.hasOwn(value, 'artifacts'), false);
    assert.equal(Object.hasOwn(value, 'artifact_inputs'), false);
    const [capture] = run.report.runs[0].artifacts;
    const [delivery] = run.report.runs[0].artifact_inputs;
    assert.equal(run.report.runs[0].artifacts.length, 1);
    assert.equal(run.report.runs[0].artifact_inputs.length, 1);
    assert.equal(capture.job_id_hex, hex('build'));
    assert.equal(delivery.job_id_hex, hex('test'));
    assert.equal(capture.outputs.length, 1);
    assert.equal(delivery.inputs.length, 1);
    assert.equal(delivery.inputs[0].producer_manifest_id_sha256, capture.manifest_id_sha256);
    assert.deepEqual(delivery.inputs[0].output, capture.outputs[0]);
    assert.equal(delivery.inputs[0].destination_path_hex, hex('.fgit-artifacts/build/result'));
    const bad = structuredClone(value); bad.artifact_contract.input_delivery.total_delivery_bytes++;
    await writeFile(markerPath, Buffer.from(JSON.stringify(bad)), { mode: 0o600 });
    await assert.rejects(once(f.config), /Original workflow marker changed/);
    assert.equal((await f.lines('published.ndjson')).length, 0);
    await writeFile(markerPath, marker, { mode: 0o600 });
    const result = await once(f.config);
    assert.equal(result.publications, 2);
    assert.equal(result.runs[0].committed, 2);
    assert.equal((await f.lines('effects.ndjson')).length, 1);
    assert.equal((await once(f.config)).publications, 0);
    assert.deepEqual(await readFile(markerPath), marker);
  });
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: successful execution publishes a check observation, not merge approval`, async t => {
    const f = await fixture(t, format); await f.run();
    const events = [], result = await once(f.config, { onObservation: event => events.push(event) });
    assert.equal(result.publications, 1); assert.equal(result.runs[0].committed, 1);
    assert.equal(events[0].conclusion, 'success'); assert.equal(events[0].authoritative_check, false);
    assert.equal(events[0].decision_sequence, '18446744073709551615');
    const calls = await f.lines('calls.ndjson'); assert.deepEqual(calls.map(args => args[0] === 'refs' ? 'refs' : args[1]), ['refs', 'dispatch', 'recover', 'publish']);
    const args = calls.at(-1), get = key => args[args.indexOf(key) + 1];
    assert.equal(get('--principal-id'), f.config.principal_id); assert.equal(get('--expected-incarnation'), f.watch.repository_incarnation);
    assert.equal(get('--object-format'), format); assert.equal(get('--minimum-pin'), `1024:${'7'.repeat(64)}`);
    assert.match(get('--idempotency-key'), /^fgwc1-[0-9a-f]{64}$/);
    assert.equal((await once(f.config)).publications, 0);
    assert.equal((await f.lines('published.ndjson')).length, 1); assert.equal((await f.lines('effects.ndjson')).length, 1);
  });
  test(`${format}: lost publication reply stops automatic work; explicit resume uses the original exact key`, async t => {
    const f = await fixture(t, format, { drop_publication: true }); await f.run();
    await assert.rejects(once(f.config));
    assert.equal((await status(f.config)).runs[0].unknown, 1);
    const count = (await f.lines('calls.ndjson')).length;
    await assert.rejects(once(f.config), /unresolved/); assert.equal((await f.lines('calls.ndjson')).length, count);
    await f.set({ drop_publication: false, commit: 'e'.repeat(format === 'sha1' ? 40 : 64) });
    assert.equal((await once(f.config, { resume: true })).runs[0].committed, 1);
    const calls = (await f.lines('calls.ndjson')).filter(args => args[1] === 'publish');
    assert.deepEqual(calls[0], calls[1]);
    assert.equal((await f.lines('published.ndjson')).length, 1); assert.equal((await f.lines('effects.ndjson')).length, 1);
  });
}

test('multiple jobs are recovered through pinned pages and partial publication resumes without duplicate effects', async t => {
  const f = await fixture(t, 'sha1', { ...multiple, recovery_page_size: 1, drop_job: 'second' }); await f.run();
  await assert.rejects(once(f.config));
  const view = await status(f.config); assert.equal(view.runs[0].committed, 1); assert.equal(view.runs[0].unknown, 1);
  const reads = (await f.lines('calls.ndjson')).filter(args => args[1] === 'recover'); assert.equal(reads.length, 2);
  assert.equal(reads[1][reads[1].indexOf('--at-pin') + 1], `1024:${'7'.repeat(64)}`);
  await f.set({ drop_job: null }); await once(f.config, { resume: true });
  const sends = (await f.lines('calls.ndjson')).filter(args => args[1] === 'publish'); assert.equal(sends.length, 3);
  assert.deepEqual(sends[1], sends[2]); assert.equal((await f.lines('published.ndjson')).length, 2);
});

test('bounded publication quota leaves only unsent original requests; later polls finish them', async t => {
  const f = await fixture(t, 'sha1', multiple); await f.run();
  const first = await once(f.config, { maxPublications: 1 }); assert.equal(first.limit_reached, true); assert.equal(first.runs[0].unknown, 0);
  const next = await once(f.config); assert.equal(next.runs[0].committed, 2);
  assert.equal((await f.lines('published.ndjson')).length, 2);
});

test('canonical stale-source refusal settles without changing refs or rerunning code', async t => {
  const f = await fixture(t, 'sha1', { refuse: true }); await f.run();
  assert.equal((await once(f.config)).runs[0].refused, 1);
  assert.equal((await once(f.config)).publications, 0); assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('no matching workflows creates no synthetic passing check or publication process', async t => {
  const f = await fixture(t, 'sha1', { no_match: true }); await f.run();
  const result = await once(f.config); assert.equal(result.publications, 0); assert.equal(result.runs[0].jobs, 0);
  assert.equal((await f.lines('calls.ndjson')).length, 2);
});

test('unresolved execution is never consumed as a completed workflow', async t => {
  const f = await fixture(t, 'sha1', { no_report: true }); await assert.rejects(execute(f.watch));
  assert.equal((await once(f.config)).runs.length, 0); assert.equal((await f.lines('calls.ndjson')).length, 2);
});

for (const patch of [
  { scope: { tenant: '9'.repeat(32), repository: '2'.repeat(32), journal_id: '1'.repeat(64) } },
  { authoritative_check: true }, { execution_retried: true }, { execution_completion: 'complete' },
  { evidence_payloads_included: true }, { retained_batches: 2 }, { entries: [] },
]) test(`foreign/incomplete native custody refuses before admission: ${JSON.stringify(patch)}`, async t => {
  const f = await fixture(t, 'sha1', { history_patch: patch }); await f.run();
  await assert.rejects(once(f.config)); assert.equal((await f.lines('published.ndjson')).length, 0);
  assert.equal((await status(f.config)).runs.length, 0);
});

for (const patch of [{ principal_id: '9'.repeat(32) }, { source_ref_hex: hex('refs/heads/other') }, { source_commit: `sha1:${'e'.repeat(40)}` },
  { journal_id: '9'.repeat(64) }, { batch_sha256: '9'.repeat(64) }, { fact_index: 1 }, { evidence_sha256: '9'.repeat(64) },
  { merge_permission: true }, { authoritative_check: true }, { conclusion: 'action_required' }, { decision_sequence: 9007199254740992 },
  { decision_sequence: '18446744073709551616' }, { node_closed: false }]) {
  test(`wrong terminal remains unresolved: ${JSON.stringify(patch)}`, async t => {
    const f = await fixture(t, 'sha1', { publication_patch: patch }); await f.run();
    await assert.rejects(once(f.config)); assert.equal((await status(f.config)).runs[0].unknown, 1);
    await assert.rejects(once(f.config), /unresolved/); assert.equal((await f.lines('published.ndjson')).length, 1);
  });
}

test('native cleanup failure preserves the validated canonical terminal and does not resubmit', async t => {
  const f = await fixture(t, 'sha1', { cleanup_failure: true }); await f.run();
  await assert.rejects(once(f.config), error => error.retained_terminal?.outcome === 'committed');
  assert.equal((await status(f.config)).runs[0].committed, 1);
  assert.equal((await once(f.config)).publications, 0);
});

test('configuration change or forged saved request cannot replace the original publisher namespace', async t => {
  const f = await fixture(t, 'sha1', { drop_publication: true }); await f.run(); await assert.rejects(once(f.config));
  await assert.rejects(once({ ...f.config, principal_id: '9'.repeat(32) }, { resume: true }), /configuration changed/);
  const file = (await readdir(f.config.state_directory)).find(name => name.startsWith('plan-'));
  const plan = await json(join(f.config.state_directory, file)); plan.jobs[0].job = 'forged'; await save(join(f.config.state_directory, file), plan);
  await assert.rejects(once(f.config, { resume: true }), /request changed/);
  assert.equal((await f.lines('published.ndjson')).length, 1);
});

test('concurrent publisher refuses another owner before any admission', async t => {
  const f = await fixture(t, 'sha1', { publish_delay: 150 }); await f.run();
  const first = once(f.config); await waitFor(async () => (await f.lines('published.ndjson')).length === 1);
  await assert.rejects(once(f.config), error => error.code === 'EEXIST'); await first;
  assert.equal((await f.lines('published.ndjson')).length, 1);
});

test('cancellation drains an active publisher and persists its terminal', async t => {
  const f = await fixture(t, 'sha1', { publish_delay: 150 }); await f.run(); const stop = new AbortController();
  const running = once(f.config, { signal: stop.signal }); await waitFor(async () => (await f.lines('published.ndjson')).length === 1); stop.abort();
  await running; assert.equal((await status(f.config)).runs[0].committed, 1); assert.equal((await status(f.config)).owner_present, false);
});

test('status works without the native executable or source store, even with a retained owner lock', async t => {
  const f = await fixture(t, 'sha1', { drop_publication: true }); await f.run(); await assert.rejects(once(f.config));
  await unlink(f.watch.fg); await rm(f.watch.storage_root, { recursive: true });
  await mkdir(join(f.config.state_directory, 'owner.lock'), { mode: 0o700 });
  assert.equal((await status(f.config)).runs[0].unknown, 1); assert.equal((await status(f.config)).owner_present, true);
});

test('continuous publisher discovers later completed executions without running workflows itself', async t => {
  const f = await fixture(t); await f.run(); let observed = 0;
  const result = await serve(f.config, { pollMs: 100, maxPolls: 2, onObservation: async () => {
    if (++observed === 1) { await f.set({ commit: 'e'.repeat(40) }); await f.run(); }
  } });
  assert.equal(result.publications, 2); assert.equal(result.polls, 2);
  assert.equal((await f.lines('published.ndjson')).length, 2); assert.equal((await f.lines('effects.ndjson')).length, 2);
});

test('actual CLI drains SIGTERM and retains historical decisions', async t => {
  const f = await fixture(t, 'sha1', { publish_delay: 200 }); await f.run();
  const run = child(f, 'serve'); t.after(() => { if (run.p.exitCode === null && run.p.signalCode === null) run.p.kill('SIGKILL'); });
  await waitFor(async () => (await f.lines('published.ndjson')).length === 1); run.p.kill('SIGTERM');
  const result = await run.done; assert.equal(result.code, 0, result.errors);
  const rows = result.output.trim().split('\n').map(JSON.parse); assert.equal(rows[0].outcome, 'committed'); assert.equal(rows.at(-1).stopped, true);
});

test('actual CLI SIGKILL retains the owner lock; status works but restart never steals it', async t => {
  const f = await fixture(t); await f.run(); const run = child(f, 'serve', ['--poll-millis', '60000']);
  t.after(() => { if (run.p.exitCode === null && run.p.signalCode === null) run.p.kill('SIGKILL'); });
  await waitFor(() => run.output.includes('workflow_check_observed')); run.p.kill('SIGKILL'); await run.done;
  const count = (await f.lines('calls.ndjson')).length;
  const restart = await child(f, 'once').done; assert.notEqual(restart.code, 0); assert.equal((await f.lines('calls.ndjson')).length, count);
  const view = await child(f, 'status').done; assert.equal(view.code, 0, view.errors); assert.equal(JSON.parse(view.output).owner_present, true);
});

test('output failure after publication retains its decision and the CLI reports delivery failure', async t => {
  const f = await fixture(t); await f.run(); let diagnostic = '';
  const stdout = new Writable({ write(_chunk, _encoding, callback) { callback(new Error('broken output')); } });
  const stderr = new Writable({ write(chunk, _encoding, callback) { diagnostic += chunk; callback(); } });
  const code = await main(['once', '--watch-config', f.watchFile, '--state', f.config.state_directory, '--principal-id', f.config.principal_id, '--trusted-local'], { stdout, stderr });
  assert.equal(code, 4); assert.equal(JSON.parse(diagnostic).retained_terminal.outcome, 'committed');
  assert.equal((await once(f.config)).publications, 0);
});

test('a CLI publication with a lost reply is exit 3, not a pre-admission input error', async t => {
  const f = await fixture(t, 'sha1', { drop_publication: true }); await f.run();
  const result = await child(f, 'once').done;
  assert.equal(result.code, 3, result.errors);
  assert.equal((await status(f.config)).runs[0].unknown, 1);
});

test('cancelling after one of several jobs retains its terminal and leaves later requests unsent', async t => {
  const f = await fixture(t, 'sha1', multiple); await f.run(); const stop = new AbortController();
  const result = await once(f.config, { signal: stop.signal, onObservation: () => stop.abort() });
  assert.equal(result.stopped, true); assert.equal(result.runs[0].committed, 1);
  assert.equal(result.runs[0].pending, 1); assert.equal(result.runs[0].unknown, 0);
  assert.equal((await f.lines('published.ndjson')).length, 1);
  assert.equal((await once(f.config)).runs[0].committed, 2);
});

test('a moved history snapshot cannot prepare a mixed job set', async t => {
  const f = await fixture(t, 'sha1', { ...multiple, recovery_page_size: 1, second_history_patch: { snapshot: `2048:${'8'.repeat(64)}` } });
  await f.run(); await assert.rejects(once(f.config), /snapshot moved/);
  assert.equal((await status(f.config)).runs.length, 0); assert.equal((await f.lines('published.ndjson')).length, 0);
});

test('acknowledged batches remain publishable observations; delivery never hides native history', async t => {
  const f = await fixture(t), run = await f.run(), path = join(run.directory, 'custody.json');
  const data = await json(path); data.history.entries[0].delivery = 'acknowledged';
  data.history.entries[0].delivery_receipt_sha256 = '8'.repeat(64); data.history.pending_batches = 0; await save(path, data);
  assert.equal((await once(f.config)).runs[0].committed, 1);
});

test('duplicated completed facts refuse before any publication', async t => {
  const f = await fixture(t), run = await f.run(), path = join(run.directory, 'custody.json');
  const data = await json(path);
  data.history.entries.push({ ...data.history.entries[0], ordinal: 1, batch_sha256: '8'.repeat(64) });
  data.history.retained_batches = data.history.pending_batches = 2; await save(path, data);
  await assert.rejects(once(f.config), /duplicated/); assert.equal((await f.lines('published.ndjson')).length, 0);
});

test('an empty completed-fact set cannot masquerade as a finished publication plan', async t => {
  const f = await fixture(t), run = await f.run(), path = join(run.directory, 'custody.json');
  const data = await json(path); data.history.entries[0].facts[0].status = 'in_progress'; await save(path, data);
  await assert.rejects(once(f.config), /omitted completed/); assert.equal((await f.lines('published.ndjson')).length, 0);
});

test('a self-consistent substituted marker still fails its selected execution binding', async t => {
  const f = await fixture(t), run = await f.run(), path = join(run.directory, 'attempt.json');
  const marker = await json(path); marker.executed_commit = `sha1:${'e'.repeat(40)}`; await save(path, marker);
  const data = await json(join(run.directory, 'custody.json')); data.history.scope.journal_id = sha256(await readFile(path));
  await save(join(run.directory, 'custody.json'), data);
  await assert.rejects(once(f.config), /marker changed/);
  assert.equal((await f.lines('calls.ndjson')).length, 2);
});

test('a changed minimum journal pin on resume is never silently refreshed', async t => {
  const f = await fixture(t, 'sha1', { drop_publication: true }), run = await f.run(); await assert.rejects(once(f.config));
  const path = join(run.directory, 'custody.json'), data = await json(path); data.history.snapshot = `72:${'9'.repeat(64)}`; await save(path, data);
  await f.set({ drop_publication: false }); await assert.rejects(once(f.config, { resume: true }));
  assert.equal((await status(f.config)).runs[0].unknown, 1);
  const calls = (await f.lines('calls.ndjson')).filter(args => args[1] === 'publish'); assert.deepEqual(calls[0], calls[1]);
});

test('native watchdog retains the owner and unresolved publication without replay', async t => {
  const f = await fixture(t, 'sha1', { publish_delay: 2000 }); await f.run();
  await assert.rejects(once(f.config, { timeoutMs: 300 }), error => error.containment_unknown && error.publication_unknown);
  const view = await status(f.config); assert.equal(view.owner_present, true); assert.equal(view.runs[0].unknown, 1);
  await assert.rejects(once(f.config, { resume: true }), error => error.code === 'EEXIST');
});

test('resume cannot prepare or publish a newly observed run', async t => {
  const f = await fixture(t); await f.run(); assert.equal((await once(f.config, { resume: true })).runs.length, 0);
  assert.equal((await f.lines('calls.ndjson')).length, 2);
});

test('unsafe or overlapping publication custody is refused before child operations', async t => {
  const f = await fixture(t); await f.run();
  assert.throws(() => configuration({ ...f.config, state_directory: f.watch.run_parent }), /disjoint/);
  assert.throws(() => configuration({ ...f.config, principal_id: 'not-a-principal' }), /principal/);
  const alias = join(f.root, 'alias'); await symlink(f.config.state_directory, alias);
  await assert.rejects(once({ ...f.config, state_directory: alias }), /symlink/);
  await chmod(f.config.state_directory, 0o755); await assert.rejects(once(f.config), /private/);
  assert.equal((await f.lines('calls.ndjson')).length, 2);
});

test('CLI rejects implicit publication, duplicate options and invalid budgets before native work', async t => {
  const f = await fixture(t); await f.run();
  for (const [operation, extra] of [['once', ['--poll-millis', '100']], ['status', ['--max-publications', '1']],
    ['serve', ['--max-polls', '0']], ['serve', ['--max-polls', '01']], ['once', ['--max-publications', '129']],
    ['serve', ['--max-polls', '1', '--max-polls', '2']]]) {
    const result = await child(f, operation, extra).done; assert.equal(result.code, 2, result.errors);
  }
  assert.equal((await f.lines('calls.ndjson')).length, 2);
});


test('receipt capacity refuses a new plan before admission while existing results stay readable', async t => {
  const f = await fixture(t); await f.run(); await once(f.config);
  const firstName = (await readdir(f.config.state_directory)).find(name => name.startsWith('plan-'));
  const original = await json(join(f.config.state_directory, firstName));
  let reserved = encode(f.config).length + encode(original).length + original.jobs.length * 2 * 8192;
  let seed = 0;
  // Seed valid private manifests, not native verification. Reserve for future
  // terminals even when those manifests have not sent any requests yet.
  while (true) {
    const watchId = sha256(Buffer.from(`capacity-${seed++}`));
    const plan = { ...original, watch_id: watchId, jobs: Array.from({ length: 128 }, (_, index) => {
      const job = { ...original.jobs[0], directory: join(f.watch.run_parent, `dispatch-${watchId.slice(0, 32)}`, 'workflow-' + 'a'.repeat(32)),
        fact_index: index, job: `reserved-job-${index}` };
      job.key = jobKey(sha256(encode(f.config)), watchId, job); return job;
    }) };
    const needed = encode(plan).length + plan.jobs.length * 2 * 8192;
    if (reserved + needed > 32 * 1024 * 1024) {
      const near = await status(f.config); assert.ok(near.runs.length > 1);
      await save(join(f.config.state_directory, `plan-${watchId}.json`), plan);
      const count = (await f.lines('calls.ndjson')).length;
      await assert.rejects(once(f.config), /receipt capacity/);
      assert.equal((await f.lines('calls.ndjson')).length, count, 'no admission when receipts could exceed recovery budget');
      await unlink(join(f.config.state_directory, `plan-${watchId}.json`));
      assert.equal((await status(f.config)).runs.find(run => run.id === original.watch_id).committed, 1);
      break;
    }
    await save(join(f.config.state_directory, `plan-${watchId}.json`), plan); reserved += needed;
  }
});


test('native mixed lifecycle batches retain the completed fact index rather than assuming zero', async t => {
  const f = await fixture(t), run = await f.run();
  const path = join(run.directory, 'custody.json'), custody = await json(path), entry = custody.history.entries[0];
  const complete = entry.facts[0];
  entry.facts = [{ ...complete, status: 'queued', conclusion: null, evidence_sha256: null },
    { ...complete, status: 'in_progress', conclusion: null, evidence_sha256: null }, complete];
  await save(path, custody);
  assert.equal((await once(f.config)).runs[0].committed, 1);
  const args = (await f.lines('calls.ndjson')).find(args => args[1] === 'publish');
  assert.equal(args[args.indexOf('--fact-index') + 1], '2');
});

for (const impossible of ['success', 'neutral']) test(`trusted custody cannot advertise native-forbidden ${impossible} conclusions`, async t => {
  const f = await fixture(t), run = await f.run(), path = join(run.directory, 'custody.json');
  const custody = await json(path); custody.history.entries[0].facts[0].conclusion = impossible; await save(path, custody);
  await assert.rejects(once(f.config), /Completed native workflow fact/);
  assert.equal((await f.lines('published.ndjson')).length, 0);
});


// Exercise the publisher's real dispatchReport boundary, not merely a stale
// outer digest. Consistently rewrite the local report hash as well: missing or
// substituted artifact evidence must still stop BEFORE a native publication.
for (const format of ['sha1', 'sha256']) {
  for (const [name, mutate] of [
    ['missing capture', run => { run.artifacts = []; }],
    ['missing delivery', run => { run.artifact_inputs = []; }],
    ['substituted producer manifest', run => { run.artifact_inputs[0].inputs[0].producer_manifest_id_sha256 = '0'.repeat(64); }],
  ]) test(`${format}: ${name} cannot reach check publication even with a matching saved report hash`, async t => {
    const f = await fixture(t, format, {}, true), run = await f.run();
    const reportPath = join(run.observation.native_directory, 'report.json');
    const resultPath = join(f.watch.state_directory, `result-${run.observation.id}.json`);
    const originalReport = await readFile(reportPath), originalResult = await readFile(resultPath);
    const markerPath = join(run.directory, 'attempt.json'), marker = await readFile(markerPath);
    const custodyPath = join(run.directory, 'custody.json'), custody = await readFile(custodyPath);
    const report = JSON.parse(originalReport), completion = JSON.parse(originalResult);
    mutate(report.runs[0]);
    completion.report_sha256 = sha256(encode(report));
    await save(reportPath, report); await save(resultPath, completion);
    const calls = (await f.lines('calls.ndjson')).length;
    await assert.rejects(once(f.config), /artifact/i);
    assert.equal((await f.lines('calls.ndjson')).length, calls, 'refuse before native recovery or publication');
    assert.equal((await f.lines('published.ndjson')).length, 0);
    assert.equal((await status(f.config)).runs.length, 0, 'no publishable plan is retained');
    assert.deepEqual(await readFile(markerPath), marker);
    assert.deepEqual(await readFile(custodyPath), custody);
    await writeFile(reportPath, originalReport); await writeFile(resultPath, originalResult);
    assert.equal((await once(f.config)).publications, 2, 'the unchanged complete attempt remains publishable');
    assert.equal((await once(f.config)).publications, 0, 'publication never reexecutes the workflow');
    assert.equal((await f.lines('effects.ndjson')).length, 1);
  });
}
