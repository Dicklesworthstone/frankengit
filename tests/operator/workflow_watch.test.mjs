// Actual filesystem/process tests against an explicit native-schema peer, not fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, chmod, readdir, symlink, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_workflow_watch.mjs';
import { configuration, once, status, reconcile, serve } from '../../scripts/operator/workflow_watch.mjs';

const hex = value => Buffer.from(value).toString('hex');
const peer = await readFile(new URL('./fixtures/workflow_watch_native.mjs', import.meta.url), 'utf8');
const cli = new URL('../../scripts/fg_workflow_watch.mjs', import.meta.url).pathname;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function fixture(t, format = 'sha1', patch = {}, configPatch = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-watch-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const name of ['store', 'state', 'runs']) await mkdir(join(root, name), { mode: 0o700 });
  const fg = join(root, 'fg'); await writeFile(fg, `#!${process.execPath}\n${peer}`, { mode: 0o700 });
  const config = configuration({ schema: 'frankengit-workflow-watch-v1', fg, storage_root: join(root, 'store'),
    tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format,
    ref_hex: hex('refs/heads/main'), workflow_directory_hex: hex('.github/workflows'), input_prefixes_hex: [hex('src'), hex('.github')],
    event: 'push', state_directory: join(root, 'state'), run_parent: join(root, 'runs'), max_runs: 16,
    trust: 'selected-branch-host-execution', ...configPatch });
  let control = { tenant: config.tenant_id, repository: config.repository_id, incarnation: config.repository_incarnation,
    format, ref_hex: config.ref_hex, commit: 'a'.repeat(format === 'sha1' ? 40 : 64),
    source_head: 'fixture-source-head', snapshot: `alg:2:${'4'.repeat(64)}`, ...patch };
  const configFile = join(root, 'config.json'); await writeFile(configFile, JSON.stringify(config), { mode: 0o600 });
  const set = async patch => { control = { ...control, ...patch }; await writeFile(join(root, 'store/control.json'), JSON.stringify(control), { mode: 0o600 }); };
  await set({});
  const lines = async name => { try { return (await readFile(join(root, 'store', name), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); } catch (e) { if (e.code === 'ENOENT') return []; throw e; } };
  return { root, config, configFile, set, lines, get control() { return control; } };
}
async function waitFor(check) {
  for (let i = 0; i < 300; i++) { if (await check()) return; await sleep(10); }
  throw new Error('condition did not arrive');
}
function child(args) {
  const p = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', errors = ''; p.stdout.on('data', b => { output += b; }); p.stderr.on('data', b => { errors += b; });
  const done = new Promise((resolve, reject) => { p.once('error', reject); p.once('close', (code, signal) => resolve({ code, signal, output, errors })); });
  return { p, done, get output() { return output; } };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: new observed tip dispatches pinned native code, persists result, and is never replayed`, async t => {
    const f = await fixture(t, format), result = await once(f.config);
    assert.equal(result.outcome, 'observed_succeeded'); assert.equal(result.authoritative_check, false);
    const calls = await f.lines('calls.ndjson'); assert.equal(calls.length, 2);
    const args = calls[1], get = key => args[args.indexOf(key) + 1];
    assert.deepEqual(args.slice(0, 6), ['workflow', 'dispatch', f.config.storage_root, f.config.tenant_id, f.config.repository_id, hex('refs/heads/main')]);
    for (const [key, value] of Object.entries({ '--event': 'push', '--expected-head': f.control.snapshot, '--expected-commit': f.control.commit,
      '--expected-incarnation': f.config.repository_incarnation, '--object-format': format, '--workflow-hex': hex('.github/workflows') })) assert.equal(get(key), value);
    assert.ok(args.includes('--trusted-local') && args.includes('--ref-hex'));
    assert.equal(get('--run-id'), result.id.slice(0, 32));
    const files = await readdir(f.config.state_directory);
    assert.equal(files.filter(n => n.startsWith('intent-')).length, 1);
    assert.equal(files.filter(n => n.startsWith('started-')).length, 1);
    assert.equal(files.filter(n => n.startsWith('result-')).length, 1);
    assert.equal(files.includes('owner.lock'), false);
    assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal((await f.lines('effects.ndjson')).length, 1);
    await f.set({ source_head: 'later-metadata-only-head', snapshot: `alg:2:${'5'.repeat(64)}` });
    assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal((await f.lines('effects.ndjson')).length, 1);
  });
  test(`${format}: a new commit runs, returning to an old commit does not duplicate its effects`, async t => {
    const f = await fixture(t, format), first = await once(f.config), old = f.control.commit;
    await f.set({ commit: 'e'.repeat(old.length), source_head: 'new-head', snapshot: `alg:2:${'5'.repeat(64)}` });
    const next = await once(f.config); assert.notEqual(first.id, next.id);
    await f.set({ commit: old }); assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal((await f.lines('effects.ndjson')).length, 2);
  });
  test(`${format}: no-match and job failure remain explicit non-authoritative observations`, async t => {
    const empty = await fixture(t, format, { no_match: true });
    const report = await once(empty.config); assert.equal(report.outcome, 'no_matching_workflows'); assert.equal(report.matched_count, 0);
    const failed = await fixture(t, format, { job_failure: true });
    assert.equal((await once(failed.config)).outcome, 'observed_failed');
    assert.equal((await once(failed.config)).reason, 'commit_already_observed');
  });
  test(`${format}: lost stdout recovers the original saved report without running again`, async t => {
    const f = await fixture(t, format, { drop_stdout: true });
    await assert.rejects(once(f.config), /Dispatch unresolved/);
    assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
    const calls = (await f.lines('calls.ndjson')).length;
    await assert.rejects(once(f.config), /unresolved/);
    assert.equal((await f.lines('calls.ndjson')).length, calls);
    const recovered = await reconcile(f.config); assert.equal(recovered.records[0].state, 'observed_succeeded');
    assert.equal((await f.lines('calls.ndjson')).length, calls, 'reconcile performs no child execution');
    assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal((await f.lines('effects.ndjson')).length, 1);
  });
}

test('missing branch is idle, whereas read refusal cannot be fabricated into absence', async t => {
  const f = await fixture(t, 'sha1', { references: [] });
  assert.equal((await once(f.config)).reason, 'branch_unavailable');
  assert.equal((await f.lines('effects.ndjson')).length, 0);
  await f.set({ read_fail: true }); await assert.rejects(once(f.config), /observation unavailable/);
  assert.equal((await status(f.config)).records.length, 0);
});

test('bounded reference pagination retains exact head and raw ref coordinates', async t => {
  const ref = hex('refs/heads/zz\u00e9'), f = await fixture(t, 'sha1', {}, { ref_hex: ref });
  const rows = Array.from({ length: 100 }, (_, i) => ({ reference_hex: hex(`refs/heads/a${String(i).padStart(3, '0')}`), tip: `sha1:${'c'.repeat(40)}` }));
  rows.push({ reference_hex: ref, tip: `sha1:${f.control.commit}` }); await f.set({ references: rows });
  await once(f.config);
  const calls = await f.lines('calls.ndjson'); assert.equal(calls.length, 3);
  const second = calls[1]; assert.equal(second[second.indexOf('--expected-head') + 1], f.control.snapshot);
  assert.equal(second[second.indexOf('--after-hex') + 1], rows[99].reference_hex);
  const other = await fixture(t, 'sha1', { references: rows, later_page_patch: { snapshot_token: `alg:2:${'6'.repeat(64)}` } }, { ref_hex: ref });
  await assert.rejects(once(other.config), /snapshot moved/); assert.equal((await other.lines('effects.ndjson')).length, 0);
});

test('byte-only native ref/workflow names are passed as hex, never decoded into arguments', async t => {
  const f = await fixture(t, 'sha1', {}, { ref_hex: `${hex('refs/heads/')}ff`, workflow_directory_hex: `${hex('.github/')}fe` });
  assert.equal((await once(f.config)).outcome, 'observed_succeeded');
  const args = (await f.lines('calls.ndjson'))[1]; assert.equal(args[5], f.config.ref_hex);
});

for (const patch of [
  { page_patch: { tenant_id: '9'.repeat(32) } }, { page_patch: { node_closed: false } },
  { page_patch: { has_more: true, next_after_hex: hex('refs/heads/main') } },
  { page_patch: { references: [{ reference_hex: hex('refs/heads/main'), tip: `sha256:${'a'.repeat(64)}` }] } },
]) test(`malformed or foreign reference observation refuses before native execution: ${JSON.stringify(patch)}`, async t => {
  const f = await fixture(t, 'sha1', patch);
  await assert.rejects(once(f.config)); assert.equal((await f.lines('effects.ndjson')).length, 0);
});

for (const patch of [
  { plan_patch: { repository_incarnation: '9'.repeat(32) } }, { plan_patch: { source_head: 'different' } },
  { plan_patch: { published: true } }, { plan_patch: { read_prefixes_hex: [] } },
  { report_patch: { executed_count: 0 } }, { report_patch: { stop_reason: 'containment_unproved' } },
  { run_patch: { workspaces_closed: false } }, { run_patch: { authoritative_check: true } },
  { run_patch: { request_interrupted: true } }, { run_patch: { run_id: '8'.repeat(32) } },
  { exit_code: 1 },
]) test(`native report mismatch leaves original responsibility pending: ${JSON.stringify(patch)}`, async t => {
  const f = await fixture(t, 'sha1', patch);
  await assert.rejects(once(f.config));
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
  await assert.rejects(once(f.config), /unresolved/);
  assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('native refuses a moved expected head; watcher never refreshes the original execution intent', async t => {
  const f = await fixture(t, 'sha1', { change_after_read: { snapshot: `alg:2:${'9'.repeat(64)}`, source_head: 'new' } });
  await assert.rejects(once(f.config), /Dispatch unresolved/);
  assert.equal((await f.lines('effects.ndjson')).length, 0);
  await reconcile(f.config);
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
  await assert.rejects(once(f.config), /unresolved/);
});

test('absent report after execution blocks every later commit, including after process restart', async t => {
  const f = await fixture(t, 'sha1', { no_report: true }); await assert.rejects(once(f.config));
  await f.set({ no_report: false, commit: 'e'.repeat(40) });
  assert.equal((await reconcile(f.config)).records[0].state, 'execution_unknown');
  const run = await child(['once', '--config', f.configFile, '--trusted-local']).done;
  assert.equal(run.code, 3); assert.match(run.errors, /unresolved/);
  assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('two concurrent owners cannot dispatch a second execution', async t => {
  const f = await fixture(t, 'sha1', { dispatch_delay: 150 });
  const first = once(f.config); await waitFor(async () => (await f.lines('effects.ndjson')).length === 1);
  await assert.rejects(once(f.config), error => error.code === 'EEXIST');
  await first; assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('signal cancellation drains a started native process and keeps its terminal report', async t => {
  const f = await fixture(t, 'sha1', { dispatch_delay: 200 }), stop = new AbortController();
  const first = once(f.config, { signal: stop.signal });
  await waitFor(async () => (await f.lines('effects.ndjson')).length === 1); stop.abort();
  assert.equal((await first).outcome, 'observed_succeeded');
  assert.equal((await status(f.config)).owner_present, false);
});

test('watchdog failure retains owner lock and cannot be mistaken for child containment', async t => {
  const f = await fixture(t, 'sha1', { dispatch_delay: 1000 });
  await assert.rejects(once(f.config, { dispatchTimeoutMs: 100 }), error => error.containment_unknown === true);
  const state = await status(f.config); assert.equal(state.owner_present, true); assert.equal(state.records[0].state, 'execution_unknown');
  await assert.rejects(once(f.config), error => error.code === 'EEXIST');
});

test('pre-aborted requests cannot spawn a child or create execution responsibility', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(once(f.config, { signal: stop.signal }));
  assert.equal((await f.lines('calls.ndjson')).length, 0); assert.equal((await status(f.config)).records.length, 0);
});

test('configuration mutation, exhausted capacity and unsafe custody do not create a new run namespace', async t => {
  const f = await fixture(t, 'sha1', {}, { max_runs: 1 }); await once(f.config);
  await assert.rejects(once({ ...f.config, event: 'workflow_dispatch' }), /configuration changed/);
  await f.set({ commit: 'e'.repeat(40) }); await assert.rejects(once(f.config), /capacity/);
  assert.equal((await f.lines('effects.ndjson')).length, 1);
  await chmod(f.config.state_directory, 0o755); await assert.rejects(once(f.config), /private/);
  await chmod(f.config.state_directory, 0o700);
  const alias = join(f.root, 'alias'); await symlink(f.config.state_directory, alias);
  await assert.rejects(once({ ...f.config, state_directory: alias }), /symlink/);
});

test('config trust, byte paths and independent directory bounds are mandatory', async t => {
  const f = await fixture(t);
  for (const patch of [{ trust: 'yes' }, { event: 'pull_request' }, { object_format: 'sha512' }, { max_runs: 0 },
    { run_parent: f.config.state_directory }, { storage_root: '/' }, { input_prefixes_hex: [hex('src')] }, { input_prefixes_hex: [hex('.github'), hex('.github')] },
    { ref_hex: hex('refs/heads/a/../main') }, { ref_hex: hex('refs/tags/main') }, { workflow_directory_hex: hex('.github/.git/x') },
    { unknown: true }]) assert.throws(() => configuration({ ...f.config, ...patch }));
});

test('actual CLI emits a machine-readable result and requires explicit trusted-local invocation', async t => {
  const f = await fixture(t);
  const bad = await child(['once', '--config', f.configFile]).done; assert.equal(bad.code, 2);
  assert.equal((await f.lines('calls.ndjson')).length, 0);
  const good = await child(['once', '--config', f.configFile, '--trusted-local']).done;
  assert.equal(good.code, 0, good.errors); assert.equal(JSON.parse(good.output).outcome, 'observed_succeeded');
  const view = await child(['status', '--config', f.configFile, '--trusted-local']).done;
  assert.equal(view.code, 0); assert.equal(JSON.parse(view.output).records.length, 1);
});

test('continuous service executes new tips, deduplicates idle polls and retains one owner', async t => {
  const f = await fixture(t), events = [];
  const result = await serve(f.config, { pollMs: 100, maxPolls: 3, onObservation: async event => {
    events.push(event); assert.equal((await status(f.config)).owner_present, true);
    if (events.length === 1) await f.set({ commit: 'e'.repeat(40), source_head: 'second-head', snapshot: `alg:2:${'7'.repeat(64)}` });
  } });
  assert.equal(result.polls, 3); assert.equal(result.runs, 2); assert.equal(result.idle_polls, 1);
  assert.equal(result.poll_limit_reached, true); assert.equal(result.execution_retried, false);
  assert.equal((await f.lines('effects.ndjson')).length, 2);
  assert.equal((await status(f.config)).owner_present, false);
});

test('ordinary failed jobs do not prevent a later tip from running', async t => {
  const f = await fixture(t, 'sha256', { job_failure: true });
  const result = await serve(f.config, { pollMs: 100, maxPolls: 2, onObservation: async event => {
    if (event.outcome === 'observed_failed') await f.set({ job_failure: false, commit: 'e'.repeat(64) });
  } });
  assert.equal(result.runs, 2); assert.equal(result.failed_runs, 1);
  assert.equal((await f.lines('effects.ndjson')).length, 2);
});

test('only observation reads receive bounded automatic retries', async t => {
  const f = await fixture(t, 'sha1', { read_fail: true }), events = [];
  const result = await serve(f.config, { pollMs: 100, maxPolls: 3, onObservation: async event => {
    events.push(event); if (event.type === 'workflow_watch_observation_unavailable') await f.set({ read_fail: false });
  } });
  assert.equal(result.read_failures, 1); assert.equal(result.runs, 1); assert.equal(result.idle_polls, 1);
  assert.equal(events[0].execution_started, false); assert.ok(events[0].native_stderr_hex);
  assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('three consecutive native observation failures stop the service, without execution', async t => {
  const f = await fixture(t, 'sha1', { read_fail: true }), events = [];
  await assert.rejects(serve(f.config, { pollMs: 100, maxPolls: 10, onObservation: event => events.push(event) }), /observation unavailable/);
  assert.equal(events.length, 2); assert.equal((await f.lines('calls.ndjson')).length, 3);
  assert.equal((await f.lines('effects.ndjson')).length, 0);
});

test('continuous service does not retry execution failures as observation failures', async t => {
  const f = await fixture(t, 'sha1', { no_report: true });
  await assert.rejects(serve(f.config, { pollMs: 100, maxPolls: 100 }), /Dispatch unresolved/);
  assert.equal((await f.lines('calls.ndjson')).length, 2);
  assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('observer failure is fatal after the completed run has been durably retained', async t => {
  const f = await fixture(t);
  await assert.rejects(serve(f.config, { pollMs: 100, maxPolls: 10, onObservation: () => { throw new Error('output lost'); } }),
    error => error.message === 'output lost' && error.retained_observation.outcome === 'observed_succeeded');
  assert.equal((await status(f.config)).records[0].state, 'observed_succeeded');
  assert.equal((await once(f.config)).reason, 'commit_already_observed');
  assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('stop during polling releases the owner without another native read', async t => {
  const f = await fixture(t), stop = new AbortController();
  const result = await serve(f.config, { signal: stop.signal, pollMs: 60000, onObservation: () => { stop.abort(); } });
  assert.equal(result.stopped, true); assert.equal(result.polls, 1);
  assert.equal((await f.lines('calls.ndjson')).length, 2);
  assert.equal((await status(f.config)).owner_present, false);
});

test('queued pre-execution intent resumes at its original pins without another source observation', async t => {
  const f = await fixture(t, 'sha1', { read_fail: true });
  const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
  const digest = bytes => createHash('sha256').update(bytes).digest('hex');
  const configuration_sha256 = digest(encode(f.config));
  const id = digest(Buffer.from(`frankengit/workflow-watch-observed-commit/v1\0${configuration_sha256}\0${f.control.commit}`));
  const intent = { schema: 'frankengit-workflow-watch-intent-v1', id, configuration_sha256,
    run_id: id.slice(0, 32), snapshot_token: f.control.snapshot, source_head: f.control.source_head,
    commit: f.control.commit, trigger_provenance: 'observed_branch_tip_not_push_event' };
  await writeFile(join(f.config.state_directory, 'binding.json'), encode(f.config), { mode: 0o600 });
  await writeFile(join(f.config.state_directory, `intent-${id}.json`), encode(intent), { mode: 0o600 });
  assert.equal((await once(f.config)).outcome, 'observed_succeeded');
  const calls = await f.lines('calls.ndjson'); assert.equal(calls.length, 1); assert.equal(calls[0][0], 'workflow');
});

test('corrupt local summary cannot gain check authority or alter complete-run accounting', async t => {
  const f = await fixture(t), result = await once(f.config), path = join(f.config.state_directory, `result-${result.id}.json`);
  const saved = JSON.parse(await readFile(path, 'utf8'));
  for (const patch of [{ authoritative_check: true }, { executed_count: 0 }, { outcome: 'no_matching_workflows' }]) {
    await writeFile(path, JSON.stringify({ ...saved, ...patch }));
    await assert.rejects(once(f.config), /custody/);
  }
  assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('actual CLI SIGTERM drains active native dispatch and exits with retained observation', async t => {
  const f = await fixture(t, 'sha1', { dispatch_delay: 300 });
  const run = child(['serve', '--config', f.configFile, '--trusted-local', '--poll-millis', '100', '--max-polls', '20']);
  t.after(() => { if (run.p.exitCode === null && run.p.signalCode === null) run.p.kill('SIGKILL'); });
  await waitFor(async () => (await f.lines('effects.ndjson')).length === 1);
  run.p.kill('SIGTERM'); const done = await run.done;
  assert.equal(done.code, 0, done.errors);
  const output = done.output.trim().split('\n').map(JSON.parse);
  assert.equal(output[0].outcome, 'observed_succeeded'); assert.equal(output.at(-1).stopped, true);
  assert.equal((await status(f.config)).owner_present, false);
  assert.equal((await f.lines('calls.ndjson')).length, 2);
});

test('actual CLI SIGKILL between polls retains the owner lock; restart never steals it', async t => {
  const f = await fixture(t);
  const run = child(['serve', '--config', f.configFile, '--trusted-local', '--poll-millis', '60000']);
  t.after(() => { if (run.p.exitCode === null && run.p.signalCode === null) run.p.kill('SIGKILL'); });
  // The progress row is written only after the native child and pipes close.
  await waitFor(() => run.output.includes('workflow_watch_result'));
  run.p.kill('SIGKILL'); assert.equal((await run.done).signal, 'SIGKILL');
  assert.equal((await status(f.config)).owner_present, true);
  const before = (await f.lines('calls.ndjson')).length;
  const restarted = await child(['serve', '--config', f.configFile, '--trusted-local', '--max-polls', '1']).done;
  assert.notEqual(restarted.code, 0); assert.equal((await f.lines('calls.ndjson')).length, before);
  assert.equal((await reconcile(f.config)).records[0].state, 'observed_succeeded');
  assert.equal((await status(f.config)).owner_present, true);
});

test('CLI output failure after native completion retains the result and reports delivery failure', async t => {
  const f = await fixture(t); let diagnostic = '';
  const stdout = new Writable({ write(_chunk, _encoding, callback) { callback(Object.assign(new Error('broken output'), { code: 'EPIPE' })); } });
  const stderr = new Writable({ write(chunk, _encoding, callback) { diagnostic += chunk; callback(); } });
  const code = await main(['once', '--config', f.configFile, '--trusted-local'], { stdout, stderr });
  assert.equal(code, 2);
  assert.equal(JSON.parse(diagnostic).retained_observation.outcome, 'observed_succeeded');
  assert.equal((await once(f.config)).reason, 'commit_already_observed');
  assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('CLI serve validates loop limits and refuses duplicate or inapplicable options', async t => {
  const f = await fixture(t);
  for (const extra of [['--poll-millis', '99'], ['--max-polls', '1000001'], ['--max-polls', '01'],
    ['--max-polls', '1', '--max-polls', '2'], ['--retry', '1']]) {
    const result = await child(['serve', '--config', f.configFile, '--trusted-local', ...extra]).done;
    assert.equal(result.code, 2, result.output);
  }
  assert.equal((await f.lines('calls.ndjson')).length, 0);
  const bounded = await child(['serve', '--config', f.configFile, '--trusted-local', '--max-polls', '1']).done;
  assert.equal(bounded.code, 0, bounded.errors);
  const rows = bounded.output.trim().split('\n').map(JSON.parse);
  assert.equal(rows.length, 2); assert.equal(rows[1].poll_limit_reached, true);
});

test('offline status and report reconciliation survive loss of the native executable and source store', async t => {
  const f = await fixture(t, 'sha1', { drop_stdout: true });
  await assert.rejects(once(f.config), /Dispatch unresolved/);
  await unlink(f.config.fg); await rm(f.config.storage_root, { recursive: true });
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
  assert.equal((await reconcile(f.config)).records[0].state, 'observed_succeeded');
  await assert.rejects(once(f.config));
});

test('pagination shares a whole-observation deadline rather than refreshing it per page', async t => {
  const f = await fixture(t, 'sha1', { read_delay: 100 }, { ref_hex: hex('refs/heads/zzzz') });
  const rows = Array.from({ length: 500 }, (_, i) => ({ reference_hex: hex(`refs/heads/a${String(i).padStart(3, '0')}`), tip: `sha1:${'c'.repeat(40)}` }));
  rows.push({ reference_hex: f.config.ref_hex, tip: `sha1:${f.control.commit}` }); await f.set({ references: rows });
  await assert.rejects(once(f.config, { readTimeoutMs: 170 }), /deadline|observation unavailable/);
  assert.equal((await f.lines('effects.ndjson')).length, 0);
  assert.ok((await f.lines('calls.ndjson')).length < 6, 'deadline prevents a full six-page scan');
});

for (const reason of ['request_stopped', 'output_budget_exhausted', 'workflow_refused', 'workflow_timed_out', 'workflow_output_limit']) {
  test(`native ${reason} with closed workspaces settles as non-green and allows a later commit`, async t => {
    const f = await fixture(t, 'sha1', { job_failure: true, report_patch: { stop_reason: reason }, run_patch: { request_interrupted: reason === 'request_stopped' } });
    const first = await once(f.config); assert.equal(first.outcome, 'observed_stopped'); assert.equal(first.stop_reason, reason);
    assert.equal(first.authoritative_check, false); assert.equal((await once(f.config)).reason, 'commit_already_observed');
    await f.set({ commit: 'e'.repeat(40), job_failure: false, report_patch: null, run_patch: null });
    assert.equal((await once(f.config)).outcome, 'observed_succeeded');
    assert.equal((await f.lines('effects.ndjson')).length, 2);
  });
}

test('explicitly stopped unstarted children are counted, never silently resumed', async t => {
  const f = await fixture(t, 'sha1', { job_failure: true, report_patch: { stop_reason: 'request_stopped', runs: [], executed_count: 0 } });
  const result = await once(f.config); assert.equal(result.outcome, 'observed_stopped');
  assert.equal(result.matched_count, 1); assert.equal(result.executed_count, 0);
  const view = await status(f.config); assert.equal(view.records[0].unstarted_workflows, 1);
  assert.equal((await once(f.config)).reason, 'commit_already_observed');
});

for (const patch of [
  { report_patch: { stop_reason: 'new_unknown_reason', succeeded: false } },
  { report_patch: { stop_reason: 'workflow_timed_out', succeeded: true } },
  { report_patch: { stop_reason: 'workflow_timed_out', succeeded: false }, run_patch: { workspaces_closed: false } },
]) test(`stopped reports cannot hide uncertainty or claim success: ${JSON.stringify(patch)}`, async t => {
  const f = await fixture(t, 'sha1', patch); await assert.rejects(once(f.config));
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
});

test('settled native stops contribute to service non-green summary and CLI exit', async t => {
  const f = await fixture(t, 'sha1', { job_failure: true, report_patch: { stop_reason: 'workflow_timed_out' } });
  const run = await child(['serve', '--config', f.configFile, '--trusted-local', '--max-polls', '1']).done;
  assert.equal(run.code, 1, run.errors);
  const rows = run.output.trim().split('\n').map(JSON.parse);
  assert.equal(rows[0].outcome, 'observed_stopped'); assert.equal(rows[1].stopped_runs, 1);
});

for (const patch of [
  { step_patch: { workspace_retained: true } }, { step_patch: { outcome: 'containment_failure' } },
  { execution_patch: { authoritative_check: true } }, { execution_patch: { jobs: [], succeeded: true } },
  { execution_patch: { profile: 'unregistered-sandbox' } }, { step_patch: { output_complete: false } },
  { step_patch: { exit_code: 1 } },
]) test(`native job evidence is checked beneath top-level success: ${JSON.stringify(patch)}`, async t => {
  const f = await fixture(t, 'sha1', patch); await assert.rejects(once(f.config));
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
  assert.equal((await f.lines('effects.ndjson')).length, 1);
});

test('even a recognized timeout cannot conceal a retained native step workspace', async t => {
  const f = await fixture(t, 'sha1', { job_failure: true, report_patch: { stop_reason: 'workflow_timed_out' }, step_patch: { workspace_retained: true } });
  await assert.rejects(once(f.config), /containment/);
  await assert.rejects(reconcile(f.config), /containment/);
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
});
