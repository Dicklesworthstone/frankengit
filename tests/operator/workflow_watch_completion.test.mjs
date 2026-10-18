// Real operator/custody/process tests with the existing native-schema peer.
// The peer is not Rust fg and this suite does not establish canonical admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, rename, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { main as watcherMain } from '../../scripts/fg_workflow_watch.mjs';
import { Writable } from 'node:stream';
import { configuration, dispatchReport, once, reconcile, serve, status } from '../../scripts/operator/workflow_watch.mjs';

const peer = await readFile(new URL('./fixtures/workflow_watch_native.mjs', import.meta.url), 'utf8');
const moduleUrl = new URL('../../scripts/operator/workflow_watch.mjs', import.meta.url).href;
const hex = value => Buffer.from(value).toString('hex');
const sha256 = value => createHash('sha256').update(value).digest('hex');
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const outcomes = ['succeeded', 'skipped', 'failed', 'cancelled', 'timed_out', 'output_limit', 'refused'];

function job(id, outcome = 'succeeded') {
  return { id, outcome, failure: null, steps: outcome === 'skipped' || outcome === 'refused' ? [] : [{
    index: 0, name: null, script: `alg:2:${'f'.repeat(64)}`, outcome,
    exit_code: outcome === 'succeeded' ? 0 : outcome === 'failed' ? 7 : null,
    stdout_hex: '', stderr_hex: '', elapsed_millis: 1, output_complete: true, workspace_retained: false,
  }] };
}
const mixedJobs = () => [job('build__matrix_000'), job('build__matrix_001'), job('diagnostics', 'skipped'), job('package')];
function reportPatch(jobs, succeeded, stopped = false) {
  return {
    execution_patch: { jobs, succeeded: jobs.length > 0 && jobs.every(value => value.outcome === 'succeeded') },
    run_patch: { succeeded, request_interrupted: stopped },
    report_patch: { succeeded: stopped ? false : succeeded, stop_reason: stopped ? 'request_stopped' : null },
  };
}
async function fixture(t, format, patch = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-watch-completion-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const name of ['store', 'state', 'runs']) await mkdir(join(root, name), { mode: 0o700 });
  const fg = join(root, 'fg');
  await writeFile(fg, `#!${process.execPath}\n${peer}`, { mode: 0o700 });
  const config = configuration({ schema: 'frankengit-workflow-watch-v1', fg, storage_root: join(root, 'store'),
    tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format,
    ref_hex: hex('refs/heads/main'), workflow_directory_hex: hex('.github/workflows'), input_prefixes_hex: [hex('.github'), hex('src')],
    event: 'push', state_directory: join(root, 'state'), run_parent: join(root, 'runs'), max_runs: 16,
    trust: 'selected-branch-host-execution' });
  await writeFile(join(root, 'store/control.json'), encode({ tenant: config.tenant_id, repository: config.repository_id,
    incarnation: config.repository_incarnation, format, ref_hex: config.ref_hex,
    commit: 'a'.repeat(format === 'sha1' ? 40 : 64), source_head: 'fixture-source-head', snapshot: `alg:2:${'4'.repeat(64)}`, ...patch }), { mode: 0o600 });
  const lines = async name => {
    try { return (await readFile(join(root, 'store', name), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  };
  const saved = async () => {
    const state = await status(config), id = state.records[0].id;
    const intent = JSON.parse(await readFile(join(config.state_directory, `intent-${id}.json`)));
    const path = join(state.records[0].native_directory, 'report.json');
    const bytes = await readFile(path);
    return { id, intent, path, bytes, report: JSON.parse(bytes), resultPath: join(config.state_directory, `result-${id}.json`) };
  };
  return { root, config, lines, saved };
}
async function newReader(config) {
  const script = `import { reconcile } from ${JSON.stringify(moduleUrl)}; process.stdout.write(JSON.stringify(await reconcile(JSON.parse(process.argv[1]))));`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, JSON.stringify(config)], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
  try {
    const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
    assert.equal(code, 0, stderr);
    return JSON.parse(stdout);
  } finally { clearTimeout(timer); }
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: conditional success reaches durable watcher completion without changing legacy evidence`, async t => {
    const f = await fixture(t, format, reportPatch(mixedJobs(), true));
    const result = await once(f.config);
    assert.equal(result.outcome, 'observed_succeeded');
    const saved = await f.saved(), before = structuredClone(saved.report);
    assert.equal(saved.report.runs[0].succeeded, true);
    assert.equal(saved.report.runs[0].execution.succeeded, false);
    assert.equal(saved.report.runs[0].execution.jobs[2].outcome, 'skipped');
    assert.equal(result.report_sha256, sha256(saved.bytes));
    assert.equal(result.authoritative_check, false);
    const originalResult = await readFile(saved.resultPath);
    for (let i = 0; i < 4; i++) {
      assert.deepEqual(dispatchReport(f.config, saved.intent, saved.report), JSON.parse(originalResult));
      assert.deepEqual(saved.report, before, 'validation must not normalize recorded booleans or job evidence');
    }
    assert.equal((await reconcile(f.config)).records[0].state, 'observed_succeeded');
    assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal((await f.lines('effects.ndjson')).length, 1);
    assert.deepEqual(await readFile(saved.path), saved.bytes);
    assert.deepEqual(await readFile(saved.resultPath), originalResult);
    assert.equal((await status(f.config)).owner_present, false);
  });

  test(`${format}: historical mixed-job failure retains its exact outcome, hash and execution identity`, async t => {
    const f = await fixture(t, format, reportPatch(mixedJobs(), false));
    const result = await once(f.config), saved = await f.saved(), originalResult = await readFile(saved.resultPath);
    assert.equal(result.outcome, 'observed_failed');
    assert.equal(result.report_sha256, sha256(saved.bytes));
    assert.equal((await reconcile(f.config)).records[0].state, 'observed_failed');
    assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal((await f.lines('effects.ndjson')).length, 1);
    assert.deepEqual(await readFile(saved.resultPath), originalResult);
    assert.deepEqual(await readFile(saved.path), saved.bytes);
    await unlink(f.config.fg); await rename(f.config.storage_root, `${f.config.storage_root}-offline`);
    assert.equal((await newReader(f.config)).records[0].state, 'observed_failed');
    assert.deepEqual(await readFile(saved.resultPath), originalResult);
  });

  test(`${format}: previously stranded conditional success reconciles without native execution or source access`, async t => {
    const f = await fixture(t, format, { ...reportPatch(mixedJobs(), true), drop_stdout: true });
    await assert.rejects(once(f.config), /Dispatch unresolved/);
    assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
    const saved = await f.saved();
    await assert.rejects(once(f.config), /unresolved/);
    assert.equal((await f.lines('effects.ndjson')).length, 1);
    await unlink(f.config.fg); await rename(f.config.storage_root, `${f.config.storage_root}-offline`);
    const recovered = await newReader(f.config);
    assert.equal(recovered.records[0].state, 'observed_succeeded');
    assert.equal(JSON.parse(await readFile(saved.resultPath)).report_sha256, sha256(saved.bytes));
    assert.deepEqual(await readFile(saved.path), saved.bytes);
    assert.equal((await newReader(f.config)).records[0].state, 'observed_succeeded');
  });

  test(`${format}: service accounts conditional success once, including after observer failure`, async t => {
    const f = await fixture(t, format, reportPatch(mixedJobs(), true));
    const events = [];
    const summary = await serve(f.config, { maxPolls: 2, pollMs: 100, onObservation: value => events.push(value) });
    assert.equal(summary.runs, 1); assert.equal(summary.failed_runs, 0); assert.equal(summary.idle_polls, 1);
    assert.equal(events[0].outcome, 'observed_succeeded');
    assert.equal((await f.lines('effects.ndjson')).length, 1);
    const failure = await fixture(t, format, reportPatch(mixedJobs(), true));
    await assert.rejects(serve(failure.config, { maxPolls: 1, onObservation() { throw new Error('consumer output failed'); } }), error => {
      assert.equal(error.retained_observation.outcome, 'observed_succeeded'); return true;
    });
    assert.equal((await once(failure.config)).reason, 'commit_already_observed');
    assert.equal((await failure.lines('effects.ndjson')).length, 1);
  });

  test(`${format}: operator CLI returns success for conditional completion and preserves non-authority flags`, async t => {
    const f = await fixture(t, format, reportPatch(mixedJobs(), true));
    const configFile = join(f.root, 'config.json');
    await writeFile(configFile, encode(f.config), { mode: 0o600 });
    let output = '', errors = '';
    const stdout = new Writable({ write(chunk, _encoding, done) { output += chunk; done(); } });
    const stderr = new Writable({ write(chunk, _encoding, done) { errors += chunk; done(); } });
    const code = await watcherMain(['once', '--config', configFile, '--trusted-local'], { stdout, stderr });
    assert.equal(code, 0, errors);
    const report = JSON.parse(output);
    assert.equal(report.outcome, 'observed_succeeded');
    assert.equal(report.authoritative_check, false);
    assert.equal((await f.lines('effects.ndjson')).length, 1);
  });

  test(`${format}: every terminal pair keeps failure, all-skipped and interruption non-success`, async t => {
    const f = await fixture(t, format); await once(f.config);
    const saved = await f.saved();
    const good = new Set(['succeeded:succeeded', 'succeeded:skipped', 'skipped:succeeded']);
    for (const first of outcomes) for (const second of outcomes) {
      const pair = `${first}:${second}`, strict = first === 'succeeded' && second === 'succeeded';
      const modern = good.has(pair), report = structuredClone(saved.report), run = report.runs[0];
      run.execution.jobs = [job('a', first), job('b', second)];
      run.execution.succeeded = strict; run.succeeded = modern; report.succeeded = modern;
      const before = encode(report), current = dispatchReport(f.config, saved.intent, report);
      assert.equal(current.outcome, modern ? 'observed_succeeded' : 'observed_failed', pair);
      assert.deepEqual(encode(report), before);
      run.succeeded = strict; report.succeeded = strict;
      assert.equal(dispatchReport(f.config, saved.intent, report).outcome, strict ? 'observed_succeeded' : 'observed_failed', `${pair} legacy`);
      if (!modern) {
        run.succeeded = true; report.succeeded = true;
        assert.throws(() => dispatchReport(f.config, saved.intent, report), undefined, `${pair} fabricated pass`);
      }
      run.request_interrupted = true; run.succeeded = false; report.succeeded = false; report.stop_reason = 'request_stopped';
      assert.equal(dispatchReport(f.config, saved.intent, report).outcome, 'observed_stopped', `${pair} stopped`);
      run.succeeded = true;
      assert.throws(() => dispatchReport(f.config, saved.intent, report), undefined, `${pair} cancellation overrides success`);
    }
  });

  test(`${format}: malformed conditional summaries cannot hide failed cleanup, executed skips or mismatched graphs`, async t => {
    const f = await fixture(t, format, reportPatch(mixedJobs(), true)); await once(f.config);
    const saved = await f.saved();
    const cases = [
      r => { r.runs[0].execution.jobs[0].failure = { detail: 'cleanup failed', workspace_retained: false }; },
      r => { r.runs[0].execution.jobs[2].failure = { detail: 'skip had failure', workspace_retained: false }; },
      r => { r.runs[0].execution.jobs[2].steps = [job('executed').steps[0]]; },
      r => { r.runs[0].execution.jobs[0].steps[0].workspace_retained = true; },
      r => { r.runs[0].execution.jobs[0].steps[0].outcome = 'containment_failure'; },
      r => { r.runs[0].execution.jobs[0].steps[0].exit_code = 1; },
      r => { r.runs[0].execution.jobs[0].steps[0].output_complete = false; },
      r => { r.runs[0].execution.jobs[0].steps[0].stdout_hex = 'zz'; },
      r => { r.runs[0].execution.jobs[0].steps[0].stdout_hex = '00'.repeat(r.runs[0].execution.stream_bytes + 1); },
      r => { r.runs[0].execution.succeeded = true; },
      r => { const run = r.runs[0]; run.execution.jobs = [job('only')]; run.execution.succeeded = true; run.succeeded = false; r.succeeded = false; },
      r => { r.runs[0].execution.workflow_graph = `alg:2:${'9'.repeat(64)}`; },
      r => { r.runs[0].workspaces_closed = false; },
      r => { r.runs[0].request_interrupted = true; },
      r => { r.succeeded = false; },
      r => { r.stop_reason = 'containment_unproved'; },
      r => { r.runs[0].succeeded = 'true'; },
      r => { r.runs[0].execution.jobs = []; },
      r => { r.runs[0].execution.jobs = [job('only', 'skipped')]; },
      r => { r.runs[0].authoritative_check = true; },
    ];
    for (const mutate of cases) {
      const changed = structuredClone(saved.report); mutate(changed);
      assert.throws(() => dispatchReport(f.config, saved.intent, changed), undefined, mutate.toString());
      assert.equal(dispatchReport(f.config, saved.intent, structuredClone(saved.report)).outcome, 'observed_succeeded');
    }
  });

  test(`${format}: job and aggregate-step limits still apply to conditionally completed runs`, async t => {
    const f = await fixture(t, format, reportPatch(mixedJobs(), true)); await once(f.config);
    const saved = await f.saved(), report = structuredClone(saved.report);
    report.runs[0].execution.jobs = [...Array.from({ length: 127 }, (_, i) => job(`build-${i}`)), job('skipped', 'skipped')];
    assert.equal(dispatchReport(f.config, saved.intent, report).outcome, 'observed_succeeded');
    report.runs[0].execution.jobs.push(job('one-too-many'));
    assert.throws(() => dispatchReport(f.config, saved.intent, report), /Unsupported native execution report/);
    const bounded = structuredClone(saved.report);
    bounded.runs[0].execution.jobs = [job('large'), job('skip', 'skipped')];
    bounded.runs[0].execution.jobs[0].steps = Array.from({ length: 512 }, (_, index) => ({ ...job('large').steps[0], index }));
    assert.equal(dispatchReport(f.config, saved.intent, bounded).outcome, 'observed_succeeded');
    bounded.runs[0].execution.jobs.push(job('overflow'));
    assert.throws(() => dispatchReport(f.config, saved.intent, bounded), /containment remains unproved/);
  });
}
