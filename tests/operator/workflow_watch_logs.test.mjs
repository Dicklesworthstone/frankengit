// Real operator process/file paths with an explicitly substituted native-schema
// peer, not fg. Offline reconciliation must not need that peer or source storage.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rename, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configuration, once, reconcile, status, serve, dispatchReport } from '../../scripts/operator/workflow_watch.mjs';
import { markerMatches } from '../../scripts/operator/workflow_attempt_report.mjs';
import { watchConfig, intentFor, encode, hex, sha256, nativeReport } from './fixtures/workflow_log_native.mjs';

async function fixture(t, format = 'sha1', event = 'push', options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-operator-logs-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const dir of ['state', 'store', 'runs', 'artifacts']) await mkdir(join(root, dir), { mode: 0o700 });
  const raw = watchConfig(root, format, event);
  if (options.files) raw.artifacts.selections = [{ workflow_path_hex: hex('ci/build.yml'), job_id: 'build', output_path_hex: hex('dist/result') }];
  const config = configuration(raw), peer = new URL('./fixtures/workflow_log_native.mjs', import.meta.url).href;
  await writeFile(config.fg, `#!${process.execPath}\nimport { runPeer } from ${JSON.stringify(peer)};\nawait runPeer(process.argv.slice(2));\n`, { mode: 0o700 });
  await writeFile(join(root, 'control.json'), encode({ config, ...options }), { mode: 0o600 });
  const lines = async name => (await readFile(join(root, name), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);
  const intent = intentFor(config), batch = join(config.run_parent, `dispatch-${intent.run_id}`);
  return { root, config, intent, batch, lines,
    report: async () => JSON.parse(await readFile(join(batch, 'report.json'))),
    marker: async report => readFile(join(batch, `workflow-${report.runs[0].run_id}`, 'attempt.json')) };
}
for (const format of ['sha1', 'sha256']) for (const event of ['push', 'workflow_dispatch']) {
  test(`${format}/${event}: logs-only dispatch settles, binds original marker and never redispatches the same commit`, async t => {
    const f = await fixture(t, format, event), result = await once(f.config), report = await f.report(), marker = await f.marker(report);
    assert.equal(result.outcome, 'observed_succeeded'); assert.equal(result.authoritative_check, false);
    assert.equal(report.plan.artifact_contract.log_capture.schema_version, 1);
    assert.deepEqual(report.plan.artifact_contract.selections, []);
    assert.equal(report.runs[0].artifact_logs[0].logs[1].payload_bytes, 0);
    assert.equal(Object.hasOwn(JSON.parse(marker), 'artifact_logs'), false);
    markerMatches(JSON.parse(marker), report.runs[0]);
    assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal((await f.lines('dispatches.ndjson')).length, 1);
    const dispatch = (await f.lines('calls.ndjson')).filter(args => args[1] === 'dispatch');
    assert.equal(dispatch.length, 1); assert.equal(dispatch[0].filter(a => a === '--artifact-logs').length, 1);
    assert.deepEqual(await f.marker(report), marker);
  });
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: lost reply reconciles logs offline without source, artifact root or executable`, async t => {
    const f = await fixture(t, format, 'push', { drop_reply: true });
    await assert.rejects(once(f.config), /Dispatch unresolved/);
    assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
    const report = await f.report(), marker = await f.marker(report), calls = await f.lines('calls.ndjson');
    for (const path of [f.config.storage_root, f.config.artifacts.root, f.config.fg]) await rename(path, `${path}-offline`);
    const result = await reconcile(f.config);
    assert.equal(result.records[0].state, 'observed_succeeded');
    const receiptPath = join(f.config.state_directory, `result-${f.intent.id}.json`), before = await readFile(receiptPath);
    assert.equal(JSON.parse(before).report_sha256, sha256(encode(report)));
    await reconcile(f.config);
    assert.deepEqual(await readFile(receiptPath), before); assert.deepEqual(await f.marker(report), marker);
    assert.deepEqual(await f.lines('calls.ndjson'), calls); assert.equal((await f.lines('dispatches.ndjson')).length, 1);
  });
}
test('corrupt log evidence blocks settlement, replay and publication preparation', async t => {
  const f = await fixture(t, 'sha1', 'push', { corrupt_log: true });
  await assert.rejects(once(f.config), /differs from the executed stream/);
  await assert.rejects(reconcile(f.config), /differs from the executed stream/);
  await assert.rejects(once(f.config), /original execution is unresolved/);
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
  assert.equal((await f.lines('dispatches.ndjson')).length, 1);
  assert.equal((await readdir(f.config.state_directory)).some(name => name.startsWith('result-')), false);
  const corrupted = await f.report();
  assert.throws(() => dispatchReport(f.config, f.intent, corrupted), /differs from the executed stream/);
});
test('changing log capture cannot reuse an already-bound file-capture namespace', async t => {
  const f = await fixture(t, 'sha1', 'push', { files: true }); await once(f.config);
  const before = await f.lines('calls.ndjson');
  await assert.rejects(once({ ...f.config, artifacts: { ...f.config.artifacts, capture_logs: false } }), /configuration changed/);
  assert.deepEqual(await f.lines('calls.ndjson'), before);
});
for (const [outcome, stopped, expected] of [['failed', false, 'observed_failed'], ['cancelled', true, 'observed_stopped'], ['timed_out', true, 'observed_stopped'], ['output_limit', true, 'observed_stopped']]) {
  test(`${outcome}: diagnostic logs survive offline reconciliation without upgrading the result`, async t => {
    const f = await fixture(t, 'sha256', 'push', { outcome, stopped, drop_reply: true });
    await assert.rejects(once(f.config), /Dispatch unresolved/);
    const report = await f.report();
    assert.equal(report.runs[0].artifact_logs[0].observed_job_outcome, outcome);
    assert.equal((await reconcile(f.config)).records[0].state, expected);
    assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal((await f.lines('dispatches.ndjson')).length, 1);
  });
}
test('continuous polling preserves one log-producing dispatch across idle polls', async t => {
  const f = await fixture(t), observed = [];
  const result = await serve(f.config, { maxPolls: 2, pollMs: 100, onObservation: row => observed.push(row) });
  assert.equal(result.runs, 1); assert.equal(result.idle_polls, 1); assert.equal(result.execution_retried, false);
  assert.equal(observed[0].outcome, 'observed_succeeded'); assert.equal((await f.lines('dispatches.ndjson')).length, 1);
});
test('complete dispatch gate joins log receipts, immutable contracts and containment requirements', () => {
  const config = configuration(watchConfig('/fixture')), intent = intentFor(config);
  const good = nativeReport(config, intent).report;
  assert.equal(dispatchReport(config, intent, good).outcome, 'observed_succeeded');
  const missing = structuredClone(good); missing.runs[0].artifact_logs[0].logs.pop();
  assert.throws(() => dispatchReport(config, intent, missing), /incomplete/);
  for (const mutate of [r => { delete r.plan.artifact_contract.log_capture; }, r => { delete r.runs[0].artifact_contract.log_capture; },
    r => { r.runs[0].workspaces_closed = false; }, r => { r.runs[0].execution.jobs[0].steps[0].workspace_retained = true; }]) {
    const bad = structuredClone(good); mutate(bad); assert.throws(() => dispatchReport(config, intent, bad));
  }
});
