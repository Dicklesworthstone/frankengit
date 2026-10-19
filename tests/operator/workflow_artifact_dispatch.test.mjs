// Native-format fixtures exercise the actual watcher/report and filesystem
// reconciliation boundaries, not native Rust execution or payload attestation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, unlink } from 'node:fs/promises';
import { configuration, dispatchReport, once, reconcile, status } from '../../scripts/operator/workflow_watch.mjs';
import { writeNew } from '../../scripts/operator/workflow_watch_io.mjs';

const hex = text => Buffer.from(text).toString('hex');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const digest = byte => byte.repeat(64);
function fixture(root = '/frankengit-artifact-report-test', format = 'sha1') {
  const config = configuration({ schema: 'frankengit-workflow-watch-v1', fg: join(root, 'absent-native-executable'),
    storage_root: join(root, 'storage'), tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
    object_format: format, ref_hex: hex('refs/heads/main'), workflow_directory_hex: hex('ci'), input_prefixes_hex: [hex('ci')], event: 'push',
    state_directory: join(root, 'state'), run_parent: join(root, 'runs'), max_runs: 4, trust: 'selected-branch-host-execution',
    artifacts: { root: join(root, 'artifacts'), selections: [{ workflow_path_hex: hex('ci/build.yml'), job_id: 'build', output_path_hex: hex('dist/program') }],
      inputs: [{ workflow_path_hex: hex('ci/build.yml'), consumer_job_id: 'test', producer_job_id: 'build', output_path_hex: hex('dist/program'), destination_hex: hex('bin/program') }] } });
  const commit = '4'.repeat(format === 'sha1' ? 40 : 64), configuration_sha256 = hash(encode(config));
  const id = hash(Buffer.from(`frankengit/workflow-watch-observed-commit/v1\0${configuration_sha256}\0${commit}`));
  const intent = { schema: 'frankengit-workflow-watch-intent-v1', id, configuration_sha256, run_id: id.slice(0, 32),
    snapshot_token: `alg:2:${digest('5')}`, source_head: `alg:2:${digest('6')}`, commit, trigger_provenance: 'observed_branch_tip_not_push_event' };
  const batch = join(config.run_parent, `dispatch-${intent.run_id}`);
  const frame = part => { const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(part.length)); return Buffer.concat([length, part]); };
  const child = hash(Buffer.concat([Buffer.from('frankengit/workflow-dispatch-child/v1\0'), Buffer.from(intent.run_id, 'hex'), frame(Buffer.from('push')), frame(Buffer.from('ci/build.yml'))])).slice(0, 32);
  const artifact_contract = { schema_version: 1, root_hex: hex(config.artifacts.root), trust_domain: 'trusted-workflow-local-owner', maximum_file_bytes: 16 * 1024 * 1024,
    total_payload_bytes: 64 * 1024 * 1024, retention_ttl_seconds: 86400, selections: [{ workflow_path_hex: hex('ci/build.yml'), job_id_hex: hex('build'), output_path_hex: hex('dist/program') }],
    input_delivery: { schema_version: 1, namespace_hex: hex('.fgit-artifacts'), total_delivery_bytes: 64 * 1024 * 1024,
      selections: [{ workflow_path_hex: hex('ci/build.yml'), consumer_job_id_hex: hex('test'), producer_job_id_hex: hex('build'), output_path_hex: hex('dist/program'), destination_hex: hex('bin/program') }] } };
  const common = { tenant_id: config.tenant_id, repository_id: config.repository_id, repository_incarnation: config.repository_incarnation,
    object_format: format, source_head: intent.source_head, source_rcr: `alg:2:${digest('7')}`, source_commit: commit, source_tree: '8'.repeat(commit.length),
    source_ref_hex: config.ref_hex, read_prefixes_hex: config.input_prefixes_hex, authoritative_check: false, hostile_code_isolated: false, published: false, artifact_contract };
  const step = { index: 0, name: null, script: `alg:2:${digest('9')}`, outcome: 'succeeded', exit_code: 0, elapsed_millis: 1, output_complete: true,
    stdout_hex: '', stderr_hex: '', workspace_retained: false };
  const file = { path_hex: hex('dist/program'), artifact_id_sha256: digest('a'), payload_sha256: digest('b'), payload_bytes: 7, executable: true };
  const run = { ...common, type: 'trusted_workflow_run', schema_version: 1, run_id: child, run_directory_hex: hex(join(batch, `workflow-${child}`)),
    executed_commit: commit, executed_tree: common.source_tree, workflow_blob: 'c'.repeat(commit.length), workflow_path_hex: hex('ci/build.yml'),
    candidate: null, merge: null, input_kind: 'canonical', workspaces_closed: true, request_interrupted: false, succeeded: true,
    execution: { schema_version: 1, profile: 'trusted-local-foreground-v1', authoritative_check: false, shell: '/bin/sh', shell_flags: ['-eu', '-c'],
      environment: { PATH: '/usr/bin:/bin', LANG: 'C' }, workflow_source: `alg:2:${digest('d')}`, workflow_graph: `alg:2:${digest('e')}`,
      run_timeout_millis: 600000, step_timeout_millis: 60000, stream_bytes: 262144, total_output_bytes: 16 * 1024 * 1024, succeeded: true,
      jobs: ['build', 'test'].map(id => ({ id, outcome: 'succeeded', failure: null, steps: [{ ...step }] })) },
    artifacts: [{ job_id_hex: hex('build'), manifest_id_sha256: digest('f'), outputs: [file] }],
    artifact_inputs: [{ job_id_hex: hex('test'), workspace_plan_sha256: digest('a'), inputs: [{ producer_job_id_hex: hex('build'),
      producer_manifest_id_sha256: digest('f'), output: { ...file }, destination_path_hex: hex('.fgit-artifacts/bin/program') }] }] };
  const plan = { ...common, type: 'trusted_workflow_dispatch_plan', schema_version: 1, workflow_directory_hex: config.workflow_directory_hex,
    event: config.event, run_id: intent.run_id, run_directory_hex: hex(batch), trigger_provenance: 'explicit_local_operator', execution_retried: false,
    run_timeout_ms: 600000, total_output_bytes: 16 * 1024 * 1024, workflows: [{ path_hex: run.workflow_path_hex, blob: run.workflow_blob,
      selected: true, graph_sha256: digest('e'), run_id: child }] };
  return { config, intent, batch, report: { type: 'trusted_workflow_dispatch', plan, runs: [run], succeeded: true, matched_count: 1, executed_count: 1, stop_reason: null } };
}
for (const format of ['sha1', 'sha256']) test(`complete ${format} artifact report settles without mutation`, () => {
  const f = fixture(undefined, format), before = encode(f.report);
  const result = dispatchReport(f.config, f.intent, f.report);
  assert.equal(result.outcome, 'observed_succeeded'); assert.equal(result.authoritative_check, false);
  assert.equal(result.report_sha256, hash(before)); assert.deepEqual(encode(f.report), before);
});
for (const [name, mutate] of Object.entries({
  'missing selected capture': f => { f.report.runs[0].artifacts = []; },
  'missing selected delivery': f => { f.report.runs[0].artifact_inputs = []; },
  'substituted producer manifest': f => { f.report.runs[0].artifact_inputs[0].inputs[0].producer_manifest_id_sha256 = digest('1'); },
  'substituted executable mode': f => { f.report.runs[0].artifact_inputs[0].inputs[0].output.executable = false; },
})) test(`dispatch settlement refuses ${name}`, () => {
  const f = fixture(); dispatchReport(f.config, f.intent, f.report); mutate(f);
  assert.throws(() => dispatchReport(f.config, f.intent, f.report));
});
test('unstarted workflow in a stopped dispatch does not need artifact receipts', () => {
  const f = fixture(); f.report.runs = []; f.report.executed_count = 0; f.report.succeeded = false; f.report.stop_reason = 'request_stopped';
  assert.equal(dispatchReport(f.config, f.intent, f.report).outcome, 'observed_stopped');
});
async function custody(t, mutate) {
  const root = await mkdtemp(join(tmpdir(), 'fgit-artifact-reconcile-')); t.after(() => rm(root, { recursive: true, force: true }));
  const f = fixture(root);
  await mkdir(f.config.state_directory, { mode: 0o700 }); await mkdir(f.config.run_parent, { mode: 0o700 }); await mkdir(f.batch, { mode: 0o700 });
  const documents = [
    [join(f.config.state_directory, 'binding.json'), f.config],
    [join(f.config.state_directory, `intent-${f.intent.id}.json`), f.intent],
    [join(f.config.state_directory, `started-${f.intent.id}.json`), { schema: 'frankengit-workflow-watch-start-v1', intent_sha256: hash(encode(f.intent)) }],
  ];
  if (mutate) mutate(f);
  documents.push([join(f.batch, 'report.json'), f.report]);
  for (const [path, value] of documents) await writeNew(path, encode(value));
  return { ...f, documents: documents.map(([path, value]) => [path, encode(value)]) };
}
test('offline reconciliation retains complete artifact custody without invoking an executable', async t => {
  const f = await custody(t); const result = await reconcile(f.config);
  assert.equal(result.records[0].state, 'observed_succeeded');
  for (const [path, bytes] of f.documents) assert.deepEqual(await readFile(path), bytes);
  assert.equal((await readdir(f.config.state_directory)).length, 4);
});
test('missing delivery leaves original execution unknown and never writes completion', async t => {
  const f = await custody(t, value => { value.report.runs[0].artifact_inputs = []; });
  await assert.rejects(reconcile(f.config), /missing.*delivery/);
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
  for (const [path, bytes] of f.documents) assert.deepEqual(await readFile(path), bytes);
  assert.equal((await readdir(f.config.state_directory)).length, 3);
});


// Existing schema peer exercises process ownership, stdout/report agreement,
// exactly-once local dispatch fencing and offline reconciliation. It is not fg.
async function processPeer(t, format = 'sha1', options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fgit-artifact-peer-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const selected = structuredClone(fixture(root, format).config);
  selected.fg = join(root, 'fg');
  selected.artifacts.selections[0].workflow_path_hex = hex('ci/ci.yml');
  selected.artifacts.inputs[0].workflow_path_hex = hex('ci/ci.yml');
  if (options.captureOnly) { delete selected.artifacts.inputs; delete selected.artifacts.total_delivery_mib; }
  if (options.legacy) delete selected.artifacts;
  const config = configuration(selected);
  for (const directory of [config.storage_root, config.state_directory, config.run_parent, join(root, 'artifacts')]) {
    await mkdir(directory, { mode: 0o700 });
  }
  const peer = await readFile(new URL('./fixtures/workflow_watch_native.mjs', import.meta.url), 'utf8');
  await writeFile(config.fg, `#!${process.execPath}
${peer}`, { mode: 0o700 });
  await writeFile(join(config.storage_root, 'control.json'), encode({ tenant: config.tenant_id, repository: config.repository_id,
    incarnation: config.repository_incarnation, format, ref_hex: config.ref_hex, commit: 'a'.repeat(format === 'sha1' ? 40 : 64),
    source_head: 'fixture-head', snapshot: `alg:2:${digest('4')}`, ...options.control }), { mode: 0o600 });
  const saved = async () => {
    const row = (await status(config)).records[0];
    return { row, report: JSON.parse(await readFile(join(row.native_directory, 'report.json'), 'utf8')) };
  };
  const effects = async () => (await readFile(join(config.storage_root, 'effects.ndjson'), 'utf8')).trim().split(String.fromCharCode(10)).length;
  return { config, saved, effects };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format} schema peer: complete capture and delivery settles once through real process IO`, async t => {
    const f = await processPeer(t, format);
    assert.equal((await once(f.config)).outcome, 'observed_succeeded');
    const { report } = await f.saved();
    assert.deepEqual(report.runs[0].execution.jobs.map(job => job.id), ['build', 'test']);
    assert.equal(report.runs[0].artifacts.length, 1);
    assert.equal(report.runs[0].artifact_inputs.length, 1);
    assert.equal((await once(f.config)).reason, 'commit_already_observed');
    assert.equal(await f.effects(), 1);
  });
  test(`${format} schema peer: lost stdout reconciles complete receipts without reexecuting`, async t => {
    const f = await processPeer(t, format, { control: { drop_stdout: true } });
    await assert.rejects(once(f.config), /Dispatch unresolved/);
    assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
    const { row } = await f.saved(), path = join(row.native_directory, 'report.json'), before = await readFile(path);
    await unlink(f.config.fg);
    assert.equal((await reconcile(f.config)).records[0].state, 'observed_succeeded');
    assert.deepEqual(await readFile(path), before);
    assert.equal(await f.effects(), 1);
  });
}
test('legacy schema peer retains the original no-artifact report shape and success', async t => {
  const f = await processPeer(t, 'sha1', { legacy: true });
  assert.equal((await once(f.config)).outcome, 'observed_succeeded');
  const { report } = await f.saved();
  assert.equal(Object.hasOwn(report.runs[0], 'artifacts'), false);
  assert.equal(Object.hasOwn(report.runs[0], 'artifact_inputs'), false);
  assert.equal(report.runs[0].execution.jobs[0].id, 'fixture-job');
});
test('capture-only schema peer settles without an input-delivery field', async t => {
  const f = await processPeer(t, 'sha1', { captureOnly: true });
  assert.equal((await once(f.config)).outcome, 'observed_succeeded');
  const { report } = await f.saved();
  assert.equal(report.runs[0].artifacts.length, 1);
  assert.equal(Object.hasOwn(report.runs[0], 'artifact_inputs'), false);
});
test('failed schema-peer producer retains diagnostic capture but skips delivery and never claims success', async t => {
  const f = await processPeer(t, 'sha1', { control: { job_failure: true } });
  assert.equal((await once(f.config)).outcome, 'observed_failed');
  const { report } = await f.saved();
  assert.deepEqual(report.runs[0].execution.jobs.map(job => job.outcome), ['failed', 'skipped']);
  assert.equal(report.runs[0].artifacts.length, 1);
  assert.deepEqual(report.runs[0].artifact_inputs, []);
  assert.equal(await f.effects(), 1);
});
test('schema-peer missing capture leaves uncertainty fenced across once and reconcile', async t => {
  const f = await processPeer(t, 'sha1', { control: { run_patch: { artifacts: [] } } });
  await assert.rejects(once(f.config), /missing.*capture/);
  await assert.rejects(reconcile(f.config), /missing.*capture/);
  await assert.rejects(once(f.config), /unresolved/);
  assert.equal((await status(f.config)).records[0].state, 'execution_unknown');
  assert.equal(await f.effects(), 1);
});
