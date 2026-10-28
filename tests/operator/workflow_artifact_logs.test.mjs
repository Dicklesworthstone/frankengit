// Execute the production operator gates against independently built native-schema
// observations. This is not Rust execution or artifact-store attestation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { artifactConfiguration, artifactArguments, verifyArtifactContract, verifyArtifactWorkflows } from '../../scripts/operator/workflow_watch_artifacts.mjs';
import { verifyArtifactReceipts } from '../../scripts/operator/workflow_artifact_report.mjs';

const MIB = 1024 * 1024, hex = value => Buffer.from(value).toString('hex');
const hash = value => createHash('sha256').update(value).digest('hex');
const workflow = hex('ci/build.yml'), directory = hex('ci');
// artifactConfiguration delegates the pre-existing generic path validator to
// its caller. These tests supply only known-valid fixture paths, not an oracle
// for that separately tested path grammar.
const validFixturePath = value => assert.match(value, /^(?:[0-9a-f]{2})+$/);
function configuration(patch = {}) {
  return artifactConfiguration({ root: '/private/artifacts', selections: [], capture_logs: true, ...patch }, validFixturePath, directory);
}
function step({ stdout = Buffer.from([0, 255, 128, 13, 10]), stderr = Buffer.alloc(0), index = 3, name = 'compile: λ 🦀', outcome = 'succeeded' } = {}) {
  return { index, name, script: `alg:2:${hash('printf binary')}`, outcome,
    exit_code: outcome === 'succeeded' ? 0 : outcome === 'failed' ? 7 : null,
    output_complete: outcome === 'succeeded' || outcome === 'failed', workspace_retained: false,
    elapsed_millis: 2, stdout_hex: hex(stdout), stderr_hex: hex(stderr) };
}
function receipt(job) {
  return { job_id_hex: hex(job.id), manifest_id_sha256: hash(`manifest:${job.id}`), observed_job_outcome: job.outcome,
    logs: job.steps.flatMap(s => ['stdout', 'stderr'].map(stream => ({
      step_index: s.index, step_name_hex: s.name === null ? null : hex(s.name), script_sha256: s.script.slice(6), stream,
      observed_step_outcome: s.outcome, exit_code: s.exit_code, output_complete: s.output_complete,
      artifact_id_sha256: hash(`artifact:${job.id}:${s.index}:${stream}`),
      payload_sha256: hash(Buffer.from(s[`${stream}_hex`], 'hex')), payload_bytes: s[`${stream}_hex`].length / 2,
    }))) };
}
function fixture(options = {}) {
  const job = { id: 'build__matrix_007', outcome: options.outcome ?? 'succeeded', failure: null, steps: [step(options)] };
  return { config: configuration(), run: { workflow_path_hex: workflow, execution: { jobs: [job] }, artifacts: [], artifact_logs: [receipt(job)] } };
}
function check(f, totals = {}) { verifyArtifactReceipts(f.config, f.run, totals); return totals; }
function fileSelection(job = 'build__matrix_007') {
  return { workflow_path_hex: workflow, job_id: job, output_path_hex: hex('dist/result') };
}
function fileContract(config) {
  return { schema_version: 1, root_hex: hex(config.root), trust_domain: 'trusted-workflow-local-owner',
    maximum_file_bytes: config.maximum_file_mib * MIB, total_payload_bytes: config.total_payload_mib * MIB,
    retention_ttl_seconds: 86400,
    selections: config.selections.map(s => ({ workflow_path_hex: s.workflow_path_hex, job_id_hex: hex(s.job_id), output_path_hex: s.output_path_hex })) };
}
function addFile(f, size) {
  f.config = configuration({ selections: [fileSelection()] });
  f.run.artifacts = [{ job_id_hex: hex('build__matrix_007'), manifest_id_sha256: hash('file-manifest'), outputs: [{
    path_hex: hex('dist/result'), artifact_id_sha256: hash('file-id'), payload_sha256: hash('file-payload'), payload_bytes: size, executable: false,
  }] }];
}

test('logs-only capture is explicit, frozen, stable and forwards one valueless native flag', () => {
  const c = configuration();
  assert.ok(Object.isFrozen(c) && Object.isFrozen(c.selections));
  assert.equal(c.capture_logs, true); assert.deepEqual(c.selections, []);
  assert.deepEqual(artifactConfiguration(c, validFixturePath, directory), c);
  assert.deepEqual(artifactArguments(c), ['--artifact-root', '/private/artifacts', '--max-artifact-mib', '16', '--max-artifact-total-mib', '64', '--artifact-logs']);
  verifyArtifactWorkflows(c, []);
});
test('omitted and explicitly disabled log capture preserve historical configuration bytes and argv', () => {
  const input = { root: '/private/artifacts', selections: [fileSelection()] };
  const legacy = { root: input.root, maximum_file_mib: 16, total_payload_mib: 64, selections: input.selections };
  for (const value of [input, { ...input, capture_logs: false }]) {
    const c = artifactConfiguration(value, validFixturePath, directory);
    assert.equal(JSON.stringify(c), JSON.stringify(legacy));
    assert.equal(artifactArguments(c).includes('--artifact-logs'), false);
    verifyArtifactContract(c, { artifact_contract: fileContract(c) });
  }
});
test('logs-only cannot be enabled by truthiness or silently replace selected file inputs', () => {
  for (const capture_logs of [undefined, null, 0, 1, 'true', [], {}]) assert.throws(() => configuration({ capture_logs }));
  assert.throws(() => configuration({ capture_logs: false }));
  assert.throws(() => configuration({ selections: undefined }));
  assert.throws(() => configuration({ selections: Array(65).fill(fileSelection()) }));
  assert.throws(() => configuration({ inputs: [{ workflow_path_hex: workflow, consumer_job_id: 'test', producer_job_id: 'build', output_path_hex: hex('dist/result'), destination_hex: hex('result') }] }), /explicitly captured/);
});
test('native log contract has exact schema, stream order and immutable input binding', () => {
  const c = configuration(), contract = { ...fileContract(c), log_capture: { schema_version: 1, streams: ['stdout', 'stderr'] } };
  verifyArtifactContract(c, { artifact_contract: contract });
  for (const change of [
    x => { delete x.log_capture; }, x => { x.log_capture.schema_version = 2; }, x => { x.log_capture.streams.reverse(); },
    x => { x.log_capture.streams.pop(); }, x => { x.log_capture.extra = true; }, x => { x.total_payload_bytes++; },
  ]) {
    const altered = structuredClone(contract); change(altered);
    assert.throws(() => verifyArtifactContract(c, { artifact_contract: altered }), /contract differs/);
  }
  const files = configuration({ selections: [fileSelection()], capture_logs: false });
  assert.throws(() => verifyArtifactContract(files, { artifact_contract: { ...fileContract(files), log_capture: contract.log_capture } }));
});
test('combined file, delivery and logs contract matches native append order', () => {
  const input = { workflow_path_hex: workflow, consumer_job_id: 'test', producer_job_id: 'build__matrix_007', output_path_hex: hex('dist/result'), destination_hex: hex('result') };
  const c = configuration({ selections: [fileSelection()], inputs: [input] });
  const contract = { ...fileContract(c), input_delivery: { schema_version: 1, namespace_hex: hex('.fgit-artifacts'), total_delivery_bytes: 64 * MIB,
    selections: [{ workflow_path_hex: workflow, consumer_job_id_hex: hex('test'), producer_job_id_hex: hex(input.producer_job_id), output_path_hex: input.output_path_hex, destination_hex: input.destination_hex }] },
    log_capture: { schema_version: 1, streams: ['stdout', 'stderr'] } };
  verifyArtifactContract(c, { artifact_contract: contract });
  const args = artifactArguments(c);
  assert.equal(args.filter(x => x === '--artifact-logs').length, 1);
  assert.ok(args.includes('--artifact-hex') && args.includes('--artifact-input-hex') && args.includes('--max-artifact-input-total-mib'));
});
test('binary, empty and Unicode-named streams join exactly without changing saved evidence', () => {
  const f = fixture(), before = structuredClone(f);
  assert.deepEqual(check(f), { artifactPayload: 5 }); assert.deepEqual(f, before);
  const unnamed = fixture({ name: null, stdout: Buffer.alloc(0) });
  assert.deepEqual(check(unnamed), { artifactPayload: 0 });
});
const mutations = {
  'missing log array': f => { delete f.run.artifact_logs; },
  'missing successful receipt': f => { f.run.artifact_logs = []; },
  'unknown job': f => { f.run.artifact_logs[0].job_id_hex = hex('other'); },
  'duplicate job': f => { f.run.execution.jobs.push({ id: 'unstarted', outcome: 'skipped', steps: [] }); f.run.artifact_logs.push(structuredClone(f.run.artifact_logs[0])); },
  'skipped job': f => { f.run.execution.jobs[0].outcome = 'skipped'; },
  'unexecuted job': f => { f.run.execution.jobs[0].steps = []; },
  'missing empty stderr': f => { f.run.artifact_logs[0].logs.pop(); },
  'duplicate stream': f => { f.run.artifact_logs[0].logs[1] = structuredClone(f.run.artifact_logs[0].logs[0]); },
  'reordered streams': f => { f.run.artifact_logs[0].logs.reverse(); },
  'extra stream': f => { f.run.artifact_logs[0].logs.push(structuredClone(f.run.artifact_logs[0].logs[0])); },
  'changed step index': f => { f.run.artifact_logs[0].logs[0].step_index++; },
  'changed Unicode name': f => { f.run.artifact_logs[0].logs[0].step_name_hex = hex('other'); },
  'changed optional name': f => { f.run.artifact_logs[0].logs[0].step_name_hex = null; },
  'changed script': f => { f.run.artifact_logs[0].logs[0].script_sha256 = hash('different'); },
  'changed step outcome': f => { f.run.artifact_logs[0].logs[0].observed_step_outcome = 'failed'; },
  'changed exit code': f => { f.run.artifact_logs[0].logs[0].exit_code = 1; },
  'changed completeness': f => { f.run.artifact_logs[0].logs[0].output_complete = false; },
  'invalid manifest digest': f => { f.run.artifact_logs[0].manifest_id_sha256 = 'bad'; },
  'invalid artifact digest': f => { f.run.artifact_logs[0].logs[0].artifact_id_sha256 = 'A'.repeat(64); },
  'changed payload digest': f => { f.run.artifact_logs[0].logs[0].payload_sha256 = hash('not executed'); },
  'changed stream bytes': f => { f.run.execution.jobs[0].steps[0].stdout_hex = '01ff800d0a'; },
  'invalid hex cannot be truncated by Buffer': f => { f.run.execution.jobs[0].steps[0].stdout_hex += 'x'; },
  'fractional byte count': f => { f.run.artifact_logs[0].logs[0].payload_bytes = 0.5; },
  'negative byte count': f => { f.run.artifact_logs[0].logs[0].payload_bytes = -1; },
  'wrong byte count': f => { f.run.artifact_logs[0].logs[0].payload_bytes++; },
  'unknown receipt field': f => { f.run.artifact_logs[0].trusted = true; },
  'unknown stream field': f => { f.run.artifact_logs[0].logs[0].trusted = true; },
  'missing stream field': f => { delete f.run.artifact_logs[0].logs[0].exit_code; },
  'unknown observed job outcome': f => { f.run.artifact_logs[0].observed_job_outcome = 'green'; },
  'failed observation cannot become green': f => { f.run.artifact_logs[0].observed_job_outcome = 'failed'; },
};
for (const [name, mutate] of Object.entries(mutations)) test(`reject ${name}, with an accepted exact twin`, () => {
  const f = fixture(); check(f); mutate(f); assert.throws(() => check(f)); check(fixture());
});
test('artifact_logs is forbidden when unrequested, with and without file capture', () => {
  const f = fixture(); addFile(f, 7);
  f.config = { ...f.config }; delete f.config.capture_logs;
  assert.throws(() => check(f), /unrequested artifact logs/);
  delete f.run.artifact_logs; assert.deepEqual(check(f), { artifactPayload: 7 });
  assert.throws(() => verifyArtifactReceipts(undefined, { artifact_logs: [] }, {}), /unrequested artifact/);
});
for (const outcome of ['failed', 'cancelled', 'timed_out', 'output_limit', 'refused']) test(`${outcome}: diagnostic receipts and custody failure remain non-green`, () => {
  const f = fixture({ outcome: outcome === 'refused' ? 'failed' : outcome });
  f.run.execution.jobs[0].outcome = outcome;
  f.run.artifact_logs[0].observed_job_outcome = outcome;
  check(f); f.run.artifact_logs = []; check(f);
  assert.equal(f.run.execution.jobs[0].outcome, outcome);
});
test('only native late custody or deadline downgrades may differ from observed job outcome', () => {
  for (const final of ['refused', 'cancelled', 'timed_out']) {
    const f = fixture(); f.run.execution.jobs[0].outcome = final;
    if (final === 'refused') f.run.execution.jobs[0].failure = { detail: 'logs: deadline exhausted', workspace_retained: false };
    check(f); assert.equal(f.run.execution.jobs[0].outcome, final);
  }
  for (const final of ['cancelled', 'timed_out']) {
    const f = fixture({ outcome: 'failed' }); f.run.execution.jobs[0].outcome = final; check(f);
  }
  for (const final of ['failed', 'output_limit', 'refused']) {
    const f = fixture(); f.run.execution.jobs[0].outcome = final; assert.throws(() => check(f));
  }
  const impossible = fixture({ outcome: 'failed' });
  impossible.run.execution.jobs[0].outcome = 'cancelled'; impossible.run.artifact_logs[0].observed_job_outcome = 'succeeded';
  assert.throws(() => check(impossible));
});
test('skipped and pre-start refused jobs need no logs; sparse executed step indexes retain their original identity', () => {
  const f = fixture();
  f.run.execution.jobs.push({ id: 'skipped', outcome: 'skipped', steps: [] }, { id: 'refused', outcome: 'refused', steps: [] });
  f.run.execution.jobs[0].steps.push(step({ index: 7, name: null, stdout: Buffer.from('next') }));
  f.run.artifact_logs = [receipt(f.run.execution.jobs[0])];
  assert.equal(check(f).artifactPayload, 9);
});
test('per-payload allowance accepts exact limit and rejects one extra byte', () => {
  const f = fixture({ stdout: Buffer.alloc(MIB) }); f.config = configuration({ maximum_file_mib: 1 });
  assert.equal(check(f).artifactPayload, MIB);
  const excess = fixture({ stdout: Buffer.alloc(MIB + 1) }); excess.config = f.config;
  assert.throws(() => check(excess), /bounded payload length/);
});
test('stream envelope is enforced before decoding even when artifact allowance is larger', () => {
  const f = fixture({ stdout: Buffer.alloc(2 * MIB) }); assert.equal(check(f).artifactPayload, 2 * MIB);
  const excess = fixture({ stdout: Buffer.alloc(2 * MIB + 1) }); assert.throws(() => check(excess), /bounded payload length/);
});
test('files and all workflow-child logs consume one cumulative allowance at the exact boundary', () => {
  const first = fixture({ stdout: Buffer.alloc(MIB / 2) }); addFile(first, MIB / 2);
  first.config = { ...first.config, total_payload_mib: 2 };
  const second = fixture({ stdout: Buffer.alloc(MIB) }); second.run.workflow_path_hex = hex('ci/test.yml'); second.config = first.config;
  const totals = {};
  check(first, totals); check(second, totals); assert.equal(totals.artifactPayload, 2 * MIB);
  const excess = fixture({ stdout: Buffer.from('!') }); excess.config = first.config; excess.run.workflow_path_hex = second.run.workflow_path_hex;
  assert.throws(() => check(excess, totals), /shared dispatch allowance/);
});
test('successful same-attempt file delivery remains independent of log capture charges', () => {
  const f = fixture(); addFile(f, 7);
  const producer = f.run.execution.jobs[0], consumer = { id: 'test', outcome: 'succeeded', failure: null, steps: [step({ stdout: Buffer.from('ok') })] };
  f.config = { ...f.config, inputs: [{ workflow_path_hex: workflow, consumer_job_id: 'test', producer_job_id: producer.id, output_path_hex: hex('dist/result'), destination_hex: hex('result') }], total_delivery_mib: 1 };
  f.run.execution.jobs.push(consumer); f.run.artifact_logs.push(receipt(consumer));
  f.run.artifact_inputs = [{ job_id_hex: hex('test'), workspace_plan_sha256: hash('workspace'), inputs: [{ producer_job_id_hex: hex(producer.id),
    producer_manifest_id_sha256: f.run.artifacts[0].manifest_id_sha256, output: structuredClone(f.run.artifacts[0].outputs[0]), destination_path_hex: hex('.fgit-artifacts/result') }] }];
  assert.deepEqual(check(f), { artifactPayload: 14, artifactDelivery: 7 });
  delete f.run.artifact_inputs; assert.throws(() => check(f));
});
test('saved JSON round-trip supports source-free repeat validation with fresh dispatch accounting', () => {
  const f = fixture({ outcome: 'output_limit' }), encoded = JSON.stringify(f), restored = JSON.parse(encoded);
  assert.deepEqual(check(restored), check(f)); assert.equal(JSON.stringify(restored), encoded);
});
