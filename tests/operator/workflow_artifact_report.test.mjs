import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyArtifactReceipts } from '../../scripts/operator/workflow_artifact_report.mjs';

const MIB = 1024 * 1024, hex = text => Buffer.from(text).toString('hex');
const hash = byte => byte.repeat(64);
function fixture({ size = 7, workflow = 'ci/build.yml', deliver = true } = {}) {
  const path = hex(workflow), out = hex('dist/program');
  const config = { maximum_file_mib: 16, total_payload_mib: 64,
    selections: [{ workflow_path_hex: path, job_id: 'build', output_path_hex: out }] };
  const file = { path_hex: out, artifact_id_sha256: hash('a'), payload_sha256: hash('b'), payload_bytes: size, executable: true };
  const run = { workflow_path_hex: path, execution: { jobs: [
    { id: 'build', outcome: 'succeeded', steps: [{}] }, { id: 'test', outcome: 'succeeded', steps: [{}] } ] },
    artifacts: [{ job_id_hex: hex('build'), manifest_id_sha256: hash('c'), outputs: [file] }] };
  if (deliver) {
    config.total_delivery_mib = 64;
    config.inputs = [{ workflow_path_hex: path, consumer_job_id: 'test', producer_job_id: 'build', output_path_hex: out, destination_hex: hex('bin/program') }];
    run.artifact_inputs = [{ job_id_hex: hex('test'), workspace_plan_sha256: hash('d'), inputs: [{
      producer_job_id_hex: hex('build'), producer_manifest_id_sha256: hash('c'), output: { ...file }, destination_path_hex: hex('.fgit-artifacts/bin/program') }] }];
  }
  return { config, run };
}
function check(f, totals = {}) { verifyArtifactReceipts(f.config, f.run, totals); return totals; }
const negatives = {
  'missing capture array': f => { delete f.run.artifacts; },
  'missing successful producer receipt': f => { f.run.artifacts = []; },
  'partial producer output set': f => { f.run.artifacts[0].outputs = []; },
  'duplicate producer': f => { f.run.artifacts.push(structuredClone(f.run.artifacts[0])); },
  'extra output': f => { f.run.artifacts[0].outputs.push(structuredClone(f.run.artifacts[0].outputs[0])); },
  'unselected producer': f => { f.run.artifacts[0].job_id_hex = hex('other'); },
  'unselected output': f => { f.run.artifacts[0].outputs[0].path_hex = hex('other'); },
  'malformed manifest': f => { f.run.artifacts[0].manifest_id_sha256 = 'x'; },
  'malformed payload digest': f => { f.run.artifacts[0].outputs[0].payload_sha256 = 'B'.repeat(64); },
  'malformed artifact identity': f => { f.run.artifacts[0].outputs[0].artifact_id_sha256 = null; },
  'fractional size': f => { f.run.artifacts[0].outputs[0].payload_bytes = 1.5; },
  'negative size': f => { f.run.artifacts[0].outputs[0].payload_bytes = -1; },
  'oversized file': f => { f.run.artifacts[0].outputs[0].payload_bytes = 16 * MIB + 1; },
  'truthy but nonboolean mode': f => { f.run.artifacts[0].outputs[0].executable = 1; },
  'unexpected output field': f => { f.run.artifacts[0].outputs[0].trusted = true; },
  'missing consumer array': f => { delete f.run.artifact_inputs; },
  'missing started consumer receipt': f => { f.run.artifact_inputs = []; },
  'partial consumer input set': f => { f.run.artifact_inputs[0].inputs = []; },
  'duplicate consumer': f => { f.run.artifact_inputs.push(structuredClone(f.run.artifact_inputs[0])); },
  'unselected consumer': f => { f.run.artifact_inputs[0].job_id_hex = hex('other'); },
  'malformed workspace commitment': f => { f.run.artifact_inputs[0].workspace_plan_sha256 = 7; },
  'substituted manifest': f => { f.run.artifact_inputs[0].inputs[0].producer_manifest_id_sha256 = hash('e'); },
  'substituted producer': f => { f.run.artifact_inputs[0].inputs[0].producer_job_id_hex = hex('test'); },
  'substituted destination': f => { f.run.artifact_inputs[0].inputs[0].destination_path_hex = hex('../program'); },
  'substituted artifact identity': f => { f.run.artifact_inputs[0].inputs[0].output.artifact_id_sha256 = hash('e'); },
  'substituted payload digest': f => { f.run.artifact_inputs[0].inputs[0].output.payload_sha256 = hash('e'); },
  'substituted payload length': f => { f.run.artifact_inputs[0].inputs[0].output.payload_bytes++; },
  'substituted executable mode': f => { f.run.artifact_inputs[0].inputs[0].output.executable = false; },
  'failed producer cannot supply an input': f => { f.run.execution.jobs[0].outcome = 'failed'; },
  'producer executed after consumer': f => { f.run.execution.jobs.reverse(); },
  'skipped producer receipt': f => { f.run.execution.jobs[0] = { id: 'build', outcome: 'skipped', steps: [] }; },
  'skipped consumer receipt': f => { f.run.execution.jobs[1] = { id: 'test', outcome: 'skipped', steps: [] }; },
  'configured job absent from execution': f => { f.run.execution.jobs.pop(); },
  'cross-workflow output substitution': f => { f.run.workflow_path_hex = hex('ci/other.yml'); },
};
for (const [name, mutate] of Object.entries(negatives)) test(name, () => {
  const permitted = fixture(); check(permitted);
  const denied = structuredClone(permitted); mutate(denied); assert.throws(() => check(denied));
});
test('capture and delivery are charged independently and source is not mutated', () => {
  const f = fixture(), before = structuredClone(f);
  assert.deepEqual(check(f), { artifactPayload: 7, artifactDelivery: 7 });
  assert.deepEqual(f, before);
});
test('empty binary output is valid', () => assert.deepEqual(check(fixture({ size: 0 })), { artifactPayload: 0, artifactDelivery: 0 }));
test('capture-only failed-job diagnostic outputs remain valid', () => {
  const f = fixture({ deliver: false }); f.run.execution.jobs[0].outcome = 'failed'; check(f);
});
test('failure before capture and dependent skip may settle without artifacts', () => {
  const f = fixture(); f.run.execution.jobs[0].outcome = 'failed';
  f.run.execution.jobs[1] = { id: 'test', outcome: 'skipped', steps: [] };
  f.run.artifacts = []; f.run.artifact_inputs = []; check(f);
});
test('consumer cancelled before any step may lack a delivered receipt', () => {
  const f = fixture(); f.run.execution.jobs[1] = { id: 'test', outcome: 'cancelled', steps: [] };
  f.run.artifact_inputs = []; check(f);
});
test('consumer failed after starting still requires its inputs', () => {
  const f = fixture(); f.run.execution.jobs[1].outcome = 'failed'; check(f);
  f.run.artifact_inputs = []; assert.throws(() => check(f), /missing.*delivery/);
});
test('capture-only and legacy no-artifact reports retain their field shape', () => {
  const f = fixture({ deliver: false }); check(f);
  f.run.artifact_inputs = []; assert.throws(() => check(f), /unrequested/);
  const run = { execution: { jobs: [] } }; verifyArtifactReceipts(undefined, run, {});
  for (const key of ['artifacts', 'artifact_inputs']) assert.throws(() => verifyArtifactReceipts(undefined, { ...run, [key]: [] }, {}), /unrequested/);
});
test('capture allowance accumulates across workflow children at its exact bound', () => {
  const first = fixture({ deliver: false, size: MIB, workflow: 'ci/a.yml' });
  const second = fixture({ deliver: false, size: MIB, workflow: 'ci/b.yml' });
  const config = { ...first.config, total_payload_mib: 2, selections: [...first.config.selections, ...second.config.selections] };
  const totals = {};
  verifyArtifactReceipts(config, first.run, totals); verifyArtifactReceipts(config, second.run, totals);
  assert.equal(totals.artifactPayload, 2 * MIB);
  assert.throws(() => verifyArtifactReceipts(config, fixture({ deliver: false, size: 1, workflow: 'ci/a.yml' }).run, totals), /shared dispatch allowance/);
});
test('fan-out charges every consumer copy, not each unique artifact identity', () => {
  const f = fixture({ size: MIB });
  f.config.total_delivery_mib = 2;
  f.config.inputs.push({ ...f.config.inputs[0], consumer_job_id: 'test2' });
  f.run.execution.jobs.push({ id: 'test2', outcome: 'succeeded', steps: [{}] });
  f.run.artifact_inputs.push({ ...structuredClone(f.run.artifact_inputs[0]), job_id_hex: hex('test2') });
  assert.equal(check(f).artifactDelivery, 2 * MIB);
  f.config.total_delivery_mib = 1;
  assert.throws(() => check(f), /shared dispatch allowance/);
});
test('delivery allowance accumulates across workflows independently of capture', () => {
  const first = fixture({ size: MIB, workflow: 'ci/a.yml' }), second = fixture({ size: MIB, workflow: 'ci/b.yml' });
  const config = { ...first.config, total_delivery_mib: 1, selections: [...first.config.selections, ...second.config.selections], inputs: [...first.config.inputs, ...second.config.inputs] };
  const totals = {}; verifyArtifactReceipts(config, first.run, totals);
  assert.throws(() => verifyArtifactReceipts(config, second.run, totals), /shared dispatch allowance/);
});
test('delivery has the native 16 MiB workspace-file bound even with larger capture budget', () => {
  const f = fixture({ size: 16 * MIB }); f.config.maximum_file_mib = 64; check(f);
  f.run.artifacts[0].outputs[0].payload_bytes++; f.run.artifact_inputs[0].inputs[0].output.payload_bytes++;
  assert.throws(() => check(f), /size or mode/);
});
test('receipt field order does not change their meaning', () => {
  const f = fixture(); f.run.artifact_inputs[0].inputs[0].output = Object.fromEntries(Object.entries(f.run.artifact_inputs[0].inputs[0].output).reverse()); check(f);
});
