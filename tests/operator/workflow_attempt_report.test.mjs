// Exercise the production publication-preparation gate with complete native
// report fixtures. These are not canonical check admission or transport tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { configuration, dispatchReport } from '../../scripts/operator/workflow_watch.mjs';
import { markerMatches } from '../../scripts/operator/workflow_attempt_report.mjs';
import { watchConfig, intentFor, nativeReport, attemptMarker, encode, sha256, hex } from './fixtures/workflow_log_native.mjs';

function fixture(format = 'sha1', options = {}) {
  const raw = watchConfig('/fixture', format);
  if (options.legacy) { raw.artifacts.capture_logs = false; raw.artifacts.selections = [{ workflow_path_hex: hex('ci/build.yml'), job_id: 'build', output_path_hex: hex('dist/result') }]; }
  const config = configuration(raw), intent = intentFor(config), report = nativeReport(config, intent, options).report;
  return { config, intent, report, marker: attemptMarker(report.runs[0]) };
}
function prepare(f) {
  // Same ordering as workflow_check_publish.prepare/completedJobs: the report
  // gate checks receipts before the original marker can select journal history.
  const result = dispatchReport(f.config, f.intent, f.report);
  markerMatches(f.marker, f.report.runs[0]);
  return result;
}
for (const format of ['sha1', 'sha256']) test(`${format}: logs are post-execution observations, not missing start-marker inputs`, () => {
  const f = fixture(format), bytes = encode(f.marker), journal = sha256(bytes);
  assert.equal(Object.hasOwn(f.marker, 'artifact_logs'), false);
  assert.equal(prepare(f).outcome, 'observed_succeeded');
  assert.equal(prepare(f).outcome, 'observed_succeeded');
  assert.deepEqual(encode(f.marker), bytes); assert.equal(sha256(encode(f.marker)), journal);
});
test('legacy file-only attempts retain the same marker and compiled-plan checks', () => {
  const f = fixture('sha1', { legacy: true });
  assert.equal(Object.hasOwn(f.report.runs[0], 'artifact_logs'), false);
  assert.equal(Object.hasOwn(f.marker.artifact_contract, 'log_capture'), false);
  assert.equal(prepare(f).outcome, 'observed_succeeded');
});
const mutations = {
  'source commit': f => { f.marker.source_commit = `sha1:${'d'.repeat(40)}`; },
  'executed commit': f => { f.marker.executed_commit = `sha1:${'d'.repeat(40)}`; },
  'source head': f => { f.marker.source_head = 'another-head'; },
  'source tree': f => { f.marker.source_tree = `sha1:${'d'.repeat(40)}`; },
  'workflow blob': f => { f.marker.workflow_blob = `sha1:${'d'.repeat(40)}`; },
  'workflow path': f => { f.marker.workflow_path_hex = hex('ci/other.yml'); },
  'attempt identity': f => { f.marker.run_id = 'e'.repeat(32); },
  'read selection': f => { f.marker.read_prefixes_hex = [hex('ci')]; },
  'repository incarnation': f => { f.marker.repository_incarnation = 'e'.repeat(32); },
  'missing capture contract': f => { delete f.marker.artifact_contract; },
  'missing log opt-in': f => { delete f.marker.artifact_contract.log_capture; },
  'changed stream selection': f => { f.marker.artifact_contract.log_capture.streams.reverse(); },
  'changed retention budget': f => { f.marker.artifact_contract.total_payload_bytes++; },
  'changed artifact root': f => { f.marker.artifact_contract.root_hex = hex('/another/root'); },
  'changed compiled graph': f => { f.marker.execution_plan.workflow_graph = `alg:2:${'e'.repeat(64)}`; },
  'changed process environment': f => { f.marker.execution_plan.environment.PATH = '/unsafe/bin'; },
  'changed output budget': f => { f.marker.execution_plan.total_output_bytes++; },
  'pre-execution jobs injected': f => { f.marker.execution_plan.jobs = f.report.runs[0].execution.jobs; },
  'pre-execution success injected': f => { f.marker.execution_plan.succeeded = true; },
  'unknown input extension': f => { f.report.runs[0].future_execution_input = 'not-bound'; },
};
for (const [name, mutate] of Object.entries(mutations)) test(`publication preparation refuses ${name}`, () => {
  const f = fixture(); prepare(f); mutate(f); assert.throws(() => prepare(f), /Original workflow marker/);
});
test('missing or invalid original start markers cannot authorize history selection', () => {
  const f = fixture();
  for (const marker of [null, [], {}, { ...f.marker, type: 'trusted_workflow_run' }, { ...f.marker, state: 'completed' },
    { ...f.marker, execution_plan: [] }, { ...f.marker, execution_plan: null }]) {
    assert.throws(() => markerMatches(marker, f.report.runs[0]), /Original workflow marker/);
  }
});
test('ignoring post-run arrays in marker matching never bypasses earlier receipt validation', () => {
  for (const mutate of [
    r => { r.artifact_logs[0].logs[0].payload_sha256 = 'f'.repeat(64); },
    r => { r.artifact_logs[0].logs.pop(); }, r => { r.artifact_logs = []; },
    r => { r.artifact_logs[0].observed_job_outcome = 'failed'; },
  ]) {
    const f = fixture(); mutate(f.report.runs[0]);
    markerMatches(f.marker, f.report.runs[0]);
    assert.throws(() => prepare(f));
  }
});
test('failed and stopped log-producing runs stay non-green through both preparation gates', () => {
  for (const outcome of ['failed', 'cancelled', 'timed_out', 'output_limit']) {
    const f = fixture('sha256', { outcome, stopped: outcome !== 'failed' });
    assert.notEqual(prepare(f).outcome, 'observed_succeeded');
  }
});
test('publisher uses the tested gate before hashing the unchanged marker for recovery', async () => {
  const source = await readFile(new URL('../../scripts/operator/workflow_check_publish.mjs', import.meta.url), 'utf8');
  assert.match(source, /import \{ markerMatches \} from '\.\/workflow_attempt_report\.mjs';/);
  assert.match(source, /markerMatches\(parseJson\(marker, 512 \* 1024\), run\);\s+const journal = sha256\(marker\)/);
  assert.equal(source.includes('function markerMatches('), false);
});
