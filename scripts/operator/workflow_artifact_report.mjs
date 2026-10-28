// Consistency gate for native artifact observations before watcher settlement or
// check-publication planning. Payload verification stays in Rust; these records
// neither attest script execution nor authorize cross-attempt cache reuse.
import { fail } from './workflow_watch_io.mjs';
import { verifyArtifactLogs } from './workflow_artifact_logs.mjs';

const MIB = 1024 * 1024;
const NAMESPACE = Buffer.from('.fgit-artifacts/').toString('hex');
const OUTPUT = ['path_hex', 'artifact_id_sha256', 'payload_sha256', 'payload_bytes', 'executable'];
const hex = text => Buffer.from(text).toString('hex');
function fields(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== expected.length || expected.some(key => !Object.hasOwn(value, key))) {
    fail('Missing or unsupported native artifact receipt fields.');
  }
}
function array(value, maximum) {
  if (!Array.isArray(value) || value.length > maximum) fail('Invalid bounded native artifact receipt array.');
  return value;
}
function digest(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('Invalid native artifact commitment.');
}
function output(value, path, maximum) {
  fields(value, OUTPUT);
  if (value.path_hex !== path || !Number.isSafeInteger(value.payload_bytes) || value.payload_bytes < 0 ||
      value.payload_bytes > maximum || typeof value.executable !== 'boolean') fail('Native artifact output changed path, size or mode.');
  digest(value.artifact_id_sha256); digest(value.payload_sha256);
}
function charge(totals, key, amount, limit) {
  const next = (totals[key] ?? 0) + amount;
  if (!Number.isSafeInteger(next) || next > limit) fail('Native artifact observations exceed the shared dispatch allowance.');
  totals[key] = next;
}
function byJob(rows, field) {
  const result = new Map();
  for (const row of rows) {
    const key = hex(row[field]);
    if (!result.has(key)) result.set(key, []);
    result.get(key).push(row);
  }
  return result;
}

// Called only after the immutable contract and execution report are validated.
// totals is owned by one dispatch, not reset between workflow children.
export function verifyArtifactReceipts(config, run, totals) {
  if (!config) {
    if (Object.hasOwn(run, 'artifacts') || Object.hasOwn(run, 'artifact_inputs') || Object.hasOwn(run, 'artifact_logs')) {
      fail('Native execution introduced unrequested artifact observations.');
    }
    return;
  }
  const jobs = new Map(run.execution.jobs.map((job, index) => [hex(job.id), { job, index }]));
  const outputs = byJob(config.selections.filter(row => row.workflow_path_hex === run.workflow_path_hex), 'job_id');
  const inputs = byJob((config.inputs ?? []).filter(row => row.workflow_path_hex === run.workflow_path_hex), 'consumer_job_id');
  for (const key of [...outputs.keys(), ...inputs.keys()]) {
    if (!jobs.has(key)) fail('Configured artifact job is absent from the native execution report.');
  }
  const captured = new Map();
  for (const receipt of array(run.artifacts, outputs.size)) {
    fields(receipt, ['job_id_hex', 'manifest_id_sha256', 'outputs']);
    const selected = outputs.get(receipt.job_id_hex), owner = jobs.get(receipt.job_id_hex);
    if (!selected || !owner || owner.job.outcome === 'skipped' || captured.has(receipt.job_id_hex)) {
      fail('Unexpected, skipped or duplicate native artifact producer.');
    }
    digest(receipt.manifest_id_sha256);
    if (array(receipt.outputs, selected.length).length !== selected.length) fail('Native artifact capture is incomplete.');
    const files = new Map();
    for (const file of receipt.outputs) {
      const selectedFile = selected.find(row => row.output_path_hex === file?.path_hex);
      if (!selectedFile || files.has(file.path_hex)) fail('Unexpected or duplicate native artifact output.');
      output(file, selectedFile.output_path_hex, config.maximum_file_mib * MIB);
      charge(totals, 'artifactPayload', file.payload_bytes, config.total_payload_mib * MIB);
      files.set(file.path_hex, file);
    }
    captured.set(receipt.job_id_hex, { manifest: receipt.manifest_id_sha256, files });
  }
  for (const key of outputs.keys()) {
    if (jobs.get(key).job.outcome === 'succeeded' && !captured.has(key)) {
      fail('Successful native producer is missing its selected artifact capture.');
    }
  }
  verifyArtifactLogs(config, run, totals);
  if (!config.inputs?.length) {
    if (Object.hasOwn(run, 'artifact_inputs')) fail('Native execution introduced unrequested artifact deliveries.');
    return;
  }
  const delivered = new Set();
  for (const receipt of array(run.artifact_inputs, inputs.size)) {
    fields(receipt, ['job_id_hex', 'workspace_plan_sha256', 'inputs']);
    const selected = inputs.get(receipt.job_id_hex), consumer = jobs.get(receipt.job_id_hex);
    if (!selected || !consumer || consumer.job.outcome === 'skipped' || delivered.has(receipt.job_id_hex)) {
      fail('Unexpected, skipped or duplicate native artifact consumer.');
    }
    digest(receipt.workspace_plan_sha256);
    if (array(receipt.inputs, selected.length).length !== selected.length) fail('Native artifact delivery is incomplete.');
    const destinations = new Set();
    let workspaceBytes = 0;
    for (const input of receipt.inputs) {
      fields(input, ['producer_job_id_hex', 'producer_manifest_id_sha256', 'output', 'destination_path_hex']);
      const requested = selected.find(row => hex(row.producer_job_id) === input.producer_job_id_hex &&
        row.output_path_hex === input.output?.path_hex && NAMESPACE + row.destination_hex === input.destination_path_hex);
      const producer = jobs.get(input.producer_job_id_hex), source = captured.get(input.producer_job_id_hex);
      const file = source?.files.get(input.output?.path_hex);
      if (!requested || destinations.has(input.destination_path_hex) || !producer || producer.index >= consumer.index ||
          producer.job.outcome !== 'succeeded' || !source || input.producer_manifest_id_sha256 !== source.manifest || !file) {
        fail('Native artifact input is not bound to a successful earlier producer from this attempt.');
      }
      output(input.output, requested.output_path_hex, 16 * MIB);
      if (OUTPUT.some(key => input.output[key] !== file[key])) fail('Native delivered artifact differs from its producing receipt.');
      destinations.add(input.destination_path_hex);
      charge(totals, 'artifactDelivery', file.payload_bytes, config.total_delivery_mib * MIB);
      workspaceBytes += file.payload_bytes;
      if (workspaceBytes > 64 * MIB) fail('Native artifact deliveries exceed one workspace payload allowance.');
    }
    delivered.add(receipt.job_id_hex);
  }
  for (const key of inputs.keys()) {
    const job = jobs.get(key).job;
    // A refused/cancelled job with no steps may have stopped before opening its
    // workspace. A prepared receipt is not evidence it actually materialized.
    if ((job.outcome === 'succeeded' || job.steps.length > 0) && !delivered.has(key)) {
      fail('Started native consumer is missing its selected artifact delivery.');
    }
  }
}
