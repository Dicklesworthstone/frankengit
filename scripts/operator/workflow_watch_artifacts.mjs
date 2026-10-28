// Operator-selected custody and same-attempt input delivery. Rust verifies and
// copies payloads; this adapter binds its exact requested native contract.
import { absolute, fail } from './workflow_watch_io.mjs';

const MIB = 1024 * 1024;
const hex = value => Buffer.from(value).toString('hex');
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const overlap = (a, b) => a === b || a.startsWith(`${b}2f`) || b.startsWith(`${a}2f`);
function fields(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      required.some(key => !Object.hasOwn(value, key)) ||
      Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) {
    fail('Missing or unsupported watcher artifact fields.');
  }
}
function budget(value, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) fail('Invalid watcher artifact MiB allowance.');
  return value;
}
function job(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.-]{1,256}$/.test(value)) fail('Invalid expanded artifact job identifier.');
  return value;
}
function order(keys) {
  return (a, b) => {
    for (const key of keys) { const result = compare(a[key], b[key]); if (result) return result; }
    return 0;
  };
}

export function artifactConfiguration(value, validatePath, workflowDirectory) {
  fields(value, ['root', 'selections'], ['maximum_file_mib', 'total_payload_mib', 'inputs', 'total_delivery_mib', 'capture_logs']);
  absolute(value.root);
  if (Object.hasOwn(value, 'capture_logs') && typeof value.capture_logs !== 'boolean') fail('Log capture requires an explicit boolean.');
  if (!Array.isArray(value.selections) || (!value.selections.length && value.capture_logs !== true) || value.selections.length > 64) {
    fail('Artifact capture requires 1..64 explicit selections or opt-in log capture.');
  }
  const path = (text, maximum = 4096, supplemental = false) => {
    validatePath(text);
    if (text.length > maximum * 2 || text === hex('.fgit-host-receipt')) fail('Invalid bounded artifact path.');
    // Match TreePath's default repository policy byte-for-byte. The final
    // JobInput path gains one .fgit-artifacts component; reserve its depth now.
    const raw = Buffer.from(text, 'hex'), components = []; let start = 0;
    for (let end = 0; end <= raw.length; end++) if (end === raw.length || raw[end] === 47) { components.push(raw.subarray(start, end)); start = end + 1; }
    if (components.length > (supplemental ? 63 : 64) || raw.some(byte => byte < 0x20) ||
        components.some(part => {
          const folded = part.toString('latin1').replace(/[A-Z]/g, byte => byte.toLowerCase());
          return part.length > 255 || folded === 'git~1' || folded.replace(/[. ]+$/g, '') === '.git';
        }) || (!supplemental && components[0].equals(Buffer.from('.fgit-host-receipt')))) {
      fail('Artifact path exceeds the native component, metadata or byte policy.');
    }
    return text;
  };
  const workflow = text => {
    path(text);
    const prefix = `${workflowDirectory}2f`, suffix = text.slice(prefix.length);
    if (!text.startsWith(prefix) || Buffer.from(suffix, 'hex').includes(47) ||
        !(suffix.endsWith('2e796d6c') || suffix.endsWith('2e79616d6c'))) {
      fail('Artifact workflow must be a direct YAML child of the selected workflow directory.');
    }
    return text;
  };
  const selectionOrder = order(['workflow_path_hex', 'job_id', 'output_path_hex']);
  const selections = value.selections.map(row => {
    fields(row, ['workflow_path_hex', 'job_id', 'output_path_hex']);
    return Object.freeze({ workflow_path_hex: workflow(row.workflow_path_hex), job_id: job(row.job_id), output_path_hex: path(row.output_path_hex) });
  }).sort(selectionOrder);
  if (selections.some((row, index) => index && selectionOrder(row, selections[index - 1]) === 0)) fail('Artifact captures must be distinct.');
  const requested = Object.hasOwn(value, 'inputs') ? value.inputs : [];
  if (!Array.isArray(requested) || requested.length > 64 ||
      (!requested.length && Object.hasOwn(value, 'total_delivery_mib'))) fail('Artifact input allowance requires 1..64 explicit inputs.');
  const inputs = requested.map(row => {
    fields(row, ['workflow_path_hex', 'consumer_job_id', 'producer_job_id', 'output_path_hex', 'destination_hex']);
    const input = { workflow_path_hex: workflow(row.workflow_path_hex), consumer_job_id: job(row.consumer_job_id),
      producer_job_id: job(row.producer_job_id), output_path_hex: path(row.output_path_hex), destination_hex: path(row.destination_hex, 4000, true) };
    if (input.consumer_job_id === input.producer_job_id || !selections.some(output => output.workflow_path_hex === input.workflow_path_hex &&
        output.job_id === input.producer_job_id && output.output_path_hex === input.output_path_hex)) {
      fail('Artifact inputs require different jobs and an explicitly captured producer output.');
    }
    return Object.freeze(input);
  }).sort(order(['workflow_path_hex', 'consumer_job_id', 'producer_job_id', 'output_path_hex', 'destination_hex']));
  for (let index = 0; index < inputs.length; index++) {
    const input = inputs[index];
    if (inputs.slice(0, index).some(previous => previous.workflow_path_hex === input.workflow_path_hex &&
        previous.consumer_job_id === input.consumer_job_id && overlap(previous.destination_hex, input.destination_hex))) {
      fail('Artifact input destinations overlap within a consumer.');
    }
  }
  const pathBytes = selections.reduce((n, row) => n + (row.workflow_path_hex.length + row.output_path_hex.length) / 2, 0) +
    inputs.reduce((n, row) => n + (row.workflow_path_hex.length + row.output_path_hex.length + row.destination_hex.length) / 2, 0);
  if (pathBytes > 64 * 1024) fail('Combined watcher artifact paths exceed 64 KiB.');
  const result = { root: value.root,
    maximum_file_mib: budget(Object.hasOwn(value, 'maximum_file_mib') ? value.maximum_file_mib : 16, 64),
    total_payload_mib: budget(Object.hasOwn(value, 'total_payload_mib') ? value.total_payload_mib : 64, 512), selections: Object.freeze(selections),
    ...(inputs.length ? { inputs: Object.freeze(inputs), total_delivery_mib: budget(Object.hasOwn(value, 'total_delivery_mib') ? value.total_delivery_mib : 64, 512) } : {}),
    // Disabled capture keeps the historical serialized configuration and keys.
    ...(value.capture_logs === true ? { capture_logs: true } : {}) };
  if (artifactArguments(result).some(argument => Buffer.byteLength(argument) > 8192)) fail('Artifact selector exceeds the native argument envelope.');
  return Object.freeze(result);
}

export function artifactArguments(value) {
  if (!value) return [];
  const args = ['--artifact-root', value.root, '--max-artifact-mib', String(value.maximum_file_mib),
    '--max-artifact-total-mib', String(value.total_payload_mib)];
  if (value.capture_logs === true) args.push('--artifact-logs');
  for (const row of value.selections) args.push('--artifact-hex', `${row.workflow_path_hex}:${row.job_id}:${row.output_path_hex}`);
  for (const row of value.inputs ?? []) {
    args.push('--artifact-input-hex', `${row.workflow_path_hex}:${row.consumer_job_id}:${row.producer_job_id}:${row.output_path_hex}:${row.destination_hex}`);
  }
  if (value.inputs?.length) args.push('--max-artifact-input-total-mib', String(value.total_delivery_mib));
  return args;
}

function nativeContract(value) {
  return { schema_version: 1, root_hex: hex(value.root), trust_domain: 'trusted-workflow-local-owner',
    maximum_file_bytes: value.maximum_file_mib * MIB, total_payload_bytes: value.total_payload_mib * MIB,
    retention_ttl_seconds: 86400,
    selections: value.selections.map(row => ({ workflow_path_hex: row.workflow_path_hex, job_id_hex: hex(row.job_id), output_path_hex: row.output_path_hex })),
    ...(value.inputs?.length ? { input_delivery: { schema_version: 1, namespace_hex: hex('.fgit-artifacts'),
      total_delivery_bytes: value.total_delivery_mib * MIB,
      selections: value.inputs.map(row => ({ workflow_path_hex: row.workflow_path_hex, consumer_job_id_hex: hex(row.consumer_job_id),
        producer_job_id_hex: hex(row.producer_job_id), output_path_hex: row.output_path_hex, destination_hex: row.destination_hex })) } } : {}),
    ...(value.capture_logs === true ? { log_capture: { schema_version: 1, streams: ['stdout', 'stderr'] } } : {}) };
}

export function verifyArtifactContract(value, record) {
  if (!value) {
    if (Object.hasOwn(record, 'artifact_contract')) fail('Native execution introduced an unrequested artifact contract.');
  } else if (JSON.stringify(record.artifact_contract) !== JSON.stringify(nativeContract(value))) {
    fail('Native artifact contract differs from the retained watcher selection.');
  }
}

export function verifyArtifactWorkflows(value, definitions) {
  if (value && value.selections.some(row => !definitions.some(definition => definition.selected && definition.path_hex === row.workflow_path_hex))) {
    fail('Native artifact workflow was absent or not selected by the dispatch.');
  }
}
