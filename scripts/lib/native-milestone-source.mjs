// Native milestone data migration. Source authors, versions and history remain
// attribution; every destination action is an ordinary newly admitted command.
import { milestoneState, milestoneMutationRequest }
  from '../../crates/fgit-node/src/smart_http/server/browser/milestones.mjs';
import { natural } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { nativeSourceIdentity, nativeMilestoneMapRows, partitionNativeIssueArchiveV3,
  NATIVE_CAPTURE_LIMIT } from './native-issue-source.mjs';
import { operatorError, recordDigest } from './forge-operator-io.mjs';

export const NATIVE_MILESTONE_MAP_SCHEMA = 'frankengit-native-milestone-map-v1';
export const NATIVE_MILESTONE_CAPTURE_SCHEMA = 'frankengit-native-milestone-capture-v1';
export const NATIVE_MILESTONE_CAPTURE_LIMIT = NATIVE_CAPTURE_LIMIT;
const SNAPSHOT = ['number', 'version', 'title', 'body', 'due_at', 'state', 'opened_by', 'last_actor'];
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const fail = reason => { throw operatorError(`native_milestone_source_${reason}`); };
function keys(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) fail('fields');
}
function decoded(input) {
  if (!(input instanceof Uint8Array) || input.buffer instanceof SharedArrayBuffer ||
      !input.length || input.length > NATIVE_CAPTURE_LIMIT) fail('capture_bytes');
  const bytes = Buffer.from(input);
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!encode(value).equals(bytes)) fail('encoding');
  return { bytes, value };
}
export function parseNativeMilestoneMap(input) {
  const { bytes, value } = decoded(input);
  keys(value, ['schema', 'mappings']);
  if (value.schema !== NATIVE_MILESTONE_MAP_SCHEMA) fail('map_schema');
  const mappings = nativeMilestoneMapRows(value.mappings);
  if (!encode({ schema: NATIVE_MILESTONE_MAP_SCHEMA, mappings }).equals(bytes)) fail('encoding');
  return mappings;
}
export function validateNativeMilestoneMap(mappings, milestones) {
  const checked = nativeMilestoneMapRows(mappings);
  if (!Array.isArray(milestones) || milestones.length > 4096 || milestones.length !== checked.length) fail('map_coverage');
  for (const [index, record] of milestones.entries()) {
    milestoneState(record.snapshot);
    if (record.snapshot.number !== checked[index].source) fail('map_coverage');
  }
  return checked;
}
export function nativeMilestoneCaptureBytes(value) {
  keys(value, ['schema', 'source', 'phase', 'milestones']);
  if (value.schema !== NATIVE_MILESTONE_CAPTURE_SCHEMA || !['open', 'close'].includes(value.phase)) fail('schema');
  const source = nativeSourceIdentity(value.source);
  if (!Array.isArray(value.milestones)) fail('milestones');
  natural(value.milestones.length, 'milestone capture count', 1, 100);
  let previous = 0; const destinations = new Set();
  const milestones = value.milestones.map(row => {
    keys(row, ['source_number', 'destination_number', 'snapshot']); keys(row.snapshot, SNAPSHOT);
    natural(row.source_number, 'source milestone number', previous + 1); previous = row.source_number;
    natural(row.destination_number, 'destination milestone number', 1);
    if (destinations.has(row.destination_number)) fail('map_destination');
    destinations.add(row.destination_number);
    if (row.snapshot.number !== row.source_number) fail('milestone_identity');
    milestoneState({ ...row.snapshot, open_issues: 0, closed_issues: 0 });
    if (value.phase === 'close' && row.snapshot.state !== 'closed') fail('close_phase');
    return { source_number: row.source_number, destination_number: row.destination_number,
      snapshot: Object.fromEntries(SNAPSHOT.map(key => [key, row.snapshot[key]])) };
  });
  const bytes = encode({ schema: NATIVE_MILESTONE_CAPTURE_SCHEMA, source, phase: value.phase, milestones });
  if (!bytes.equals(encode(value))) fail('encoding');
  if (bytes.length > NATIVE_CAPTURE_LIMIT) fail('capture_bytes');
  return bytes;
}
export function parseNativeMilestoneCapture(input) {
  const { bytes, value } = decoded(input);
  if (!nativeMilestoneCaptureBytes(value).equals(bytes)) fail('encoding');
  return value;
}
function provenance(source, row) {
  const metadata = { ...source, milestone_number: row.source_number,
    destination_milestone_number: row.destination_number, source_version: row.snapshot.version,
    source_state: row.snapshot.state, source_opened_by: row.snapshot.opened_by, source_last_actor: row.snapshot.last_actor };
  const json = JSON.stringify(metadata), runs = json.match(/~+/g) ?? [];
  const fence = '~'.repeat(runs.reduce((n, run) => Math.max(n, run.length + 1), 3));
  return `Imported native milestone snapshot. Source identities below are attribution only, not destination principals, permissions or audit events.\n\n${fence}json\n${json}\n${fence}\n\n${row.snapshot.body}`;
}
export function nativeMilestoneImportSteps(value) {
  nativeMilestoneCaptureBytes(value);
  const steps = value.milestones.map(row => {
    const fields = value.phase === 'open' ? { title: row.snapshot.title,
      body: provenance(value.source, row), due_at: row.snapshot.due_at } : {};
    const request = milestoneMutationRequest(row.destination_number, value.phase === 'open' ? 0 : 1, value.phase, fields);
    return { source: `native-milestone:${value.source.archive_sha256}:${row.source_number}:${row.snapshot.version}:${value.phase}`,
      number: row.destination_number, expected_version: request.expected_version, action: value.phase, fields: request.fields };
  });
  if (encode(steps).length > NATIVE_CAPTURE_LIMIT) fail('plan_bytes');
  return steps;
}
function milestoneBatches(source, phase, rows) {
  const wrap = milestones => ({ schema: NATIVE_MILESTONE_CAPTURE_SCHEMA, source, phase, milestones });
  const batches = [], overhead = encode(wrap([])).length;
  let group = [], captureBytes = overhead, planBytes = 3;
  const finish = () => {
    if (!group.length) return;
    const value = wrap(group), bytes = nativeMilestoneCaptureBytes(value), steps = nativeMilestoneImportSteps(value);
    if (bytes.length !== captureBytes || encode(steps).length !== planBytes) fail('partition_accounting');
    batches.push({ kind: 'milestone', phase, bytes, sha256: recordDigest(bytes), steps: steps.length,
      milestones: group.map(row => ({ source: row.source_number, destination: row.destination_number })) });
    group = []; captureBytes = overhead; planBytes = 3;
  };
  for (const row of rows) {
    const steps = nativeMilestoneImportSteps(wrap([row]));
    const rowBytes = encode(row).length - 1, stepBytes = encode(steps).length - 3;
    if (group.length && (group.length === 100 || captureBytes + rowBytes + 1 > NATIVE_CAPTURE_LIMIT ||
        planBytes + stepBytes + 1 > NATIVE_CAPTURE_LIMIT)) finish();
    captureBytes += rowBytes + Number(group.length > 0); planBytes += stepBytes + Number(group.length > 0);
    group.push(row);
  }
  finish(); return batches;
}
export function partitionNativeIssueArchiveWithMilestones(view, { offset = 0, milestoneMap } = {}) {
  const { archive, records, milestones } = view;
  if (archive?.schema_version !== 2 || archive.complete !== true || archive.canonical_backup !== false ||
      !Array.isArray(records) || !Array.isArray(milestones) || records.length !== archive.issues ||
      milestones.length !== archive.milestones) fail('archive_view');
  natural(records.length, 'source issue count', 0, 4096);
  natural(milestones.length, 'source milestone count', 0, 4096);
  natural(offset, 'target issue offset');
  if (!records.length && !milestones.length) fail('empty_migration');
  const mappings = validateNativeMilestoneMap(milestoneMap, milestones);
  const source = nativeSourceIdentity(Object.fromEntries(['href', 'tenant_id', 'repository_id',
    'snapshot_token', 'source_head', 'archive_sha256'].map(key => [key, archive[key]])));
  const rows = milestones.map((record, index) => ({ source_number: record.snapshot.number,
    destination_number: mappings[index].destination,
    snapshot: Object.fromEntries(SNAPSHOT.map(key => [key, record.snapshot[key]])) }));
  // All target milestones stay at version one until every membership is set.
  // Source-closed milestones are closed last, retaining their issue members.
  const batches = [...milestoneBatches(source, 'open', rows),
    ...partitionNativeIssueArchiveV3(view, { offset, milestoneMap: mappings })
      .map(batch => ({ kind: 'issue', phase: 'issues', ...batch })),
    ...milestoneBatches(source, 'close', rows.filter(row => row.snapshot.state === 'closed'))];
  if (batches.length > 128) fail('batch_limit');
  if (batches.reduce((n, batch) => n + batch.steps, 0) > 10000) fail('step_limit');
  return batches;
}
