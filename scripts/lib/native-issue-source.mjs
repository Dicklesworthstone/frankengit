// Current issue state and discussion from a completely verified native archive.
// Source identities are attribution only; NEVER destination actor/assignee IDs.
import { IssueClient, issueState, issueLocked, issueMilestone, issueAction, mutationRequest, natural, snapshotToken }
  from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { recordDigest, operatorError } from './forge-operator-io.mjs';

export const NATIVE_CAPTURE_SCHEMA = 'frankengit-native-issue-capture-v1';
export const NATIVE_CAPTURE_SCHEMA_V2 = 'frankengit-native-issue-capture-v2';
export const NATIVE_CAPTURE_LIMIT = 1024 * 1024;
const MAX_STEPS = 2200;
const SNAPSHOT_V1 = ['number', 'version', 'title', 'body', 'labels', 'state', 'opened_by', 'last_actor', 'comments', 'assignees'];
const SNAPSHOT_V2 = [...SNAPSHOT_V1, 'locked'];
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const fail = code => { throw operatorError(`native_issue_source_${code}`); };
function keys(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== names.length || names.some(k => !Object.hasOwn(value, k))) fail('fields');
}
function opaque(value) {
  if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value) > 256 ||
      /[\x00-\x1f\x7f-\x9f\uD800-\uDFFF]/u.test(value)) fail('identity');
  return value;
}
export function nativeCaptureBytes(value) {
  keys(value, ['schema', 'source', 'issues']);
  // V1 is frozen: its exact field set, canonical order, provenance and compiled
  // requests must remain recoverable with the original saved plan and keys.
  const snapshotFields = value.schema === NATIVE_CAPTURE_SCHEMA ? SNAPSHOT_V1
    : value.schema === NATIVE_CAPTURE_SCHEMA_V2 ? SNAPSHOT_V2 : null;
  if (!snapshotFields) fail('schema');
  const s = value.source;
  keys(s, ['href', 'tenant_id', 'repository_id', 'snapshot_token', 'source_head', 'archive_sha256']);
  if (typeof s.href !== 'string' || s.href.length > 4096 || new URL(s.href).href !== s.href) fail('url');
  new IssueClient({ href: s.href });
  for (const k of ['tenant_id', 'repository_id']) if (typeof s[k] !== 'string' || !/^[0-9a-f]{32}$/.test(s[k])) fail('identity');
  snapshotToken(s.snapshot_token); opaque(s.source_head);
  if (typeof s.archive_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(s.archive_sha256)) fail('archive_pin');
  if (!Array.isArray(value.issues)) fail('issues');
  natural(value.issues.length, 'native capture issues', 1, 100);
  let previous = 0, commentCount = 0;
  for (const row of value.issues) {
    keys(row, ['number', 'id', 'snapshot', 'comments']);
    natural(row.number, 'source issue', previous + 1); previous = row.number;
    if (row.id !== String(row.number) || row.snapshot?.number !== row.number) fail('issue_identity');
    if (issueMilestone(row.snapshot) !== null) fail('milestones_unsupported');
    keys(row.snapshot, snapshotFields);
    issueState(row.snapshot);
    if (!Array.isArray(row.comments) || row.comments.length !== row.snapshot.comments) fail('comment_count');
    commentCount += row.comments.length;
    if (commentCount > 2000) fail('comment_limit');
    let version = 1;
    for (const c of row.comments) {
      keys(c, ['version', 'actor', 'body']);
      natural(c.version, 'source comment version', version + 1, row.snapshot.version); version = c.version;
      opaque(c.actor); issueAction('comment', { body: c.body });
    }
  }
  const ordered = (row, fields) => Object.fromEntries(fields.map(k => [k, row[k]]));
  const checked = { schema: value.schema,
    source: ordered(s, ['href', 'tenant_id', 'repository_id', 'snapshot_token', 'source_head', 'archive_sha256']),
    issues: value.issues.map(row => ({ number: row.number, id: row.id,
      snapshot: ordered(row.snapshot, snapshotFields),
      comments: row.comments.map(c => ordered(c, ['version', 'actor', 'body'])) })) };
  const bytes = encode(checked);
  if (!bytes.equals(encode(value))) fail('encoding');
  if (bytes.length > NATIVE_CAPTURE_LIMIT) fail('capture_bytes');
  return bytes;
}
export function parseNativeIssueCapture(input) {
  if (!(input instanceof Uint8Array) || input.buffer instanceof SharedArrayBuffer ||
      !input.length || input.length > NATIVE_CAPTURE_LIMIT) fail('capture_bytes');
  const bytes = Buffer.from(input);
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!nativeCaptureBytes(value).equals(bytes)) fail('encoding');
  return value;
}
function provenance(source, row, comment) {
  const metadata = { ...source, issue_number: row.number, source_version: row.snapshot.version,
    ...(comment ? { comment_version: comment.version, source_actor: comment.actor }
      : { source_opened_by: row.snapshot.opened_by, source_last_actor: row.snapshot.last_actor,
        source_assignees: row.snapshot.assignees }) };
  const json = JSON.stringify(metadata), runs = json.match(/~+/g) ?? [];
  const fence = '~'.repeat(runs.reduce((n, run) => Math.max(n, run.length + 1), 3));
  return `Imported native issue snapshot. Source identities below are attribution only, not destination principals, assignments, permissions or audit events.\n\n${fence}json\n${json}\n${fence}\n\n${comment ? comment.body : row.snapshot.body}`;
}
export function nativeIssueImportSteps(value, offset = 0) {
  nativeCaptureBytes(value); natural(offset, 'target issue offset');
  const steps = [];
  for (const row of value.issues) {
    const number = natural(row.number + offset, 'target issue number', 1);
    let version = 0;
    const add = (action, fields, sourceVersion) => {
      const request = mutationRequest(number, version++, action, fields);
      steps.push({ source: `native:${value.source.archive_sha256}:${row.number}:${sourceVersion}`,
        number, expected_version: request.expected_version, action, fields: request.fields });
      if (steps.length > MAX_STEPS) fail('native_plan_steps');
    };
    add('open', { title: row.snapshot.title, body: provenance(value.source, row), labels: row.snapshot.labels }, row.snapshot.version);
    for (const comment of row.comments) add('comment', { body: provenance(value.source, row, comment) }, comment.version);
    if (row.snapshot.state === 'closed') add('close', {}, row.snapshot.version);
    // Newly opened issues are unlocked. Preserve discussion first, then apply
    // the source's final moderation state using the destination's next version.
    if (value.schema === NATIVE_CAPTURE_SCHEMA_V2 && row.snapshot.locked) add('lock', {}, row.snapshot.version);
  }
  if (encode(steps).length > NATIVE_CAPTURE_LIMIT) fail('native_plan_bytes');
  return steps;
}
// Partition without quadratic re-encoding. Each complete issue is indivisible;
// one over-envelope discussion refuses rather than losing comments or reopening
// the same destination number in another batch. Every byte bound includes JSON
// delimiters and provenance expansion, not just raw user text.
export function partitionNativeIssueArchive({ archive, records }, offset = 0) {
  if (archive?.complete !== true || archive.canonical_backup !== false ||
      !Array.isArray(records) || records.length !== archive.issues) fail('archive_view');
  natural(records.length, 'source issue count', 1, 4096); natural(offset, 'target issue offset');
  const source = Object.fromEntries(['href', 'tenant_id', 'repository_id', 'snapshot_token', 'source_head', 'archive_sha256']
    .map(k => [k, archive[k]]));
  const wrap = issues => ({ schema: NATIVE_CAPTURE_SCHEMA_V2, source, issues });
  const overhead = encode(wrap([])).length, batches = [];
  let group = [], captureBytes = overhead, planBytes = 3, comments = 0, count = 0, totalSteps = 0, previous = 0;
  const finish = () => {
    if (!group.length) return;
    const value = wrap(group), bytes = nativeCaptureBytes(value), steps = nativeIssueImportSteps(value, offset);
    if (bytes.length !== captureBytes || encode(steps).length !== planBytes || steps.length !== count) fail('partition_accounting');
    batches.push({ bytes, sha256: recordDigest(bytes), steps: count, issues: group.map(r => ({ number: r.number, id: r.id })) });
    if (batches.length > 128) fail('batch_limit');
    group = []; captureBytes = overhead; planBytes = 3; comments = 0; count = 0;
  };
  for (const record of records) {
    // Normalize only the historical absence of the flag. Never coerce a
    // malformed supplied value, mutate the verified source view or rewrite v1.
    const locked = issueLocked(record.snapshot);
    if (issueMilestone(record.snapshot) !== null) fail('milestones_unsupported');
    const snapshot = structuredClone(record.snapshot);
    delete snapshot.milestone;
    delete snapshot.locked;
    snapshot.locked = locked;
    const row = { number: record.snapshot.number, id: String(record.snapshot.number),
      snapshot, comments: structuredClone(record.comments) };
    natural(row.number, 'archive issue order', previous + 1); previous = row.number;
    const single = wrap([row]), steps = nativeIssueImportSteps(single, offset);
    const rowBytes = encode(row).length - 1, stepBytes = encode(steps).length - 3;
    totalSteps += steps.length;
    if (totalSteps > 10000) fail('step_limit');
    if (group.length && (group.length === 100 || comments + row.comments.length > 2000 || count + steps.length > MAX_STEPS ||
        captureBytes + rowBytes + 1 > NATIVE_CAPTURE_LIMIT || planBytes + stepBytes + 1 > NATIVE_CAPTURE_LIMIT)) finish();
    captureBytes += rowBytes + Number(group.length > 0); planBytes += stepBytes + Number(count > 0);
    group.push(row); count += steps.length; comments += row.comments.length;
  }
  finish(); return batches;
}
