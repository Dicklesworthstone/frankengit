// Closed native queue observations, commands and immutable terminal receipts.
// Queue membership is metadata; only native landing decides a protected ref move.
import { binding, copy, fail, form, format, hex, integer, keys, oid, opaque, pinned,
  principal, record, snapshot, text, unhex, utf8 } from './pulls-core.mjs';

export const MAX_QUEUE_ENTRIES = 1024;
export const COMMAND_LIMIT = 64 * 1024;
export const RECEIPT_LIMIT = 256 * 1024;
const SCOPE_FIELDS = ['schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format'];
const READ_FIELDS = [...SCOPE_FIELDS, 'source_head', 'snapshot_token'];
const REASONS = ['withdrawn', 'conflict', 'check-failed', 'base-moved', 'evicted', 'admin-override'];
export function queueInteger(value, name, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  integer(value, name, minimum, maximum);
  if (Object.is(value, -0)) fail(`Invalid ${name}; negative zero is not canonical.`);
  return value;
}
function closed(value, names) {
  keys(value, names);
  if (names.some(name => !Object.hasOwn(value, name))) fail('Missing queue response field.');
  return value;
}
export function queueScope(value) {
  closed(value, ['tenant', 'repository', 'incarnation', 'format']);
  return { tenant: principal(value.tenant), repository: principal(value.repository),
    incarnation: principal(value.incarnation), format: format(value.format) };
}
function selected(reply, scope, expected) {
  const result = pinned(reply, scope, expected);
  queueScope(result.binding);
  return result;
}
export function queueBranch(value) {
  const bytes = unhex(value, 1024), raw = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
  if (!raw.startsWith('refs/heads/') || raw.length === 11 || /[\x00-\x20\x7f~^:?*\[\\]/.test(raw) ||
      raw.includes('..') || raw.includes('@{') || raw.endsWith('.') ||
      raw.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) fail('Invalid native queue branch bytes.');
  return value;
}
export function queueReference(row, name) {
  record(row);
  const bytes = queueBranch(row[`${name}_hex`]);
  if (row[name] !== null) {
    text(row[name], 1024, 'native branch text');
    if (hex(utf8.encode(row[name])) !== bytes) fail('Queue branch text and native bytes disagree.');
  }
  return bytes;
}
function branchField(fields, name) {
  const raw = Object.hasOwn(fields, name), encoded = Object.hasOwn(fields, `${name}_hex`);
  if (raw === encoded) fail(`Supply exactly one ${name} encoding.`);
  return queueBranch(encoded ? fields[`${name}_hex`] : hex(utf8.encode(text(fields[name], 1024, name))));
}
export function queueSnapshot(row, algorithm) {
  closed(row, ['number', 'target_ref', 'target_ref_hex', 'version', 'entries', 'order', 'active_batch']);
  queueInteger(row.number, 'queue number', 1); queueInteger(row.version, 'queue version', 1);
  const target = queueReference(row, 'target_ref');
  if (!Array.isArray(row.entries) || row.entries.length > MAX_QUEUE_ENTRIES || !Array.isArray(row.order) ||
      row.order.length !== row.entries.length) fail('Invalid bounded queue membership.');
  const seen = new Set();
  for (let index = 0; index < row.entries.length; index++) {
    const entry = closed(row.entries[index], ['pull_request', 'source_ref', 'source_ref_hex', 'head_tip', 'enqueued_by', 'priority', 'enqueued_version']);
    queueInteger(entry.pull_request, 'queued PR number', 1); queueInteger(entry.priority, 'priority', 0, 0xffffffff);
    queueInteger(entry.enqueued_version, 'enqueue version', 1, row.version);
    principal(entry.enqueued_by); oid(entry.head_tip, algorithm);
    if (queueReference(entry, 'source_ref') === target || seen.has(entry.pull_request) || row.order[index] !== entry.pull_request) fail('Queue order or exact membership is inconsistent.');
    seen.add(entry.pull_request);
  }
  if (row.active_batch !== null && (typeof row.active_batch !== 'string' || !/^[0-9a-f]{64}$/.test(row.active_batch))) fail('Invalid active queue batch.');
  return row;
}
export function queuePage(reply, { after = 0, limit = 20, head = null, scope = null } = {}) {
  queueInteger(after, 'queue cursor'); queueInteger(limit, 'queue page size', 1, 100);
  if (head !== null) snapshot(head); if (after && head === null) fail('Continuation requires its original snapshot.');
  closed(reply, ['type', ...READ_FIELDS, 'after', 'limit', 'next_after', 'queues', 'complete']);
  const result = selected(reply, scope, head);
  queueInteger(reply.after, 'returned queue cursor'); queueInteger(reply.limit, 'returned queue page size', 1, 100);
  if (reply.type !== 'merge_queue_page' || reply.complete !== true || reply.after !== after || reply.limit !== limit ||
      !Array.isArray(reply.queues) || reply.queues.length > limit) fail('Invalid complete queue page.');
  let previous = after;
  for (const row of reply.queues) {
    queueSnapshot(row, result.binding.format);
    if (row.number <= previous) fail('Queue page is not strictly ordered.');
    previous = row.number;
  }
  if (reply.next_after !== null && (reply.queues.length !== limit || reply.next_after !== previous || !reply.queues.length)) fail('Invalid queue continuation.');
  return { ...result, reply };
}
export function queueShow(reply, number, { head = null, scope = null } = {}) {
  queueInteger(number, 'queue number', 1); if (head !== null) snapshot(head);
  closed(reply, ['type', ...READ_FIELDS, 'number', 'found', 'version', 'queue', 'complete']);
  const result = selected(reply, scope, head);
  queueInteger(reply.version, 'returned queue version');
  if (reply.type !== 'merge_queue' || reply.complete !== true || reply.number !== number || typeof reply.found !== 'boolean') fail('Invalid complete queue response.');
  if (reply.found) {
    queueSnapshot(reply.queue, result.binding.format);
    if (reply.queue.number !== number || reply.version !== reply.queue.version) fail('Wrong queue or version returned.');
  } else if (reply.queue !== null || reply.version !== 0) fail('Absent queue contains state.');
  return { ...result, reply };
}
export function normalizeQueueFields(action, fields, algorithm) {
  const common = ['expected_version', 'target_ref', 'target_ref_hex'];
  const candidate = ['pull_request', 'expected_pull_request_version', 'source_ref', 'source_ref_hex', 'expected_source_tip', 'expected_target_tip'];
  const extra = ({ enqueue: [...candidate, 'priority'], dequeue: ['pull_request', 'reason'], reorder: ['entry'], land: [...candidate, 'expected_policy_epoch'] })[action];
  if (!extra) fail('Unsupported queue action.');
  keys(fields, [...common, ...extra]); format(algorithm);
  const normalized = { expected_version: queueInteger(fields.expected_version, 'expected queue version', action === 'enqueue' ? 0 : 1,
    Number.MAX_SAFE_INTEGER - (action === 'land' ? 2 : 1)), target_ref_hex: branchField(fields, 'target_ref') };
  if (action === 'enqueue' || action === 'land') {
    Object.assign(normalized, { pull_request: queueInteger(fields.pull_request, 'PR number', 1),
      expected_pull_request_version: queueInteger(fields.expected_pull_request_version, 'expected PR version', 1,
        Number.MAX_SAFE_INTEGER - (action === 'land' ? 1 : 0)),
      source_ref_hex: branchField(fields, 'source_ref'), expected_source_tip: oid(fields.expected_source_tip, algorithm),
      expected_target_tip: oid(fields.expected_target_tip, algorithm) });
    if (normalized.source_ref_hex === normalized.target_ref_hex) fail('Queue source and target branches must differ.');
    if (action === 'enqueue') normalized.priority = queueInteger(fields.priority === undefined ? 0 : fields.priority, 'priority', 0, 0xffffffff);
    else {
      normalized.expected_policy_epoch = queueInteger(fields.expected_policy_epoch, 'policy epoch', 1);
      if (normalized.expected_source_tip === normalized.expected_target_tip) fail('Fast-forward landing requires distinct source and target tips.');
    }
  } else if (action === 'dequeue') {
    normalized.pull_request = queueInteger(fields.pull_request, 'PR number', 1);
    if (!REASONS.includes(fields.reason)) fail('Select an explicit native dequeue reason.');
    normalized.reason = fields.reason;
  } else {
    if (!Array.isArray(fields.entry) || !fields.entry.length || fields.entry.length > MAX_QUEUE_ENTRIES) fail('Supply the complete nonempty queue order.');
    normalized.entry = fields.entry.map(value => queueInteger(value, 'PR number', 1));
    if (new Set(normalized.entry).size !== normalized.entry.length) fail('Duplicate PR in queue order.');
  }
  return normalized;
}
export function queueCommand(action, fields, scope) {
  const selected = queueScope(scope);
  return { expected_incarnation: selected.incarnation, object_format: selected.format,
    ...normalizeQueueFields(action, fields, selected.format) };
}
export function queueMutationRequest(number, action, fields, scope) {
  queueInteger(number, 'queue number', 1);
  const command = queueCommand(action, fields, scope), normalized = normalizeQueueFields(action, fields, scope.format);
  const body = form(command), bytes = utf8.encode(body);
  if (bytes.length > COMMAND_LIMIT) fail('Queue command exceeds 64 KiB.');
  return { number, action, fields: normalized, command, path: `queues/${number}/${action}`, body, bytes,
    contentType: 'application/x-www-form-urlencoded' };
}
export async function queueRequestKey(root, fingerprint, scope, number, action, nonce, request, crypto) {
  if (!/^[0-9a-f]{64}$/.test(fingerprint) || !/^[0-9a-f]{32}$/.test(nonce)) fail('Invalid queue recovery commitment.');
  const digest = async bytes => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
  const s = queueScope(scope), bodyDigest = await digest(request.bytes);
  const message = JSON.stringify(['frankengit-browser-queue-intent-v1', root.origin, root.route, fingerprint,
    [s.tenant, s.repository, s.incarnation, s.format], number, action, nonce, request.contentType, bodyDigest]);
  return `fgq1-${nonce}-${await digest(utf8.encode(message))}`;
}
function sameAction(reply, pending) {
  const { action, fields: f, scope } = pending, proposed = reply.proposed_action;
  const base = ['name'];
  if (action === 'enqueue' || action === 'land') {
    closed(proposed, [...base, 'pull_request', 'expected_pull_request_version', 'source_ref', 'source_ref_hex', 'expected_source_tip', 'expected_target_tip',
      ...(action === 'enqueue' ? ['priority'] : ['method', 'expected_policy_epoch'])]);
    if (proposed.pull_request !== f.pull_request || proposed.expected_pull_request_version !== f.expected_pull_request_version ||
        queueReference(proposed, 'source_ref') !== f.source_ref_hex || oid(proposed.expected_source_tip, scope.format) !== f.expected_source_tip ||
        oid(proposed.expected_target_tip, scope.format) !== f.expected_target_tip) fail('Queue publication changed the exact PR or tips.');
    if (action === 'enqueue') queueInteger(proposed.priority, 'returned queue priority', 0, 0xffffffff);
    if (action === 'enqueue' ? proposed.priority !== f.priority : proposed.method !== 'fast-forward-only' || proposed.expected_policy_epoch !== f.expected_policy_epoch) fail('Queue publication changed priority, method or policy.');
  } else if (action === 'dequeue') {
    closed(proposed, [...base, 'pull_request', 'reason']);
    if (proposed.pull_request !== f.pull_request || proposed.reason !== f.reason) fail('Queue removal command changed.');
  } else {
    closed(proposed, [...base, 'order']);
    if (!Array.isArray(proposed.order) || JSON.stringify(proposed.order) !== JSON.stringify(f.entry)) fail('Queue order changed.');
  }
  if (proposed.name !== action) fail('Queue publication action changed.');
}
export function queuePublication(reply, pending, status) {
  closed(reply, ['type', ...SCOPE_FIELDS, 'principal_id', 'number', 'target_ref', 'target_ref_hex', 'expected_version', 'proposed_action',
    'tx_id', 'decision_sequence', 'outcome', 'committed', 'repository_commit_id', 'refusal_record_id', 'refusal_code',
    'refs_changed', 'delivery_acknowledged', 'historical_outcome', 'complete']);
  binding(reply, pending.scope); queueScope(pending.scope); principal(reply.principal_id); opaque(reply.tx_id);
  queueInteger(reply.decision_sequence, 'decision sequence', 1);
  queueInteger(reply.expected_version, 'returned expected queue version');
  if (reply.type !== 'merge_queue_publication' || reply.number !== pending.number || reply.expected_version !== pending.fields.expected_version ||
      queueReference(reply, 'target_ref') !== pending.fields.target_ref_hex || reply.complete !== true || reply.historical_outcome !== true ||
      reply.delivery_acknowledged !== null || !['committed', 'refused'].includes(reply.outcome) ||
      reply.committed !== (reply.outcome === 'committed') || status !== (reply.committed ? 200 : 409) ||
      reply.refs_changed !== (pending.action === 'land' && reply.committed)) fail('Response is not the matching canonical queue decision.');
  sameAction(reply, pending);
  if (pending.observedTx !== null && pending.observedTx !== reply.tx_id) fail('Queue transaction identity changed.');
  if (pending.observedPrincipal !== null && pending.observedPrincipal !== reply.principal_id) fail('Queue recovery principal changed.');
  if (reply.committed) {
    opaque(reply.repository_commit_id);
    if (reply.refusal_record_id !== null || reply.refusal_code !== null) fail('Conflicting queue terminal outcomes.');
  } else {
    opaque(reply.refusal_record_id); opaque(reply.refusal_code);
    if (reply.repository_commit_id !== null) fail('Conflicting queue terminal outcomes.');
  }
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    rcr: reply.repository_commit_id, refusal: reply.refusal_code, deliveryAcknowledged: null,
    number: pending.number, action: pending.action, refsChanged: reply.refs_changed, reply: copy(reply) };
}
