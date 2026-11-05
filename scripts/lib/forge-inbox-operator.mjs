// Authenticated self-only inbox operations over the shipped notification clients.
// Private records retain original request custody; they never establish authority.
import { natural, snapshotToken, MAX_RECEIPT_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { NotificationClient, DiscussionNotificationClient, notificationMutationRequest }
  from '../../crates/fgit-node/src/smart_http/server/browser/notifications.mjs';
import { connectIssueToken, issueOperatorFetch } from './forge-issue-operator.mjs';
import { operatorError, operatorPath, operatorJson, privateRecordPath, absentRecord,
  readPrivateOperatorFile, readSynchronizedOperatorRecord, saveOperatorRecord, recordDigest } from './forge-operator-io.mjs';

const ACTIONS = ['subscribe', 'mute', 'automatic', 'read', 'unread'];
const RECOVERY = ['status', 'retry'];
const READS = ['list', 'show'];
const SCHEMA = 'frankengit-inbox-operator-v1';
const MAX_RECORD = MAX_RECEIPT_BYTES * 2;
const fail = code => { throw operatorError(code); };
const own = (value, key) => Object.hasOwn(value, key);
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => own(value, key));
const identity = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
const clientType = kind => kind === 'discussion' ? DiscussionNotificationClient : NotificationClient;

export function inboxOperatorOptions(raw) {
  const keys = ['operation', 'kind', 'href', 'tenant', 'repository', 'tokenFile', 'record',
    'number', 'expectedVersion', 'readThrough', 'expectedPrincipal', 'expectedIncarnation',
    'after', 'head', 'limit', 'maxPages', 'maxOutputBytes', 'unreadOnly', 'includeMuted',
    'timeoutMs', 'signal', 'onProgress'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(key => !keys.includes(key))) fail('inbox_operator_options');
  const o = { ...raw, timeoutMs: raw.timeoutMs ?? 30000, onProgress: raw.onProgress ?? (() => {}) };
  if (!['issue', 'discussion'].includes(o.kind)) fail('inbox_operator_kind_required');
  if (![...READS, ...ACTIONS, ...RECOVERY].includes(o.operation)) fail('inbox_operator_operation');
  if (!identity(o.tenant) || !identity(o.repository)) fail('inbox_operator_repository_identity');
  if (typeof o.href !== 'string' || o.href.length > 4096 || /[\u0000-\u0020\u007f-\u009f\uD800-\uDFFF]/u.test(o.href) ||
      new URL(o.href).href !== o.href) fail('inbox_operator_url');
  const Client = clientType(o.kind);
  new Client({ href: o.href, timeoutMs: o.timeoutMs }); // Owns HTTPS/loopback and exact per-kind route validation.
  if ((o.signal !== undefined && !(o.signal instanceof AbortSignal)) || typeof o.onProgress !== 'function') fail('inbox_operator_lifetime');
  o.tokenFile = operatorPath(o.tokenFile);
  const guarded = raw.expectedPrincipal !== undefined || raw.expectedIncarnation !== undefined;
  if (guarded && (!identity(o.expectedPrincipal) || !identity(o.expectedIncarnation))) fail('inbox_operator_identity_guards_required');
  if (READS.includes(o.operation)) {
    if (['record', 'expectedVersion', 'readThrough'].some(key => raw[key] !== undefined)) fail('inbox_read_mutation_option');
    o.head = raw.head ?? null;
    if (o.head !== null) { snapshotToken(o.head); if (!guarded) fail('inbox_read_identity_guards_required'); }
    o.maxOutputBytes = natural(raw.maxOutputBytes ?? 8 * 1024 * 1024, 'output budget', 1, 8 * 1024 * 1024);
    if (o.operation === 'show') {
      natural(o.number, 'thread number', 1);
      if (['after', 'limit', 'maxPages', 'unreadOnly', 'includeMuted'].some(key => raw[key] !== undefined)) fail('inbox_show_list_option');
      o.after = 0; o.limit = 1; o.maxPages = 1; o.unreadOnly = false; o.includeMuted = false;
    } else {
      if (raw.number !== undefined) fail('inbox_list_number_inapplicable');
      o.after = natural(raw.after ?? 0, 'cursor');
      o.limit = natural(raw.limit ?? 20, 'page size', 1, 100);
      o.maxPages = natural(raw.maxPages ?? 1, 'page budget', 1, 100);
      o.unreadOnly = raw.unreadOnly ?? false; o.includeMuted = raw.includeMuted ?? false;
      if (typeof o.unreadOnly !== 'boolean' || typeof o.includeMuted !== 'boolean') fail('inbox_read_filters');
      if (o.after && o.head === null) fail('inbox_read_snapshot_required');
    }
  } else {
    if (['after', 'head', 'limit', 'maxPages', 'maxOutputBytes', 'unreadOnly', 'includeMuted'].some(key => raw[key] !== undefined)) fail('inbox_mutation_read_option');
    o.record = operatorPath(o.record);
    if (o.record === o.tokenFile) fail('inbox_operator_separate_record');
    if (RECOVERY.includes(o.operation)) {
      if (['number', 'expectedVersion', 'readThrough', 'expectedPrincipal', 'expectedIncarnation'].some(key => raw[key] !== undefined)) fail('inbox_recovery_is_exact');
    } else {
      if (!guarded) fail('inbox_operator_identity_guards_required');
      if (o.operation !== 'read' && raw.readThrough !== undefined) fail('inbox_read_through_inapplicable');
      const fields = o.operation === 'read' ? { read_through: o.readThrough } : {};
      notificationMutationRequest(o.number, o.expectedVersion, o.operation, fields,
        { principal: o.expectedPrincipal, incarnation: o.expectedIncarnation });
    }
  }
  return o;
}

function checkBinding(binding, o) {
  if (!exact(binding, ['tenant', 'repository', 'principal', 'incarnation']) ||
      binding.tenant !== o.tenant || binding.repository !== o.repository) fail('inbox_operator_repository_mismatch');
  if (o.expectedPrincipal !== undefined && (binding.principal !== o.expectedPrincipal || binding.incarnation !== o.expectedIncarnation)) fail('inbox_operator_identity_changed');
}

function restoreRecord(bytes, o) {
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { fail('inbox_operator_invalid_record'); }
  if (!exact(value, ['schema', 'kind', 'href', 'tenant', 'repository', 'receipt']) ||
      value.schema !== SCHEMA || value.kind !== o.kind || value.href !== o.href || value.tenant !== o.tenant || value.repository !== o.repository ||
      !Buffer.from(JSON.stringify(value) + '\n').equals(bytes)) fail('inbox_operator_record_mismatch');
  checkBinding(value.receipt?.request?.binding, o);
  // The shipped client validates the profile, credential fingerprint, body,
  // principal/incarnation binding and the original key's exact commitment.
  return JSON.stringify(value.receipt);
}

// Export only the fields the shipped client validated, never arbitrary extra
// server response data. A view is a server observation, not a signed proof.
function checkedPage(page, o) {
  const reply = page.reply, version = o.kind === 'discussion' ? 'discussion_version' : 'issue_version';
  const thread = row => row === null ? null : Object.fromEntries([
    'number', version, 'title', 'state', 'preference_version', 'mode', 'read_through',
    'latest_other_version', 'unread', 'reasons',
  ].map(key => [key, row[key]]));
  const result = { type: reply.type, schema_version: reply.schema_version, tenant_id: page.binding.tenant,
    repository_id: page.binding.repository, principal_id: page.binding.principal, repository_incarnation: page.binding.incarnation,
    ...(o.kind === 'discussion' ? { target_kind: 'discussion' } : {}), snapshot_token: page.head,
    source_positions: Object.fromEntries(['authority_head_generation', 'forge_position_root', 'outbox_root', 'complete']
      .map(key => [key, reply.source_positions[key]])) };
  return o.operation === 'show' ? { ...result, found: reply.found, thread: thread(reply.thread) }
    : { ...result, after: reply.after, limit: reply.limit, unread_only: reply.unread_only, include_muted: reply.include_muted,
      next_after: reply.next_after, threads: reply.threads.map(thread) };
}

async function readInbox(client, o, check) {
  const pages = []; let head = o.head, after = o.after, next = null, retained = 0, binding = null, positions = null;
  while (pages.length < o.maxPages) {
    check();
    const page = await client.read(o.operation === 'show' ? o.number : null,
      { after, limit: o.limit, head, unreadOnly: o.unreadOnly, includeMuted: o.includeMuted });
    check(); checkBinding(page.binding, o);
    head = page.head; binding = page.binding;
    next = o.operation === 'show' ? null : page.reply.next_after;
    if (next !== null && (!Number.isSafeInteger(next) || next <= after)) fail('inbox_read_cursor_stalled');
    const visible = checkedPage(page, o);
    if (positions && Object.keys(positions).some(key => positions[key] !== visible.source_positions[key])) fail('inbox_read_source_positions_changed');
    positions ??= visible.source_positions;
    retained += Buffer.byteLength(operatorJson(visible));
    if (retained > o.maxOutputBytes) fail('inbox_read_output_limit');
    pages.push(visible);
    o.onProgress(Object.freeze({ phase: 'page_checked', pages: pages.length, next_after: next })); check();
    if (next === null) break;
    after = next;
  }
  const continuation = next === null ? null : { operation: 'list', kind: o.kind, href: o.href,
    tenant_id: o.tenant, repository_id: o.repository, expected_principal: binding.principal,
    expected_incarnation: binding.incarnation, expected_head: head, after: next, limit: o.limit,
    unread_only: o.unreadOnly, include_muted: o.includeMuted };
  const result = { type: 'forge_inbox_operator_read', operation: o.operation, kind: o.kind, href: o.href,
    tenant_id: o.tenant, repository_id: o.repository, principal_id: binding.principal, repository_incarnation: binding.incarnation,
    snapshot_token: head, initial_after: o.after, page_count: pages.length, complete: next === null,
    stop_reason: next === null ? 'exhausted' : 'page_budget', read_only: true, mutation_submitted: false, continuation, pages };
  if (Buffer.byteLength(operatorJson(result)) > o.maxOutputBytes) fail('inbox_read_output_limit');
  check(); return result;
}

export async function runInboxOperation(raw) {
  const o = inboxOperatorOptions(raw), stop = new AbortController();
  const signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const timer = setTimeout(() => stop.abort(), o.timeoutMs);
  const check = () => { if (signal.aborted) fail('inbox_operator_cancelled_or_deadline'); };
  const progress = phase => { o.onProgress(Object.freeze({ phase })); check(); };
  const Client = clientType(o.kind), client = new Client({ href: o.href, timeoutMs: o.timeoutMs,
    fetchImpl: (url, init) => issueOperatorFetch(url, init, signal) });
  let state = READS.includes(o.operation) ? 'read_incomplete' : RECOVERY.includes(o.operation) ? 'existing_unknown' : 'not_submitted';
  let path = o.record ?? null, digest = null, bytes;
  const result = (terminal, submitted) => ({ type: 'forge_inbox_operator_result', operation: o.operation, kind: o.kind,
    state: terminal.terminal === false ? 'unresolved' : 'terminal_observed', record: path, record_sha256: digest,
    result: terminal, mutation_submitted: submitted, absence_proves_non_commit: false });
  try {
    check();
    if (!READS.includes(o.operation)) {
      path = await privateRecordPath(path); check();
      if (ACTIONS.includes(o.operation)) await absentRecord(path);
      else { bytes = await readPrivateOperatorFile(path, MAX_RECORD, check); digest = recordDigest(bytes); restoreRecord(bytes, o); }
    }
    await connectIssueToken(client, o, check);
    if (READS.includes(o.operation)) return await readInbox(client, o, check);
    if (ACTIONS.includes(o.operation)) {
      const observed = await client.read(o.number, { limit: 1 }); check(); checkBinding(observed.binding, o);
      if (!observed.reply.found) fail('inbox_operator_thread_missing');
      const row = observed.reply.thread;
      if ((row.preference_version ?? 0) !== o.expectedVersion) fail('inbox_operator_preference_moved');
      const fields = o.operation === 'read' ? { read_through: o.readThrough } : {};
      if (o.operation === 'read' && o.readThrough > row[o.kind === 'discussion' ? 'discussion_version' : 'issue_version']) fail('inbox_operator_read_prefix_unobserved');
      progress('source_checked');
      await client.stage(o.number, o.expectedVersion, o.operation, fields); check();
      const exported = client.exportReceipt();
      if (Buffer.byteLength(exported) > MAX_RECEIPT_BYTES) fail('inbox_operator_receipt_limit');
      bytes = Buffer.from(JSON.stringify({ schema: SCHEMA, kind: o.kind, href: o.href,
        tenant: o.tenant, repository: o.repository, receipt: JSON.parse(exported) }) + '\n');
      if (bytes.length > MAX_RECORD) fail('inbox_operator_receipt_limit');
      state = 'record_write_started';
      digest = (await saveOperatorRecord(path, bytes, check)).sha256;
      state = 'recorded_unknown'; progress('receipt_saved');
    } else {
      await client.restoreReceipt(restoreRecord(bytes, o)); check();
      const outcome = await client.recover();
      if (outcome.terminal || o.operation === 'status') return result(outcome, false);
      progress('recovery_observed');
    }
    const synchronized = await readSynchronizedOperatorRecord(path, MAX_RECORD, check);
    if (!synchronized.equals(bytes)) fail('inbox_operator_record_changed');
    state = 'submitted_unknown';
    // A fully parsed terminal observation wins over later cancellation. Neither
    // outcome lookup nor a send failure creates a replacement request/key.
    return result(await client.send(), true);
  } catch (cause) {
    const error = cause instanceof Error ? cause : operatorError('inbox_operator_failed');
    error.operator_state = state; error.record = path; error.record_sha256 = digest;
    throw error;
  } finally { clearTimeout(timer); client.disconnect(); }
}
