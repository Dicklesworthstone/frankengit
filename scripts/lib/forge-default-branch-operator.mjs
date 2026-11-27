// Remote symbolic HEAD administration through the shipped native client.
// Private records retain request custody; only native admission publishes HEAD.
import { DefaultBranchClient, defaultBranchCommand, defaultBranchSnapshot, DEFAULT_BRANCH_RECEIPT_LIMIT }
  from '../../crates/fgit-node/src/smart_http/server/browser/default-branch.mjs';
import { Transport, form, integer, oid } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { refBytes, refsPage } from '../../crates/fgit-node/src/smart_http/server/browser/branches.mjs';
import { issueOperatorFetch } from './forge-issue-operator.mjs';
import { operatorError, operatorPath, operatorJson, parseOperatorJson, privateRecordPath, absentRecord,
  readPrivateOperatorFile, readSynchronizedOperatorRecord, saveOperatorRecord, recordDigest } from './forge-operator-io.mjs';

const SCHEMA = 'frankengit-default-branch-operator-v1', MAX_RECORD = DEFAULT_BRANCH_RECEIPT_LIMIT * 2;
const fail = code => { throw operatorError('default_branch_operator_' + code); };
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const snapshot = value => {
  if (typeof value !== 'string' || !/^alg:[12]:[0-9a-f]{64}$/.test(value)) fail('snapshot');
  return value;
};
const reading = operation => ['show', 'list'].includes(operation);
function command(o) {
  return defaultBranchCommand({
    ...(o.expectedDefaultHex === undefined ? { expect_no_default: o.expectNoDefault } : { expected_default_hex: o.expectedDefaultHex }),
    reference_hex: o.referenceHex, expected_tip: o.expectedTip,
  }, typeof o.expectedTip === 'string' ? o.expectedTip.split(':')[0] : undefined);
}

export function defaultBranchOperatorOptions(raw) {
  const common = ['operation', 'href', 'tenant', 'repository', 'tokenFile', 'timeoutMs', 'signal', 'onProgress'];
  const mutation = ['record', 'referenceHex', 'expectedDefaultHex', 'expectNoDefault', 'expectedTip', 'maxPages'];
  const reads = ['head', 'afterHex', 'limit', 'maxPages', 'maxOutputBytes'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
      !['show', 'list', 'set-default', 'status', 'retry'].includes(raw.operation)) fail('operation');
  const allowed = [...common, ...(reading(raw.operation) ? reads : raw.operation === 'set-default' ? mutation : ['record'])];
  if (Object.keys(raw).some(key => !allowed.includes(key))) fail('options');
  const o = { ...raw, timeoutMs: raw.timeoutMs ?? 30000, onProgress: raw.onProgress ?? (() => {}) };
  for (const key of ['tenant', 'repository']) {
    if (typeof o[key] !== 'string' || !/^[0-9a-f]{32}$/.test(o[key])) fail('identity');
  }
  if (typeof o.href !== 'string' || o.href.length > 4096 || /[\u0000-\u0020\u007f-\u009f\uD800-\uDFFF]/u.test(o.href) ||
      new URL(o.href).href !== o.href) fail('url');
  new DefaultBranchClient({ href: o.href, timeoutMs: o.timeoutMs });
  if ((o.signal !== undefined && !(o.signal instanceof AbortSignal)) || typeof o.onProgress !== 'function') fail('lifetime');
  o.tokenFile = operatorPath(o.tokenFile);
  if (reading(o.operation)) {
    o.head = raw.head ?? null;
    if (o.head !== null) snapshot(o.head);
    o.maxOutputBytes = integer(raw.maxOutputBytes ?? 8 * 1024 * 1024, 'output budget', 1, 8 * 1024 * 1024);
    if (o.operation === 'show') {
      if (['afterHex', 'limit', 'maxPages'].some(key => raw[key] !== undefined)) fail('list_option');
    } else {
      o.afterHex = raw.afterHex ?? null;
      if (o.afterHex !== null) { refBytes(o.afterHex, 'branches'); if (o.head === null) fail('snapshot_required'); }
      o.limit = integer(raw.limit ?? 100, 'page size', 1, 100);
      o.maxPages = integer(raw.maxPages ?? 1, 'page budget', 1, 100);
    }
  } else {
    o.record = operatorPath(o.record);
    if (o.record === o.tokenFile) fail('separate_record');
    if (o.operation === 'set-default') {
      if (Object.hasOwn(raw, 'expectedDefaultHex') === Object.hasOwn(raw, 'expectNoDefault')) fail('original_expectation');
      command(o);
      o.maxPages = integer(raw.maxPages ?? 21, 'selection page budget', 1, 21);
    }
  }
  return o;
}

function scopeMatches(scope, o) {
  if (scope?.tenant !== o.tenant || scope?.repository !== o.repository) fail('repository_mismatch');
}
async function connect(client, o, check) {
  // The default-branch administrator profile deliberately excludes agents.
  const bytes = await readPrivateOperatorFile(o.tokenFile, 65, check);
  try {
    const token = bytes.toString('ascii').replace(/\n$/, '');
    if (bytes.some(byte => byte > 127) || !/^[0-9a-f]{64}$/.test(token)) fail('invalid_token');
    await client.connect(token); check();
  } finally { bytes.fill(0); }
}
function restoreRecord(bytes, o) {
  const saved = parseOperatorJson(bytes, 'default_branch_operator_invalid_record');
  if (!exact(saved, ['schema', 'href', 'tenant', 'repository', 'receipt']) ||
      saved.schema !== SCHEMA || saved.href !== o.href || saved.tenant !== o.tenant || saved.repository !== o.repository ||
      !Buffer.from(JSON.stringify(saved) + '\n').equals(bytes)) fail('record_mismatch');
  scopeMatches(saved.receipt?.source?.scope, o);
  return JSON.stringify(saved.receipt);
}
function observationResult(o, observed) {
  return { type: 'forge_default_branch_operator_read', schema_version: 1, operation: o.operation, href: o.href,
    tenant_id: observed.scope.tenant, repository_id: observed.scope.repository,
    repository_incarnation: observed.scope.incarnation, object_format: observed.scope.format,
    principal_id: observed.principal, snapshot_token: observed.head, source_head: observed.sourceHead,
    default_reference_hex: observed.referenceHex, tip: observed.tip, unborn: observed.unborn,
    read_only: true, mutation_submitted: false };
}
async function read(o, transport, check) {
  const path = o.head === null ? 'default-branch' : 'default-branch?expected_head=' + encodeURIComponent(o.head);
  const { value } = await transport.request(path, { maximum: 16 * 1024 });
  check();
  const observed = defaultBranchSnapshot(value, null, o.head); scopeMatches(observed.scope, o);
  const result = observationResult(o, observed);
  if (o.operation === 'show') return { ...result, complete: true };
  const pages = []; let after = o.afterHex, next = null, bytes = 0;
  while (pages.length < o.maxPages) {
    check();
    const query = { object_format: observed.scope.format, namespace: 'branches', cursor_encoding: 'hex',
      expected_head: observed.head, limit: o.limit, ...(after === null ? {} : { after }) };
    const { value: page } = await transport.request('source/refs', { method: 'POST', body: form(query), maximum: 1024 * 1024 });
    check(); refsPage(page, query, observed.scope);
    if (page.source_head !== observed.sourceHead) fail('source_head_changed');
    // Only native-validated fields are emitted; extensions are not CLI data.
    const checked = { after_hex: after, limit: page.limit, next_after_hex: page.next_after,
      refs: page.refs.map(row => ({ ref: row.ref, ref_hex: row.ref_hex, object_id: row.object_id })) };
    bytes += Buffer.byteLength(operatorJson(checked));
    if (bytes > o.maxOutputBytes) fail('output_limit');
    pages.push(checked); next = page.next_after;
    o.onProgress(Object.freeze({ phase: 'page_checked', pages: pages.length, next_after_hex: next })); check();
    if (next === null) break;
    after = next;
  }
  return { ...result, initial_after_hex: o.afterHex, page_count: pages.length, pages, complete: next === null,
    stop_reason: next === null ? 'exhausted' : 'page_budget',
    continuation: next === null ? null : { operation: 'list', expected_head: observed.head, after_hex: next, limit: o.limit } };
}

async function select(o, client, check) {
  let observed = await client.load(), pages = 1; check(); scopeMatches(observed.scope, o);
  if (observed.referenceHex !== (o.expectedDefaultHex ?? null)) fail('expected_default_moved');
  for (;;) {
    const row = client.knownRefs.find(value => value.ref_hex === o.referenceHex);
    if (row) {
      if (observed.scope.format + ':' + oid(row.object_id, observed.scope.format) !== o.expectedTip) fail('target_tip_moved');
      return;
    }
    if (client.page.next_after === null) fail('target_not_found');
    if (pages >= o.maxPages) fail('selection_page_limit');
    o.onProgress(Object.freeze({ phase: 'selection_page_checked', pages })); check();
    observed = await client.load({ next: true }); pages++; check(); scopeMatches(observed.scope, o);
  }
}

export async function runDefaultBranchOperation(raw) {
  const o = defaultBranchOperatorOptions(raw), stop = new AbortController();
  const signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const check = () => { if (signal.aborted) fail('cancelled_or_deadline'); };
  const timer = setTimeout(() => stop.abort(), o.timeoutMs);
  const clientOptions = { href: o.href, timeoutMs: o.timeoutMs,
    fetchImpl: (url, init) => issueOperatorFetch(url, init, signal) };
  const client = reading(o.operation) ? new Transport({ ...clientOptions, pageSuffix: '/ui/default-branch/' }) : new DefaultBranchClient(clientOptions);
  let state = reading(o.operation) ? 'read_incomplete' : o.operation === 'set-default' ? 'not_submitted' : 'existing_unknown';
  let path = o.record ?? null, digest = null, bytes;
  try {
    check();
    if (!reading(o.operation)) {
      path = await privateRecordPath(path); check();
      if (o.operation === 'set-default') await absentRecord(path);
      else { bytes = await readPrivateOperatorFile(path, MAX_RECORD, check); digest = recordDigest(bytes); restoreRecord(bytes, o); }
    }
    await connect(client, o, check);
    if (reading(o.operation)) {
      const result = await read(o, client, check);
      if (Buffer.byteLength(operatorJson(result)) > o.maxOutputBytes) fail('output_limit');
      check(); return result;
    }
    if (o.operation === 'set-default') {
      await select(o, client, check);
      o.onProgress(Object.freeze({ phase: 'source_checked' })); check();
      const pending = await client.prepare(o.referenceHex); check();
      if (JSON.stringify(pending.command) !== JSON.stringify(command(o))) fail('command_changed');
      scopeMatches(pending.source.scope, o);
      const receipt = client.exportReceipt();
      if (Buffer.byteLength(receipt) > DEFAULT_BRANCH_RECEIPT_LIMIT) fail('receipt_limit');
      bytes = Buffer.from(JSON.stringify({ schema: SCHEMA, href: o.href, tenant: o.tenant, repository: o.repository,
        receipt: JSON.parse(receipt) }) + '\n');
      const saved = await saveOperatorRecord(path, bytes, check); digest = saved.sha256;
      state = 'recorded_unknown';
      o.onProgress(Object.freeze({ phase: 'receipt_saved' })); check();
    } else {
      await client.restoreReceipt(restoreRecord(bytes, o)); check();
      const result = await client.recover();
      if (result.terminal || o.operation === 'status') return {
        type: 'forge_default_branch_operator_result', operation: o.operation,
        state: result.terminal ? 'terminal_observed' : 'unresolved', record: path, record_sha256: digest,
        result, mutation_submitted: false, absence_proves_non_commit: false };
      o.onProgress(Object.freeze({ phase: 'recovery_observed' })); check();
    }
    const synchronized = await readSynchronizedOperatorRecord(path, MAX_RECORD, check);
    if (!synchronized.equals(bytes)) fail('record_changed');
    state = 'submitted_unknown';
    const result = await client.send();
    return { type: 'forge_default_branch_operator_result', operation: o.operation, state: 'terminal_observed',
      record: path, record_sha256: digest, result, mutation_submitted: true, absence_proves_non_commit: false };
  } catch (cause) {
    const error = cause instanceof Error ? cause : operatorError('default_branch_operator_failed');
    error.operator_state = state; error.record = path; error.record_sha256 = digest;
    throw error;
  } finally { clearTimeout(timer); client.disconnect(); }
}
