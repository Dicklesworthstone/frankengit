// Authenticated network operator over the SHIPPED issue client and native API.
// No local node principal, database access, parallel mutation codec or authority.
import { IssueClient, mutationRequest, MAX_RECEIPT_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { MilestoneClient, milestoneMutationRequest } from '../../crates/fgit-node/src/smart_http/server/browser/milestones.mjs';
import { operatorError, operatorPath, privateRecordPath, absentRecord, readPrivateOperatorFile,
  readSynchronizedOperatorRecord, saveOperatorRecord, recordDigest } from './forge-operator-io.mjs';

const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const fail = code => { throw operatorError(code); };
// Shared connection validation; each entrypoint checks its own closed grammar.
export function issueConnectionOptions(raw) {
  const o = { ...raw, timeoutMs: raw.timeoutMs ?? 30000, onProgress: raw.onProgress ?? (() => {}) };
  for (const key of ['tenant', 'repository']) if (typeof o[key] !== 'string' || !/^[0-9a-f]{32}$/.test(o[key])) fail('issue_operator_identity');
  if (typeof o.href !== 'string' || o.href.length > 4096 || /[\u0000-\u0020\u007f-\u009f\uD800-\uDFFF]/u.test(o.href)) fail('issue_operator_url');
  // The shipped client validates HTTPS/loopback, origin, path and no credentials.
  // Reject URL normalization too: the exact destination is selected by the user.
  if (new URL(o.href).href !== o.href) fail('issue_operator_url');
  new IssueClient({ href: o.href, timeoutMs: o.timeoutMs });
  if ((o.signal !== undefined && !(o.signal instanceof AbortSignal)) || typeof o.onProgress !== 'function') fail('issue_operator_lifetime');
  o.tokenFile = operatorPath(o.tokenFile);
  return o;
}
export async function connectIssueToken(client, o, check) {
  const token = await readPrivateOperatorFile(o.tokenFile, 65, check);
  try {
    if (!/^[0-9a-f]{64}\n?$/.test(token.toString('ascii')) || token.some(b => b > 127)) fail('issue_operator_invalid_token');
    await client.connect(token.toString('ascii').replace(/\n$/, '')); check();
  } finally { token.fill(0); }
}
// Node operators identify themselves; browser clients retain browser-owned headers.
export function issueOperatorFetch(url, init, signal) {
  const headers = new Headers(init.headers);
  headers.set('User-Agent', 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)');
  return fetch(url, { ...init, headers, signal: AbortSignal.any([signal, init.signal]) });
}
// A closed repository-owned selection, never a route or callback from custody.
// Both metadata families use the same private-file, cancellation and original
// outcome path; legacy issue records and key derivation remain unchanged.
export function createMetadataOperator(entity) {
if (!['issue', 'milestone'].includes(entity)) throw operatorError('issue_operator_profile');
const milestone = entity === 'milestone';
const Client = milestone ? MilestoneClient : IssueClient;
const request = milestone ? milestoneMutationRequest : mutationRequest;
const schema = `frankengit-${entity}-operator-v1`;
const ACTIONS = milestone ? ['open', 'edit', 'close', 'reopen']
  : ['open', 'edit', 'comment', 'close', 'reopen', 'assign', 'unassign', 'add-labels', 'lock', 'unlock', 'set-milestone', 'clear-milestone'];
const fail = code => { throw operatorError(milestone ? code.replace(/^issue_operator_/, 'milestone_operator_') : code); };
function options(raw) {
  const keys = ['operation', 'href', 'tenant', 'repository', 'tokenFile', 'record', 'number', 'expectedVersion', 'fields', 'timeoutMs', 'signal', 'onProgress'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !keys.includes(k))) fail('issue_operator_options');
  const o = issueConnectionOptions(raw);
  if (![...ACTIONS, 'status', 'retry'].includes(o.operation)) fail('issue_operator_operation');
  o.tokenFile = operatorPath(o.tokenFile); o.record = operatorPath(o.record);
  if (o.tokenFile === o.record) fail('issue_operator_separate_record');
  if (ACTIONS.includes(o.operation)) {
    if (o.operation === 'add-labels') {
      if (raw.expectedVersion !== undefined && raw.expectedVersion !== null) fail('issue_operator_add_labels_has_no_version');
      o.expectedVersion = null;
    }
    const checked = request(o.number, o.expectedVersion, o.operation, o.fields ?? {});
    o.fields = structuredClone(checked.fields);
  } else if (['number', 'expectedVersion', 'fields'].some(k => raw[k] !== undefined)) fail('issue_operator_recovery_is_exact');
  return o;
}
function checkedBinding(value, o) {
  if (!exact(value, ['tenant', 'repository']) || value.tenant !== o.tenant || value.repository !== o.repository) fail('issue_operator_repository_mismatch');
}
function readRecord(bytes, o) {
  let v;
  try { v = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { fail('issue_operator_invalid_record'); }
  if (!exact(v, ['schema', 'href', 'tenant', 'repository', 'receipt']) ||
      v.schema !== schema || v.href !== o.href || v.tenant !== o.tenant || v.repository !== o.repository ||
      !Buffer.from(JSON.stringify(v) + '\n').equals(bytes)) fail('issue_operator_record_mismatch');
  checkedBinding(v.receipt?.request?.binding, o);
  return JSON.stringify(v.receipt);
}
async function run(raw) {
  const o = options(raw), stop = new AbortController();
  const signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const timer = setTimeout(() => stop.abort(), o.timeoutMs);
  const check = () => { if (signal.aborted) fail('issue_operator_cancelled_or_deadline'); };
  const progress = phase => { o.onProgress(Object.freeze({ phase })); check(); };
  const client = new Client({ href: o.href, timeoutMs: o.timeoutMs,
    fetchImpl: (url, init) => issueOperatorFetch(url, init, signal) });
  let state = ACTIONS.includes(o.operation) ? 'not_submitted' : 'existing_unknown';
  let path = o.record, digest = null, bytes;
  try {
    check(); path = await privateRecordPath(path); check();
    if (ACTIONS.includes(o.operation)) await absentRecord(path);
    else { bytes = await readPrivateOperatorFile(path, MAX_RECEIPT_BYTES * 2, check); digest = recordDigest(bytes); readRecord(bytes, o); }
    await connectIssueToken(client, o, check);
    if (ACTIONS.includes(o.operation)) {
      const observed = await client.read(o.number, { limit: 1 }); check();
      checkedBinding(observed.binding, o);
      const version = observed.reply.found ? observed.reply[entity].version : 0;
      if (o.operation === 'add-labels' ? !observed.reply.found : version !== o.expectedVersion) fail('issue_operator_version_moved');
      progress('source_checked');
      await client.stage(o.number, o.expectedVersion, o.operation, o.fields); check();
      const exported = client.exportReceipt();
      if (Buffer.byteLength(exported) > MAX_RECEIPT_BYTES) fail('issue_operator_receipt_limit');
      bytes = Buffer.from(JSON.stringify({ schema, href: o.href,
        tenant: o.tenant, repository: o.repository, receipt: JSON.parse(exported) }) + '\n');
      const saved = await saveOperatorRecord(path, bytes, check); digest = saved.sha256;
      state = 'recorded_unknown'; progress('receipt_saved');
    } else {
      await client.restoreReceipt(readRecord(bytes, o)); check();
      const outcome = await client.recover();
      if (outcome.terminal || o.operation === 'status') return {
        type: `forge_${entity}_operator_result`, operation: o.operation, state: outcome.terminal ? 'terminal_observed' : 'unresolved',
        record: path, record_sha256: digest, result: outcome, mutation_submitted: false, absence_proves_non_commit: false };
      progress('recovery_observed'); // Only explicit retry proceeds after lookup.
    }
    // Every sender, including a retry racing the original creator, establishes
    // its own exact-file and directory sync barrier before any HTTP mutation.
    // Never replace an uncertain key, refresh a version, or recreate a record.
    const current = await readSynchronizedOperatorRecord(path, MAX_RECEIPT_BYTES * 2, check);
    if (!current.equals(bytes)) fail('issue_operator_record_changed');
    state = 'submitted_unknown';
    const result = await client.send();
    // A parsed terminal decision wins over a later cancellation or output error.
    return { type: `forge_${entity}_operator_result`, operation: o.operation, state: 'terminal_observed',
      record: path, record_sha256: digest, result, mutation_submitted: true, absence_proves_non_commit: false };
  } catch (cause) {
    const error = cause instanceof Error ? cause : operatorError('issue_operator_failed');
    error.operator_state = state; error.record = path; error.record_sha256 = digest;
    throw error;
  } finally { clearTimeout(timer); client.disconnect(); }
}
return Object.freeze({ options, run });
}
const issue = createMetadataOperator('issue');
export const issueOperatorOptions = issue.options;
export const runIssueOperation = issue.run;
