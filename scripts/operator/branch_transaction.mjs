// Exact external branch transactions. Native Rust owns reachability, policy,
// atomic admission and transaction identity; this peer retains original inputs.
import { createHash, randomBytes } from 'node:crypto';
import { transactionCommand, transactionForm, expectedUpdates } from '../../crates/fgit-node/src/smart_http/server/browser/branches.mjs';
import { outcomeEndpoint, outcomeScope, validateOutcomeReply } from './transaction_outcome.mjs';
import { isCredentialToken, isAgentCredentialToken } from './credential_token.mjs';
import { parsePullJson, pullCanonical } from './pull_command.mjs';

export const BRANCH_LIMITS = Object.freeze({ intent: 256 * 1024, reply: 256 * 1024, record: 320 * 1024 });
const SCHEMA = 'frankengit-remote-branch-transaction-v1';
export class BranchTransactionError extends Error {
  constructor(code, details = {}) {
    super(code); this.name = 'BranchTransactionError'; this.code = code;
    this.phase = details.phase ?? 'validation'; this.dispatched = details.dispatched ?? false;
    this.publication = details.publication ?? null; this.outcome = details.outcome ?? null;
    this.status = details.status ?? null; this.outcomeUnknown = true;
  }
}
export const fail = code => { throw new BranchTransactionError(code); };
export const hash = value => createHash('sha256').update(value).digest('hex');
export const encode = value => Buffer.from(pullCanonical(value));
export function fields(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).some(name => !names.includes(name)) || required.some(name => !Object.hasOwn(value, name)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) fail('branch_transaction_fields');
  return value;
}
export function pin(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('branch_transaction_pin');
  return value;
}
export function parse(bytes, wire = false, maximum = BRANCH_LIMITS.intent) {
  try { return parsePullJson(bytes, { wire, maximum }); }
  catch { fail('branch_transaction_json'); }
}
export function binding(scope) {
  return outcomeScope(Object.fromEntries(['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id'].map(k => [k, scope[k]])));
}
function scope(value) {
  fields(value, ['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id', 'object_format']);
  if (!['sha1', 'sha256'].includes(value.object_format)) fail('branch_transaction_format');
  return { ...binding(value), object_format: value.object_format };
}
export function credential(value, send = false) {
  if (!isCredentialToken(value)) fail('branch_transaction_credential');
  // Native sponsored source-branch-create is a distinct, single-create route.
  // Even a create-only batch must not infer an atomic receive grant from it.
  if (send && isAgentCredentialToken(value)) fail('branch_transaction_agent_receive_unsupported');
  return value;
}
function command(value, format) {
  try {
    const checked = transactionCommand({ object_format: format, changes: value });
    return { changes: checked.changes, body: transactionForm(checked) };
  } catch { fail('branch_transaction_command'); }
}
function build(value) {
  const selected = scope(value.scope), checked = command(value.changes, selected.object_format);
  const writerBound = Object.hasOwn(value, 'bind_writer_scope');
  if (writerBound && value.bind_writer_scope !== true) fail('branch_transaction_writer_scope');
  if (typeof value.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(value.nonce)) fail('branch_transaction_nonce');
  const basis = { schema: SCHEMA, endpoint: outcomeEndpoint(value.endpoint), scope: selected,
    changes: checked.changes,
    body: writerBound ? checked.body + '&expected_scope=' +
      [selected.tenant_id, selected.repository_id, selected.repository_incarnation, selected.principal_id].join(':') : checked.body,
    credential_sha256: pin(value.credential_sha256), nonce: value.nonce,
    ...(writerBound ? { bind_writer_scope: true } : {}) };
  const intent = { ...basis, key: 'fgbt1-' + basis.nonce + '-' + hash(encode(basis)) };
  if (encode(intent).length > BRANCH_LIMITS.intent) fail('branch_transaction_intent_limit');
  return intent;
}
export function prepareBranchTransaction(value, token) {
  const required = ['endpoint', 'scope', 'changes'];
  fields(value, [...required, 'bind_writer_scope'], required); credential(token, true);
  return build({ ...value, credential_sha256: hash(token), nonce: randomBytes(16).toString('hex') });
}
export function validateBranchIntent(value) {
  const required = ['schema', 'endpoint', 'scope', 'changes', 'body', 'credential_sha256', 'nonce', 'key'];
  fields(value, [...required, 'bind_writer_scope'], required);
  const expected = build(value);
  if (!encode(value).equals(encode(expected))) fail('branch_transaction_intent_changed');
  return expected;
}
function opaque(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 ||
      /[\s\x00-\x1f\x7f-\x9f\uD800-\uDFFF]/u.test(value)) fail('branch_transaction_identity');
}
function oid(value, format) {
  const raw = typeof value === 'string' && value.startsWith(format + ':') ? value.slice(format.length + 1) : value;
  if (typeof raw !== 'string' || !new RegExp('^[0-9a-f]{' + (format === 'sha1' ? 40 : 64) + '}$').test(raw) || /^0+$/.test(raw)) fail('branch_transaction_oid');
  return raw;
}
export function publication(value, input, status) {
  const intent = validateBranchIntent(input), committed = value?.outcome === 'committed';
  fields(value, ['type', 'schema_version', ...Object.keys(intent.scope), 'operation', 'atomic', 'terminal', 'tx_id',
    'decision_sequence', 'outcome', 'forge_transition', 'updates',
    ...(committed ? ['repository_commit_id'] : ['code', 'code_point', 'refusal_record_id'])]);
  if (value.type !== 'branch_publication' || value.schema_version !== 1 ||
      Object.keys(intent.scope).some(k => intent.scope[k] !== value[k]) || value.operation !== 'transaction' ||
      value.atomic !== true || value.terminal !== true || value.forge_transition !== false ||
      !['committed', 'refused'].includes(value.outcome) || status !== (committed ? 200 : 409)) fail('branch_transaction_publication_binding');
  const expected = expectedUpdates('transaction', { object_format: intent.scope.object_format, changes: intent.changes });
  if (!Array.isArray(value.updates) || value.updates.length !== expected.length) fail('branch_transaction_publication_effect');
  for (let i = 0; i < expected.length; i++) {
    const row = fields(value.updates[i], ['ref', 'ref_hex', 'expected_commit', 'new_commit', 'force']), want = expected[i];
    if (row.ref !== want.ref || row.ref_hex !== want.ref_hex || row.force !== false ||
        (row.expected_commit === null ? null : oid(row.expected_commit, intent.scope.object_format)) !== want.expected_commit ||
        (row.new_commit === null ? null : oid(row.new_commit, intent.scope.object_format)) !== want.new_commit) fail('branch_transaction_publication_effect');
  }
  opaque(value.tx_id);
  if (typeof value.decision_sequence !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value.decision_sequence) ||
      BigInt(value.decision_sequence) > 18446744073709551615n) fail('branch_transaction_sequence');
  if (committed) opaque(value.repository_commit_id);
  else {
    opaque(value.code); opaque(value.refusal_record_id);
    if (!Number.isSafeInteger(value.code_point) || value.code_point < 0 || value.code_point > 65535) fail('branch_transaction_refusal');
  }
  return structuredClone(value);
}
export function matchObservation(outcome, receipt) {
  if (!outcome || !receipt) return;
  if (outcome.transaction && outcome.transaction.tx_id !== receipt.tx_id) fail('branch_transaction_outcome_conflict');
  if (!outcome.terminal) return;
  const d = outcome.decision;
  if (d.kind !== receipt.outcome || d.decision_sequence !== receipt.decision_sequence ||
      (d.repository_commit_id ?? null) !== (receipt.repository_commit_id ?? null) ||
      (d.refusal_record_id ?? null) !== (receipt.refusal_record_id ?? null) ||
      (d.code ?? null) !== (receipt.code ?? null) || (d.code_point ?? null) !== (receipt.code_point ?? null)) fail('branch_transaction_outcome_conflict');
}
export function branchRecord(input, observation, error = null) {
  const intent = validateBranchIntent(input);
  return validateBranchRecord({ schema: SCHEMA + '/record', intent_sha256: hash(encode(intent)), key: intent.key,
    outcome: observation?.outcome ?? error?.outcome ?? null, publication: observation?.publication ?? error?.publication ?? null,
    dispatched: observation?.dispatched ?? error?.dispatched ?? false,
    error: error === null ? null : { code: error instanceof BranchTransactionError ? error.code : 'branch_transaction_unavailable',
      phase: error instanceof BranchTransactionError ? error.phase : 'validation',
      status: error instanceof BranchTransactionError ? error.status : null } }, intent);
}
export function validateBranchRecord(value, input) {
  const intent = validateBranchIntent(input);
  fields(value, ['schema', 'intent_sha256', 'key', 'outcome', 'publication', 'dispatched', 'error']);
  if (value.schema !== SCHEMA + '/record' || value.intent_sha256 !== hash(encode(intent)) ||
      value.key !== intent.key || typeof value.dispatched !== 'boolean') fail('branch_transaction_record_binding');
  const outcome = value.outcome === null ? null : validateOutcomeReply(value.outcome, binding(intent.scope));
  const receipt = value.publication === null ? null : publication(value.publication, intent, value.publication.outcome === 'committed' ? 200 : 409);
  matchObservation(outcome, receipt);
  if (value.error === null) { if (outcome === null && receipt === null) fail('branch_transaction_empty_record'); }
  else {
    fields(value.error, ['code', 'phase', 'status']);
    if (typeof value.error.code !== 'string' || !/^[a-z_]{1,128}$/.test(value.error.code) ||
        !['validation', 'preflight', 'publication', 'confirmation'].includes(value.error.phase) ||
        value.error.status !== null && (!Number.isSafeInteger(value.error.status) || value.error.status < 100 || value.error.status > 599)) fail('branch_transaction_record_error');
  }
  return { ...value, outcome, publication: receipt, error: value.error === null ? null : { ...value.error } };
}
