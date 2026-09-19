// Exact commands and terminal decisions. Transport errors never prove rollback.
import { keys, record, integer, principal, opaque, text, oid, binding, subject, SUBJECT_FIELDS, metadataCommand,
  matchSubject, form, utf8, fail, hex } from './pulls-core.mjs';
import { BUNDLE_LIMIT, multipart, checkedBundle, digest } from './pulls-candidate.mjs';
export const RECEIPT_LIMIT = 24 * 1024 * 1024;
export function collaborationCommand(action, fields) {
  if (!['approve', 'request-changes', 'withdraw', 'merge'].includes(action)) fail('Unsupported review action.');
  keys(fields, [...SUBJECT_FIELDS, 'merge_base', 'candidate_commit', ...(action === 'merge' ? ['required_reviewer'] : ['expected_version', 'reason'])]);
  const result = { ...subject(fields), merge_base: oid(fields.merge_base, fields.object_format), candidate_commit: oid(fields.candidate_commit, fields.object_format) };
  if (action === 'merge') {
    if (!Array.isArray(fields.required_reviewer) || !fields.required_reviewer.length || fields.required_reviewer.length > 32) fail('Select 1 through 32 explicit required reviewers.');
    result.required_reviewer = fields.required_reviewer.map(principal).sort();
    if (new Set(result.required_reviewer).size !== result.required_reviewer.length) fail('Duplicate required reviewer.');
  } else {
    result.expected_version = integer(fields.expected_version, 'reviewer stream version', action === 'withdraw' ? 1 : 0, Number.MAX_SAFE_INTEGER - 1);
    result.reason = text(fields.reason, 4096, 'review reason');
    if (!result.reason.trim()) fail('An explicit nonempty review reason is required.');
  }
  form(result); return result;
}
export function command(action, fields) {
  return ['open', 'update', 'close'].includes(action) ? metadataCommand(action, fields) : collaborationCommand(action, fields);
}
export function requestPath(number, action) {
  integer(number, 'PR number', 1);
  if (!['open', 'update', 'close', 'approve', 'request-changes', 'withdraw', 'merge'].includes(action)) fail('Unknown action.');
  return `pulls/${number}/${['approve', 'request-changes', 'withdraw'].includes(action) ? `reviews/${action}` : action}`;
}
export function requestBody(action, fields, bundle, nonce) {
  const normalized = command(action, fields), encoded = form(normalized);
  if (!/^[0-9a-f]{32}$/.test(nonce)) fail('Invalid request nonce.');
  if (['approve', 'request-changes', 'merge'].includes(action)) {
    return { fields: normalized, ...multipart(encoded, checkedBundle(bundle), `fg-browser-${nonce}`) };
  }
  if (bundle !== null) fail('This command must not carry a bundle.');
  return { fields: normalized, bytes: utf8.encode(encoded), contentType: 'application/x-www-form-urlencoded' };
}
export async function requestKey(root, fingerprint, scope, number, action, nonce, body, crypto) {
  const bodyDigest = await digest(body.bytes, crypto);
  const message = JSON.stringify([root.origin, root.route, fingerprint, [scope.tenant, scope.repository, scope.incarnation, scope.format],
    number, action, nonce, body.contentType, bodyDigest]);
  return `fgpr1-${nonce}-${await digest(utf8.encode(message), crypto)}`;
}
export function publication(reply, pending, status) {
  binding(reply, pending.scope); principal(reply.principal_id); opaque(reply.tx_id);
  integer(reply.decision_sequence, 'decision sequence', 1);
  if (!['committed', 'refused'].includes(reply.outcome) || status !== (reply.outcome === 'committed' ? 200 : 409) || reply.delivery_acknowledged !== null || reply.action !== pending.action) fail('HTTP status is not a matching terminal decision.');
  const metadata = ['open', 'update', 'close'].includes(pending.action);
  if (metadata) {
    if (reply.type !== 'pull_request_publication' || reply.number !== pending.number || reply.expected_version !== pending.fields.expected_version) fail('Wrong terminal PR command.');
  } else {
    const merge = pending.action === 'merge', fields = pending.fields;
    if (reply.type !== (merge ? 'reviewed_merge_publication' : 'candidate_review_publication') || reply.review_expected_version !== (merge ? null : fields.expected_version)) fail('Wrong review/merge terminal command.');
    matchSubject(reply.subject, fields, pending.number, fields.object_format);
    if (oid(reply.merge_base, fields.object_format) !== fields.merge_base || oid(reply.candidate_commit, fields.object_format) !== fields.candidate_commit) fail('Terminal candidate changed.');
    if (merge) {
      if (!Array.isArray(reply.required_reviewers) || JSON.stringify(reply.required_reviewers) !== JSON.stringify(fields.required_reviewer)) fail('Terminal reviewer requirements changed.');
    } else if (reply.required_reviewers !== null) fail('Review unexpectedly contains merge requirements.');
  }
  if (pending.observedTx && pending.observedTx !== reply.tx_id) fail('Transaction identity changed.');
  if (pending.observedPrincipal && pending.observedPrincipal !== reply.principal_id) fail('Recovery principal changed.');
  if (reply.outcome === 'committed') {
    opaque(reply.repository_commit_id);
    if (reply.refusal_record_id !== null || reply.refusal_code !== null || reply.refusal_code_point !== null) fail('Conflicting terminal decisions.');
  } else {
    opaque(reply.refusal_record_id); opaque(reply.refusal_code); integer(reply.refusal_code_point, 'refusal code', 0, 65535);
    if (reply.repository_commit_id !== null) fail('Conflicting terminal decisions.');
  }
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    rcr: reply.repository_commit_id, refusal: reply.refusal_code, deliveryAcknowledged: null };
}
export function recovery(reply, pending) {
  record(reply);
  if (reply.schema_version !== 1 || reply.tenant_id !== pending.scope.tenant || reply.repository_id !== pending.scope.repository ||
      reply.repository_incarnation !== pending.scope.incarnation || reply.type !== 'transaction_outcome' || reply.selector !== 'transaction' || reply.command_index !== null ||
      reply.read_only !== true || reply.request_reexecuted !== false || reply.absence_proves_non_commit !== false || reply.session_completeness_established !== false) fail('Invalid recovery scope or semantics.');
  principal(reply.principal_id);
  if (pending.observedPrincipal && pending.observedPrincipal !== reply.principal_id) fail('Recovery principal changed.');
  if (!['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused'].includes(reply.state) || reply.terminal !== ['committed', 'refused'].includes(reply.state)) fail('Invalid recovery state.');
  if (pending.observedTx && reply.transaction === null) fail('Recovery no longer observes the previously identified transaction. Outcome remains unknown.');
  if (reply.transaction !== null) {
    const tx = record(reply.transaction); opaque(tx.tx_id); opaque(tx.seal_id); opaque(tx.request_schema);
    record(tx.canonical_request_digest); integer(tx.canonical_request_digest.algorithm, 'digest algorithm', 1, 65535);
    if (!/^(?:[0-9a-f]{2}){1,64}$/.test(tx.canonical_request_digest.hex)) fail('Invalid seal digest.');
    if (pending.observedTx && pending.observedTx !== tx.tx_id) fail('Recovery transaction changed.');
  }
  if (!reply.terminal) {
    if (reply.decision !== null || (reply.state === 'undecided') !== (reply.transaction !== null)) fail('Invalid nonterminal recovery.');
    return { terminal: false, state: reply.state, tx: reply.transaction?.tx_id ?? null, principal: reply.principal_id };
  }
  const decision = record(reply.decision);
  if (reply.transaction === null || decision.kind !== reply.state) fail('Terminal recovery lacks its transaction decision.');
  integer(decision.decision_sequence, 'decision sequence', 1);
  if (reply.state === 'committed') {
    opaque(decision.repository_commit_id);
    if ('refusal_record_id' in decision || 'code' in decision) fail('Conflicting recovered decisions.');
  } else {
    opaque(decision.refusal_record_id); opaque(decision.code); integer(decision.code_point, 'refusal code', 0, 65535);
    if ('repository_commit_id' in decision) fail('Conflicting recovered decisions.');
  }
  return { terminal: true, outcome: reply.state, tx: reply.transaction.tx_id, principal: reply.principal_id,
    rcr: decision.repository_commit_id ?? null, refusal: decision.code ?? null, deliveryAcknowledged: null };
}
export function base64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 16384) binary += String.fromCharCode(...bytes.subarray(offset, offset + 16384));
  return btoa(binary);
}
export function fromBase64(value) {
  if (typeof value !== 'string' || value.length > Math.ceil(BUNDLE_LIMIT / 3) * 4 || value.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) fail('Invalid or oversized bundle encoding.');
  const binary = atob(value), bytes = Uint8Array.from(binary, char => char.charCodeAt(0)); checkedBundle(bytes);
  if (base64(bytes) !== value) fail('Noncanonical bundle encoding.');
  return bytes;
}
export function receiptScope(value) {
  keys(value, ['tenant', 'repository', 'incarnation', 'format']);
  return binding({ schema_version: 1, tenant_id: value.tenant, repository_id: value.repository, repository_incarnation: value.incarnation, object_format: value.format });
}
