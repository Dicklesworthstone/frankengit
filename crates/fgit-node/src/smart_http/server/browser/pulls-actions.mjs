// Exact commands and terminal decisions. Transport errors never prove rollback.
import { keys, record, integer, principal, opaque, text, oid, binding, subject, SUBJECT_FIELDS, metadataCommand,
  matchSubject, form, utf8, fail, hex, format, branch, reference, unhex, snapshot, rootFor, readBytes, apiError } from './pulls-core.mjs';
import { BUNDLE_LIMIT, multipart, checkedBundle, digest, mergeMethod } from './pulls-candidate.mjs';
export const RECEIPT_LIMIT = 24 * 1024 * 1024;
export function commentCommand(fields) {
  keys(fields, ['object_format', 'expected_version', 'body']);
  const body = text(fields.body, 64 * 1024, 'comment body');
  if (!body.trim()) fail('Write a nonblank comment.');
  return { object_format: format(fields.object_format),
    expected_version: integer(fields.expected_version, 'conversation version', 0, Number.MAX_SAFE_INTEGER - 1), body };
}
export function collaborationCommand(action, fields) {
  if (!['approve', 'request-changes', 'withdraw', 'merge'].includes(action)) fail('Unsupported review action.');
  keys(fields, [...SUBJECT_FIELDS, 'merge_base', 'candidate_commit', ...(action === 'merge' ? ['required_reviewer', 'method'] : ['expected_version', 'reason'])]);
  const result = { ...subject(fields), merge_base: oid(fields.merge_base, fields.object_format), candidate_commit: oid(fields.candidate_commit, fields.object_format) };
  if (action === 'merge') {
    if (!Array.isArray(fields.required_reviewer) || !fields.required_reviewer.length || fields.required_reviewer.length > 32) fail('Select 1 through 32 explicit required reviewers.');
    result.required_reviewer = fields.required_reviewer.map(principal).sort();
    if (new Set(result.required_reviewer).size !== result.required_reviewer.length) fail('Duplicate required reviewer.');
    if (Object.hasOwn(fields, 'method')) result.method = mergeMethod(fields.method);
  } else {
    result.expected_version = integer(fields.expected_version, 'reviewer stream version', action === 'withdraw' ? 1 : 0, Number.MAX_SAFE_INTEGER - 1);
    result.reason = text(fields.reason, 4096, 'review reason');
    if (!result.reason.trim()) fail('An explicit nonempty review reason is required.');
  }
  form(result); return result;
}
// Fast-forward publishes an existing native tip. It has no constructed candidate,
// review assertion, policy-epoch claim or bundle; the native engine checks gates.
export function fastForwardCommand(fields) {
  keys(fields, ['object_format', 'pull_request_version', 'source_ref', 'source_tip', 'target_ref', 'target_tip']);
  const algorithm = format(fields.object_format);
  const result = { object_format: algorithm,
    pull_request_version: integer(fields.pull_request_version, 'PR version', 1, Number.MAX_SAFE_INTEGER - 1),
    source_ref: branch(fields.source_ref), source_tip: oid(fields.source_tip, algorithm),
    target_ref: branch(fields.target_ref), target_tip: oid(fields.target_tip, algorithm) };
  if (result.source_ref === result.target_ref || result.source_tip === result.target_tip) fail('Fast-forward requires distinct branches and tips.');
  if (form(result).length > 8192) fail('Fast-forward command exceeds 8 KiB.');
  return result;
}
export function command(action, fields) {
  if (action === 'comment') return commentCommand(fields);
  if (action === 'fast-forward') return fastForwardCommand(fields);
  return ['open', 'update', 'close', 'reopen'].includes(action) ? metadataCommand(action, fields) : collaborationCommand(action, fields);
}
export function requestPath(number, action) {
  integer(number, 'PR number', 1);
  if (action === 'comment') return `pulls/${number}/comments`;
  if (!['open', 'update', 'close', 'reopen', 'approve', 'request-changes', 'withdraw', 'merge', 'fast-forward'].includes(action)) fail('Unknown action.');
  return `pulls/${number}/${['approve', 'request-changes', 'withdraw'].includes(action) ? `reviews/${action}` : action}`;
}
export function requestBody(action, fields, bundle, nonce) {
  const normalized = command(action, fields);
  // The native comment form accepts only its predecessor and literal body;
  // the retained request scope independently binds the repository hash domain.
  const encoded = form(action === 'comment' ? { expected_version: normalized.expected_version, body: normalized.body } : normalized);
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
  const metadata = ['open', 'update', 'close', 'reopen'].includes(pending.action);
  if (metadata) {
    if (reply.type !== 'pull_request_publication' || reply.number !== pending.number || reply.expected_version !== pending.fields.expected_version) fail('Wrong terminal PR command.');
  } else if (pending.action === 'comment') {
    if (reply.type !== 'pull_request_comment_publication' || reply.number !== pending.number ||
        reply.expected_version !== pending.fields.expected_version || reply.refs_changed !== false ||
        reply.comment_version !== (reply.outcome === 'committed' ? pending.fields.expected_version + 1 : null)) fail('Wrong terminal conversation command.');
  } else if (pending.action === 'fast-forward') {
    const fields = pending.fields;
    if (reply.type !== 'fast_forward_merge_publication' || reply.number !== pending.number ||
        reply.pull_request_version !== fields.pull_request_version) fail('Wrong terminal fast-forward command.');
    for (const side of ['source', 'target']) {
      reference(reply, `${side}_ref`);
      if (reply[`${side}_ref`] !== fields[`${side}_ref`] ||
          oid(reply[`${side}_tip`], fields.object_format) !== fields[`${side}_tip`]) fail('Terminal fast-forward coordinates changed.');
    }
  } else {
    const merge = pending.action === 'merge', fields = pending.fields;
    if (reply.type !== (merge ? 'reviewed_merge_publication' : 'candidate_review_publication') || reply.review_expected_version !== (merge ? null : fields.expected_version)) fail('Wrong review/merge terminal command.');
    matchSubject(reply.subject, fields, pending.number, fields.object_format);
    if (oid(reply.merge_base, fields.object_format) !== fields.merge_base || oid(reply.candidate_commit, fields.object_format) !== fields.candidate_commit) fail('Terminal candidate changed.');
    if (merge) {
      const expectedMethod = Object.hasOwn(fields, 'method') ? mergeMethod(fields.method) : 'merge-commit';
      if (mergeMethod(reply.method === undefined ? 'merge-commit' : reply.method) !== expectedMethod) fail('Terminal merge method changed.');
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

// Repository review protection is independent of PR mutation authority. Keep
// this client in the already-served action asset; no route or grant is widened.
export const PROTECTION_RECEIPT_LIMIT = 2 * 1024 * 1024;
const PROTECTION_U64 = 18446744073709551615n;
const protectionCopy = value => structuredClone(value);
const protectionEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function protectionFields(value, names) {
  keys(value, names);
  if (names.some(name => !Object.hasOwn(value, name))) fail('Missing protection field.');
  return value;
}
export function protectionU64(value, minimum = 0n, maximum = PROTECTION_U64) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
      BigInt(value) < minimum || BigInt(value) > maximum) fail('Invalid exact protection counter.');
  return value;
}
function protectionHash(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('Invalid protection digest or token.');
  return value;
}
function protectionScope(value) {
  protectionFields(value, ['tenant', 'repository', 'incarnation', 'format']);
  return { tenant: principal(value.tenant), repository: principal(value.repository),
    incarnation: principal(value.incarnation), format: format(value.format) };
}
export function protectionBranch(value) {
  const bytes = unhex(value, 1024);
  const raw = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
  if (!raw.startsWith('refs/heads/') || raw.length === 11 || /[\x00-\x20\x7f~^:?*\[\\]/.test(raw) ||
      raw.includes('..') || raw.includes('@{') || raw.endsWith('.') ||
      raw.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) fail('Invalid protected branch bytes.');
  return value;
}
function protectionPeople(values, allowEmpty = false) {
  if (!Array.isArray(values) || (!values.length && !allowEmpty) || values.length > 32) fail('Select 1 through 32 distinct principals.');
  const result = values.map(principal).sort();
  if (new Set(result).size !== result.length) fail('Duplicate protection principal.');
  return result;
}
function protectionChecks(values) {
  if (!Array.isArray(values) || values.length > 32) fail('Select at most 32 required workflow checks per branch.');
  const result = values.map(value => {
    protectionFields(value, ['source_ref_hex', 'publisher', 'graph_root', 'job']);
    if (typeof value.job !== 'string' || !value.job.length || utf8.encode(value.job).length > 1024 ||
        /[\u0000-\u001f\u007f-\u009f]/u.test(value.job) ||
        new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(utf8.encode(value.job)) !== value.job) fail('Invalid exact workflow job name.');
    return { source_ref_hex: protectionBranch(value.source_ref_hex), publisher: principal(value.publisher),
      graph_root: protectionHash(value.graph_root), job: value.job };
  });
  const order = (a, b) => {
    for (const field of ['source_ref_hex', 'publisher', 'graph_root']) {
      if (a[field] !== b[field]) return a[field] < b[field] ? -1 : 1;
    }
    const x = hex(utf8.encode(a.job)), y = hex(utf8.encode(b.job));
    return x < y ? -1 : x > y ? 1 : 0;
  };
  result.sort(order);
  if (result.some((value, index) => index && order(result[index - 1], value) === 0)) fail('Duplicate required workflow check.');
  return result;
}
export function protectionPolicy(value) {
  protectionFields(value, ['administrators', 'branches']);
  if (!Array.isArray(value.branches) || value.branches.length > 64) fail('Select at most 64 protected branches.');
  const branches = value.branches.map(row => {
    protectionFields(row, ['reference_hex', 'required_reviewers', ...(Object.hasOwn(row, 'required_checks') ? ['required_checks'] : []),
      ...(Object.hasOwn(row, 'required_approvals') ? ['required_approvals'] : [])]);
    const checks = protectionChecks(Object.hasOwn(row, 'required_checks') ? row.required_checks : []);
    const reviewers = protectionPeople(row.required_reviewers, checks.length > 0);
    const approvals = Object.hasOwn(row, 'required_approvals') ? row.required_approvals : reviewers.length;
    if (!Number.isSafeInteger(approvals) || Object.is(approvals, -0) || approvals < (reviewers.length ? 1 : 0) ||
        approvals > reviewers.length) fail('Required approvals must be 1 through the number of eligible reviewers, or 0 for a check-only branch.');
    // Preserve the historical spelling of default unanimity and empty checks
    // so saved v1 receipts retain their original digest and retry identity.
    return { reference_hex: protectionBranch(row.reference_hex), required_reviewers: reviewers,
      ...(checks.length ? { required_checks: checks } : {}),
      ...(approvals !== reviewers.length ? { required_approvals: approvals } : {}) };
  }).sort((a, b) => a.reference_hex < b.reference_hex ? -1 : a.reference_hex > b.reference_hex ? 1 : 0);
  if (new Set(branches.map(row => row.reference_hex)).size !== branches.length) fail('Duplicate protected branch.');
  return { administrators: protectionPeople(value.administrators), branches };
}
export function protectionSnapshot(reply, expectedScope = null, expectedHead = null) {
  protectionFields(reply, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
    'source_head', 'policy_epoch', 'version', 'installed', 'enabled', 'policy', 'complete', 'transaction_created', 'published']);
  const scope = protectionScope(binding(reply, expectedScope));
  const head = snapshot(reply.source_head), version = protectionU64(reply.version), epoch = protectionU64(reply.policy_epoch, 1n);
  if (reply.type !== 'repository_review_protection' || reply.complete !== true || reply.transaction_created !== false || reply.published !== false ||
      reply.installed !== (version !== '0') || (expectedHead !== null && head !== snapshot(expectedHead))) fail('Invalid or moved protection snapshot.');
  const policy = reply.installed ? protectionPolicy(reply.policy) : null;
  if ((!reply.installed && reply.policy !== null) || reply.enabled !== Boolean(policy?.branches.length)) fail('Inconsistent protection installation.');
  return { scope, head, version, epoch, policy };
}
function protectionSource(value) {
  protectionFields(value, ['scope', 'head', 'version', 'epoch', 'policy']);
  return { scope: protectionScope(value.scope), head: snapshot(value.head),
    version: protectionU64(value.version, 1n, PROTECTION_U64 - 1n),
    epoch: protectionU64(value.epoch, 1n, PROTECTION_U64 - 1n), policy: protectionPolicy(value.policy) };
}
export function protectionChanges(before, after) {
  before = protectionPolicy(before); after = protectionPolicy(after);
  const difference = (a, b) => a.filter(value => !b.includes(value));
  const old = new Map(before.branches.map(row => [row.reference_hex, row]));
  const next = new Map(after.branches.map(row => [row.reference_hex, row]));
  const branches = [];
  for (const name of [...new Set([...old.keys(), ...next.keys()])].sort()) {
    const added = difference(next.get(name)?.required_reviewers ?? [], old.get(name)?.required_reviewers ?? []);
    const removed = difference(old.get(name)?.required_reviewers ?? [], next.get(name)?.required_reviewers ?? []);
    const oldChecks = (old.get(name)?.required_checks ?? []).map(value => JSON.stringify(value));
    const nextChecks = (next.get(name)?.required_checks ?? []).map(value => JSON.stringify(value));
    const checksAdded = difference(nextChecks, oldChecks).map(value => JSON.parse(value));
    const checksRemoved = difference(oldChecks, nextChecks).map(value => JSON.parse(value));
    const oldApprovals = old.get(name)?.required_approvals ?? old.get(name)?.required_reviewers.length ?? null;
    const nextApprovals = next.get(name)?.required_approvals ?? next.get(name)?.required_reviewers.length ?? null;
    const quorumChanged = oldApprovals !== nextApprovals &&
      (Object.hasOwn(old.get(name) ?? {}, 'required_approvals') || Object.hasOwn(next.get(name) ?? {}, 'required_approvals'));
    if (added.length || removed.length || checksAdded.length || checksRemoved.length || quorumChanged) branches.push({ reference_hex: name,
      change: !old.has(name) ? 'added' : !next.has(name) ? 'removed' : 'updated', added, removed,
      ...(checksAdded.length || checksRemoved.length ? { checks_added: checksAdded, checks_removed: checksRemoved } : {}),
      ...(quorumChanged ? { required_approvals_before: oldApprovals, required_approvals_after: nextApprovals } : {}) });
  }
  return { administrators_added: difference(after.administrators, before.administrators),
    administrators_removed: difference(before.administrators, after.administrators), branches };
}
function protectionBody(source, replacement, clear) {
  if (typeof clear !== 'boolean' || clear !== (replacement.branches.length === 0)) fail('Empty protection requires explicit clear; clear cannot accompany branch rules.');
  return form({ expected_version: source.version, expected_epoch: source.epoch,
    administrator: replacement.administrators,
    required_reviewer: replacement.branches.flatMap(row => row.required_reviewers.map(person => `${row.reference_hex}:${person}`)),
    required_check: replacement.branches.flatMap(row => (row.required_checks ?? []).map(check =>
      `${row.reference_hex}:${check.source_ref_hex}:${check.publisher}:${check.graph_root}:${hex(utf8.encode(check.job))}`)),
    required_approvals: replacement.branches.filter(row => Object.hasOwn(row, 'required_approvals'))
      .map(row => `${row.reference_hex}:${row.required_approvals}`),
    ...(clear ? { clear: 'true' } : {}) });
}
async function protectionIntent(value, crypto) {
  const source = protectionSource(value.source), replacement = protectionPolicy(value.replacement);
  const basis = { schema: 'frankengit-browser-protection-intent-v1', origin: value.origin, route: value.route,
    principal: principal(value.principal), fingerprint: protectionHash(value.fingerprint), source, replacement,
    clear: value.clear, nonce: principal(value.nonce), body: protectionBody(source, replacement, value.clear) };
  return { ...basis, key: `fgbp1-${basis.nonce}-${await digest(utf8.encode(JSON.stringify(basis)), crypto)}` };
}
// Protection versions/epochs are strings. Only outcome decision_sequence is a
// native unquoted u64. Old browsers may read safe numbers; never round larger
// decisions when JSON.parse lacks source-text access.
export function protectionJson(bytes) {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), (name, value, context) => {
    if (name === 'decision_sequence' && typeof value === 'number') {
      const source = context?.source ?? (Number.isSafeInteger(value) ? String(value) : null);
      return protectionU64(source, 1n);
    }
    if (typeof value === 'number' && !Number.isSafeInteger(value)) fail('Unsafe JSON protection integer.');
    return value;
  });
}
function protectionTransaction(value) {
  protectionFields(value, ['tx_id', 'seal_id', 'request_schema', 'canonical_request_digest']);
  const d = protectionFields(value.canonical_request_digest, ['algorithm', 'hex']);
  integer(d.algorithm, 'seal digest algorithm', 1, 65535);
  if (typeof d.hex !== 'string' || !/^(?:[0-9a-f]{2}){1,64}$/.test(d.hex)) fail('Invalid protection seal digest.');
  return { tx_id: opaque(value.tx_id), seal_id: opaque(value.seal_id), request_schema: opaque(value.request_schema),
    canonical_request_digest: { algorithm: d.algorithm, hex: d.hex } };
}
function protectionOutcome(reply, intent, prior = null) {
  protectionFields(reply, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'principal_id',
    'selector', 'command_index', 'state', 'terminal', 'transaction', 'decision', 'read_only', 'request_reexecuted',
    'absence_proves_non_commit', 'session_completeness_established']);
  binding({ ...reply, object_format: intent.source.scope.format }, intent.source.scope);
  if (reply.type !== 'transaction_outcome' || reply.principal_id !== intent.principal || reply.selector !== 'transaction' ||
      reply.command_index !== null || reply.read_only !== true || reply.request_reexecuted !== false ||
      reply.absence_proves_non_commit !== false || reply.session_completeness_established !== false ||
      !['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused'].includes(reply.state) ||
      reply.terminal !== ['committed', 'refused'].includes(reply.state)) fail('Invalid original protection outcome.');
  const present = !['key_not_observed', 'seal_not_observed'].includes(reply.state);
  if (present !== (reply.transaction !== null)) fail('Inconsistent protection transaction.');
  const transaction = present ? protectionTransaction(reply.transaction) : null;
  if (prior !== null && !protectionEqual(prior, transaction)) fail('Protection transaction or seal regressed.');
  if (!reply.terminal) {
    if (reply.decision !== null) fail('Nonterminal outcome contains a decision.');
    return { terminal: false, state: reply.state, transaction };
  }
  const committed = reply.state === 'committed';
  const decision = protectionFields(reply.decision, committed ? ['kind', 'decision_sequence', 'repository_commit_id']
    : ['kind', 'decision_sequence', 'code', 'code_point', 'refusal_record_id']);
  if (decision.kind !== reply.state) fail('Conflicting protection outcome.');
  protectionU64(decision.decision_sequence, 1n);
  if (committed) opaque(decision.repository_commit_id);
  else { opaque(decision.code); opaque(decision.refusal_record_id); integer(decision.code_point, 'refusal code', 0, 65535); }
  return { terminal: true, outcome: reply.state, tx: transaction.tx_id, principal: intent.principal,
    sequence: decision.decision_sequence, rcr: decision.repository_commit_id ?? null, refusal: decision.code ?? null,
    deliveryAcknowledged: null };
}
function protectionPublication(reply, intent, status, prior) {
  protectionFields(reply, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
    'principal_id', 'expected_version', 'expected_epoch', 'resulting_epoch', 'tx_id', 'outcome', 'decision_sequence',
    'repository_commit_id', 'refusal_record_id', 'refusal_code', 'refusal_code_point', 'delivery_acknowledged']);
  binding(reply, intent.source.scope);
  const committed = reply.outcome === 'committed';
  if (reply.type !== 'review_protection_publication' || reply.principal_id !== intent.principal ||
      reply.expected_version !== intent.source.version || reply.expected_epoch !== intent.source.epoch ||
      !['committed', 'refused'].includes(reply.outcome) || status !== (committed ? 200 : 409) ||
      reply.delivery_acknowledged !== null || (prior && prior.tx_id !== reply.tx_id)) fail('Protection terminal does not match the saved request.');
  opaque(reply.tx_id); protectionU64(reply.decision_sequence, 1n);
  if (committed) {
    opaque(reply.repository_commit_id);
    if (reply.resulting_epoch !== String(BigInt(intent.source.epoch) + 1n) || reply.refusal_record_id !== null ||
        reply.refusal_code !== null || reply.refusal_code_point !== null) fail('Conflicting protection terminal.');
  } else {
    opaque(reply.refusal_record_id); opaque(reply.refusal_code); integer(reply.refusal_code_point, 'refusal code', 0, 65535);
    if (reply.repository_commit_id !== null || reply.resulting_epoch !== null) fail('Conflicting protection terminal.');
  }
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    sequence: reply.decision_sequence, rcr: reply.repository_commit_id, refusal: reply.refusal_code, deliveryAcknowledged: null };
}
export class ProtectionClient {
  #root; #fetch; #crypto; #timeout; #token = ''; #fingerprint = ''; #principal = ''; #recoveryOnly = false;
  #epoch = 0; #busy = false; #controller = null; #scope = null; #observed = null; #pending = null;
  constructor({ href, fetchImpl = globalThis.fetch, cryptoImpl = globalThis.crypto, timeoutMs = 30_000 }) {
    this.#root = Object.freeze(rootFor(href)); this.#fetch = (...args) => fetchImpl(...args); this.#crypto = cryptoImpl;
    this.#timeout = integer(timeoutMs, 'protection timeout', 1, 300_000);
  }
  get connected() { return this.#token !== ''; }
  get busy() { return this.#busy; }
  get recoveryOnly() { return this.#recoveryOnly; }
  get observed() { return protectionCopy(this.#observed); }
  get pending() { return protectionCopy(this.#pending); }
  disconnect() {
    this.#epoch++; this.#controller?.abort(); this.#token = ''; this.#fingerprint = ''; this.#principal = '';
    this.#recoveryOnly = false; this.#observed = null; this.#scope = null;
  }
  #check(epoch) { if (epoch !== this.#epoch || !this.connected) fail('Protection connection superseded or disconnected.'); }
  #idle() { if (this.#busy) fail('A protection operation is still settling.'); }
  #ordinary() { if (!this.connected || this.#recoveryOnly) fail('Connect for ordinary protection access; recovery-only cannot submit changes.'); }
  async connect(token, person, { recoveryOnly = false } = {}) {
    this.#idle(); this.disconnect();
    protectionHash(token); principal(person);
    if (typeof recoveryOnly !== 'boolean') fail('Choose protection recovery mode explicitly.');
    if (this.#pending && this.#pending.intent.principal !== person) fail('Pending protection request belongs to another principal.');
    const epoch = this.#epoch; this.#busy = true;
    try {
      const fingerprint = await digest(utf8.encode(token), this.#crypto);
      if (epoch !== this.#epoch) fail('Protection connection superseded.');
      if (this.#pending && !recoveryOnly && this.#pending.intent.fingerprint !== fingerprint) fail('Original protection credential required; choose recovery-only for rotation.');
      this.#recoveryOnly = recoveryOnly; this.#fingerprint = fingerprint; this.#principal = person; this.#token = token;
    } finally { this.#busy = false; }
  }
  // There is deliberately no public arbitrary-path request method.
  async #request(kind, epoch, expectedHead = null) {
    this.#check(epoch);
    if (!['read', 'send', 'recover'].includes(kind)) fail('Invalid protection operation.');
    if (kind !== 'recover') this.#ordinary();
    const intent = this.#pending?.intent;
    if (kind !== 'read' && !intent) fail('Keep the original protection request.');
    const path = kind === 'recover' ? 'outcomes' : `protection${expectedHead === null ? '' : `?${new URLSearchParams({ expected_head: snapshot(expectedHead) })}`}`;
    const url = new URL(path, this.#root.api), controller = new AbortController(); this.#controller = controller;
    const timer = setTimeout(() => controller.abort(), this.#timeout);
    const headers = { Authorization: `Bearer ${this.#token}`, Accept: 'application/json' };
    if (kind !== 'read') headers['Idempotency-Key'] = intent.key;
    if (kind === 'send') headers['Content-Type'] = 'application/x-www-form-urlencoded';
    let response;
    try {
      response = await this.#fetch(url, { method: kind === 'read' ? 'GET' : 'POST',
        ...(kind === 'send' ? { body: intent.body } : {}), headers, signal: controller.signal,
        mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer' });
      controller.signal.throwIfAborted(); this.#check(epoch);
      if (response.redirected || (response.url && response.url !== url.href)) fail('Protection redirect refused.');
      if (response.status !== 200 && !(kind === 'send' && response.status === 409)) throw apiError(response.status);
      if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) fail('Expected protection JSON.');
      const bytes = await readBytes(response, controller.signal, kind === 'read' ? 1024 * 1024 : 32 * 1024);
      this.#check(epoch); return { reply: protectionJson(bytes), status: response.status };
    } catch (error) { if (epoch === this.#epoch && error.status === 401) this.disconnect(); throw error; }
    finally {
      clearTimeout(timer); this.#controller = null;
      if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {});
    }
  }
  async load(expectedHead = null) {
    this.#idle(); this.#ordinary(); this.#busy = true; const epoch = this.#epoch; this.#observed = null;
    try {
      const { reply } = await this.#request('read', epoch, expectedHead);
      const observed = protectionSnapshot(reply, this.#scope ?? this.#pending?.intent.source.scope ?? null, expectedHead);
      this.#scope = observed.scope; this.#observed = observed; return this.observed;
    } finally { this.#busy = false; }
  }
  async stage(replacement, clear = false) {
    this.#idle(); this.#ordinary();
    if (this.#pending) fail('Resolve or discard the existing protection request first.');
    if (!this.#observed?.policy) fail('Load an installed protection policy; first installation is trusted-local only.');
    const input = { origin: this.#root.origin, route: this.#root.route, principal: this.#principal, fingerprint: this.#fingerprint,
      source: protectionSource(this.#observed), replacement: protectionPolicy(replacement), clear,
      nonce: hex(this.#crypto.getRandomValues(new Uint8Array(16))) };
    const epoch = this.#epoch; this.#busy = true;
    try {
      const intent = await protectionIntent(input, this.#crypto); this.#check(epoch);
      this.#pending = { intent, sent: false, exported: false, observedTransaction: null }; return this.pending;
    } finally { this.#busy = false; }
  }
  discardUnsent() {
    this.#idle();
    if (!this.#pending || this.#pending.sent || this.#pending.exported || this.#recoveryOnly) fail('Only a never-sent, never-exported protection draft can be discarded.');
    this.#pending = null;
  }
  exportReceipt() {
    this.#idle(); if (!this.#pending) fail('No protection request to export.');
    const serialized = JSON.stringify({ schema: 'frankengit-browser-protection-receipt-v1', intent: this.#pending.intent,
      observedTransaction: this.#pending.observedTransaction });
    text(serialized, PROTECTION_RECEIPT_LIMIT, 'protection receipt');
    this.#pending.exported = true; return serialized;
  }
  async restoreReceipt(serialized) {
    this.#idle(); if (!this.connected || this.#pending) fail('Connect with no pending protection request before importing.');
    text(serialized, PROTECTION_RECEIPT_LIMIT, 'protection receipt');
    const receipt = protectionFields(protectionJson(utf8.encode(serialized)), ['schema', 'intent', 'observedTransaction']);
    const input = protectionFields(receipt.intent, ['schema', 'origin', 'route', 'principal', 'fingerprint', 'source', 'replacement', 'clear', 'nonce', 'body', 'key']);
    if (receipt.schema !== 'frankengit-browser-protection-receipt-v1' || input.schema !== 'frankengit-browser-protection-intent-v1' ||
        input.origin !== this.#root.origin || input.route !== this.#root.route || input.principal !== this.#principal ||
        (!this.#recoveryOnly && input.fingerprint !== this.#fingerprint)) fail('Protection receipt belongs to another route, principal or credential.');
    const prior = receipt.observedTransaction === null ? null : protectionTransaction(receipt.observedTransaction);
    const epoch = this.#epoch; this.#busy = true;
    try {
      const intent = await protectionIntent(input, this.#crypto); this.#check(epoch);
      if (intent.key !== input.key || intent.body !== input.body) fail('Protection receipt does not bind its exact command.');
      if (this.#scope && !protectionEqual(intent.source.scope, this.#scope)) fail('Protection receipt repository incarnation changed.');
      this.#pending = { intent, sent: true, exported: true, observedTransaction: prior };
      this.#scope = intent.source.scope; this.#observed = null; return this.pending;
    } finally { this.#busy = false; }
  }
  async send() {
    this.#idle(); this.#ordinary(); if (!this.#pending) fail('Prepare the protection request first.');
    const pending = this.#pending, epoch = this.#epoch; this.#busy = true; pending.sent = true;
    try {
      const { reply, status } = await this.#request('send', epoch);
      const terminal = protectionPublication(reply, pending.intent, status, pending.observedTransaction);
      this.#pending = null; this.#observed = null; return terminal;
    } catch (error) { error.outcomeUnknown = true; throw error; }
    finally { this.#busy = false; }
  }
  async recover() {
    this.#idle(); if (!this.connected || !this.#pending) fail('Connect and retain the original protection request.');
    const pending = this.#pending, epoch = this.#epoch; this.#busy = true;
    try {
      const { reply } = await this.#request('recover', epoch);
      const result = protectionOutcome(reply, pending.intent, pending.observedTransaction);
      if (result.terminal) { this.#pending = null; this.#observed = null; }
      else if (result.transaction) { pending.observedTransaction = result.transaction; pending.sent = true; }
      return result;
    } finally { this.#busy = false; }
  }
}
