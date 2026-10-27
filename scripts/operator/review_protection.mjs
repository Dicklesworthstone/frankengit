// Remote operator client for the existing native review-protection API.
// This is not a Git engine, policy evaluator, bootstrap path or authority store.
import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

export const LIMITS = Object.freeze({ command: 256 * 1024, response: 1024 * 1024,
  intent: 2 * 1024 * 1024, administrators: 32, branches: 64, reviewers: 32, checks: 32, job: 1024, ref: 1024 });
const U64_MAX = 18446744073709551615n;
const ID = /^[0-9a-f]{32}$/, HASH = /^[0-9a-f]{64}$/;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
export class ProtectionError extends Error {
  constructor(code, { outcomeUnknown = false, status = null } = {}) {
    super(code); this.name = 'ProtectionError'; this.code = code;
    this.outcomeUnknown = outcomeUnknown; this.status = status;
  }
}
const fail = code => { throw new ProtectionError(code); };
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const canonical = value => `${JSON.stringify(value, null, 2)}\n`;
function fields(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== expected.length || expected.some(key => !Object.hasOwn(value, key))) fail('invalid_record_fields');
  return value;
}
function identity(value) { if (typeof value !== 'string' || !ID.test(value)) fail('invalid_principal_or_scope'); return value; }
function hash(value) { if (typeof value !== 'string' || !HASH.test(value)) fail('invalid_digest'); return value; }
function opaque(value) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > 256 || /[\s\u0000-\u001f\u007f]/u.test(value)) fail('invalid_identity');
  return value;
}
export function decimal(value, minimum = 0n, maximum = U64_MAX) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
      BigInt(value) < minimum || BigInt(value) > maximum) fail('invalid_exact_u64');
  return value;
}
function head(value) {
  if (typeof value !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(value) || Number(value.split(':')[1]) > 65535) fail('invalid_source_head');
  return value;
}
export function endpoint(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\]/u.test(value)) fail('invalid_endpoint');
  let parsed; try { parsed = new URL(value); } catch { fail('invalid_endpoint'); }
  // A numeric loopback address avoids DNS rebinding of a cleartext localhost alias.
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash ||
      (parsed.protocol === 'http:' && !['127.0.0.1', '[::1]'].includes(parsed.hostname))) fail('https_or_numeric_loopback_required');
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(parsed.pathname) ||
      parsed.pathname.split('/').some(part => part === '.' || part === '..') || parsed.href !== value) fail('canonical_repository_endpoint_required');
  return parsed.href;
}
export function scope(value) {
  fields(value, ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format']);
  if (!['sha1', 'sha256'].includes(value.object_format)) fail('invalid_object_format');
  return { tenant_id: identity(value.tenant_id), repository_id: identity(value.repository_id),
    repository_incarnation: identity(value.repository_incarnation), object_format: value.object_format };
}
function binding(value, expected = null, withFormat = true) {
  const selected = scope({ tenant_id: value.tenant_id, repository_id: value.repository_id,
    repository_incarnation: value.repository_incarnation, object_format: withFormat ? value.object_format : expected.object_format });
  if (expected && JSON.stringify(selected) !== JSON.stringify(scope(expected))) fail('repository_scope_changed');
  return selected;
}
function people(value, maximum, allowEmpty = false) {
  if (!Array.isArray(value) || (!value.length && !allowEmpty) || value.length > maximum) fail('invalid_principal_count');
  const result = value.map(identity).sort();
  if (new Set(result).size !== result.length) fail('duplicate_principal');
  return result;
}
function branchHex(value) {
  if (typeof value !== 'string' || !value.length || value.length > LIMITS.ref * 2 || value.length % 2 || !/^[0-9a-f]+$/.test(value)) fail('invalid_reference_hex');
  const bytes = Buffer.from(value, 'hex');
  if (!bytes.subarray(0, 11).equals(Buffer.from('refs/heads/')) || bytes.length === 11 ||
      bytes.some(byte => byte <= 32 || byte === 127 || [126, 94, 58, 63, 42, 91, 92].includes(byte)) ||
      bytes.includes(Buffer.from('..')) || bytes.includes(Buffer.from('@{')) || bytes.at(-1) === 46) fail('invalid_protected_branch');
  for (const part of bytes.toString('latin1').split('/')) {
    if (!part || part.startsWith('.') || part.endsWith('.lock')) fail('invalid_protected_branch');
  }
  return value;
}
function requiredChecks(values) {
  if (!Array.isArray(values) || values.length > LIMITS.checks) fail('invalid_required_check_count');
  const result = values.map(value => {
    fields(value, ['source_ref_hex', 'publisher', 'graph_root', 'job']);
    if (typeof value.job !== 'string' || !value.job.length || Buffer.byteLength(value.job) > LIMITS.job ||
        /[\u0000-\u001f\u007f-\u009f]/u.test(value.job) || Buffer.from(value.job).toString('utf8') !== value.job) fail('invalid_check_job');
    return { source_ref_hex: branchHex(value.source_ref_hex), publisher: identity(value.publisher),
      graph_root: hash(value.graph_root), job: value.job };
  });
  const order = (a, b) => {
    for (const field of ['source_ref_hex', 'publisher', 'graph_root']) {
      if (a[field] !== b[field]) return a[field] < b[field] ? -1 : 1;
    }
    return Buffer.compare(Buffer.from(a.job), Buffer.from(b.job));
  };
  result.sort(order);
  if (result.some((value, index) => index && order(result[index - 1], value) === 0)) fail('duplicate_required_check');
  return result;
}
function refPolicy(value) {
  fields(value, ['snapshot_id', 'profile', 'mode', 'frame_hex']);
  const id = opaque(value.snapshot_id);
  if (!id.startsWith('frankengit/policy-snapshot/v1/') || value.profile !== 'reference_facts_v1' || value.mode !== 'enforce' ||
      typeof value.frame_hex !== 'string' || !value.frame_hex.length || value.frame_hex.length > 128 * 1024 ||
      value.frame_hex.length % 2 || !/^[0-9a-f]+$/.test(value.frame_hex)) fail('invalid_ref_policy');
  // The native decoder verifies the canonical frame and derives its identity.
  // The client retains the complete observed descriptor in the frozen intent.
  return { snapshot_id: id, profile: value.profile, mode: value.mode, frame_hex: value.frame_hex };
}
export function policy(value) {
  fields(value, ['administrators', 'branches', ...(Object.hasOwn(value, 'ref_policy') ? ['ref_policy'] : [])]);
  if (!Array.isArray(value.branches) || value.branches.length > LIMITS.branches) fail('invalid_branch_count');
  const branches = value.branches.map(row => {
    fields(row, ['reference_hex', 'required_reviewers', ...(Object.hasOwn(row, 'required_checks') ? ['required_checks'] : []),
      ...(Object.hasOwn(row, 'required_approvals') ? ['required_approvals'] : [])]);
    const checks = requiredChecks(Object.hasOwn(row, 'required_checks') ? row.required_checks : []);
    const reviewers = people(row.required_reviewers, LIMITS.reviewers, checks.length > 0);
    const approvals = Object.hasOwn(row, 'required_approvals') ? row.required_approvals : reviewers.length;
    if (!Number.isSafeInteger(approvals) || Object.is(approvals, -0) || approvals < (reviewers.length ? 1 : 0) ||
        approvals > reviewers.length) fail('invalid_required_approval_count');
    // Default unanimity and empty checks preserve saved v1 intent bytes, hashes,
    // request bodies and retry identities. An explicit smaller quorum survives.
    return { reference_hex: branchHex(row.reference_hex), required_reviewers: reviewers,
      ...(checks.length ? { required_checks: checks } : {}),
      ...(approvals !== reviewers.length ? { required_approvals: approvals } : {}) };
  }).sort((a, b) => a.reference_hex < b.reference_hex ? -1 : a.reference_hex > b.reference_hex ? 1 : 0);
  if (new Set(branches.map(row => row.reference_hex)).size !== branches.length) fail('duplicate_branch');
  return { administrators: people(value.administrators, LIMITS.administrators), branches,
    ...(value.ref_policy !== undefined && value.ref_policy !== null ? { ref_policy: refPolicy(value.ref_policy) } : {}) };
}
const SCOPE_FIELDS = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format'];
export function snapshotReply(value, expectedScope = null, expectedHead = null) {
  fields(value, ['type', 'schema_version', ...SCOPE_FIELDS, 'source_head', 'policy_epoch', 'version',
    'installed', 'enabled', 'policy', 'complete', 'transaction_created', 'published']);
  if (value.type !== 'repository_review_protection' || value.schema_version !== 1 || value.complete !== true ||
      value.transaction_created !== false || value.published !== false || typeof value.installed !== 'boolean' ||
      typeof value.enabled !== 'boolean') fail('invalid_protection_snapshot');
  const selected = binding(value, expectedScope);
  head(value.source_head); decimal(value.policy_epoch, 1n); decimal(value.version);
  if (expectedHead !== null && value.source_head !== head(expectedHead)) fail('source_head_changed');
  if (value.installed !== (value.version !== '0')) fail('inconsistent_installed_policy');
  const normalized = value.installed ? policy(value.policy) : null;
  if ((!value.installed && value.policy !== null) || value.enabled !== Boolean(normalized?.branches.length || normalized?.ref_policy)) fail('inconsistent_enabled_policy');
  return { scope: selected, source_head: value.source_head, policy_epoch: value.policy_epoch,
    version: value.version, installed: value.installed, enabled: value.enabled, policy: normalized };
}
function command(source, replacement, clear) {
  decimal(source.version, 1n, U64_MAX - 1n); decimal(source.policy_epoch, 1n, U64_MAX - 1n);
  if (typeof clear !== 'boolean' || clear !== (replacement.branches.length === 0 && !replacement.ref_policy)) fail('explicit_clear_required_only_for_empty_protection');
  const form = new URLSearchParams({ expected_version: source.version, expected_epoch: source.policy_epoch });
  for (const person of replacement.administrators) form.append('administrator', person);
  for (const row of replacement.branches) for (const person of row.required_reviewers) form.append('required_reviewer', `${row.reference_hex}:${person}`);
  for (const row of replacement.branches) for (const check of row.required_checks ?? []) {
    form.append('required_check', `${row.reference_hex}:${check.source_ref_hex}:${check.publisher}:${check.graph_root}:${Buffer.from(check.job).toString('hex')}`);
  }
  for (const row of replacement.branches) if (Object.hasOwn(row, 'required_approvals')) {
    form.append('required_approvals', `${row.reference_hex}:${row.required_approvals}`);
  }
  if (replacement.ref_policy) form.set('ref_policy_frame_hex', replacement.ref_policy.frame_hex);
  if (clear) form.set('clear', 'true');
  const body = form.toString();
  if (Buffer.byteLength(body) > LIMITS.command) fail('command_byte_limit');
  return body;
}
function buildIntent(input) {
  const selected = scope(input.scope);
  const source = fields(input.source, ['source_head', 'policy_epoch', 'version', 'policy']);
  const normalizedSource = { source_head: head(source.source_head), policy_epoch: decimal(source.policy_epoch, 1n),
    version: decimal(source.version, 1n), policy: policy(source.policy) };
  const replacement = policy(input.replacement), body = command(normalizedSource, replacement, input.clear);
  if (typeof input.nonce !== 'string' || !ID.test(input.nonce)) fail('invalid_intent_nonce');
  const basis = { schema: 'frankengit-review-protection-intent-v1', endpoint: endpoint(input.endpoint), scope: selected,
    principal_id: identity(input.principal_id), credential_sha256: hash(input.credential_sha256), source: normalizedSource,
    replacement, clear: input.clear, nonce: input.nonce };
  // The original principal pin and token fingerprint are identity material, not
  // authority assertions. Only the native server authenticates and authorizes.
  const key = `fgprotection1-${input.nonce}-${sha256(JSON.stringify(basis))}`;
  const prepared = { ...basis, request: { method: 'POST', path: 'protection',
    content_type: 'application/x-www-form-urlencoded', body, key } };
  return { ...prepared, intent_sha256: sha256(canonical(prepared)) };
}
export function tokenFingerprint(token) { return sha256(hash(token)); }
export function prepareIntent({ endpoint: address, token, principal_id, expectedScope, snapshot, replacement, clear = false, nonce = randomBytes(16).toString('hex') }) {
  const selected = snapshotReply(snapshot, scope(expectedScope));
  if (!selected.installed) fail('trusted_local_bootstrap_required');
  return buildIntent({ endpoint: address, scope: selected.scope, principal_id, credential_sha256: tokenFingerprint(token),
    source: { source_head: selected.source_head, policy_epoch: selected.policy_epoch, version: selected.version, policy: selected.policy },
    replacement, clear, nonce });
}
export function validateIntent(value) {
  fields(value, ['schema', 'endpoint', 'scope', 'principal_id', 'credential_sha256', 'source', 'replacement', 'clear', 'nonce', 'request', 'intent_sha256']);
  const rebuilt = buildIntent(value);
  if (canonical(value) !== canonical(rebuilt) || Buffer.byteLength(canonical(rebuilt)) > LIMITS.intent) fail('intent_integrity_mismatch');
  return rebuilt;
}
export function parseJson(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > LIMITS.intent) fail('json_byte_limit');
  let value;
  try {
    value = JSON.parse(decoder.decode(bytes), (name, item, context) => {
      // The outcome API emits an unquoted u64. Never round its last bits, even
      // though the protection API already emits string-encoded versions/epochs.
      if (name === 'decision_sequence' && typeof item === 'number') return decimal(context?.source, 1n);
      if (typeof item === 'number' && !Number.isSafeInteger(item)) fail('unsafe_json_integer');
      return item;
    });
  } catch (error) { if (error instanceof ProtectionError) throw error; fail('invalid_json'); }
  return value;
}

// One owned socket/request, no pool, redirects, ambient cookies, retries, proxy
// inference or TLS downgrade. Resolution waits for this request's close event.
export async function jsonRequest(address, token, { path = 'protection', method = 'GET', body, key,
  maximum = LIMITS.response, timeoutMs = 30_000, signal } = {}) {
  const base = endpoint(address); tokenFingerprint(token);
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > LIMITS.response ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) fail('invalid_request_limits');
  const isRead = method === 'GET' && /^protection(?:\?expected_head=alg%3A[0-9]+%3A[0-9a-f]+)?$/.test(path) && body === undefined && key === undefined;
  const isWrite = method === 'POST' && path === 'protection' && typeof body === 'string' && Buffer.byteLength(body) <= LIMITS.command && body.length > 0;
  const isOutcome = method === 'POST' && path === 'outcomes' && body === undefined;
  if ((!isRead && !isWrite && !isOutcome) || (!isRead && (typeof key !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(key)))) fail('invalid_request_envelope');
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('invalid_abort_signal');
  if (signal?.aborted) fail('cancelled');
  const url = new URL(`${base}/api/v1/${path}`), headers = { Authorization: `Bearer ${token}`, Accept: 'application/json',
    'Accept-Encoding': 'identity', 'Cache-Control': 'no-store', Connection: 'close' };
  if (key !== undefined) headers['Idempotency-Key'] = key;
  if (method === 'POST') headers['Content-Length'] = String(body === undefined ? 0 : Buffer.byteLength(body));
  if (body !== undefined) headers['Content-Type'] = 'application/x-www-form-urlencoded';
  return new Promise((resolve, reject) => {
    let request, response, result, error, finishing = false, closed = false, timer;
    const deliver = () => { if (error) reject(error); else resolve(result); };
    const finish = (failure, value) => {
      if (finishing) return;
      finishing = true; error = failure; result = value;
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      response?.destroy(); request?.destroy();
      if (closed || !request) deliver();
    };
    const abort = () => finish(new ProtectionError('cancelled', { outcomeUnknown: isWrite }));
    try {
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
        method, headers, agent: false, maxHeaderSize: 16 * 1024, rejectUnauthorized: true,
      });
      request.once('close', () => {
        closed = true;
        if (!finishing) finish(new ProtectionError('response_incomplete', { outcomeUnknown: isWrite }));
        else deliver();
      });
      request.on('error', () => finish(new ProtectionError('transport_unavailable', { outcomeUnknown: isWrite })));
      request.once('response', incoming => {
        response = incoming;
        const status = incoming.statusCode;
        if (status !== 200 && !(isWrite && status === 409)) {
          finish(new ProtectionError('http_request_refused', { status, outcomeUnknown: isWrite })); return;
        }
        if (!/^application\/json(?:\s*;|$)/i.test(incoming.headers['content-type'] ?? '') ||
            (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') {
          finish(new ProtectionError('unsupported_response_encoding', { outcomeUnknown: isWrite })); return;
        }
        const framingNames = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(name => name.toLowerCase())
          .filter(name => ['content-type', 'content-length', 'content-encoding'].includes(name));
        if (new Set(framingNames).size !== framingNames.length) {
          finish(new ProtectionError('ambiguous_response_headers', { outcomeUnknown: isWrite })); return;
        }
        const declared = incoming.headers['content-length'];
        if (declared !== undefined && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(maximum))) {
          finish(new ProtectionError('response_byte_limit', { outcomeUnknown: isWrite })); return;
        }
        let bytes = 0; const chunks = [];
        incoming.on('error', () => finish(new ProtectionError('response_incomplete', { outcomeUnknown: isWrite })));
        incoming.on('data', chunk => {
          if (finishing) return;
          bytes += chunk.length;
          if (bytes > maximum || chunks.length >= 16_384) finish(new ProtectionError('response_byte_limit', { outcomeUnknown: isWrite }));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (finishing) return;
          if (!incoming.complete || (declared !== undefined && BigInt(declared) !== BigInt(bytes))) {
            finish(new ProtectionError('response_incomplete', { outcomeUnknown: isWrite })); return;
          }
          try { finish(null, { status, value: parseJson(Buffer.concat(chunks, bytes)) }); }
          catch (failure) { failure.outcomeUnknown ||= isWrite; finish(failure); }
        });
      });
      signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(new ProtectionError('request_timeout', { outcomeUnknown: isWrite })), timeoutMs);
      if (signal?.aborted) abort(); else request.end(body);
    } catch { finish(new ProtectionError('transport_unavailable', { outcomeUnknown: isWrite })); }
  });
}
export async function inspectProtection(address, token, { expectedScope = null, expectedHead = null, ...options } = {}) {
  const expected = expectedScope === null ? null : scope(expectedScope);
  const query = expectedHead === null ? '' : `?${new URLSearchParams({ expected_head: head(expectedHead) })}`;
  const { value } = await jsonRequest(address, token, { ...options, path: `protection${query}`, method: 'GET' });
  snapshotReply(value, expected, expectedHead);
  return value;
}

function codePoint(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 65535) fail('invalid_refusal_code_point');
}
function result(kind, tx, sequence, principal, rcr = null, refusal = null, refusalId = null, refusalPoint = null) {
  return { state: kind, terminal: ['committed', 'refused'].includes(kind), tx_id: tx,
    decision_sequence: sequence, principal_id: principal, repository_commit_id: rcr,
    refusal_code: refusal, refusal_record_id: refusalId, refusal_code_point: refusalPoint };
}
export function publicationReply(value, intent, status) {
  fields(value, ['type', 'schema_version', ...SCOPE_FIELDS, 'principal_id', 'expected_version', 'expected_epoch',
    'resulting_epoch', 'tx_id', 'outcome', 'decision_sequence', 'repository_commit_id', 'refusal_record_id',
    'refusal_code', 'refusal_code_point', 'delivery_acknowledged']);
  binding(value, intent.scope);
  if (value.type !== 'review_protection_publication' || value.schema_version !== 1 ||
      identity(value.principal_id) !== intent.principal_id || value.expected_version !== intent.source.version ||
      value.expected_epoch !== intent.source.policy_epoch || value.delivery_acknowledged !== null ||
      !['committed', 'refused'].includes(value.outcome) || status !== (value.outcome === 'committed' ? 200 : 409)) fail('terminal_does_not_match_intent');
  opaque(value.tx_id); decimal(value.decision_sequence, 1n);
  if (value.outcome === 'committed') {
    opaque(value.repository_commit_id);
    if (value.resulting_epoch !== (BigInt(intent.source.policy_epoch) + 1n).toString() ||
        value.refusal_record_id !== null || value.refusal_code !== null || value.refusal_code_point !== null) fail('inconsistent_terminal_decision');
  } else {
    opaque(value.refusal_record_id); opaque(value.refusal_code); codePoint(value.refusal_code_point);
    if (value.repository_commit_id !== null || value.resulting_epoch !== null) fail('inconsistent_terminal_decision');
  }
  return result(value.outcome, value.tx_id, value.decision_sequence, value.principal_id,
    value.repository_commit_id, value.refusal_code, value.refusal_record_id, value.refusal_code_point);
}
export function outcomeReply(value, intent) {
  fields(value, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'principal_id',
    'selector', 'command_index', 'state', 'terminal', 'transaction', 'decision', 'read_only', 'request_reexecuted',
    'absence_proves_non_commit', 'session_completeness_established']);
  binding(value, intent.scope, false);
  if (value.type !== 'transaction_outcome' || value.schema_version !== 1 || identity(value.principal_id) !== intent.principal_id ||
      value.selector !== 'transaction' || value.command_index !== null || value.read_only !== true || value.request_reexecuted !== false ||
      value.absence_proves_non_commit !== false || value.session_completeness_established !== false ||
      !['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused'].includes(value.state) ||
      value.terminal !== ['committed', 'refused'].includes(value.state)) fail('invalid_original_outcome');
  const present = !['key_not_observed', 'seal_not_observed'].includes(value.state);
  if (present !== (value.transaction !== null)) fail('inconsistent_outcome_transaction');
  if (present) {
    const transaction = fields(value.transaction, ['tx_id', 'seal_id', 'request_schema', 'canonical_request_digest']);
    opaque(transaction.tx_id); opaque(transaction.seal_id); opaque(transaction.request_schema);
    const digest = fields(transaction.canonical_request_digest, ['algorithm', 'hex']);
    codePoint(digest.algorithm);
    if (!digest.algorithm || typeof digest.hex !== 'string' || !/^(?:[0-9a-f]{2}){1,64}$/.test(digest.hex)) fail('invalid_seal_digest');
  }
  if (!value.terminal) {
    if (value.decision !== null) fail('inconsistent_nonterminal_outcome');
    return result(value.state, value.transaction?.tx_id ?? null, null, value.principal_id);
  }
  const committed = value.state === 'committed';
  const decision = fields(value.decision, committed ? ['kind', 'decision_sequence', 'repository_commit_id']
    : ['kind', 'decision_sequence', 'code', 'code_point', 'refusal_record_id']);
  if (decision.kind !== value.state) fail('inconsistent_terminal_decision');
  decimal(decision.decision_sequence, 1n);
  if (committed) opaque(decision.repository_commit_id);
  else { opaque(decision.code); codePoint(decision.code_point); opaque(decision.refusal_record_id); }
  return result(value.state, value.transaction.tx_id, decision.decision_sequence, value.principal_id,
    decision.repository_commit_id ?? null, decision.code ?? null, decision.refusal_record_id ?? null, decision.code_point ?? null);
}
export function observation(intent, kind, status, reply) {
  if (!['publication', 'outcome'].includes(kind) || (kind === 'outcome' && status !== 200)) fail('invalid_observation_kind');
  const selected = kind === 'publication' ? publicationReply(reply, intent, status) : outcomeReply(reply, intent);
  return { record: { schema: 'frankengit-review-protection-observation-v1', intent_sha256: intent.intent_sha256, kind, status, reply: structuredClone(reply) },
    summary: selected };
}
export function verifyObservation(value, intent) {
  fields(value, ['schema', 'intent_sha256', 'kind', 'status', 'reply']);
  if (value.schema !== 'frankengit-review-protection-observation-v1' || value.intent_sha256 !== intent.intent_sha256) fail('observation_intent_mismatch');
  return observation(intent, value.kind, value.status, value.reply);
}
export function extendsObservation(next, known) {
  if (!known) return;
  const n = next.summary, k = known.summary;
  if ((k.tx_id !== null && n.tx_id !== k.tx_id) || n.principal_id !== k.principal_id ||
      (k.terminal && JSON.stringify(n) !== JSON.stringify(k))) fail('outcome_regressed_or_conflicted');
  const previousSeal = known.record.reply.transaction, nextSeal = next.record.reply.transaction;
  if (previousSeal && nextSeal && JSON.stringify(previousSeal) !== JSON.stringify(nextSeal)) fail('outcome_seal_changed');
}
export function publicationPreflight(value, token, expectedEndpoint, confirmation) {
  const intent = validateIntent(value);
  if (endpoint(expectedEndpoint) !== intent.endpoint) fail('independent_endpoint_pin_mismatch');
  if (confirmation !== intent.intent_sha256) fail('explicit_intent_confirmation_required');
  if (tokenFingerprint(token) !== intent.credential_sha256) fail('original_token_required_for_resend');
  return intent;
}
export async function publishIntent(value, token, { expectedEndpoint, confirmation, known = null, timeoutMs = 30_000, signal } = {}) {
  const intent = publicationPreflight(value, token, expectedEndpoint, confirmation);
  const prior = known === null ? null : verifyObservation(known, intent);
  try {
    const reply = await jsonRequest(intent.endpoint, token, { method: 'POST', path: 'protection', body: intent.request.body,
      key: intent.request.key, maximum: 32 * 1024, timeoutMs, signal });
    const selected = observation(intent, 'publication', reply.status, reply.value); extendsObservation(selected, prior);
    return selected;
  } catch (error) { error.outcomeUnknown = true; throw error; }
}
export async function recoverIntent(value, token, { expectedEndpoint, known = null, timeoutMs = 30_000, signal } = {}) {
  const intent = validateIntent(value);
  if (endpoint(expectedEndpoint) !== intent.endpoint) fail('independent_endpoint_pin_mismatch');
  const prior = known === null ? null : verifyObservation(known, intent);
  // Rotation permits only this bodyless original-key lookup. It does not change
  // the prepared credential fingerprint or enable publication with a new token.
  try {
    const reply = await jsonRequest(intent.endpoint, token, { method: 'POST', path: 'outcomes', key: intent.request.key,
      maximum: 32 * 1024, timeoutMs, signal });
    const selected = observation(intent, 'outcome', reply.status, reply.value); extendsObservation(selected, prior);
    return selected;
  } catch (error) { error.outcomeUnknown = true; throw error; }
}
