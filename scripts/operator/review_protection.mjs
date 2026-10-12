// Remote operator client for the existing native review-protection API.
// This is not a Git engine, policy evaluator, bootstrap path or authority store.
import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

export const LIMITS = Object.freeze({ command: 256 * 1024, response: 1024 * 1024,
  intent: 2 * 1024 * 1024, administrators: 32, branches: 64, reviewers: 32, ref: 1024 });
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
function people(value, maximum) {
  if (!Array.isArray(value) || !value.length || value.length > maximum) fail('invalid_principal_count');
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
export function policy(value) {
  fields(value, ['administrators', 'branches']);
  if (!Array.isArray(value.branches) || value.branches.length > LIMITS.branches) fail('invalid_branch_count');
  const branches = value.branches.map(row => {
    fields(row, ['reference_hex', 'required_reviewers']);
    return { reference_hex: branchHex(row.reference_hex), required_reviewers: people(row.required_reviewers, LIMITS.reviewers) };
  }).sort((a, b) => a.reference_hex < b.reference_hex ? -1 : a.reference_hex > b.reference_hex ? 1 : 0);
  if (new Set(branches.map(row => row.reference_hex)).size !== branches.length) fail('duplicate_branch');
  return { administrators: people(value.administrators, LIMITS.administrators), branches };
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
  if ((!value.installed && value.policy !== null) || value.enabled !== Boolean(normalized?.branches.length)) fail('inconsistent_enabled_policy');
  return { scope: selected, source_head: value.source_head, policy_epoch: value.policy_epoch,
    version: value.version, installed: value.installed, enabled: value.enabled, policy: normalized };
}
function command(source, replacement, clear) {
  decimal(source.version, 1n, U64_MAX - 1n); decimal(source.policy_epoch, 1n, U64_MAX - 1n);
  if (typeof clear !== 'boolean' || clear !== (replacement.branches.length === 0)) fail('explicit_clear_required_only_for_empty_branches');
  const form = new URLSearchParams({ expected_version: source.version, expected_epoch: source.policy_epoch });
  for (const person of replacement.administrators) form.append('administrator', person);
  for (const row of replacement.branches) for (const person of row.required_reviewers) form.append('required_reviewer', `${row.reference_hex}:${person}`);
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
        const declared = incoming.headers['content-length'];
        if (declared !== undefined && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(maximum))) {
          finish(new ProtectionError('response_byte_limit', { outcomeUnknown: isWrite })); return;
        }
        let bytes = 0; const chunks = [];
        incoming.on('error', () => finish(new ProtectionError('response_incomplete', { outcomeUnknown: isWrite })));
        incoming.on('data', chunk => {
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
