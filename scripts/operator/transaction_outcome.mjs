// Closed, original-key recovery client for the native /api/v1/outcomes API.
// This module has no publication method, native command body or retry generator.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

export const OUTCOME_BYTES = 16 * 1024;
const U64_MAX = 18446744073709551615n;
const SCOPE = ['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id'];
const STATES = ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused'];
export class OutcomeError extends Error {
  constructor(code, status = null) {
    super(code); this.name = 'OutcomeError'; this.code = code;
    this.status = status; this.outcomeUnknown = true;
  }
}
const fail = code => { throw new OutcomeError(code); };
function fields(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== expected.length || expected.some(key => !Object.hasOwn(value, key))) fail('invalid_outcome_fields');
  return value;
}
function identity(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('invalid_outcome_scope');
  return value;
}
function opaque(value) {
  if (typeof value !== 'string' || !value || value.length > 256 || Buffer.byteLength(value) > 256 ||
      /[\s\u0000-\u001f\u007f-\u009f\uD800-\uDFFF]/u.test(value)) fail('invalid_outcome_identity');
  return value;
}
function integer(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail('invalid_outcome_counter');
  return value;
}
function sequence(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > U64_MAX) fail('invalid_outcome_sequence');
  return value;
}
export function outcomeScope(value) {
  fields(value, SCOPE);
  return Object.fromEntries(SCOPE.map(key => [key, identity(value[key])]));
}
export function outcomeEndpoint(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\]/u.test(value)) fail('invalid_outcome_endpoint');
  let url; try { url = new URL(value); } catch { fail('invalid_outcome_endpoint'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
      (url.protocol === 'http:' && !['127.0.0.1', '[::1]'].includes(url.hostname)) || url.href !== value ||
      !/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(url.pathname) ||
      url.pathname.split('/').some(part => part === '.' || part === '..')) fail('https_or_canonical_numeric_loopback_required');
  return value;
}
export function parseOutcomeJson(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > OUTCOME_BYTES) fail('outcome_byte_limit');
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), (key, value, context) => {
      if (typeof value !== 'number') return value;
      // Native Rust emits the decision sequence as an unquoted u64. The raw
      // lexical value, not the rounded JS number, owns every one of those bits.
      if (!/^(0|[1-9][0-9]*)$/.test(context?.source ?? '')) fail('invalid_outcome_json_number');
      if (key === 'decision_sequence') return sequence(context.source);
      return integer(value, 0, Number.MAX_SAFE_INTEGER);
    });
  } catch (error) { if (error instanceof OutcomeError) throw error; fail('invalid_outcome_json'); }
}
// Return a detached, normalized native reply. The server still owns authority;
// these checks bind an observation to the caller's independently retained scope.
export function validateOutcomeReply(value, expected, known = null) {
  const scope = outcomeScope(expected);
  fields(value, ['type', 'schema_version', ...SCOPE, 'selector', 'command_index', 'state', 'terminal',
    'transaction', 'decision', 'read_only', 'request_reexecuted', 'absence_proves_non_commit', 'session_completeness_established']);
  if (SCOPE.some(key => value[key] !== scope[key]) || value.type !== 'transaction_outcome' || value.schema_version !== 1 ||
      value.selector !== 'transaction' || value.command_index !== null || value.read_only !== true ||
      value.request_reexecuted !== false || value.absence_proves_non_commit !== false || value.session_completeness_established !== false ||
      !STATES.includes(value.state) || value.terminal !== ['committed', 'refused'].includes(value.state)) fail('outcome_scope_or_semantics_changed');
  const present = !['key_not_observed', 'seal_not_observed'].includes(value.state);
  if (present !== (value.transaction !== null)) fail('inconsistent_outcome_transaction');
  let transaction = null, decision = null;
  if (present) {
    const tx = fields(value.transaction, ['tx_id', 'seal_id', 'request_schema', 'canonical_request_digest']);
    const digest = fields(tx.canonical_request_digest, ['algorithm', 'hex']);
    integer(digest.algorithm, 1, 65535);
    if (typeof digest.hex !== 'string' || !/^(?:[0-9a-f]{2}){1,64}$/.test(digest.hex)) fail('invalid_outcome_seal_digest');
    transaction = { tx_id: opaque(tx.tx_id), seal_id: opaque(tx.seal_id), request_schema: opaque(tx.request_schema),
      canonical_request_digest: { algorithm: digest.algorithm, hex: digest.hex } };
  }
  if (!value.terminal) {
    if (value.decision !== null) fail('inconsistent_nonterminal_outcome');
  } else {
    const committed = value.state === 'committed';
    const d = fields(value.decision, committed ? ['kind', 'decision_sequence', 'repository_commit_id']
      : ['kind', 'decision_sequence', 'code', 'code_point', 'refusal_record_id']);
    if (d.kind !== value.state) fail('conflicting_outcome_decision');
    decision = { kind: d.kind, decision_sequence: sequence(d.decision_sequence), ...(committed
      ? { repository_commit_id: opaque(d.repository_commit_id) }
      : { code: opaque(d.code), code_point: integer(d.code_point, 0, 65535), refusal_record_id: opaque(d.refusal_record_id) }) };
  }
  const checked = { type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null,
    state: value.state, terminal: value.terminal, transaction, decision, read_only: true, request_reexecuted: false,
    absence_proves_non_commit: false, session_completeness_established: false };
  if (known !== null) {
    const previous = validateOutcomeReply(known, scope);
    if ((previous.transaction !== null && JSON.stringify(previous.transaction) !== JSON.stringify(transaction)) ||
        (previous.terminal && JSON.stringify(previous.decision) !== JSON.stringify(decision)) ||
        (previous.state !== 'key_not_observed' && checked.state === 'key_not_observed')) fail('outcome_regressed_or_conflicted');
  }
  return checked;
}

// Numeric-loopback HTTP or certificate-verified HTTPS. No ambient credentials,
// connection pool, redirects, body, query key, mutation endpoint or auto-retry.
export async function lookupOutcome(address, token, selected, options = {}) {
  fields(selected, [...SCOPE, 'key']);
  const scope = outcomeScope(Object.fromEntries(SCOPE.map(key => [key, selected[key]]))), key = selected.key;
  const base = outcomeEndpoint(address);
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) fail('invalid_outcome_credential');
  if (typeof key !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(key)) fail('invalid_original_outcome_key');
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(key => !['timeoutMs', 'signal', 'known', 'ca'].includes(key))) fail('invalid_outcome_options');
  const timeout = integer(options.timeoutMs ?? 30_000, 1, 300_000), signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('invalid_outcome_signal');
  const known = options.known == null ? null : validateOutcomeReply(options.known, scope);
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : fail('invalid_outcome_tls_ca');
  if (signal?.aborted) fail('outcome_cancelled');
  const url = new URL(`${base}/api/v1/outcomes`);
  const reply = await new Promise((resolve, reject) => {
    let request, response, result, error, finishing = false, closed = false, timer, delivered = false;
    const deliver = () => { if (delivered) return; delivered = true; if (error) reject(error); else resolve(result); };
    const finish = (failure, value) => {
      if (finishing) return;
      finishing = true; error = failure; result = value;
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      response?.destroy(); request?.destroy();
      if (closed || !request) deliver();
    };
    const abort = () => finish(new OutcomeError('outcome_cancelled'));
    try {
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
        method: 'POST', agent: false, maxHeaderSize: 16 * 1024, rejectUnauthorized: true, ...(ca ? { ca } : {}),
        headers: { Authorization: `Bearer ${token}`, 'Idempotency-Key': key, Accept: 'application/json',
          'Accept-Encoding': 'identity', 'Content-Length': '0', 'Cache-Control': 'no-store', Connection: 'close' },
      });
      request.once('close', () => { closed = true; if (!finishing) finish(new OutcomeError('outcome_response_incomplete')); else deliver(); });
      request.on('error', () => finish(new OutcomeError('outcome_transport_unavailable')));
      request.once('response', incoming => {
        response = incoming;
        if (incoming.statusCode !== 200) { finish(new OutcomeError('outcome_http_refused', incoming.statusCode)); return; }
        const headers = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(name => name.toLowerCase())
          .filter(name => ['content-type', 'content-length', 'content-encoding'].includes(name));
        if (new Set(headers).size !== headers.length || !/^application\/json(?:\s*;|$)/i.test(incoming.headers['content-type'] ?? '') ||
            (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') {
          finish(new OutcomeError('outcome_response_encoding')); return;
        }
        const declared = incoming.headers['content-length'];
        if (declared !== undefined && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(OUTCOME_BYTES))) {
          finish(new OutcomeError('outcome_byte_limit')); return;
        }
        const chunks = []; let size = 0;
        incoming.on('error', () => finish(new OutcomeError('outcome_response_incomplete')));
        incoming.on('data', chunk => {
          if (finishing) return;
          size += chunk.length;
          if (size > OUTCOME_BYTES || chunks.length >= OUTCOME_BYTES) finish(new OutcomeError('outcome_byte_limit'));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (finishing) return;
          if (!incoming.complete || (declared !== undefined && BigInt(declared) !== BigInt(size))) {
            finish(new OutcomeError('outcome_response_incomplete')); return;
          }
          try { finish(null, validateOutcomeReply(parseOutcomeJson(Buffer.concat(chunks, size)), scope, known)); }
          catch (failure) { finish(failure); }
        });
      });
      signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(new OutcomeError('outcome_timeout')), timeout);
      if (signal?.aborted) abort(); else request.end();
    } catch { finish(new OutcomeError('outcome_transport_unavailable')); }
  });
  // A fully validated terminal wins over cancellation racing socket cleanup.
  return reply;
}
