// Closed remote PR metadata profile. Native Rust owns authorization and admission.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { outcomeEndpoint } from './transaction_outcome.mjs';
import { form, integer, snapshot, branch, metadataCommand } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

export class PullSyncError extends Error {
  constructor(code, status = null) { super(code); this.name = 'PullSyncError'; this.code = code; this.status = status; }
}
export const fail = code => { throw new PullSyncError(code); };
export function exactKeys(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== names.length ||
      names.some(name => !Object.hasOwn(value, name))) fail('invalid_sync_fields');
  return value;
}
export function tokenValue(token) {
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) fail('invalid_sync_credential');
  return token;
}
export function parseSyncJson(bytes, maximum = 8 * 1024 * 1024) {
  if (!Buffer.isBuffer(bytes) || bytes.length > maximum) fail('sync_json_byte_limit');
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), (key, value, context) => {
    if (typeof value !== 'number') return value;
    if (!/^(0|[1-9][0-9]*)$/.test(context?.source ?? '')) fail('invalid_sync_json_counter');
    if (key === 'decision_sequence') {
      if (BigInt(context.source) < 1n || BigInt(context.source) > 18446744073709551615n) fail('invalid_sync_decision_sequence');
      return context.source;
    }
    return integer(value, 'sync JSON counter');
  }); } catch (error) {
    // A parser exception can quote server bytes, including reflected secrets.
    if (error instanceof PullSyncError) throw error;
    fail('invalid_sync_json');
  }
}
function envelope(operation) {
  const limit = 50;
  if (operation.kind === 'pulls') {
    exactKeys(operation, ['kind', 'after', 'head']); integer(operation.after, 'PR cursor');
    if (operation.head !== null) snapshot(operation.head);
    if (operation.after && operation.head === null) fail('sync_continuation_requires_snapshot');
    const query = new URLSearchParams({ after: String(operation.after), limit: String(limit) });
    if (operation.head) query.set('expected_head', operation.head);
    return { path: `pulls?${query}`, method: 'GET', maximum: 8 * 1024 * 1024, statuses: [200] };
  }
  if (operation.kind === 'show') {
    exactKeys(operation, ['kind', 'number', 'head']); integer(operation.number, 'PR number', 1);
    if (operation.head !== null) snapshot(operation.head);
    const query = operation.head === null ? '' : `?${new URLSearchParams({ expected_head: operation.head })}`;
    return { path: `pulls/${operation.number}${query}`, method: 'GET', maximum: 256 * 1024, statuses: [200, 404] };
  }
  if (operation.kind === 'refs') {
    exactKeys(operation, ['kind', 'after', 'head', 'format']); snapshot(operation.head);
    if (!['sha1', 'sha256'].includes(operation.format)) fail('invalid_sync_format');
    if (operation.after !== null) branch(operation.after);
    return { path: 'source/refs', method: 'POST', maximum: 1024 * 1024, statuses: [200], body: form({
      object_format: operation.format, namespace: 'branches', limit, expected_head: operation.head,
      ...(operation.after === null ? {} : { after: operation.after }),
    }) };
  }
  if (operation.kind === 'update') {
    exactKeys(operation, ['kind', 'number', 'fields', 'key']); integer(operation.number, 'PR number', 1);
    if (typeof operation.key !== 'string' || !/^fgsync1-[0-9a-f]{32}-[0-9a-f]{64}$/.test(operation.key)) fail('invalid_original_sync_key');
    return { path: `pulls/${operation.number}/update`, method: 'POST', maximum: 16 * 1024, statuses: [200, 409],
      body: form(metadataCommand('update', operation.fields)), key: operation.key };
  }
  fail('unsupported_sync_operation');
}
// Each call owns and closes one socket. No redirects, ambient auth, retry, or
// server-selected route. Cancellation may leave an update committed remotely.
export async function syncRequest(address, token, operation, options = {}) {
  const base = outcomeEndpoint(address); tokenValue(token);
  const selected = envelope(operation);
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(key => !['timeoutMs', 'signal', 'ca', 'maximum'].includes(key))) fail('invalid_sync_transport_options');
  const maximum = Math.min(selected.maximum, integer(options.maximum ?? selected.maximum, 'response byte bound', 1, 8 * 1024 * 1024));
  const timeout = integer(options.timeoutMs ?? 30000, 'request timeout', 1, 300000), signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('invalid_sync_signal');
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : fail('invalid_sync_ca');
  signal?.throwIfAborted();
  const url = new URL(`${base}/api/v1/${selected.path}`);
  return new Promise((resolve, reject) => {
    let request, response, result, failure, finished = false, closed = false, timer;
    const deliver = () => failure ? reject(failure) : resolve(result);
    const finish = (error, value) => {
      if (finished) return;
      finished = true; failure = error; result = value;
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      response?.destroy(); request?.destroy();
      if (closed || !request) deliver();
    };
    const abort = () => finish(new PullSyncError('sync_request_cancelled'));
    try {
      const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Accept-Encoding': 'identity',
        'Cache-Control': 'no-store', Connection: 'close' };
      if (selected.body !== undefined) {
        headers['Content-Type'] = 'application/x-www-form-urlencoded'; headers['Content-Length'] = String(Buffer.byteLength(selected.body));
      }
      if (selected.key) headers['Idempotency-Key'] = selected.key;
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, { method: selected.method, headers,
        agent: false, maxHeaderSize: 16384, rejectUnauthorized: true, ...(ca ? { ca } : {}) });
      request.once('close', () => { closed = true; if (!finished) finish(new PullSyncError('sync_response_incomplete')); else deliver(); });
      request.on('error', () => finish(new PullSyncError('sync_transport_unavailable')));
      request.once('response', incoming => {
        response = incoming;
        if (!selected.statuses.includes(incoming.statusCode)) { finish(new PullSyncError('sync_http_refused', incoming.statusCode)); return; }
        const names = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(name => name.toLowerCase())
          .filter(name => ['content-type', 'content-length', 'content-encoding'].includes(name));
        const length = incoming.headers['content-length'];
        if (new Set(names).size !== names.length || !/^application\/json(?:\s*;|$)/i.test(incoming.headers['content-type'] ?? '') ||
            (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') { finish(new PullSyncError('sync_response_encoding')); return; }
        if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(maximum))) {
          finish(new PullSyncError('sync_response_byte_limit')); return;
        }
        const chunks = []; let size = 0;
        incoming.on('error', () => finish(new PullSyncError('sync_response_incomplete')));
        incoming.on('data', chunk => {
          if (finished) return;
          size += chunk.length;
          if (size > maximum || chunks.length >= 16384) finish(new PullSyncError('sync_response_byte_limit'));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (finished) return;
          if (!incoming.complete || (length !== undefined && BigInt(length) !== BigInt(size))) { finish(new PullSyncError('sync_response_incomplete')); return; }
          try { finish(null, { status: incoming.statusCode, bytes: size, value: parseSyncJson(Buffer.concat(chunks, size), maximum) }); }
          catch (error) { finish(error); }
        });
      });
      signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(new PullSyncError('sync_request_timeout')), timeout);
      if (signal?.aborted) abort(); else request.end(selected.body);
    } catch { finish(new PullSyncError('sync_transport_unavailable')); }
  });
}
