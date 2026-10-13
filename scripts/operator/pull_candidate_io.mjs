// External read-only operator transport. No mutation route, transaction key,
// ambient credential, redirect, Git implementation or automatic retry exists.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { rootFor, integer, snapshot, principal } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { PREPARATION_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';

export const CANDIDATE_IO_LIMITS = Object.freeze({ json: 8 * 1024 * 1024, capture: 16 * 1024 * 1024,
  wire: 64 * 1024 * 1024, reviewPages: 8, reviewPageSize: 50 });
export class CandidateError extends Error {
  constructor(code, { phase = 'validation', status = null } = {}) {
    super(code); this.name = 'CandidateError'; this.code = code; this.phase = phase; this.status = status;
  }
}
export const candidateFail = code => { throw new CandidateError(code); };
export function candidateKeys(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).some(key => !names.includes(key)) || required.some(key => !Object.hasOwn(value, key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(row => !Object.hasOwn(row, 'value'))) candidateFail('invalid_candidate_fields');
  return value;
}
export function candidateEndpoint(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\]/u.test(value)) candidateFail('invalid_candidate_endpoint');
  const parsed = new URL(value);
  if (parsed.href !== value || (parsed.protocol === 'http:' && !['127.0.0.1', '[::1]'].includes(parsed.hostname))) {
    candidateFail('candidate_requires_https_or_numeric_loopback');
  }
  rootFor(`${value}/ui/pulls/`);
  return value;
}
export function candidateToken(token) {
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) candidateFail('invalid_candidate_credential');
  return token;
}
// Additional intake constraints around the unchanged shared schema validators.
// This is JSON framing, not a second Git parser. Numbers outside the shared
// validators' safe-integer profile refuse; they are never rounded or clamped.
export function candidateJson(bytes, maximum = CANDIDATE_IO_LIMITS.json) {
  if (!(bytes instanceof Uint8Array) || !Number.isSafeInteger(maximum) || maximum < 1 ||
      maximum > CANDIDATE_IO_LIMITS.capture || bytes.length > maximum) candidateFail('candidate_json_limit');
  try {
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), stack = [];
    let nodes = 0;
    for (let i = 0; i < source.length; i++) {
      const c = source[i];
      if (c === '{' || c === '[') {
        if (++nodes > 100000 || stack.length >= 32) candidateFail('candidate_json_structure_limit');
        stack.push({ type: c, keys: new Set() });
      } else if (c === '}' || c === ']') {
        if (stack.pop()?.type !== (c === '}' ? '{' : '[')) candidateFail('invalid_candidate_json');
      } else if (c === '"') {
        const start = i++;
        for (; i < source.length && source[i] !== '"'; i++) if (source[i] === '\\') i++;
        if (i >= source.length || ++nodes > 100000) candidateFail('candidate_json_structure_limit');
        let next = i + 1; while (next < source.length && /[\x20\t\r\n]/.test(source[next])) next++;
        if (source[next] === ':') {
          const current = stack.at(-1), key = JSON.parse(source.slice(start, i + 1));
          if (current?.type !== '{' || current.keys.has(key)) candidateFail('duplicate_candidate_json_key');
          current.keys.add(key);
        }
      }
    }
    if (stack.length) candidateFail('invalid_candidate_json');
    return JSON.parse(source, (_key, value, context) => {
      if (typeof value === 'number' && (!/^(0|[1-9][0-9]*)$/.test(context?.source ?? '') || !Number.isSafeInteger(value))) {
        candidateFail('unsupported_candidate_json_integer');
      }
      return value;
    });
  } catch (error) { if (error instanceof CandidateError) throw error; candidateFail('invalid_candidate_json'); }
}
function envelope(operation) {
  const number = integer(operation.number, 'candidate PR number', 1);
  const prefix = `pulls/${number}`;
  if (operation.kind === 'show') {
    candidateKeys(operation, ['kind', 'number', 'head']);
    const query = operation.head === null ? '' : `?${new URLSearchParams({ expected_head: snapshot(operation.head) })}`;
    return { path: prefix + query, method: 'GET', maximum: 256 * 1024, statuses: [200, 404] };
  }
  if (operation.kind === 'reviews') {
    candidateKeys(operation, ['kind', 'number', 'head', 'after']); snapshot(operation.head);
    const query = new URLSearchParams({ limit: String(CANDIDATE_IO_LIMITS.reviewPageSize), expected_head: operation.head });
    if (operation.after !== null) query.set('after', principal(operation.after));
    return { path: `${prefix}/reviews?${query}`, method: 'GET', maximum: CANDIDATE_IO_LIMITS.json, statuses: [200, 404] };
  }
  if (operation.kind === 'prepare') {
    candidateKeys(operation, ['kind', 'number', 'body']);
    if (typeof operation.body !== 'string' || Buffer.byteLength(operation.body) > 256 * 1024) candidateFail('candidate_form_limit');
    return { path: `${prefix}/prepare`, method: 'POST', body: operation.body,
      type: 'application/x-www-form-urlencoded', maximum: PREPARATION_LIMIT, statuses: [200, 409] };
  }
  if (operation.kind === 'inspect') {
    candidateKeys(operation, ['kind', 'number', 'body', 'type']);
    if (!(operation.body instanceof Uint8Array) || !operation.body.length || operation.body.length > PREPARATION_LIMIT ||
        !/^multipart\/form-data; boundary=[A-Za-z0-9_.-]{1,70}$/.test(operation.type)) candidateFail('invalid_candidate_inspection_upload');
    return { path: `${prefix}/inspect`, method: 'POST', body: Buffer.from(operation.body), type: operation.type,
      maximum: CANDIDATE_IO_LIMITS.json, statuses: [200] };
  }
  candidateFail('unsupported_candidate_operation');
}
export async function candidateRequest(address, token, operation, options = {}) {
  const endpoint = candidateEndpoint(address); candidateToken(token);
  const selected = envelope(operation), preparation = operation.kind === 'prepare';
  candidateKeys(options, ['timeoutMs', 'signal', 'ca', 'maximum'], []);
  const timeout = integer(options.timeoutMs ?? 30000, 'candidate timeout', 1, 300000);
  const maximum = Math.min(selected.maximum, integer(options.maximum ?? selected.maximum, 'candidate response limit', 1, PREPARATION_LIMIT));
  const signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) candidateFail('invalid_candidate_signal');
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : candidateFail('invalid_candidate_ca');
  if (signal?.aborted) candidateFail('candidate_cancelled');
  const url = new URL(`${endpoint}/api/v1/${selected.path}`);
  return new Promise((resolve, reject) => {
    let request, response, result, failure, timer, finished = false, closed = false, delivered = false;
    const deliver = () => { if (delivered) return; delivered = true; failure ? reject(failure) : resolve(result); };
    const finish = (error, value) => {
      if (finished) return;
      finished = true; failure = error; result = value;
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      response?.destroy(); request?.destroy();
      if (!request || closed) deliver();
    };
    const abort = () => finish(new CandidateError('candidate_cancelled'));
    try {
      const headers = { Authorization: `Bearer ${token}`, Accept: 'multipart/mixed, application/json',
        'Accept-Encoding': 'identity', 'Cache-Control': 'no-store', Connection: 'close' };
      if (selected.body !== undefined) {
        headers['Content-Type'] = selected.type; headers['Content-Length'] = String(Buffer.byteLength(selected.body));
      }
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, { method: selected.method, headers,
        agent: false, maxHeaderSize: 16384, rejectUnauthorized: true, ...(ca ? { ca } : {}) });
      request.once('close', () => { closed = true; if (!finished) finish(new CandidateError('candidate_response_incomplete')); else deliver(); });
      request.on('error', () => finish(new CandidateError('candidate_transport_unavailable')));
      request.once('response', incoming => {
        response = incoming;
        if (!selected.statuses.includes(incoming.statusCode)) {
          finish(new CandidateError('candidate_http_refused', { status: incoming.statusCode })); return;
        }
        const names = incoming.rawHeaders.filter((_, index) => index % 2 === 0).map(name => name.toLowerCase())
          .filter(name => ['content-type', 'content-length', 'content-encoding'].includes(name));
        const type = incoming.headers['content-type'] ?? '', length = incoming.headers['content-length'];
        if (new Set(names).size !== names.length || (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity' ||
            !(preparation ? /^(application\/json(?:\s*;|$)|multipart\/mixed; boundary=)/i.test(type)
              : /^application\/json(?:\s*;|$)/i.test(type))) {
          finish(new CandidateError('candidate_response_encoding')); return;
        }
        if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(maximum))) {
          finish(new CandidateError('candidate_response_limit')); return;
        }
        const chunks = []; let size = 0;
        incoming.on('error', () => finish(new CandidateError('candidate_response_incomplete')));
        incoming.on('data', chunk => {
          if (finished) return;
          size += chunk.length;
          if (size > maximum || chunks.length >= 32768) finish(new CandidateError('candidate_response_limit'));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (finished) return;
          if (!incoming.complete || (length !== undefined && BigInt(length) !== BigInt(size))) {
            finish(new CandidateError('candidate_response_incomplete')); return;
          }
          finish(null, { status: incoming.statusCode, type, value: Buffer.concat(chunks, size) });
        });
      });
      signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(new CandidateError('candidate_timeout')), timeout);
      if (signal?.aborted) abort(); else request.end(selected.body);
    } catch { finish(new CandidateError('candidate_transport_unavailable')); }
  });
}
