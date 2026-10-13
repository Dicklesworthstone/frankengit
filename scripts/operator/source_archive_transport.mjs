// Closed source-read transport for the external archive operator, not a Git engine.
import { request as http } from 'node:http';
import { request as https } from 'node:https';
import { outcomeEndpoint } from './transaction_outcome.mjs';

export const fail = message => { throw new Error(message); };
export function integer(value, min, max, label = 'counter') {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`Invalid ${label}.`);
  return value;
}
export function fields(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !allowed.includes(key)) || required.some(key => !Object.hasOwn(value, key))) fail('Invalid source archive fields.');
  return value;
}
export function parse(bytes) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), (_key, value, context) => {
    if (typeof value === 'number') {
      if (!/^(0|[1-9][0-9]*)$/.test(context?.source ?? '')) fail('Noncanonical or inexact source counter.');
      integer(value, 0, Number.MAX_SAFE_INTEGER);
    }
    return value;
  }); } catch { fail('Invalid source JSON; response text is not disclosed.'); }
}

// One operation deadline covers every request, body, and verification checkpoint.
// No redirects, automatic retry, cookie jar, ambient proxy or mutation/key lane.
export class SourceReader {
  #endpoint; #token; #ca; #signal; #deadline; #limits;
  requests = 0; wireBytes = 0;
  constructor(endpoint, token, limits, { signal, ca } = {}) {
    this.#endpoint = outcomeEndpoint(endpoint);
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) fail('Invalid source-read token.');
    if (signal !== undefined && !(signal instanceof AbortSignal)) fail('Invalid archive cancellation signal.');
    if (ca !== undefined && (!Buffer.isBuffer(ca) || !ca.length || ca.length > 128 * 1024)) fail('Invalid private CA bundle.');
    this.#token = token; this.#ca = ca === undefined ? undefined : Buffer.from(ca);
    this.#signal = signal; this.#limits = limits; this.#deadline = performance.now() + limits.timeoutMs;
  }
  check() {
    this.#signal?.throwIfAborted();
    if (performance.now() >= this.#deadline) fail('Source archive deadline exceeded.');
  }
  async read(operation, values, maximum = 3 * 1024 * 1024) {
    this.check();
    if (!['log', 'tree', 'blob'].includes(operation)) fail('Unsupported source-read operation.');
    if (++this.requests > this.#limits.maxRequests) fail('Source archive request budget exceeded.');
    maximum = Math.min(integer(maximum, 1, 3 * 1024 * 1024), this.#limits.maxWireBytes - this.wireBytes);
    if (maximum <= 0) fail('Source archive wire budget exceeded.');
    const body = new URLSearchParams(values).toString();
    if (Buffer.byteLength(body) > 256 * 1024) fail('Source form exceeds native intake limit.');
    const url = new URL(`${this.#endpoint}/api/v1/source/${operation}`), signal = this.#signal;
    const bytes = await new Promise((resolve, reject) => {
      let request, response, result, failure, done = false, closed = false, timer;
      const deliver = () => failure ? reject(failure) : resolve(result);
      const finish = (error, value) => {
        if (done) return;
        done = true; failure = error; result = value;
        clearTimeout(timer); signal?.removeEventListener('abort', abort);
        response?.destroy(); request?.destroy();
        if (closed || !request) deliver();
      };
      const abort = () => finish(new Error('Source archive cancelled.'));
      try {
        request = (url.protocol === 'https:' ? https : http)(url, {
          method: 'POST', agent: false, maxHeaderSize: 16384, rejectUnauthorized: true,
          ...(this.#ca ? { ca: this.#ca } : {}), headers: {
            Authorization: `Bearer ${this.#token}`, Accept: 'application/json', 'Accept-Encoding': 'identity',
            'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body),
            'Cache-Control': 'no-store', Connection: 'close',
          },
        });
        request.on('error', () => finish(new Error('Source archive transport unavailable.')));
        request.once('close', () => { closed = true; if (!done) finish(new Error('Source response incomplete.')); else deliver(); });
        request.once('response', incoming => {
          response = incoming;
          if (incoming.statusCode !== 200) {
            const error = new Error(`Source read refused (HTTP ${incoming.statusCode}); no partial archive is available.`);
            error.status = incoming.statusCode; finish(error); return;
          }
          const framing = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(name => name.toLowerCase())
            .filter(name => ['content-type', 'content-length', 'content-encoding'].includes(name));
          const declared = incoming.headers['content-length'];
          if (new Set(framing).size !== framing.length || !/^application\/json(?:\s*;|$)/i.test(incoming.headers['content-type'] ?? '') ||
              (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity' ||
              (declared !== undefined && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(maximum)))) {
            finish(new Error('Invalid or oversized source response framing.')); return;
          }
          const chunks = []; let length = 0;
          incoming.on('error', () => finish(new Error('Source response incomplete.')));
          incoming.on('data', chunk => {
            if (done) return;
            length += chunk.length; this.wireBytes += chunk.length;
            if (length > maximum || chunks.length >= maximum || this.wireBytes > this.#limits.maxWireBytes) finish(new Error('Source archive wire budget exceeded.'));
            else chunks.push(chunk);
          });
          incoming.once('end', () => {
            if (done) return;
            if (!incoming.complete || (declared !== undefined && BigInt(declared) !== BigInt(length))) finish(new Error('Source response incomplete.'));
            else finish(null, Buffer.concat(chunks, length));
          });
        });
        signal?.addEventListener('abort', abort, { once: true });
        timer = setTimeout(() => finish(new Error('Source archive deadline exceeded.')), Math.max(1, this.#deadline - performance.now()));
        if (signal?.aborted) abort(); else request.end(body);
      } catch { finish(new Error('Source archive transport unavailable.')); }
    });
    this.check(); const result = parse(bytes); this.check(); return result;
  }
}
