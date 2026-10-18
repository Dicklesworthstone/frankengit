// FG-049: one bounded, read-only GitHub HTTP lifetime for capture and discovery.
// Source retries never submit native mutations or change a sealed import plan.
import { setTimeout as sleep } from 'node:timers/promises';
import { operatorError } from './forge-operator-io.mjs';

export const API_VERSION = '2026-03-10';
export const GITHUB_API = 'https://api.github.com';
export const SOURCE_RETRY_LIMIT = 10;
const UA = 'frankengit-issue-import (+https://github.com/Dicklesworthstone/frankengit)';
const fail = code => { throw operatorError(`github_import_${code}`); };
function integer(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(name);
  return value;
}
export function githubIdentity(value) {
  if (typeof value === 'number') value = String(integer(value, 1, Number.MAX_SAFE_INTEGER, 'identity'));
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > 18446744073709551615n) fail('identity');
  return value;
}
export function githubRepository(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(value) ||
      ['.', '..'].includes(value.split('/')[1])) fail('repository');
  return value;
}
// Never round GitHub numeric aliases through IEEE-754. The Node profile must
// provide the JSON reviver's original numeric source, as the capture did before.
function githubJson(bytes) {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), (key, value, context) => {
    if (typeof value !== 'number') return value;
    const raw = context?.source;
    if (typeof raw !== 'string' || !/^(0|[1-9][0-9]*)$/.test(raw)) fail('numeric_wire_value');
    if (key === 'id') return githubIdentity(raw);
    return integer(value, 0, Number.MAX_SAFE_INTEGER, 'numeric_wire_value');
  });
}
function seconds(value) {
  return typeof value === 'string' && /^[0-9]{1,10}$/.test(value) ? Number(value) : null;
}
// A null delay is a refusal to retry, not permission to ignore a server delay.
// GitHub documents delta-seconds Retry-After, primary reset epochs and a
// one-minute minimum for secondary limits without a Retry-After header.
export function githubRetryDelay(status, headers, attempt, nowMs = Date.now()) {
  integer(attempt, 0, SOURCE_RETRY_LIMIT, 'source_retries');
  const after = headers.get('Retry-After'), remaining = headers.get('X-RateLimit-Remaining');
  const limited = status === 429 || (status === 403 && (after !== null || remaining === '0'));
  if (!limited && ![502, 503, 504].includes(status)) return null;
  let delay = null;
  if (after !== null) {
    const value = seconds(after);
    if (value === null) return null;
    delay = value * 1000;
  }
  if (limited && remaining === '0') {
    const reset = seconds(headers.get('X-RateLimit-Reset'));
    if (reset === null || !Number.isFinite(nowMs)) return null;
    // Wait strictly beyond the reset second, even when the response arrives at
    // its boundary. A second header can lengthen but never shorten Retry-After.
    delay = Math.max(delay ?? 0, reset * 1000 - nowMs + 1000, 0);
  }
  return delay ?? (limited ? 60000 : 1000) * (2 ** attempt);
}
export function createGithubSource({ token = null, signal, timeoutMs = 300000,
  maxReadBytes = 64 * 1024 * 1024, maxSourceRetries = 0, fetchImpl = globalThis.fetch, maxRequests = 4096 } = {}) {
  integer(timeoutMs, 1, 300000, 'capture_timeout');
  integer(maxReadBytes, 1, 256 * 1024 * 1024, 'capture_read_limit');
  integer(maxSourceRetries, 0, SOURCE_RETRY_LIMIT, 'source_retries');
  integer(maxRequests, 1, 4096, 'request_limit');
  if (token !== null && (typeof token !== 'string' || !/^[A-Za-z0-9_]{1,255}$/.test(token))) fail('token');
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('signal');
  if (typeof fetchImpl !== 'function') fail('fetch');
  const stop = new AbortController(), combined = signal ? AbortSignal.any([signal, stop.signal]) : stop.signal;
  const deadline = performance.now() + timeoutMs;
  const timer = setTimeout(() => stop.abort(), timeoutMs);
  let requests = 0, readBytes = 0, retries = 0, busy = false;
  const check = () => {
    if (performance.now() >= deadline) stop.abort();
    combined.throwIfAborted();
  };
  async function attempt(url) {
    check(); if (requests === maxRequests) fail('request_limit');
    requests++;
    const response = await fetchImpl(url, { method: 'GET', redirect: 'error', credentials: 'omit', cache: 'no-store',
      signal: combined, headers: { Accept: 'application/vnd.github.raw+json', 'X-GitHub-Api-Version': API_VERSION,
        'User-Agent': UA, ...(token === null ? {} : { Authorization: `Bearer ${token}` }) } });
    let reader, cancelled, cleanupFailed = false;
    const cancel = () => {
      cancelled ??= Promise.resolve().then(() => (reader ?? response.body)?.cancel())
        .catch(() => { cleanupFailed = true; });
      return cancelled;
    };
    try {
      check();
      if (response.redirected || (response.url && response.url !== url)) fail('redirect');
      if (response.status !== 200) {
        const error = operatorError('github_import_source_http'); error.status = response.status;
        const after = response.headers.get('Retry-After');
        if (seconds(after) !== null) error.retry_after_seconds = after;
        return { error, delay: githubRetryDelay(response.status, response.headers, retries) };
      }
      if (!/^application\/(?:json|vnd\.github(?:\.raw)?\+json)(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') || !response.body) fail('json_media');
      reader = response.body.getReader(); combined.addEventListener('abort', cancel, { once: true });
      const chunks = []; let bytes = 0;
      for (;;) {
        check(); const next = await reader.read(); check(); if (next.done) break;
        if (!(next.value instanceof Uint8Array)) fail('read_bytes');
        bytes += next.value.byteLength; readBytes += next.value.byteLength;
        if (bytes > 8 * 1024 * 1024 || readBytes > maxReadBytes) fail('read_bytes');
        chunks.push(Buffer.from(next.value));
      }
      return { result: { value: githubJson(Buffer.concat(chunks, bytes)), link: response.headers.get('Link') } };
    } finally {
      combined.removeEventListener('abort', cancel);
      await cancel(); reader?.releaseLock();
      if (cleanupFailed) fail('source_cleanup');
    }
  }
  async function get(path) {
    check();
    if (busy) fail('concurrent_source_read');
    if (typeof path !== 'string' || path.length > 2048 || !path.startsWith('/repos/') || /[\u0000-\u0020\u007f\\#]/u.test(path)) fail('source_path');
    const url = `${GITHUB_API}${path}`, parsed = new URL(url);
    if (parsed.origin !== GITHUB_API || parsed.href !== url || parsed.username || parsed.password) fail('source_path');
    busy = true;
    try {
      for (;;) {
        const reply = await attempt(url);
        check();
        if (reply.result) return reply.result;
        if (reply.delay === null || retries >= maxSourceRetries || reply.delay >= deadline - performance.now()) throw reply.error;
        retries++;
        await sleep(reply.delay, undefined, { signal: combined });
      }
    } finally { busy = false; }
  }
  return Object.freeze({ get, check,
    statistics: () => ({ requests, read_bytes: readBytes, source_retries: retries }),
    close: () => { clearTimeout(timer); stop.abort(); },
  });
}
