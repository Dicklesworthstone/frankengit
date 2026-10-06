// Read-only, credential-scoped canonical activity. Event frames remain opaque:
// this client neither reimplements the native codec nor treats a feed as authority.
export const ACTIVITY_LIMITS = Object.freeze({ reply: 2 * 1024 * 1024, frame: 256 * 1024, frames: 512 * 1024 });
const refuse = message => { throw new Error(message); };
const clone = value => structuredClone(value);
const U64 = 18446744073709551615n, U32 = 4294967295n;
function exact(value, maximum, nonzero = false) {
  if (typeof value !== 'string' || value.length > 20 || !/^(0|[1-9][0-9]*)$/.test(value)) refuse('Invalid exact activity coordinate.');
  const number = BigInt(value);
  if (number > maximum || (nonzero && number === 0n)) refuse('Activity coordinate out of range.');
  return number;
}
export function activityCursor(value) {
  if (value === '0') return [0n, 0n];
  if (typeof value !== 'string' || value.length > 31) refuse('Invalid activity cursor.');
  const parts = value.split(':');
  if (parts.length !== 2) refuse('Invalid activity cursor.');
  return [exact(parts[0], U64, true), exact(parts[1], U32)];
}
function compare(left, right) {
  const a = activityCursor(left), b = activityCursor(right);
  return a[0] === b[0] ? (a[1] > b[1] ? 1 : a[1] < b[1] ? -1 : 0) : a[0] > b[0] ? 1 : -1;
}
function fields(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) refuse('Invalid activity response fields.');
}
function opaque(value) {
  if (typeof value !== 'string' || !value || value.length > 256 || /[\u0000-\u0020\u007f-\u009f\uD800-\uDFFF]/u.test(value)) refuse('Invalid activity identity.');
  return value;
}
function pageLimit(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 100) refuse('Activity page size must be an integer from 1 to 100.');
  return value;
}
const PAGE_FIELDS = ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
  'source_head', 'snapshot_token', 'read_only', 'disclosure_profile', 'issues_read', 'pulls_read',
  'omits_other_event_families', 'cursor_discloses_repository_activity', 'events', 'next_after', 'resume_after', 'has_more', 'complete'];
const EVENT_FIELDS = ['cursor', 'repository_sequence', 'event_index', 'tx_id', 'policy_epoch', 'aggregate', 'aggregate_version', 'kind', 'event_frame_hex'];
const SCOPE_FIELDS = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'issues_read', 'pulls_read'];
export function activityPage(raw, { after = '0', limit = 20, previous = null, expectedHead = null } = {}) {
  activityCursor(after); pageLimit(limit); fields(raw, PAGE_FIELDS);
  if (raw.type !== 'forge_event_page' || raw.schema_version !== 1 || raw.read_only !== true ||
      raw.disclosure_profile !== 'issues-pulls-v1' || raw.omits_other_event_families !== true ||
      raw.cursor_discloses_repository_activity !== true || typeof raw.issues_read !== 'boolean' ||
      typeof raw.pulls_read !== 'boolean' || (!raw.issues_read && !raw.pulls_read) ||
      !['sha1', 'sha256'].includes(raw.object_format)) refuse('Unsupported activity disclosure profile.');
  for (const name of ['tenant_id', 'repository_id', 'repository_incarnation', 'source_head']) opaque(raw[name]);
  if (typeof raw.snapshot_token !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(raw.snapshot_token) ||
      Number(raw.snapshot_token.split(':')[1]) > 65535) refuse('Invalid activity snapshot token.');
  if (previous && SCOPE_FIELDS.some(name => raw[name] !== previous[name])) {
    const error = new Error('Repository incarnation or disclosure grants changed. Reconnect explicitly.'); error.clearActivity = true; throw error;
  }
  if (expectedHead !== null && (raw.snapshot_token !== expectedHead || (previous && raw.source_head !== previous.source_head))) refuse('Activity snapshot moved. Refresh explicitly.');
  if (!Array.isArray(raw.events) || raw.events.length > limit) refuse('Activity page exceeds its requested bound.');
  let last = after, bytes = 0;
  for (const event of raw.events) {
    fields(event, EVENT_FIELDS);
    exact(event.repository_sequence, U64, true); exact(event.event_index, U32);
    if (event.cursor !== `${event.repository_sequence}:${event.event_index}` || compare(event.cursor, last) <= 0) refuse('Activity events are not in exact cursor order.');
    exact(event.policy_epoch, U64); exact(event.aggregate_version, U64, true);
    opaque(event.tx_id); opaque(event.aggregate);
    if (!Number.isSafeInteger(event.kind) || event.kind < 0 || event.kind > Number(U32)) refuse('Invalid activity event kind.');
    const frame = event.event_frame_hex;
    if (typeof frame !== 'string' || !frame.length || frame.length > ACTIVITY_LIMITS.frame * 2 ||
        frame.length % 2 || !/^[0-9a-f]+$/.test(frame)) refuse('Invalid or oversized canonical event frame.');
    bytes += frame.length / 2;
    if (bytes > ACTIVITY_LIMITS.frames) refuse('Activity frame budget exceeded.');
    last = event.cursor;
  }
  for (const name of ['next_after', 'resume_after']) if (raw[name] !== null) {
    activityCursor(raw[name]); if (raw[name] === '0') refuse('Use null for an absent activity watermark.');
  }
  const resume = raw.resume_after ?? '0';
  if (compare(resume, last) < 0 || raw.has_more !== (raw.next_after !== null) || raw.complete !== !raw.has_more ||
      (raw.has_more && (raw.next_after !== raw.resume_after || compare(resume, after) <= 0))) refuse('Invalid activity continuation or resume watermark.');
  return clone(raw);
}
function rootFor(href) {
  const page = new URL(href), suffix = '/ui/activity/';
  if (!['http:', 'https:'].includes(page.protocol) || page.username || page.password || page.search || page.hash ||
      !page.pathname.endsWith(suffix)) refuse('Open the exact repository /ui/activity/ endpoint.');
  if (page.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(page.hostname)) refuse('Use HTTPS outside trusted loopback.');
  const route = page.pathname.slice(0, -suffix.length);
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(route) || route.split('/').some(part => ['.', '..'].includes(part))) refuse('Invalid repository route.');
  return `${page.origin}${route}/api/v1/events`;
}
function discard(response) {
  try { if (response?.body && !response.body.locked) void Promise.resolve(response.body.cancel()).catch(() => {}); } catch { /* Best-effort disposal, never a replacement read. */ }
}
function active(value, signal, late = () => {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, result) => { if (settled) return; settled = true; signal.removeEventListener('abort', abort); fn(result); };
    const abort = () => finish(reject, signal.reason ?? new DOMException('Activity read cancelled.', 'AbortError'));
    Promise.resolve(value).then(result => { if (settled) late(result); else finish(resolve, result); }, error => finish(reject, error));
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
  });
}
async function readJson(response, signal) {
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) refuse('Activity requires a JSON response.');
  const length = response.headers.get('Content-Length');
  if (length !== null && (!/^(0|[1-9][0-9]*)$/.test(length) || length.length > 10 || Number(length) > ACTIVITY_LIMITS.reply)) refuse('Activity response exceeds its byte limit.');
  if (!response.body?.getReader) refuse('Activity requires a bounded response stream.');
  const reader = response.body.getReader(), chunks = []; let size = 0, complete = false;
  try {
    while (true) {
      const { done, value } = await active(reader.read(), signal);
      signal.throwIfAborted();
      if (done) break;
      if (!(value instanceof Uint8Array) || size + value.byteLength > ACTIVITY_LIMITS.reply) refuse('Activity response exceeds its byte limit.');
      size += value.byteLength; chunks.push(value);
    }
    // Fetch exposes decoded bytes, while a proxy's Content-Length can describe
    // the compressed wire representation. The decoded byte cap always applies.
    const encoding = response.headers.get('Content-Encoding');
    if (length !== null && (!encoding || encoding.toLowerCase() === 'identity') && Number(length) !== size) refuse('Activity response length mismatch.');
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); complete = true; return result;
  } finally {
    if (!complete) { try { void Promise.resolve(reader.cancel()).catch(() => {}); } catch { /* A failed stream is already unusable. */ } }
    reader.releaseLock();
  }
}
function httpError(status) {
  const error = new Error(({ 401: 'Activity credential rejected or revoked.', 403: 'Issue or pull-request read permission is missing or disabled.',
    404: 'Repository activity is unavailable.', 409: 'Activity snapshot moved. Refresh explicitly from the last successful watermark.',
    413: 'Activity exceeds the server response limit.', 429: 'Activity read quota exceeded. Retry explicitly later.',
    503: 'Canonical activity is temporarily unavailable.' })[status] ?? `Activity read failed (HTTP ${status}).`);
  error.status = status; return error;
}
export class ActivityClient {
  #root; #fetch; #timeout; #token = ''; #generation = 0; #active = null; #page = null; #scope = null;
  constructor({ href, fetchImpl = globalThis.fetch, timeoutMs = 30000 } = {}) {
    this.#root = rootFor(href); this.#fetch = (...args) => fetchImpl(...args);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) refuse('Invalid activity read timeout.');
    this.#timeout = timeoutMs;
  }
  get connected() { return Boolean(this.#token); }
  get page() { return this.#page ? clone(this.#page) : null; }
  connect(token) {
    this.disconnect();
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) refuse('A 64-character lowercase hexadecimal token is required.');
    this.#token = token;
  }
  cancel() { this.#generation++; this.#active?.abort(); this.#active = null; }
  disconnect() { this.cancel(); this.#token = ''; this.#page = null; this.#scope = null; }
  open({ after = '0', limit = 20 } = {}) { return this.#read(after, limit, null); }
  next() {
    if (!this.#page?.has_more) return Promise.reject(new Error('No next activity page.'));
    return this.#read(this.#page.next_after, this.#pageLimit, this.#page.snapshot_token);
  }
  refresh() {
    if (!this.#page) return Promise.reject(new Error('Load an activity page before refreshing its watermark.'));
    return this.#read(this.#page.resume_after ?? '0', this.#pageLimit, null);
  }
  #pageLimit = 20;
  async #read(after, limit, expectedHead) {
    if (!this.connected) refuse('Connect an issue-read or pull-request-read credential first.');
    activityCursor(after); pageLimit(limit);
    this.cancel(); const generation = this.#generation, controller = new AbortController(); this.#active = controller;
    const timer = setTimeout(() => controller.abort(new DOMException('Activity read timed out.', 'TimeoutError')), this.#timeout);
    const check = () => { controller.signal.throwIfAborted(); if (generation !== this.#generation || !this.connected) refuse('Activity read superseded.'); };
    const url = new URL(this.#root); url.searchParams.set('after', after); url.searchParams.set('limit', String(limit));
    if (expectedHead !== null) url.searchParams.set('expected_head', expectedHead);
    let response;
    try {
      check();
      response = await active(this.#fetch(url, { method: 'GET', signal: controller.signal, redirect: 'error', credentials: 'omit',
        mode: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: { Authorization: `Bearer ${this.#token}`, Accept: 'application/json' } }), controller.signal, discard);
      check();
      if (response.redirected || (response.url && response.url !== url.href)) refuse('Activity redirect refused.');
      if (response.status !== 200) throw httpError(response.status);
      const raw = await readJson(response, controller.signal); check();
      const page = activityPage(raw, { after, limit, expectedHead, previous: this.#scope }); check();
      this.#scope = Object.fromEntries([...SCOPE_FIELDS, 'source_head'].map(name => [name, page[name]]));
      this.#page = page; this.#pageLimit = limit; return clone(page);
    } catch (error) {
      if (generation === this.#generation && (error.status === 401 || error.status === 403 || error.clearActivity)) this.disconnect();
      throw error;
    } finally {
      clearTimeout(timer); discard(response); if (this.#active === controller) this.#active = null;
    }
  }
}
