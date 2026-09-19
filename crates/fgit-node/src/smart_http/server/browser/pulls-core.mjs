// Bounded native PR protocol data. None of these views grants mutation authority.
export const FORM_LIMIT = 256 * 1024;
export const REPLY_LIMIT = 8 * 1024 * 1024;
export const utf8 = new TextEncoder();
export const fail = message => { throw new Error(message); };
export const copy = value => structuredClone(value);
export function record(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Invalid API record.');
  return value;
}
export function keys(value, allowed) {
  record(value);
  if (Object.keys(value).some(key => !allowed.includes(key))) fail('Unknown or inapplicable field.');
}
export function integer(value, name, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(`Invalid or unsupported ${name}; exact safe integers are required.`);
  return value;
}
export function decimal(value, name, minimum = 0) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail(`Invalid ${name}.`);
  return integer(Number(value), name, minimum);
}
export function text(value, maximum, name, single = false) {
  if (typeof value !== 'string' || value.length > maximum || utf8.encode(value).length > maximum ||
      /[\uD800-\uDFFF]/u.test(value) || value.includes('\0') ||
      (single && (!value.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(value)))) fail(`Invalid or oversized ${name}.`);
  return value;
}
export const opaque = value => text(value, 256, 'identity', true);
export const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
export function unhex(value, maximum = REPLY_LIMIT) {
  if (typeof value !== 'string' || value.length > maximum * 2 || value.length % 2 || !/^[0-9a-f]*$/.test(value)) fail('Invalid hex bytes.');
  return Uint8Array.from(value.match(/../g) ?? [], pair => Number.parseInt(pair, 16));
}
export function format(value) { if (!['sha1', 'sha256'].includes(value)) fail('Choose SHA-1 or SHA-256.'); return value; }
export function oid(value, algorithm) {
  format(algorithm);
  if (typeof value !== 'string') fail('Missing object identity.');
  const raw = value.startsWith(`${algorithm}:`) ? value.slice(algorithm.length + 1) : value;
  if (!new RegExp(`^[0-9a-f]{${algorithm === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) fail('Invalid object identity or hash domain.');
  return raw;
}
export function principal(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('Invalid principal identity.');
  return value;
}
export function snapshot(value) {
  if (typeof value !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(value) || Number(value.split(':')[1]) > 65535) fail('Invalid snapshot token.');
  return value;
}
export function branch(value) {
  text(value, 1024, 'branch reference', true);
  if (!value.startsWith('refs/heads/') || /[\s~^:?*\[\\]/u.test(value) || value.includes('..') || value.includes('@{') ||
      value.endsWith('.') || value.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) fail('A complete native branch reference is required.');
  return value;
}
export function reference(row, name) {
  const bytes = unhex(row[`${name}_hex`], 1024);
  if (!bytes.length || bytes.includes(0)) fail('Invalid native ref bytes.');
  if (row[name] !== null) {
    branch(row[name]);
    if (hex(utf8.encode(row[name])) !== row[`${name}_hex`]) fail('Ref text and native bytes disagree.');
  }
  return row[name]; // null is a byte-only ref; readable, but not this form API's input.
}
export function binding(reply, previous = null) {
  record(reply);
  if (reply.schema_version !== 1) fail('Unsupported PR response version.');
  const result = { tenant: opaque(reply.tenant_id), repository: opaque(reply.repository_id),
    incarnation: opaque(reply.repository_incarnation), format: format(reply.object_format) };
  if (previous && Object.keys(result).some(key => previous[key] !== result[key])) fail('Repository identity or incarnation changed. Reconnect explicitly.');
  return result;
}
export function pinned(reply, previous = null, expected = null) {
  const scope = binding(reply, previous), head = snapshot(reply.snapshot_token);
  opaque(reply.source_head);
  if (expected !== null && expected !== head) fail('Snapshot moved. Reload explicitly rather than combining views.');
  return { binding: scope, head };
}
export function prData(row, algorithm) {
  record(row);
  if (format(row.object_format) !== algorithm) fail('PR object format changed.');
  reference(row, 'source_ref'); reference(row, 'target_ref');
  if (row.source_ref_hex === row.target_ref_hex) fail('PR source and target must differ.');
  oid(row.source_tip, algorithm); oid(row.target_tip, algorithm);
  text(row.title, 256, 'title', true); text(row.body, 64 * 1024, 'body');
  return row;
}
export function prRow(row, algorithm) {
  record(row); integer(row.number, 'PR number', 1); integer(row.version, 'PR version', 1);
  if (!['open', 'closed', 'merged'].includes(row.state) || typeof row.merge_only !== 'boolean') fail('Invalid PR lifecycle.');
  if (row.data === null) { if (!row.merge_only || row.state !== 'merged') fail('Missing PR metadata.'); }
  else { prData(row.data, algorithm); if (row.merge_only) fail('Inconsistent PR metadata.'); }
  for (const name of ['opened_by', 'last_metadata_actor']) if (row[name] !== null) principal(row[name]);
  if (row.state === 'merged') {
    record(row.merge);
    if (row.merge.object_format !== algorithm) fail('Invalid merge format.');
    reference(row.merge, 'source_ref'); reference(row.merge, 'target_ref');
    for (const field of ['source_tip', 'target_tip_before', 'base_tip', 'merge_commit']) oid(row.merge[field], algorithm);
    if (row.data && (row.data.source_ref_hex !== row.merge.source_ref_hex || row.data.target_ref_hex !== row.merge.target_ref_hex ||
        oid(row.data.source_tip, algorithm) !== oid(row.merge.source_tip, algorithm) || oid(row.data.target_tip, algorithm) !== oid(row.merge.target_tip_before, algorithm))) fail('Merge does not match PR metadata.');
  } else if (row.merge !== null) fail('Unmerged PR has a merge record.');
  return row;
}
export function listReply(reply, { after = 0, limit = 20, head = null, scope = null } = {}) {
  const selected = pinned(reply, scope, head);
  if (reply.type !== 'pull_request_page' || reply.after !== after || reply.limit !== limit || !Array.isArray(reply.pull_requests) || reply.pull_requests.length > limit) fail('Invalid PR page.');
  let previous = after;
  for (const row of reply.pull_requests) { prRow(row, selected.binding.format); if (row.number <= previous) fail('Invalid PR ordering.'); previous = row.number; }
  if (reply.next_after !== null && (reply.pull_requests.length !== limit || reply.next_after !== previous)) fail('Invalid PR continuation.');
  return { ...selected, reply };
}
export function showReply(reply, number, { head = null, scope = null } = {}) {
  const selected = pinned(reply, scope, head);
  if (reply.type !== 'pull_request' || reply.number !== number || typeof reply.found !== 'boolean') fail('Invalid PR response.');
  if (reply.found) { prRow(reply.pull_request, selected.binding.format); if (reply.pull_request.number !== number) fail('Wrong PR returned.'); }
  else if (reply.pull_request !== null) fail('Missing PR disclosed another record.');
  return { ...selected, reply };
}
export const SUBJECT_FIELDS = ['object_format', 'pull_request_version', 'policy_epoch', 'source_ref', 'target_ref', 'source_tip', 'target_tip'];
export function subject(fields) {
  const algorithm = format(fields.object_format);
  const result = { object_format: algorithm,
    pull_request_version: integer(fields.pull_request_version, 'PR version', 1, Number.MAX_SAFE_INTEGER - 1),
    policy_epoch: integer(fields.policy_epoch, 'policy epoch', 1),
    source_ref: branch(fields.source_ref), target_ref: branch(fields.target_ref),
    source_tip: oid(fields.source_tip, algorithm), target_tip: oid(fields.target_tip, algorithm) };
  if (result.source_ref === result.target_ref) fail('Source and target must differ.');
  return result;
}
export function matchSubject(raw, expected, number, algorithm, numberField = 'number') {
  record(raw);
  if (raw[numberField] !== number) fail('Review subject belongs to another PR.');
  reference(raw, 'source_ref'); reference(raw, 'target_ref');
  integer(raw.pull_request_version, 'PR version', 1); integer(raw.policy_epoch, 'policy epoch', 1);
  oid(raw.source_tip, algorithm); oid(raw.target_tip, algorithm);
  if (expected) {
    for (const key of SUBJECT_FIELDS.filter(key => key !== 'object_format')) {
      const value = key.endsWith('_tip') ? oid(raw[key], algorithm) : raw[key];
      if (value !== expected[key]) fail('Review subject changed; no implicit version or tip refresh.');
    }
  }
}
const FRESHNESS = ['current', 'withdrawn', 'pull_request_unavailable', 'pull_request_closed', 'pull_request_changed', 'source_moved', 'target_moved', 'policy_changed'];
export function reviewsReply(reply, number, { after = null, limit = 20, head = null, scope = null } = {}) {
  binding(reply, scope);
  if (reply.type !== 'review_page' || reply.number !== number || typeof reply.found !== 'boolean' || reply.merge_authorized !== false ||
      reply.after !== after || reply.limit !== limit || !Array.isArray(reply.reviews) || reply.reviews.length > limit) fail('Invalid review page.');
  if (!reply.found) {
    if (reply.reviews.length || reply.next_after !== null || reply.source_head !== null || reply.snapshot_token !== null || reply.pull_request_version !== null || reply.policy_epoch !== null) fail('Invalid absent review page.');
    return { reply, binding: binding(reply, scope), head: null };
  }
  const selected = pinned(reply, scope, head);
  integer(reply.pull_request_version, 'PR version', 1); integer(reply.policy_epoch, 'policy epoch', 1);
  let previous = after;
  for (const row of reply.reviews) {
    record(row); principal(row.reviewer); integer(row.version, 'review version', 1);
    if (previous !== null && row.reviewer <= previous) fail('Invalid reviewer ordering.'); previous = row.reviewer;
    matchSubject(row.subject, null, number, selected.binding.format);
    if (row.candidate !== null) { record(row.candidate); oid(row.candidate.merge_base, selected.binding.format); oid(row.candidate.candidate_commit, selected.binding.format); }
    if (!['approve', 'request-changes', 'withdraw'].includes(row.decision) || !FRESHNESS.includes(row.freshness) ||
        ![true, false, null].includes(row.reviewer_is_opener)) fail('Unsupported review state.');
    text(row.reason, 64 * 1024, 'review reason');
    if (row.freshness === 'current' && (row.subject.pull_request_version !== reply.pull_request_version || row.subject.policy_epoch !== reply.policy_epoch || row.decision === 'withdraw')) fail('Inconsistent review freshness.');
  }
  if (reply.next_after !== null && (reply.reviews.length !== limit || reply.next_after !== previous)) fail('Invalid review continuation.');
  return { ...selected, reply };
}
export function form(fields) {
  const out = new URLSearchParams();
  for (const [name, value] of Object.entries(fields)) {
    for (const part of Array.isArray(value) ? value : [value]) out.append(name, String(part));
  }
  const body = out.toString();
  if (body.length > FORM_LIMIT) fail('Encoded command exceeds 256 KiB.');
  return body;
}
export function metadataCommand(action, fields) {
  if (!['open', 'update', 'close'].includes(action)) fail('Unsupported PR metadata action.');
  keys(fields, ['expected_version', 'object_format', 'source_ref', 'target_ref', 'source_tip', 'target_tip', 'title', 'body']);
  const version = integer(fields.expected_version, 'expected PR version', 0, Number.MAX_SAFE_INTEGER - 1);
  if ((action === 'open') !== (version === 0)) fail('Only a new PR uses expected version zero.');
  const algorithm = format(fields.object_format);
  const result = { expected_version: version, object_format: algorithm, source_ref: branch(fields.source_ref), target_ref: branch(fields.target_ref),
    source_tip: oid(fields.source_tip, algorithm), target_tip: oid(fields.target_tip, algorithm),
    title: text(fields.title, 256, 'title', true), body: text(fields.body, 64 * 1024, 'body') };
  if (result.source_ref === result.target_ref) fail('Source and target must differ.');
  form(result); return result;
}
export function rootFor(href) {
  const page = new URL(href), suffix = '/ui/pulls/';
  if (!['https:', 'http:'].includes(page.protocol) || page.search || page.hash || page.username || page.password || !page.pathname.endsWith(suffix)) fail('Open the exact repository /ui/pulls/ endpoint.');
  if (page.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(page.hostname)) fail('Use HTTPS outside loopback.');
  const route = page.pathname.slice(0, -suffix.length);
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(route) || route.split('/').some(part => part === '.' || part === '..')) fail('Invalid repository route.');
  return { origin: page.origin, route, api: `${page.origin}${route}/api/v1/` };
}
export async function readBytes(response, signal, maximum) {
  const declared = response.headers.get('Content-Length');
  if (declared !== null && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(maximum))) { await response.body?.cancel(); fail('Response exceeds the browser byte limit.'); }
  if (!response.body) fail('Missing response body.');
  const reader = response.body.getReader(), chunks = []; let size = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    while (true) {
      signal.throwIfAborted(); const next = await reader.read(); signal.throwIfAborted();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maximum) fail('Response exceeds the browser byte limit.');
      chunks.push(next.value);
    }
    if (declared !== null && BigInt(declared) !== BigInt(size)) fail('Truncated or inconsistent HTTP response length.');
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return bytes;
  } finally { signal.removeEventListener('abort', cancel); await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
export function json(bytes) { return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
export function apiError(status) {
  const error = new Error(({ 401: 'Credential rejected or revoked.', 403: 'Required independent scope is missing or this endpoint is disabled.',
    404: 'PR or repository unavailable.', 409: 'Subject or snapshot changed; refresh explicitly.', 429: 'Quota exceeded; retry after the server quota window.' })[status] ?? `API request failed (HTTP ${status}).`);
  error.status = status; return error;
}
// Abort an old view without cancelling a submitted mutation; disconnect cancels
// both but never erases the pending request's responsibility.
export class Transport {
  #fetch; #crypto; #token = ''; #fingerprint = ''; #epoch = 0; #all = new Set(); #reads = new Set(); #timeout;
  constructor({ href, fetchImpl = globalThis.fetch, cryptoImpl = globalThis.crypto, timeoutMs = 30_000 }) {
    this.root = Object.freeze(rootFor(href)); this.#fetch = fetchImpl; this.#crypto = cryptoImpl;
    this.#timeout = integer(timeoutMs, 'timeout', 1, 300_000);
  }
  get connected() { return Boolean(this.#token); }
  get fingerprint() { return this.#fingerprint; }
  get epoch() { return this.#epoch; }
  get crypto() { return this.#crypto; }
  async connect(token, requiredFingerprint = null) {
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) fail('A 64-character lowercase hexadecimal token is required.');
    this.disconnect(); const epoch = this.#epoch;
    const fingerprint = hex(new Uint8Array(await this.#crypto.subtle.digest('SHA-256', utf8.encode(token))));
    if (epoch !== this.#epoch) fail('Connection superseded.');
    if (requiredFingerprint !== null && fingerprint !== requiredFingerprint) fail('Unresolved request belongs to another credential.');
    this.#fingerprint = fingerprint; this.#token = token;
  }
  disconnect() { this.#epoch += 1; for (const c of this.#all) c.abort(); this.#token = ''; this.#fingerprint = ''; }
  cancelReads() { for (const c of this.#reads) c.abort(); }
  async request(path, { method = 'GET', body, contentType = 'application/x-www-form-urlencoded', key, statuses = [200], maximum = REPLY_LIMIT, read = true, binary = false } = {}) {
    if (!this.connected) fail('Connect an explicitly scoped token first.');
    const url = new URL(path, this.root.api);
    if (!/^(pulls(?:\/[^?#]*)?(?:\?[^#]*)?|outcomes)$/.test(path) || url.origin !== this.root.origin || !url.pathname.startsWith(`${this.root.route}/api/v1/`)) fail('Invalid API route.');
    const epoch = this.#epoch, controller = new AbortController(); this.#all.add(controller); if (read) this.#reads.add(controller);
    const timer = setTimeout(() => controller.abort(), this.#timeout);
    const headers = { Authorization: `Bearer ${this.#token}`, Accept: binary ? 'multipart/mixed, application/json' : 'application/json' };
    if (body !== undefined) headers['Content-Type'] = contentType;
    if (key) headers['Idempotency-Key'] = key;
    let response;
    try {
      response = await this.#fetch(url, { method, body, headers, signal: controller.signal, redirect: 'error', mode: 'same-origin',
        credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
      controller.signal.throwIfAborted();
      if (epoch !== this.#epoch) fail('Connection superseded.');
      if (response.redirected || (response.url && response.url !== url.href)) fail('API redirect refused.');
      if (!statuses.includes(response.status)) throw apiError(response.status);
      const type = response.headers.get('Content-Type') ?? '';
      if (!binary && !/^application\/json(?:\s*;|$)/i.test(type)) fail('Expected a JSON API response.');
      const bytes = await readBytes(response, controller.signal, maximum);
      if (epoch !== this.#epoch) fail('Connection superseded.');
      return { status: response.status, type, value: binary ? bytes : json(bytes) };
    } catch (error) { if (epoch === this.#epoch && error.status === 401) this.disconnect(); throw error; }
    finally {
      clearTimeout(timer); this.#all.delete(controller); this.#reads.delete(controller);
      if (response?.body && !response.body.locked) await response.body.cancel().catch(() => {});
    }
  }
}
