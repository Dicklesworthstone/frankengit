// Read-only, snapshot-pinned native PR/review inspection. No publication API,
// policy evaluator, candidate generator, automatic retry or Git implementation.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';

export const REVIEW_LIMITS = Object.freeze({ reply: 2 * 1024 * 1024, capture: 8 * 1024 * 1024,
  wire: 8 * 1024 * 1024, reviewers: 1024, pages: 32 });
const U64 = 18446744073709551615n;
const SCOPE = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format'];
const HEADER = ['type', 'schema_version', ...SCOPE, 'source_head', 'snapshot_token'];
const REFS = ['source_ref', 'source_ref_hex', 'target_ref', 'target_ref_hex'];
const COUNTERS = new Set(['number', 'version', 'pull_request_version', 'policy_epoch']);
const FRESHNESS = ['current', 'withdrawn', 'pull_request_unavailable', 'pull_request_closed',
  'pull_request_changed', 'source_moved', 'target_moved', 'policy_changed'];
export class ReviewSnapshotError extends Error {
  constructor(code, status = null) { super(code); this.name = 'ReviewSnapshotError'; this.code = code; this.status = status; }
}
export const failReview = code => { throw new ReviewSnapshotError(code); };
export function reviewFields(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).some(key => !names.includes(key)) || required.some(key => !Object.hasOwn(value, key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) failReview('invalid_review_fields');
  return value;
}
export function reviewU64(value, minimum = 0n) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
      BigInt(value) < minimum || BigInt(value) > U64) failReview('invalid_review_u64');
  return value;
}
export function reviewPrincipal(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) failReview('invalid_review_principal');
  return value;
}
export function reviewText(value, maximum, single = false) {
  if (typeof value !== 'string' || value.length > maximum || Buffer.byteLength(value) > maximum ||
      /[\uD800-\uDFFF]/u.test(value) || value.includes('\0') ||
      (single && (!value.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(value)))) failReview('invalid_review_text');
  return value;
}
function opaque(value) { reviewText(value, 256, true); if (/\s/u.test(value)) failReview('invalid_review_identity'); return value; }
export function reviewHead(value) {
  if (typeof value !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(value) ||
      Number(value.split(':')[1]) > 65535) failReview('invalid_review_snapshot');
  return value;
}
export function reviewEndpoint(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\]/u.test(value)) failReview('invalid_review_endpoint');
  let url; try { url = new URL(value); } catch { failReview('invalid_review_endpoint'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.href !== value ||
      (url.protocol === 'http:' && !['127.0.0.1', '[::1]'].includes(url.hostname)) ||
      !/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(url.pathname) ||
      url.pathname.split('/').some(part => part === '.' || part === '..')) failReview('https_or_numeric_loopback_required');
  return value;
}
function scope(value) {
  reviewFields(value, SCOPE);
  if (!['sha1', 'sha256'].includes(value.object_format)) failReview('invalid_review_format');
  return Object.fromEntries(SCOPE.map(key => [key, key === 'object_format' ? value[key] : reviewPrincipal(value[key])]));
}
export function reviewSelection(value) {
  reviewFields(value, ['endpoint', 'scope', 'number', 'expected_head']);
  return { endpoint: reviewEndpoint(value.endpoint), scope: scope(value.scope), number: reviewU64(value.number, 1n),
    expected_head: value.expected_head === null ? null : reviewHead(value.expected_head) };
}
export function reviewOid(value, format) {
  // Native GitOid Display is algorithm-qualified. Preserve that spelling in the
  // capture; strip only this checked domain when creating an operator input.
  if (typeof value !== 'string' || !new RegExp(`^${format}:[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(value) ||
      /^0+$/.test(value.slice(format.length + 1))) failReview('invalid_review_oid');
  return value;
}
function refs(row) {
  for (const side of ['source', 'target']) {
    const value = row[`${side}_ref`], hex = row[`${side}_ref_hex`];
    if (typeof hex !== 'string' || !/^(?:[0-9a-f]{2}){1,1024}$/.test(hex)) failReview('invalid_review_ref_bytes');
    const bytes = Buffer.from(hex, 'hex');
    let decoded = null;
    try { decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { /* Byte-only name. */ }
    if (value !== decoded || !bytes.subarray(0, 11).equals(Buffer.from('refs/heads/')) || bytes.length === 11 ||
        bytes.some(b => b <= 32 || b === 127 || [126, 94, 58, 63, 42, 91, 92].includes(b)) ||
        bytes.includes(Buffer.from('..')) || bytes.includes(Buffer.from('@{')) || bytes.at(-1) === 46 ||
        bytes.toString('latin1').split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) failReview('invalid_review_ref_bytes');
  }
  if (row.source_ref_hex === row.target_ref_hex) failReview('invalid_review_coordinates');
}
function header(row, selected, expected, source = null) {
  if (row.schema_version !== 1 || SCOPE.some(key => row[key] !== selected.scope[key])) failReview('review_scope_changed');
  reviewHead(row.snapshot_token); opaque(row.source_head);
  if ((expected !== null && row.snapshot_token !== expected) || (source !== null && row.source_head !== source)) failReview('review_snapshot_changed');
}
function metadata(data, format) {
  reviewFields(data, [...REFS, 'object_format', 'source_tip', 'target_tip', 'title', 'body']);
  if (data.object_format !== format) failReview('review_format_changed');
  refs(data); reviewOid(data.source_tip, format); reviewOid(data.target_tip, format);
  reviewText(data.title, 256, true); reviewText(data.body, 65536);
}
function pullView(row, selected) {
  reviewFields(row, ['number', 'version', 'state', 'data', 'opened_by', 'last_metadata_actor', 'merge_only', 'merge']);
  if (row.number !== selected.number || !['open', 'closed', 'merged'].includes(row.state) ||
      typeof row.merge_only !== 'boolean' || row.merge_only !== (row.data === null)) failReview('invalid_review_pull');
  reviewU64(row.version, 1n);
  for (const key of ['opened_by', 'last_metadata_actor']) if (row[key] !== null) reviewPrincipal(row[key]);
  const format = selected.scope.object_format;
  if (row.data !== null) metadata(row.data, format);
  if (row.state !== 'merged') {
    if (row.data === null || row.merge !== null) failReview('invalid_review_pull');
  } else {
    const m = reviewFields(row.merge, ['object_format', ...REFS, 'source_tip', 'target_tip_before', 'base_tip', 'merge_commit']);
    if (m.object_format !== format) failReview('review_format_changed');
    refs(m); for (const key of ['source_tip', 'target_tip_before', 'base_tip', 'merge_commit']) reviewOid(m[key], format);
    if (row.data !== null && (REFS.some(key => m[key] !== row.data[key]) || m.source_tip !== row.data.source_tip ||
        m.target_tip_before !== row.data.target_tip)) failReview('review_merge_metadata_conflict');
  }
}
function pullReply(value, selected, status) {
  reviewFields(value, [...HEADER, 'number', 'found', 'pull_request']);
  header(value, selected, selected.expected_head);
  if (value.type !== 'pull_request' || value.number !== selected.number || typeof value.found !== 'boolean' ||
      status !== (value.found ? 200 : 404)) failReview('invalid_review_pull_reply');
  if (value.found) pullView(value.pull_request, selected);
  else if (value.pull_request !== null) failReview('invalid_review_absence');
}
function subject(value, selected) {
  reviewFields(value, ['number', 'pull_request_version', 'policy_epoch', ...REFS, 'source_tip', 'target_tip']);
  if (value.number !== selected.number) failReview('review_subject_changed');
  reviewU64(value.pull_request_version, 1n); reviewU64(value.policy_epoch, 1n); refs(value);
  reviewOid(value.source_tip, selected.scope.object_format); reviewOid(value.target_tip, selected.scope.object_format);
}
function vote(row, selected, pull, epoch) {
  reviewFields(row, ['reviewer', 'version', 'subject', 'candidate', 'decision', 'reason', 'freshness', 'reviewer_is_opener']);
  reviewPrincipal(row.reviewer); reviewU64(row.version, 1n); subject(row.subject, selected); reviewText(row.reason, 4096);
  if (!['approve', 'request-changes', 'withdraw'].includes(row.decision) || !FRESHNESS.includes(row.freshness) ||
      ![true, false, null].includes(row.reviewer_is_opener)) failReview('invalid_review_vote');
  if (row.candidate !== null) {
    reviewFields(row.candidate, ['merge_base', 'candidate_commit']);
    for (const key of ['merge_base', 'candidate_commit']) reviewOid(row.candidate[key], selected.scope.object_format);
  }
  // Check only observable consistency, never reimplement eligibility or infer
  // that a candidate/approval is valid, independent, or authorized to merge.
  if (row.reviewer_is_opener !== (pull.opened_by === null ? null : row.reviewer === pull.opened_by)) failReview('review_opener_conflict');
  if (row.freshness === 'current' && (row.decision === 'withdraw' || pull.state !== 'open' || pull.data === null ||
      row.subject.pull_request_version !== pull.version || row.subject.policy_epoch !== epoch ||
      [...REFS, 'source_tip', 'target_tip'].some(key => row.subject[key] !== pull.data[key]))) failReview('review_current_subject_conflict');
}
function reviewPage(value, selected, pull, after, limit, epoch) {
  reviewFields(value, [...HEADER, 'number', 'found', 'pull_request_version', 'policy_epoch', 'after', 'limit',
    'next_after', 'merge_authorized', 'reviews']);
  header(value, selected, pull.snapshot_token, pull.source_head);
  if (value.type !== 'review_page' || value.found !== true || value.number !== selected.number ||
      value.pull_request_version !== pull.pull_request.version || value.after !== after || value.limit !== limit ||
      value.merge_authorized !== false || !Array.isArray(value.reviews) || value.reviews.length > limit) failReview('invalid_review_page');
  reviewU64(value.policy_epoch, 1n);
  if (epoch !== null && value.policy_epoch !== epoch) failReview('review_policy_changed');
  let previous = after;
  for (const row of value.reviews) {
    vote(row, selected, pull.pull_request, value.policy_epoch);
    if (previous !== null && row.reviewer <= previous) failReview('review_cursor_order');
    previous = row.reviewer;
  }
  if (value.next_after !== null && (value.reviews.length !== limit || value.next_after !== previous || value.next_after === after)) failReview('invalid_review_continuation');
}
export const reviewCanonical = value => `${JSON.stringify(value, null, 2).replace(
  /[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu,
  c => `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`)}\n`;
export const reviewHash = bytes => createHash('sha256').update(bytes).digest('hex');
export function parseReviewJson(bytes, { wire = false, maximum = REVIEW_LIMITS.capture } = {}) {
  if (!Buffer.isBuffer(bytes) || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > REVIEW_LIMITS.capture ||
      bytes.length > maximum || typeof wire !== 'boolean') failReview('review_json_limit');
  try {
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), stack = [];
    let nodes = 0;
    for (let i = 0; i < source.length; i++) {
      if (source[i] === '{' || source[i] === '[') {
        if (++nodes > 50000 || stack.length >= 16) failReview('review_json_structure_limit');
        stack.push({ kind: source[i], keys: new Set() });
      } else if (source[i] === '}' || source[i] === ']') {
        if (stack.pop()?.kind !== (source[i] === '}' ? '{' : '[')) failReview('invalid_review_json');
      } else if (source[i] === '"') {
        const start = i++;
        for (; i < source.length && source[i] !== '"'; i++) if (source[i] === '\\') i++;
        if (i >= source.length || ++nodes > 50000) failReview('review_json_structure_limit');
        let next = i + 1; while (next < source.length && /[\x20\t\r\n]/.test(source[next])) next++;
        if (source[next] === ':') {
          const frame = stack.at(-1), key = JSON.parse(source.slice(start, i + 1));
          if (frame?.kind !== '{' || frame.keys.has(key)) failReview('duplicate_review_json_key');
          frame.keys.add(key);
        }
      }
    }
    if (stack.length) failReview('invalid_review_json');
    return JSON.parse(source, (key, value, context) => {
      if (typeof value !== 'number') return value;
      if (!/^(0|[1-9][0-9]*)$/.test(context?.source ?? '')) failReview('invalid_review_json_number');
      if (wire && COUNTERS.has(key)) return reviewU64(context.source);
      if (!Number.isSafeInteger(value)) failReview('unsafe_review_json_number');
      return value;
    });
  } catch (error) { if (error instanceof ReviewSnapshotError) throw error; failReview('invalid_review_json'); }
}
function integer(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) failReview('review_resource_limit');
  return value;
}
export function validateReviewCapture(value) {
  reviewFields(value, ['schema', 'selection', 'page_limit', 'pull', 'review_pages', 'complete', 'merge_authorized']);
  if (value.schema !== 'frankengit-pull-review-capture-v1' || value.complete !== true || value.merge_authorized !== false ||
      !Array.isArray(value.review_pages)) failReview('invalid_review_capture');
  const selected = reviewSelection(value.selection), limit = integer(value.page_limit, 1, 100);
  pullReply(value.pull, selected, value.pull.found ? 200 : 404);
  if (value.review_pages.length > REVIEW_LIMITS.pages || value.pull.found !== (value.review_pages.length > 0)) failReview('incomplete_review_capture');
  let after = null, epoch = null, count = 0;
  for (let i = 0; i < value.review_pages.length; i++) {
    const page = value.review_pages[i]; reviewPage(page, selected, value.pull, after, limit, epoch);
    epoch = page.policy_epoch; count += page.reviews.length;
    if (count > REVIEW_LIMITS.reviewers || (page.next_after === null) !== (i === value.review_pages.length - 1)) failReview('incomplete_review_capture');
    after = page.next_after;
  }
  if (Buffer.byteLength(reviewCanonical(value)) > REVIEW_LIMITS.capture) failReview('review_capture_limit');
  return structuredClone(value);
}
// Exactly two GET route shapes. The caller cannot provide headers, arbitrary
// paths, bodies, redirects, idempotency keys, TLS overrides or a mutation method.
function get(address, token, number, page, config) {
  const query = new URLSearchParams();
  if (page.head !== null) query.set('expected_head', page.head);
  if (page.reviews) { query.set('limit', String(config.pageLimit)); if (page.after !== null) query.set('after', page.after); }
  const url = new URL(`${address}/api/v1/pulls/${number}${page.reviews ? '/reviews' : ''}${query.size ? `?${query}` : ''}`);
  return new Promise((resolve, reject) => {
    let request, response, value, failure, timer, done = false, closed = false, delivered = false;
    const signal = config.signal;
    const deliver = () => { if (delivered) return; delivered = true; failure ? reject(failure) : resolve(value); };
    const finish = (error, result) => {
      if (done) return; done = true; failure = error; value = result;
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      response?.destroy(); request?.destroy(); if (!request || closed) deliver();
    };
    const abort = () => finish(new ReviewSnapshotError('review_cancelled'));
    if (signal?.aborted) { abort(); return; }
    try {
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
        method: 'GET', agent: false, maxHeaderSize: 16384, rejectUnauthorized: true, ...(config.ca ? { ca: config.ca } : {}),
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Accept-Encoding': 'identity',
          Connection: 'close', 'Cache-Control': 'no-store' },
      });
      request.once('close', () => { closed = true; if (!done) finish(new ReviewSnapshotError('review_response_incomplete')); else deliver(); });
      request.on('error', () => finish(new ReviewSnapshotError('review_transport_unavailable')));
      request.once('response', incoming => {
        response = incoming;
        if (![200, 404].includes(incoming.statusCode)) { finish(new ReviewSnapshotError('review_http_refused', incoming.statusCode)); return; }
        const names = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(s => s.toLowerCase())
          .filter(s => ['content-type', 'content-length', 'content-encoding'].includes(s));
        if (new Set(names).size !== names.length || !/^application\/json(?:\s*;|$)/i.test(incoming.headers['content-type'] ?? '') ||
            (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') { finish(new ReviewSnapshotError('review_response_encoding')); return; }
        const length = incoming.headers['content-length'];
        if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(config.maximum))) {
          finish(new ReviewSnapshotError('review_response_limit')); return;
        }
        let size = 0; const chunks = [];
        incoming.on('error', () => finish(new ReviewSnapshotError('review_response_incomplete')));
        incoming.on('data', chunk => {
          if (done) return; size += chunk.length;
          if (size > config.maximum || chunks.length >= 16384) finish(new ReviewSnapshotError('review_response_limit'));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (done) return;
          if (!incoming.complete || (length !== undefined && BigInt(length) !== BigInt(size))) { finish(new ReviewSnapshotError('review_response_incomplete')); return; }
          try { finish(null, { value: parseReviewJson(Buffer.concat(chunks, size), { wire: true, maximum: config.maximum }), bytes: size, status: incoming.statusCode }); }
          catch (error) { finish(error); }
        });
      });
      signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(new ReviewSnapshotError('review_timeout')), config.timeoutMs);
      if (signal?.aborted) abort(); else request.end();
    } catch { finish(new ReviewSnapshotError('review_transport_unavailable')); }
  });
}
export async function capturePullReviews(input, token, options = {}) {
  const selected = reviewSelection(input);
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) failReview('invalid_review_credential');
  reviewFields(options, ['timeoutMs', 'signal', 'ca', 'pageLimit', 'maxPages', 'maxReviewers', 'maxWireBytes'], []);
  const timeoutMs = integer(options.timeoutMs ?? 30000, 1, 300000), signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) failReview('invalid_review_signal');
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 131072
    ? Buffer.from(options.ca) : failReview('invalid_review_ca');
  const pageLimit = integer(options.pageLimit ?? 50, 1, 100), maxPages = integer(options.maxPages ?? 32, 1, REVIEW_LIMITS.pages);
  const maxReviewers = integer(options.maxReviewers ?? 1024, 1, REVIEW_LIMITS.reviewers);
  const maxWire = integer(options.maxWireBytes ?? REVIEW_LIMITS.wire, 1, REVIEW_LIMITS.wire);
  const deadline = performance.now() + timeoutMs; let wire = 0, count = 0;
  const request = async page => {
    if (signal?.aborted) failReview('review_cancelled');
    const remaining = Math.ceil(deadline - performance.now()); if (remaining <= 0) failReview('review_timeout');
    if (wire >= maxWire) failReview('review_wire_limit');
    const result = await get(selected.endpoint, token, selected.number, page,
      { timeoutMs: remaining, signal, ca, pageLimit, maximum: Math.min(REVIEW_LIMITS.reply, maxWire - wire) });
    wire += result.bytes; return result;
  };
  const first = await request({ reviews: false, head: selected.expected_head, after: null });
  pullReply(first.value, selected, first.status);
  const capture = { schema: 'frankengit-pull-review-capture-v1', selection: selected, page_limit: pageLimit,
    pull: first.value, review_pages: [], complete: true, merge_authorized: false };
  if (first.value.found) {
    let after = null, epoch = null;
    do {
      if (capture.review_pages.length >= maxPages) failReview('review_page_limit');
      const result = await request({ reviews: true, head: first.value.snapshot_token, after });
      if (result.status !== 200) failReview('review_snapshot_unavailable');
      reviewPage(result.value, selected, first.value, after, pageLimit, epoch);
      count += result.value.reviews.length; if (count > maxReviewers) failReview('review_reviewer_limit');
      epoch = result.value.policy_epoch; after = result.value.next_after;
      capture.review_pages.push(result.value);
      if (Buffer.byteLength(reviewCanonical(capture)) > REVIEW_LIMITS.capture) failReview('review_capture_limit');
    } while (after !== null);
  }
  if (signal?.aborted) failReview('review_cancelled');
  if (performance.now() > deadline) failReview('review_timeout');
  const validated = validateReviewCapture(capture);
  if (performance.now() > deadline) failReview('review_timeout');
  return validated;
}
