// Read-only repository investigation. No arbitrary route, write key, mutation,
// credential persistence, automatic retry, or client-side authorization oracle.
import { fail, keys, integer, format, oid, utf8, copy, form, readBytes, json } from './pulls-core.mjs';
import { HISTORY_LIMITS, fullRef, bytePath, logPage, blamePage, historicalPage, comparisonQuery, comparisonPage, COMPARISON_LIMITS } from './history-data.mjs';
const ENDPOINTS = new Set(['log', 'blame', 'historical-tree', 'historical-blob', 'diff']);
function rootFor(href) {
  const page = new URL(href), suffix = '/ui/history/';
  if (!['http:', 'https:'].includes(page.protocol) || page.username || page.password || page.search || page.hash ||
      !page.pathname.endsWith(suffix)) fail('Open the exact repository /ui/history/ endpoint.');
  if (page.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(page.hostname)) fail('Use HTTPS outside trusted loopback.');
  const route = page.pathname.slice(0, -suffix.length);
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(route) || route.split('/').some(part => ['.', '..'].includes(part))) fail('Invalid repository route.');
  return Object.freeze({ origin: page.origin, api: `${page.origin}${route}/api/v1/source/` });
}
function logOptions(options = {}) {
  keys(options, ['after', 'limit', 'path_hex']);
  return { after: integer(options.after ?? 0, 'history cursor', 0, HISTORY_LIMITS.commits),
    limit: integer(options.limit ?? 20, 'history page limit', 1, 100), path_hex: bytePath(options.path_hex ?? null, true) };
}
function httpError(status) {
  const error = new Error(({ 401: 'Credential rejected or revoked.', 403: 'Source read permission is missing or disabled.',
    404: 'Ref, path, or selected ancestry is unavailable.', 409: 'Snapshot, source, or line-blame profile conflict. Reopen explicitly.',
    413: 'Native history exceeded its resource limit; no complete result is available.', 429: 'Read quota exceeded.' })[status] ?? `History read failed (HTTP ${status}).`);
  error.status = status; return error;
}
export class HistoryClient {
  #root; #fetch; #crypto; #timeout; #token = ''; #generation = 0; #active = null; #selection = null; #scope = null; #blame = null; #comparison = null; #beforePin = null;
  // WebIDL fetch refuses any receiver but the global (Chrome: "Illegal invocation"),
  // so the stored fetch is always invoked as a plain call, never as a method of this client.
  constructor({ href, fetchImpl = globalThis.fetch, cryptoImpl = globalThis.crypto, timeoutMs = 30000 }) {
    this.#root = rootFor(href); this.#fetch = (...request) => fetchImpl(...request); this.#crypto = cryptoImpl;
    this.#timeout = integer(timeoutMs, 'read timeout', 1, 300000);
  }
  get connected() { return Boolean(this.#token); }
  get selection() { return this.#selection ? copy(this.#selection) : null; }
  connect(token) {
    this.disconnect();
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) fail('A 64-character lowercase hexadecimal token is required.');
    this.#token = token;
  }
  cancel() { this.#generation++; this.#active?.abort(); this.#active = null; this.#blame = null; }
  disconnect() { this.cancel(); this.#token = ''; this.#selection = null; this.#scope = null; this.#comparison = null; this.#beforePin = null; }
  async #run(work) {
    if (!this.connected) fail('Connect a source-read credential first.');
    this.cancel(); const generation = this.#generation, controller = new AbortController(); this.#active = controller;
    const timer = setTimeout(() => controller.abort(), this.#timeout);
    const check = () => {
      controller.signal.throwIfAborted();
      if (generation !== this.#generation || !this.connected) fail('History read superseded.');
    };
    try { const value = await work(controller.signal, check); check(); return copy(value); }
    catch (error) { if (generation === this.#generation && error.status === 401) this.disconnect(); throw error; }
    finally { clearTimeout(timer); if (this.#active === controller) this.#active = null; }
  }
  async #request(endpoint, fields, signal) {
    if (!ENDPOINTS.has(endpoint)) fail('Unsupported read-only history endpoint.');
    const url = new URL(endpoint, this.#root.api), response = await this.#fetch(url, {
      method: 'POST', body: form(fields), signal, redirect: 'error', credentials: 'omit', mode: 'same-origin', cache: 'no-store',
      referrerPolicy: 'no-referrer', headers: { Authorization: `Bearer ${this.#token}`, Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    try {
      signal.throwIfAborted();
      if (response.redirected || (response.url && response.url !== url.href)) fail('History redirect refused.');
      if (response.status !== 200) throw httpError(response.status);
      if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) fail('History requires a JSON response.');
      return json(await readBytes(response, signal, HISTORY_LIMITS.reply));
    // Stream cleanup can return a non-settling promise. It must not hide a
    // refusal or keep a cancelled read alive beyond the owned deadline.
    } finally { if (response.body && !response.body.locked) void response.body.cancel().catch(() => {}); }
  }
  #base() {
    if (!this.#selection) fail('Open a reference before investigating its history.');
    return copy(this.#selection);
  }
  #fields(selection) {
    return { ref: selection.ref, object_format: selection.object_format, expected_head: selection.head, expected_commit: selection.tip };
  }
  async open(ref, algorithm) {
    this.#selection = null; this.#comparison = null; this.#beforePin = null;
    return this.#run(async (signal, check) => {
      const request = { ref: fullRef(ref), object_format: format(algorithm) }, options = logOptions();
      const raw = await this.#request('log', { ...request, after: 0, limit: options.limit }, signal); check();
      const page = await logPage(raw, request, null, options, this.#crypto, check); check();
      if (this.#scope && Object.keys(page.selection.scope).some(key => page.selection.scope[key] !== this.#scope[key])) fail('Repository incarnation changed. Reconnect explicitly.');
      this.#scope = page.selection.scope; this.#selection = page.selection; return page;
    });
  }
  async log(options = {}) {
    const selection = this.#base(), query = logOptions(options);
    return this.#run(async (signal, check) => {
      const fields = { ...this.#fields(selection), after: query.after, limit: query.limit };
      if (query.path_hex !== null) fields.path_hex = query.path_hex;
      const raw = await this.#request('log', fields, signal); check();
      return logPage(raw, selection, selection, query, this.#crypto, check);
    });
  }
  // The first read selects the before tip at the already-pinned authority head.
  // Later modes/filters keep that tip. Only an explicit reopen clears this pin.
  async compare(beforeRef, options = {}) {
    const selection = this.#base(), query = comparisonQuery(beforeRef, options);
    const retained = this.#beforePin?.ref === query.before_ref ? this.#beforePin.tip : null;
    if (query.expected_before !== null) query.expected_before = oid(query.expected_before, selection.object_format);
    if (retained !== null && query.expected_before !== null && retained !== query.expected_before) fail('Before-tip pin changed. Reopen explicitly.');
    query.expected_before ??= retained;
    this.#comparison = null;
    return this.#run(async (signal, check) => {
      const fields = { before_ref: query.before_ref, after_ref: selection.ref, object_format: selection.object_format,
        expected_head: selection.head, expected_after: selection.tip, mode: query.mode, context_lines: 3,
        path_prefix_hex: query.path_prefixes_hex, ...COMPARISON_LIMITS };
      if (query.expected_before !== null) fields.expected_before = query.expected_before;
      const raw = await this.#request('diff', fields, signal); check();
      const result = comparisonPage(raw, selection, query, check); check();
      this.#beforePin = { ref: query.before_ref, tip: result.before };
      this.#comparison = copy(result); return result;
    });
  }
  // File reads use that side's authorized ref, not an arbitrary OID lookup.
  // Merge-base mode reads the base commit while retaining the original ref tip.
  async comparisonFile(side, path, options = {}) {
    const compared = this.#comparison;
    if (!compared || !['before', 'after'].includes(side)) fail('Select a complete reference comparison first.');
    keys(options, ['offset', 'limit']); bytePath(path);
    const entry = compared.entries.find(value => value.path_hex === path), identity = entry?.[side];
    const kinds = { '100644': 'file', '100755': 'executable', '120000': 'symlink' };
    if (!identity || !Object.hasOwn(kinds, identity.mode)) fail('This comparison side has no readable file; directories and gitlinks are not followed.');
    const selection = { ...compared.selection, ref: side === 'before' ? compared.query.before_ref : compared.selection.ref,
      tip: side === 'before' ? compared.before : compared.after };
    const query = { kind: 'blob', commit: side === 'before' ? compared.base : compared.after, path_hex: path,
      offset: integer(options.offset ?? 0, 'comparison byte offset', 0, 16 * 1024 * 1024),
      limit: integer(options.limit ?? 65536, 'comparison file range', 1, HISTORY_LIMITS.blob) };
    return this.#run(async (signal, check) => {
      const result = await this.#historical(selection, query, signal, check); check();
      if (oid(result.source.object_id, selection.object_format) !== identity.object_id || result.source.kind !== kinds[identity.mode] ||
          oid(result.source.root_tree, selection.object_format) !== (side === 'before' ? compared.beforeTree : compared.afterTree)) fail('Historical file differs from its compared entry.');
      return { ...result, comparisonSide: side, comparisonEntry: copy(entry),
        fullBlobVerified: query.offset === 0 && result.source.returned_bytes === result.source.total_bytes };
    });
  }
  async blame(path, options = {}) {
    const selection = this.#base(); keys(options, ['first', 'end']);
    const query = { path_hex: bytePath(path), first: integer(options.first ?? 0, 'first line', 0, HISTORY_LIMITS.lines), end: options.end ?? null };
    if (query.end !== null) integer(query.end, 'end line', query.first, HISTORY_LIMITS.lines);
    return this.#run(async (signal, check) => {
      const fields = { ...this.#fields(selection), path_hex: query.path_hex, line_start: query.first };
      if (query.end !== null) fields.line_end = query.end;
      const raw = await this.#request('blame', fields, signal); check();
      const result = await blamePage(raw, selection, query, this.#crypto, check); check();
      this.#blame = copy(result); return result;
    });
  }
  async historical(kind, commit, path = null, options = {}) {
    const selection = this.#base();
    if (!['tree', 'blob'].includes(kind)) fail('Choose historical tree or blob.');
    keys(options, kind === 'tree' ? ['after', 'limit'] : ['offset', 'limit']);
    const query = { kind, commit: oid(commit, selection.object_format), path_hex: bytePath(path, kind === 'tree'),
      limit: integer(options.limit ?? (kind === 'tree' ? 100 : 65536), 'source page limit', 1, kind === 'tree' ? 1000 : HISTORY_LIMITS.blob) };
    if (kind === 'tree') {
      query.after = bytePath(options.after ?? null, true);
      if (query.after !== null && query.after.match(/../g).includes('2f')) fail('Directory cursor must name one child.');
    } else query.offset = integer(options.offset ?? 0, 'source byte offset', 0, 16 * 1024 * 1024);
    return this.#run((signal, check) => this.#historical(selection, query, signal, check));
  }
  async #historical(selection, query, signal, check) {
    const fields = { ref: selection.ref, object_format: selection.object_format, expected_head: selection.head,
      expected_ref_tip: selection.tip, at_commit: query.commit, limit: query.limit };
    if (query.path_hex !== null) fields.path_hex = query.path_hex;
    if (query.kind === 'tree' && query.after !== null) fields.after_hex = query.after;
    if (query.kind === 'blob') fields.offset = query.offset;
    const raw = await this.#request(`historical-${query.kind}`, fields, signal); check();
    return historicalPage(raw, selection, query, this.#crypto, check);
  }
  async origin(index) {
    const blame = this.#blame;
    if (!blame) fail('Select a verified blame range first.');
    integer(index, 'attribution row', 0, blame.lines.length - 1);
    const line = blame.lines[index], query = { kind: 'blob', commit: line.origin_commit, path_hex: blame.query.path_hex,
      offset: line.origin_byte_start, limit: line.origin_byte_end - line.origin_byte_start };
    return this.#run(async (signal, check) => {
      const result = await this.#historical(blame.selection, query, signal, check);
      if (!['file', 'executable'].includes(result.source.kind) ||
          oid(result.source.object_id, blame.selection.object_format) !== line.origin_blob || result.source.content_hex !== line.content_hex) fail('Historical origin does not reproduce the attributed bytes.');
      return { ...result, attribution: copy(line), originBytesVerified: true };
    });
  }
}
