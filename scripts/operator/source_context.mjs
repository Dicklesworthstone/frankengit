// Remote context acquisition over the native joined retrieval/hydration API.
// This is a read client, not an index, Git engine, authority or Agent ContextPacket.
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

export const LIMITS = Object.freeze({ response: 8 * 1024 * 1024, request: 256 * 1024,
  files: 32, anchors: 4096, windows: 128, source: 64 * 1024 * 1024, file: 8 * 1024 * 1024,
  excerpts: 1024 * 1024, results: 100, work: 16 * 1024 * 1024, payload: 32 * 1024 * 1024 });
const U64 = 18446744073709551615n;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export class ContextError extends Error {
  constructor(code, status = null) { super(code); this.name = 'ContextError'; this.code = code; this.status = status; }
}
export const fail = code => { throw new ContextError(code); };
function record(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_context_record');
  return value;
}
function keys(value, allowed, required = allowed) {
  record(value);
  if (Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail('unsupported_context_fields');
}
function count(value, maximum, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail('invalid_context_counter');
  return value;
}
function exact(value) {
  if (typeof value === 'number') { count(value, Number.MAX_SAFE_INTEGER, 1); value = String(value); }
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > U64) fail('invalid_exact_context_counter');
  return value;
}
function identifier(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('invalid_context_identity');
  return value;
}
function opaque(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 || /[\s\x00-\x1f\x7f]/u.test(value)) fail('invalid_context_source_record');
  return value;
}
function token(value) {
  if (typeof value !== 'string' || !/^alg:[1-9][0-9]{0,4}:[0-9a-f]{64}$/.test(value) ||
      Number(value.split(':')[1]) > 65535 || /^0+$/.test(value.split(':')[2])) fail('invalid_context_snapshot');
  return value;
}
function oid(value, format) {
  const raw = typeof value === 'string' && value.startsWith(`${format}:`) ? value.slice(format.length + 1) : value;
  if (typeof raw !== 'string' || !new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) fail('invalid_context_object');
  return raw;
}
function unhex(value, maximum, empty = false) {
  if (typeof value !== 'string' || value.length > maximum * 2 || !/^(?:[0-9a-f]{2})*$/.test(value) || (!empty && !value.length)) fail('invalid_context_bytes');
  return Buffer.from(value, 'hex');
}
function path(value) {
  const bytes = unhex(value, 4096);
  const parts = bytes.toString('latin1').split('/');
  if (bytes.includes(0) || parts.length > 64 || parts.some(p => !p || ['.', '..', '.git'].includes(p.toLowerCase()))) fail('invalid_context_path');
  return value;
}
function reference(value) {
  if (typeof value !== 'string' || !value.startsWith('refs/') || Buffer.byteLength(value) > 1024 ||
      /[\x00-\x20\x7f~^:?*\[\\\uD800-\uDFFF]/u.test(value) || value.includes('..') || value.includes('@{') ||
      value.endsWith('.') || value.split('/').some(p => !p || p.startsWith('.') || p.endsWith('.lock'))) fail('invalid_context_reference');
  return value;
}
export function endpoint(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\]/u.test(value)) fail('invalid_context_endpoint');
  let url; try { url = new URL(value); } catch { fail('invalid_context_endpoint'); }
  if (url.href !== value || url.username || url.password || url.search || url.hash ||
      !['http:', 'https:'].includes(url.protocol) || (url.protocol === 'http:' && !['127.0.0.1', '[::1]'].includes(url.hostname)) ||
      !/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(url.pathname) ||
      url.pathname.split('/').some(p => p === '.' || p === '..')) fail('https_or_numeric_loopback_context_endpoint_required');
  return value;
}
function activation(value) {
  keys(value, ['token', 'number']); return { token: token(value.token), number: exact(value.number) };
}
function atLeast(observed, floor) {
  if (floor && (BigInt(observed.number) < BigInt(floor.number) ||
      (observed.number === floor.number && observed.token !== floor.token))) fail('context_index_checkpoint_regressed');
}
export function query(input) {
  keys(input, ['schema', 'scope', 'reference', 'terms', 'prefixes_hex', 'expected_head', 'expected_commit', 'minimum_lexical', 'limits'],
    ['schema', 'scope', 'reference', 'terms']);
  if (input.schema !== 'frankengit-source-context-query-v1') fail('unsupported_context_query');
  keys(input.scope, ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format']);
  const scope = { ...input.scope };
  for (const key of ['tenant_id', 'repository_id', 'repository_incarnation']) identifier(scope[key]);
  if (!['sha1', 'sha256'].includes(scope.object_format)) fail('unsupported_context_object_format');
  if (!Array.isArray(input.terms) || !input.terms.length || input.terms.length > 32 ||
      input.terms.some(t => typeof t !== 'string' || !/^[A-Za-z0-9_]{1,128}$/.test(t))) fail('context_requires_whole_ascii_words');
  const prefixes = input.prefixes_hex ?? [];
  if (!Array.isArray(prefixes) || prefixes.length > 128) fail('context_path_scope_limit');
  let prefixBytes = 0;
  for (const prefix of prefixes) { path(prefix); prefixBytes += prefix.length / 2; }
  if (prefixBytes > 32 * 1024) fail('context_path_scope_limit');
  const defaults = { max_results_per_channel: 100, max_work: LIMITS.work, max_payload_bytes: LIMITS.payload,
    max_result_bytes: 2 * 1024 * 1024, context_max_files: 8, context_radius_bytes: 128,
    context_max_source_bytes: LIMITS.source, context_max_excerpt_bytes: 256 * 1024 };
  const limits = input.limits ?? {}; keys(limits, Object.keys(defaults), []);
  const selected = { ...defaults, ...limits };
  for (const [name, maximum, minimum] of [['max_results_per_channel', 100, 1], ['max_work', LIMITS.work, 2],
    ['max_payload_bytes', LIMITS.payload, 2], ['max_result_bytes', 2 * 1024 * 1024, 1], ['context_max_files', 32, 1],
    ['context_radius_bytes', 4096, 0], ['context_max_source_bytes', LIMITS.source, 1], ['context_max_excerpt_bytes', LIMITS.excerpts, 1]]) count(selected[name], maximum, minimum);
  return { schema: input.schema, scope, reference: reference(input.reference),
    terms: [...new Set(input.terms.map(t => t.toLowerCase()))].sort(), prefixes_hex: [...new Set(prefixes)].sort(),
    expected_head: input.expected_head == null ? null : token(input.expected_head),
    expected_commit: input.expected_commit == null ? null : oid(input.expected_commit, scope.object_format),
    minimum_lexical: input.minimum_lexical == null ? null : activation(input.minimum_lexical), limits: selected };
}
export function command(input) {
  const q = query(input), values = { object_format: q.scope.object_format, ref: q.reference, ...q.limits };
  if (q.expected_head !== null) values.expected_head = q.expected_head;
  if (q.expected_commit !== null) values.expected_commit = q.expected_commit;
  if (q.minimum_lexical) Object.assign(values, { minimum_lexical_token: q.minimum_lexical.token, minimum_lexical_number: q.minimum_lexical.number });
  const body = new URLSearchParams(values);
  for (const t of q.terms) body.append('term_hex', Buffer.from(t).toString('hex'));
  for (const p of q.prefixes_hex) body.append('path_prefix_hex', p);
  if (Buffer.byteLength(body.toString()) > LIMITS.request) fail('context_request_limit');
  return { query: q, body: body.toString() };
}
// Native u64 IDs/generations are retained exactly, not rounded by JSON.parse.
export function parse(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > LIMITS.response) fail('context_response_limit');
  try {
    return JSON.parse(decoder.decode(bytes), (key, value, context) => {
      if (['index_number', 'selected_index_number', 'document_id', 'next_after'].includes(key) && typeof value === 'number') return exact(context.source);
      if (typeof value === 'number' && !Number.isSafeInteger(value)) fail('unsafe_context_json_number');
      return value;
    });
  } catch (error) { if (error instanceof ContextError) throw error; fail('invalid_context_json'); }
}
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function source(value, q, prior = null) {
  record(value);
  if (Object.keys(q.scope).some(k => value[k] !== q.scope[k]) || value.ref_hex !== Buffer.from(q.reference).toString('hex') ||
      value.ref !== q.reference || value.read_only !== true || value.transaction_created !== false) fail('context_source_scope_changed');
  const selected = { ...q.scope, reference: q.reference, snapshot_token: token(value.snapshot_token),
    source_rcr: opaque(value.source_rcr), source_commit: oid(value.source_commit, q.scope.object_format), root_tree: oid(value.root_tree, q.scope.object_format) };
  if ((q.expected_head !== null && q.expected_head !== selected.snapshot_token) ||
      (q.expected_commit !== null && q.expected_commit !== selected.source_commit) || (prior && !same(selected, prior))) fail('context_source_snapshot_changed');
  return selected;
}
const word = b => b >= 48 && b <= 57 || b >= 65 && b <= 90 || b >= 97 && b <= 122 || b === 95;
function matchWord(bytes, offset, expected) {
  const actual = bytes.subarray(offset, offset + expected.length);
  return actual.length === expected.length && actual.every((b, i) => (b >= 65 && b <= 90 ? b + 32 : b) === expected[i]);
}
function verifyPathWord(bytes, span, expected) {
  if (!matchWord(bytes, span.byte_offset, expected) || (span.byte_offset && word(bytes[span.byte_offset - 1])) ||
      (span.byte_offset + span.byte_length < bytes.length && word(bytes[span.byte_offset + span.byte_length]))) fail('context_path_anchor_mismatch');
}
function lexical(value, name, q, selected, generation, ordinal, check) {
  source(value, q, selected); opaque(value.source_head);
  const limits = q.limits, share = total => Math.floor(total / 2) + Number(ordinal < total % 2);
  if (value.type !== 'source_search_index' || ![1, 2].includes(value.schema_version) || value.profile !== 'ascii-word-postings-v1' ||
      value.published !== false || value.channel !== name || value.after !== null || value.limit !== limits.max_results_per_channel ||
      !same(value.terms_hex, q.terms.map(t => Buffer.from(t).toString('hex'))) || !same(value.path_prefix_hex, q.prefixes_hex) ||
      !Array.isArray(value.hits) || value.hits.length > limits.max_results_per_channel || value.returned_hits !== value.hits.length ||
      typeof value.complete !== 'boolean') fail('invalid_context_retrieval_channel');
  const index = activation({ token: value.index_token, number: value.index_number });
  const current = activation({ token: value.selected_index_token, number: value.selected_index_number });
  if (!same(index, generation)) fail('context_generation_join_changed');
  atLeast(current, index); atLeast(current, q.minimum_lexical);
  count(value.indexed_documents, 20000); count(value.indexed_source_bytes, LIMITS.source);
  count(value.non_regular_entries, 50000); count(value.segments_read, 20000); count(value.generation_bytes_read, Number.MAX_SAFE_INTEGER);
  count(value.payload_bytes_read, share(limits.max_payload_bytes)); count(value.work_units, share(limits.max_work));
  if (value.hits.length > value.indexed_documents || (value.hits.length && (!value.segments_read || !value.payload_bytes_read))) fail('invalid_context_retrieval_accounting');
  let previous = '', lastId = 0n;
  for (const hit of value.hits) {
    check(); record(hit); path(hit.path_hex); const id = BigInt(exact(hit.document_id));
    if (id <= lastId || hit.path_hex <= previous || (q.prefixes_hex.length && !q.prefixes_hex.some(p => hit.path_hex === p || hit.path_hex.startsWith(`${p}2f`)))) fail('context_hit_order_or_scope');
    previous = hit.path_hex; lastId = id; oid(hit.blob, q.scope.object_format);
    count(hit.content_bytes, LIMITS.file);
    if (hit.content_bytes > value.indexed_source_bytes || !Array.isArray(hit.spans) || hit.spans.length !== q.terms.length) fail('invalid_context_hit');
    const extent = name === 'path' ? hit.path_hex.length / 2 : hit.content_bytes;
    for (let i = 0; i < hit.spans.length; i++) {
      const span = record(hit.spans[i]); count(span.byte_offset, extent); count(span.byte_length, 128, 1);
      if (span.query_index !== i || span.byte_length !== q.terms[i].length || span.byte_offset + span.byte_length > extent) fail('invalid_context_anchor');
      if (name === 'path') verifyPathWord(Buffer.from(hit.path_hex, 'hex'), span, Buffer.from(q.terms[i]));
    }
  }
  if (value.complete ? value.next_after !== null : (!value.hits.length || value.hits.length !== limits.max_results_per_channel ||
      exact(value.next_after) !== lastId.toString() || value.hits.length >= value.indexed_documents)) fail('invalid_context_retrieval_completion');
  if (value.schema_version === 1) {
    if (['index_profile', 'coverage_complete', 'omitted_files', 'omissions', 'omitted_source_bytes', 'coverage_scope'].some(k => Object.hasOwn(value, k))) fail('ambiguous_context_coverage');
    return true;
  }
  if (value.index_profile !== 'ascii-word-postings-omissions-v1' || value.coverage_complete !== false ||
      Object.hasOwn(value, 'coverage_scope') || !Array.isArray(value.omissions) || !value.omissions.length ||
      value.omitted_files !== value.omissions.length || value.indexed_documents + value.omissions.length > 20000) fail('invalid_context_omissions');
  let total = 0; previous = ''; const paths = new Set(value.hits.map(h => h.path_hex));
  for (const omission of value.omissions) {
    check(); keys(omission, ['path_hex', 'blob', 'source_bytes', 'reason', 'limit']); path(omission.path_hex); oid(omission.blob, q.scope.object_format);
    count(omission.limit, LIMITS.file, 1); count(omission.source_bytes, LIMITS.source, omission.limit + 1);
    if (omission.reason !== 'file_bytes' || omission.path_hex <= previous || paths.has(omission.path_hex)) fail('invalid_context_omission');
    previous = omission.path_hex; total += omission.source_bytes;
  }
  if (total !== value.omitted_source_bytes || total + value.indexed_source_bytes > LIMITS.source) fail('invalid_context_omission_accounting');
  return false;
}
export function validate(reply, input, check = () => {}) {
  const q = query(input), limits = q.limits; check(); record(reply);
  if (reply.type !== 'source_context_initial' || reply.schema_version !== 1 || reply.profile !== 'source-initial-context-v1' ||
      reply.read_only !== true || reply.transaction_created !== false || reply.source_material_untrusted !== true ||
      reply.selection !== 'raw-path-prefix' || !Array.isArray(reply.files)) fail('unsupported_native_context');
  for (const k of ['context_max_files', 'context_radius_bytes', 'context_max_source_bytes', 'context_max_excerpt_bytes']) if (reply[k] !== limits[k]) fail('context_budget_echo_changed');
  const r = record(reply.retrieval), selected = source(r, q);
  if (r.type !== 'source_search_initial' || r.schema_version !== 1 || r.profile !== 'source-initial-retrieval-v1' || r.phase !== 'Initial' ||
      r.streaming !== false || r.semantic_refinement !== false || r.source_blobs_read !== 0 || r.source_bytes_read !== 0 ||
      !same(r.symbols, { state: 'not_requested' })) fail('unsupported_context_retrieval');
  for (const k of ['max_results_per_channel', 'max_work', 'max_payload_bytes', 'max_result_bytes']) if (r[k] !== limits[k]) fail('context_query_budget_changed');
  keys(r.generation_vector, ['lexical', 'symbols']);
  const vector = r.generation_vector.lexical; keys(vector, ['index_token', 'index_number']);
  const generation = activation({ token: vector.index_token, number: vector.index_number });
  if (r.generation_vector.symbols !== null) fail('unexpected_context_symbol_generation');
  const contentCoverage = lexical(r.content, 'content', q, selected, generation, 0, check);
  const pathCoverage = lexical(r.path, 'path', q, selected, generation, 1, check);
  if (r.content.source_head !== r.path.source_head || r.content.indexed_documents !== r.path.indexed_documents ||
      r.content.indexed_source_bytes !== r.path.indexed_source_bytes || r.content.non_regular_entries !== r.path.non_regular_entries ||
      !same(r.content.omissions ?? [], r.path.omissions ?? [])) fail('context_lexical_corpus_changed');
  const contentHead = activation({ token: r.content.selected_index_token, number: r.content.selected_index_number });
  const pathHead = activation({ token: r.path.selected_index_token, number: r.path.selected_index_number });
  if (contentHead.number === pathHead.number && contentHead.token !== pathHead.token) fail('conflicting_context_index_heads');
  const checkpoint = BigInt(contentHead.number) >= BigInt(pathHead.number) ? contentHead : pathHead;
  const retained = [r.content, r.path].reduce((n, channel) => n + channel.hits.reduce((sum, h) => sum + h.path_hex.length / 2 + h.spans.length * 24 + 64, 0)
    + (channel.omissions ?? []).reduce((sum, omission) => sum + omission.path_hex.length / 2 + 96, 0), 0);
  if (count(r.retained_result_bytes, limits.max_result_bytes) !== retained) fail('context_retained_bytes_changed');
  if (r.completed_work_units !== r.content.work_units + r.path.work_units ||
      r.completed_payload_bytes_read !== r.content.payload_bytes_read + r.path.payload_bytes_read ||
      r.complete !== (contentCoverage && pathCoverage && r.content.complete && r.path.complete)) fail('context_retrieval_accounting_changed');
  const candidates = new Map(), documents = new Map(); let anchorCount = 0;
  for (const channel of ['content', 'path']) for (const hit of r[channel].hits) {
    check(); const blob = oid(hit.blob, q.scope.object_format), prior = candidates.get(hit.path_hex);
    const document = exact(hit.document_id);
    if (documents.has(document) && documents.get(document) !== hit.path_hex) fail('context_document_identity_conflict');
    documents.set(document, hit.path_hex);
    if (prior && (prior.document !== document || prior.blob !== blob || prior.size !== hit.content_bytes)) fail('context_file_identity_conflict');
    const row = prior ?? { blob, document, size: hit.content_bytes, anchors: [], witnesses: [] };
    hit.spans.forEach((s, i) => {
      row.anchors.push({ channel, byte_offset: s.byte_offset, byte_length: s.byte_length });
      row.witnesses.push({ channel, offset: s.byte_offset, word: Buffer.from(q.terms[i]) });
    }); candidates.set(hit.path_hex, row);
  }
  const paths = [...candidates.keys()].sort().slice(0, limits.context_max_files), fileLimit = Math.min(LIMITS.file, Math.floor(limits.context_max_source_bytes / Math.max(1, paths.length)));
  if (!fileLimit || reply.source_file_limit !== fileLimit || reply.candidate_files !== candidates.size || reply.returned_files !== paths.length ||
      reply.files.length !== paths.length || reply.omitted_files !== candidates.size - paths.length || reply.source_blobs_read !== paths.length ||
      reply.complete !== (r.complete && paths.length === candidates.size)) fail('context_selection_or_completeness_changed');
  let sourceBytes = 0, excerptBytes = 0, windows = 0; const fullBlobs = [];
  for (let i = 0; i < paths.length; i++) {
    check(); const file = record(reply.files[i]), expected = candidates.get(paths[i]);
    if ((anchorCount += expected.anchors.length) > LIMITS.anchors) fail('context_anchor_limit');
    const anchors = [...new Map(expected.anchors.map(a => [JSON.stringify(a), a])).values()].sort((a, b) =>
      (a.channel === b.channel ? a.byte_offset - b.byte_offset || a.byte_length - b.byte_length : a.channel === 'content' ? -1 : 1));
    if (file.path_hex !== paths[i] || oid(file.blob, q.scope.object_format) !== expected.blob || file.source_bytes !== expected.size ||
        file.source_bytes > fileLimit || !same(file.anchors, anchors) || !Array.isArray(file.excerpts)) fail('context_file_or_anchors_changed');
    let ranges = anchors.filter(a => a.channel !== 'path').map(a => [Math.max(0, a.byte_offset - limits.context_radius_bytes),
      Math.min(file.source_bytes, a.byte_offset + a.byte_length + limits.context_radius_bytes)]);
    if (!ranges.length) ranges = [[0, Math.min(file.source_bytes, Math.max(1, limits.context_radius_bytes) * 2)]];
    ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]); const merged = [];
    for (const range of ranges) { const last = merged.at(-1); if (last && range[0] <= last[1]) last[1] = Math.max(last[1], range[1]); else merged.push([...range]); }
    if (file.excerpts.length !== merged.length || (windows += merged.length) > LIMITS.windows) fail('context_excerpt_windows_changed');
    const bytes = file.excerpts.map((excerpt, j) => {
      check(); keys(excerpt, ['byte_offset', 'untrusted_bytes_hex']);
      const value = unhex(excerpt.untrusted_bytes_hex, limits.context_max_excerpt_bytes, true), range = merged[j];
      if (excerpt.byte_offset !== range[0] || value.length !== range[1] - range[0]) fail('context_excerpt_range_changed');
      excerptBytes += value.length;
      if (excerptBytes > limits.context_max_excerpt_bytes) fail('context_excerpt_byte_limit');
      return value;
    });
    for (const witness of expected.witnesses.filter(w => w.channel === 'content')) {
      const index = merged.findIndex(([from, to]) => from <= witness.offset && to >= witness.offset + witness.word.length);
      if (index < 0 || !matchWord(bytes[index], witness.offset - merged[index][0], witness.word)) fail('context_excerpt_anchor_mismatch');
      const [from] = merged[index], offset = witness.offset - from, end = offset + witness.word.length;
      if ((offset && word(bytes[index][offset - 1])) || (end < bytes[index].length && word(bytes[index][end]))) fail('context_excerpt_word_boundary_mismatch');
      // Missing boundary bytes at a zero-radius window are not independent proof.
    }
    if (merged.length === 1 && merged[0][0] === 0 && merged[0][1] === file.source_bytes) {
      const actual = createHash(q.scope.object_format).update(`blob ${file.source_bytes}\0`).update(bytes[0]).digest('hex');
      if (actual !== expected.blob) fail('context_complete_blob_hash_mismatch');
      fullBlobs.push(file.path_hex);
    }
    sourceBytes += file.source_bytes;
    if (sourceBytes > limits.context_max_source_bytes) fail('context_source_byte_limit');
  }
  if (sourceBytes !== reply.source_bytes_read || excerptBytes !== reply.excerpt_bytes) fail('context_byte_accounting_changed');
  check();
  return { query: q, source: selected, lexical_generation: generation, lexical_checkpoint: checkpoint, complete: reply.complete,
    candidate_files: candidates.size, returned_files: paths.length, omitted_files: candidates.size - paths.length,
    full_blob_hash_verified_paths: fullBlobs, partial_excerpts_hash_verified: false,
    source_material_untrusted: true, agent_context_packet: false, authority_verified: false,
    source_bytes_read: sourceBytes, excerpt_bytes: excerptBytes };
}

// Closed single-request acquisition. Never follows redirects or changes the
// selected query, credential, pins or endpoint in response to a refusal.
export async function acquire(address, credential, input, options = {}) {
  keys(options, ['signal', 'timeoutMs', 'ca'], []);
  const base = endpoint(address), prepared = command(input);
  if (typeof credential !== 'string' || !/^[0-9a-f]{64}$/.test(credential)) fail('invalid_source_read_token');
  const timeout = count(options.timeoutMs ?? 30000, 300000, 1), signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('invalid_context_signal');
  if (options.ca !== undefined && (!(options.ca instanceof Uint8Array) || !options.ca.length || options.ca.length > 256 * 1024 || !base.startsWith('https:'))) fail('invalid_context_ca');
  const ca = options.ca === undefined ? undefined : Buffer.from(options.ca);
  const started = performance.now(), check = () => { signal?.throwIfAborted(); if (performance.now() - started >= timeout) fail('context_deadline_exceeded'); };
  check();
  const url = new URL(`${base}/api/v1/source/context-initial`);
  const raw = await new Promise((resolve, reject) => {
    let req, res, closed = false, settled = false, result, failure, timer;
    const deliver = () => failure ? reject(failure) : resolve(result);
    const finish = (error, bytes) => {
      if (settled) return; settled = true; failure = error; result = bytes;
      clearTimeout(timer); signal?.removeEventListener('abort', abort); res?.destroy(); req?.destroy();
      if (closed || !req) deliver();
    };
    const abort = () => finish(new ContextError('context_cancelled'));
    try {
      req = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, { method: 'POST', agent: false,
        rejectUnauthorized: true, ...(ca ? { ca } : {}), maxHeaderSize: 16384,
        headers: { Authorization: `Bearer ${credential}`, Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(prepared.body), 'Accept-Encoding': 'identity', Connection: 'close', 'Cache-Control': 'no-store' } });
      req.on('error', () => finish(new ContextError('context_transport_unavailable')));
      req.once('close', () => { closed = true; if (!settled) finish(new ContextError('context_response_incomplete')); else deliver(); });
      req.once('response', incoming => {
        res = incoming;
        if (res.statusCode !== 200) { finish(new ContextError('context_http_refused', res.statusCode)); return; }
        const names = res.rawHeaders.filter((_, i) => i % 2 === 0).map(n => n.toLowerCase()).filter(n => ['content-type', 'content-length', 'content-encoding'].includes(n));
        if (names.length !== new Set(names).size || !/^application\/json(?:\s*;|$)/i.test(res.headers['content-type'] ?? '') ||
            (res.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') { finish(new ContextError('invalid_context_response_headers')); return; }
        const length = res.headers['content-length'];
        if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(LIMITS.response))) { finish(new ContextError('context_response_limit')); return; }
        const chunks = []; let size = 0;
        res.on('error', () => finish(new ContextError('context_response_incomplete')));
        res.on('data', bytes => { if (settled) return; size += bytes.length;
          if (size > LIMITS.response || chunks.length >= 16384) finish(new ContextError('context_response_limit')); else chunks.push(bytes); });
        res.once('end', () => {
          if (!res.complete || length !== undefined && BigInt(length) !== BigInt(size)) finish(new ContextError('context_response_incomplete'));
          else finish(null, Buffer.concat(chunks, size));
        });
      });
      timer = setTimeout(() => finish(new ContextError('context_deadline_exceeded')), timeout);
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort(); else req.end(prepared.body);
    } catch { finish(new ContextError('context_transport_unavailable')); }
  });
  check(); const native = parse(raw), summary = validate(native, prepared.query, check); check();
  return { schema: 'frankengit-source-context-capture-v1', endpoint: base, request_sha256: sha256(prepared.body),
    response_sha256: sha256(raw), summary, native_response: native };
}
