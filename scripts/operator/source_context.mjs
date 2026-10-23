// Remote context acquisition over the native joined retrieval/hydration API.
// This is a read client, not an index, Git engine, authority or Agent ContextPacket.
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

export const LIMITS = Object.freeze({ response: 8 * 1024 * 1024, request: 256 * 1024,
  files: 32, anchors: 4096, windows: 128, source: 64 * 1024 * 1024, file: 8 * 1024 * 1024,
  excerpts: 1024 * 1024, results: 100, work: 16 * 1024 * 1024, payload: 32 * 1024 * 1024 });
export const RANKING_PROFILE = "context-weighted-rrf-q16-v1";
const U64 = 18446744073709551615n;
const SYMBOL_KINDS = Object.freeze(['enum', 'function', 'macro', 'module', 'struct', 'trait', 'type', 'union']);
const READ_LABEL_PROFILE = 'source-read-result-labels-v1';
const positionDomain = channel => channel === 'path' ? 'raw-path-bytes' : 'source-blob-bytes';
const channelShare = (total, q, ordinal) => {
  const channels = q.symbols ? 3 : 2;
  return Math.floor(total / channels) + Number(ordinal < total % channels);
};
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
function resultLabel(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('invalid_context_read_label');
  return value;
}
function readLabels(retrieval) {
  if (!Object.hasOwn(retrieval, 'authorization')) return { state: 'legacy-unlabelled' };
  const value = retrieval.authorization;
  keys(value, ['profile', 'host', 'principal', 'scope', 'binding', 'reusable_capability']);
  if (value.profile !== READ_LABEL_PROFILE || !['trusted-local-native', 'trusted-local-cli', 'trusted-local-mcp', 'http-repository-read-credential'].includes(value.host) ||
      value.scope !== 'whole-repository' || value.reusable_capability !== false ||
      (value.host === 'http-repository-read-credential' ? typeof value.principal !== 'string' || !/^[0-9a-f]{32}$/.test(value.principal) : value.principal !== null)) fail('context_read_label_profile_changed');
  return { state: 'labelled', profile: value.profile, host: value.host, principal: value.principal,
    scope: value.scope, binding: resultLabel(value.binding), reusable_capability: false };
}
function rowLabel(hit, evidence, domain) {
  if (evidence.state === 'legacy-unlabelled') {
    if (Object.hasOwn(hit, 'authorization_label') || Object.hasOwn(hit, 'position_domain')) fail('undeclared_context_read_labels');
    return;
  }
  resultLabel(hit.authorization_label);
  if (hit.position_domain !== domain) fail('context_read_label_domain_changed');
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
  keys(input, ['schema', 'scope', 'reference', 'terms', 'prefixes_hex', 'expected_head', 'expected_commit', 'minimum_lexical', 'symbols', 'minimum_symbol', 'selection', 'limits'],
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
  let symbols = null;
  if (Object.hasOwn(input, 'symbols')) {
    keys(input.symbols, ['name', 'match', 'policy', 'kinds'], ['name']);
    const value = input.symbols, kinds = value.kinds ?? [];
    if (typeof value.name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value.name) ||
        !['exact', 'prefix'].includes(value.match ?? 'exact') || !['optional', 'required'].includes(value.policy ?? 'optional') ||
        !Array.isArray(kinds) || kinds.length > 8 || kinds.some(k => !SYMBOL_KINDS.includes(k))) fail('invalid_context_symbol_query');
    symbols = { name: value.name, match: value.match ?? 'exact', policy: value.policy ?? 'optional', kinds: [...new Set(kinds)].sort() };
  }
  if (!symbols && input.minimum_symbol != null) fail('context_symbol_floor_without_query');
  if (Object.hasOwn(input, 'selection') && !['raw-path-prefix', RANKING_PROFILE].includes(input.selection)) fail('unsupported_context_selection');
  const limits = input.limits ?? {}; keys(limits, Object.keys(defaults), []);
  const selected = { ...defaults, ...limits };
  for (const [name, maximum, minimum] of [['max_results_per_channel', 100, 1], ['max_work', LIMITS.work, symbols ? 3 : 2],
    ['max_payload_bytes', LIMITS.payload, symbols ? 3 : 2], ['max_result_bytes', 2 * 1024 * 1024, 1], ['context_max_files', 32, 1],
    ['context_radius_bytes', 4096, 0], ['context_max_source_bytes', LIMITS.source, 1], ['context_max_excerpt_bytes', LIMITS.excerpts, 1]]) count(selected[name], maximum, minimum);
  return { schema: input.schema, scope, reference: reference(input.reference),
    terms: [...new Set(input.terms.map(t => t.toLowerCase()))].sort(), prefixes_hex: [...new Set(prefixes)].sort(),
    expected_head: input.expected_head == null ? null : token(input.expected_head),
    expected_commit: input.expected_commit == null ? null : oid(input.expected_commit, scope.object_format),
    minimum_lexical: input.minimum_lexical == null ? null : activation(input.minimum_lexical), limits: selected,
    ...(symbols ? { symbols, minimum_symbol: input.minimum_symbol == null ? null : activation(input.minimum_symbol) } : {}),
    ...(Object.hasOwn(input, 'selection') ? { selection: input.selection } : {}) };
}
export function command(input) {
  const q = query(input), values = { object_format: q.scope.object_format, ref: q.reference, ...q.limits };
  if (q.expected_head !== null) values.expected_head = q.expected_head;
  if (q.expected_commit !== null) values.expected_commit = q.expected_commit;
  if (q.minimum_lexical) Object.assign(values, { minimum_lexical_token: q.minimum_lexical.token, minimum_lexical_number: q.minimum_lexical.number });
  if (q.symbols) Object.assign(values, { symbol_name_hex: Buffer.from(q.symbols.name).toString('hex'),
    symbol_match: q.symbols.match, symbol_policy: q.symbols.policy });
  if (q.minimum_symbol) Object.assign(values, { minimum_symbol_token: q.minimum_symbol.token, minimum_symbol_number: q.minimum_symbol.number });
  if (q.selection) values.context_selection = q.selection;
  const body = new URLSearchParams(values);
  for (const kind of q.symbols?.kinds ?? []) body.append('symbol_kind', kind);
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
function lexical(value, name, q, selected, generation, ordinal, check, evidence) {
  source(value, q, selected); opaque(value.source_head);
  const limits = q.limits, share = total => channelShare(total, q, ordinal);
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
    rowLabel(hit, evidence, positionDomain(name));
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
// Symbol declarations are a distinct native profile, never folded lexical
// terms. A missing optional index is not an empty successful symbol corpus.
function symbols(channel, vector, q, selected, sourceHead, check, evidence) {
  const empty = { state: 'not_requested', generation: null, complete: true, coverage: true,
    retained: 0, payload: 0, work: 0, matches: [] };
  if (!q.symbols) {
    if (!same(channel, { state: 'not_requested' }) || vector !== null) fail('unexpected_context_symbol_generation');
    return empty;
  }
  keys(channel, ['state', 'result', 'reason'], ['state', 'result']);
  if (channel.state === 'unavailable') {
    if (q.symbols.policy !== 'optional' || q.minimum_symbol || channel.result !== null || vector !== null ||
        !['uninitialized', 'stale'].includes(channel.reason)) fail('context_symbol_unavailable_not_permitted');
    return { ...empty, state: 'unavailable', reason: channel.reason, complete: false, coverage: false };
  }
  if (channel.state !== 'available' || Object.hasOwn(channel, 'reason')) fail('unsupported_context_symbol_state');
  keys(vector, ['index_token', 'index_number']);
  const generation = activation({ token: vector.index_token, number: vector.index_number });
  const value = record(channel.result), limits = q.limits, requested = q.symbols;
  source(value, q, selected);
  const index = activation({ token: value.index_token, number: value.index_number });
  if (!same(index, generation)) fail('context_symbol_generation_join_changed');
  atLeast(index, q.minimum_symbol);
  if (value.source_head !== sourceHead || value.type !== 'source_search_symbols_index' || ![1, 2].includes(value.schema_version) ||
      value.profile !== 'rust-declaration-heads-v1' || value.authority_class !== 'deterministic-derived' ||
      value.compiler_resolved !== false || value.macro_expansion !== false || value.cfg_evaluated !== false || value.published !== false ||
      value.source_blobs_read !== 0 || value.source_bytes_read !== 0 || value.name_hex !== Buffer.from(requested.name).toString('hex') ||
      value.match !== requested.match || !same(value.kinds, requested.kinds) || !same(value.path_prefix_hex, q.prefixes_hex) ||
      value.max_matches !== limits.max_results_per_channel || typeof value.complete !== 'boolean' ||
      value.completion !== (value.complete ? 'complete' : 'match_limit') || !Array.isArray(value.matches) ||
      value.matches.length > limits.max_results_per_channel || value.returned_matches !== value.matches.length) fail('invalid_context_symbol_channel');
  count(value.indexed_files, 20000); count(value.indexed_declarations, 20000); count(value.indexed_source_bytes, LIMITS.source);
  count(value.unsupported_language_files, 20000 - value.indexed_files); count(value.non_regular_entries, 50000);
  count(value.tables_read, value.indexed_files); count(value.payload_bytes_read, channelShare(limits.max_payload_bytes, q, 2), 1);
  // The native renderer echoes the query's fixed scanner ceiling; actual
  // lookup work must fit the smaller pre-I/O Initial channel share.
  if (value.max_work !== LIMITS.work) fail('context_symbol_work_profile_changed');
  count(value.work_units, channelShare(limits.max_work, q, 2));
  if (value.matches.length > value.indexed_declarations || (!value.complete &&
      (value.matches.length !== limits.max_results_per_channel || value.matches.length >= value.indexed_declarations))) fail('invalid_context_symbol_completion');
  let previous = '', offset = -1, retained = 0; const documents = new Map();
  for (const hit of value.matches) {
    check(); keys(hit, ['name_hex', 'kind', 'raw_identifier', 'path_hex', 'blob', 'byte_offset', 'line', 'byte_column',
      'match_length', 'excerpt_hex', 'excerpt_offset', 'match_truncated_in_excerpt',
      ...(evidence.state === 'labelled' ? ['authorization_label', 'position_domain'] : [])]);
    rowLabel(hit, evidence, 'source-declaration-bytes');
    path(hit.path_hex); const blob = oid(hit.blob, q.scope.object_format), name = unhex(hit.name_hex, 128);
    const text = name.toString('ascii');
    if (!name.every(b => b < 128) || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(text) ||
        !(requested.match === 'exact' ? text === requested.name : text.startsWith(requested.name)) ||
        !SYMBOL_KINDS.includes(hit.kind) || (requested.kinds.length && !requested.kinds.includes(hit.kind)) ||
        typeof hit.raw_identifier !== 'boolean' || hit.match_truncated_in_excerpt !== false ||
        !hit.path_hex.endsWith('2e7273') || (q.prefixes_hex.length && !q.prefixes_hex.some(p => hit.path_hex === p || hit.path_hex.startsWith(`${p}2f`)))) fail('invalid_context_symbol_match');
    count(hit.byte_offset, LIMITS.file); count(hit.match_length, 128, 1);
    count(hit.line, LIMITS.file + 1, 1); count(hit.byte_column, hit.byte_offset + 1, 1); count(hit.excerpt_offset, hit.byte_offset);
    const excerpt = unhex(hit.excerpt_hex, 416), end = hit.byte_offset + hit.match_length, excerptEnd = hit.excerpt_offset + excerpt.length;
    if (hit.match_length !== name.length || end > LIMITS.file || excerptEnd > LIMITS.file ||
        excerptEnd > value.indexed_source_bytes || excerpt.includes(10) || excerptEnd < end ||
        hit.excerpt_offset < hit.byte_offset - (hit.byte_column - 1) || hit.line > hit.byte_offset + 1 ||
        !excerpt.subarray(hit.byte_offset - hit.excerpt_offset, end - hit.excerpt_offset).equals(name) ||
        (hit.raw_identifier && (hit.byte_offset - hit.excerpt_offset < 2 ||
          !excerpt.subarray(hit.byte_offset - hit.excerpt_offset - 2, hit.byte_offset - hit.excerpt_offset).equals(Buffer.from('r#'))))) fail('context_symbol_excerpt_mismatch');
    if (hit.path_hex < previous || (hit.path_hex === previous && hit.byte_offset <= offset) ||
        (documents.has(hit.path_hex) && documents.get(hit.path_hex) !== blob)) fail('context_symbol_order_or_identity');
    previous = hit.path_hex; offset = hit.byte_offset; documents.set(hit.path_hex, blob);
    retained += hit.path_hex.length / 2 + name.length + excerpt.length + 96;
  }
  if (documents.size > value.tables_read) fail('context_symbol_read_accounting');
  let coverage = true;
  const coverageFields = ['coverage_complete', 'coverage_scope', 'omitted_files', 'omitted_source_bytes', 'omissions'];
  if (value.schema_version === 1) {
    if (value.index_profile !== 'rust-declaration-tables-v1' || coverageFields.some(k => Object.hasOwn(value, k))) fail('ambiguous_context_symbol_coverage');
  } else {
    if (value.index_profile !== 'rust-declaration-omissions-v1' || value.coverage_complete !== false ||
        value.coverage_scope !== 'recorded-rust-files' || !Array.isArray(value.omissions) || !value.omissions.length ||
        value.omitted_files !== value.omissions.length || value.indexed_files + value.unsupported_language_files + value.omissions.length > 20000) fail('invalid_context_symbol_omissions');
    coverage = false; let total = 0; previous = '';
    const syntax = ['invalid_utf8', 'unsupported_identifier', 'unterminated_comment', 'unterminated_literal', 'unbalanced_delimiter', 'depth_limit', 'name_limit'];
    for (const omission of value.omissions) {
      check(); keys(omission, ['path_hex', 'blob', 'source_bytes', 'reason', 'byte_offset', 'limit']);
      path(omission.path_hex); oid(omission.blob, q.scope.object_format); count(omission.source_bytes, LIMITS.source, 1);
      if (!omission.path_hex.endsWith('2e7273') || omission.path_hex <= previous || documents.has(omission.path_hex)) fail('invalid_context_symbol_omission');
      if (omission.reason === 'file_bytes') {
        count(omission.limit, LIMITS.file, 1);
        if (omission.byte_offset !== null || omission.source_bytes <= omission.limit) fail('invalid_context_symbol_omission');
      } else if (omission.reason === 'table_bytes') {
        if (omission.byte_offset !== null || omission.limit !== 1024 * 1024 || omission.source_bytes > LIMITS.file) fail('invalid_context_symbol_omission');
      } else {
        if (!syntax.includes(omission.reason) || omission.limit !== null || omission.source_bytes > LIMITS.file) fail('invalid_context_symbol_omission');
        count(omission.byte_offset, omission.source_bytes);
      }
      previous = omission.path_hex; total += omission.source_bytes; retained += omission.path_hex.length / 2 + 96;
    }
    if (total !== value.omitted_source_bytes || total + value.indexed_source_bytes > LIMITS.source) fail('context_symbol_omission_accounting');
  }
  return { state: 'available', generation, complete: value.complete, coverage, retained,
    payload: value.payload_bytes_read, work: value.work_units, matches: value.matches };
}

// Preserve the native original witness order/dedup key. An opaque origin label
// cannot change anchor ordering, merge two different witnesses or add a rank.
function plannedWitnesses(row) {
  const channels = ['content', 'path', 'symbol'];
  const ordered = [...row.witnesses].sort((left, right) => channels.indexOf(left.channel) - channels.indexOf(right.channel) ||
    left.offset - right.offset || left.word.length - right.word.length || Buffer.compare(left.word, right.word) || Number(!!left.raw) - Number(!!right.raw));
  return ordered.filter((value, i, values) => !i || value.channel !== values[i - 1].channel || value.offset !== values[i - 1].offset ||
    value.word.length !== values[i - 1].word.length || !value.word.equals(values[i - 1].word) || !!value.raw !== !!values[i - 1].raw);
}

// Recompute the COMPLETE returned candidate ordering, not just the scores in
// the selected prefix. A self-consistent receipt for a lower-scoring substitute
// must fail even when all of its arithmetic and hydrated source bytes agree.
function ranking(value, q, candidates, channels, check) {
  check();
  keys(value, ['profile', 'rank_constant', 'score_scale', 'input_order', 'tie_break', 'ranked_over', 'semantic_relevance', 'selected']);
  if (value.profile !== RANKING_PROFILE || value.rank_constant !== 60 || value.score_scale !== 65536 ||
      value.input_order !== 'raw-path-distinct-documents' || value.tie_break !== 'raw-path-ascending' ||
      value.ranked_over !== 'returned-channel-hits' || value.semantic_relevance !== false || !Array.isArray(value.selected)) fail('context_ranking_profile_changed');
  let pathBytes = 0;
  const scores = new Map();
  for (const [path, candidate] of candidates) {
    check(); pathBytes += path.length / 2;
    if (pathBytes > 2 * 1024 * 1024) fail('context_ranking_path_limit');
    scores.set(path, { path_hex: path, blob: candidate.blob, score_q16: 0, contributions: [] });
  }
  for (const [channel, hits] of channels) {
    if (hits.length > 1024) fail('context_ranking_hit_limit');
    const weight = channel === 'symbol' ? 2 : 1;
    let previous = null, documentRank = 0;
    for (const hit of hits) {
      check();
      if (previous === hit.path_hex) continue;
      previous = hit.path_hex; documentRank++;
      const row = scores.get(hit.path_hex);
      if (!row) fail('context_ranking_unknown_candidate');
      // Products and sums are below 2^53: exact integer arithmetic, no
      // accumulated floating scores and no caller-supplied weights/constant.
      const contribution = Math.floor(weight * 65536 / (60 + documentRank));
      row.score_q16 += contribution;
      row.contributions.push({ channel, document_rank: documentRank, weight, score_q16: contribution });
    }
  }
  const selected = [...scores.values()].sort((a, b) => {
    check(); return b.score_q16 - a.score_q16 || (a.path_hex < b.path_hex ? -1 : a.path_hex > b.path_hex ? 1 : 0);
  }).slice(0, q.limits.context_max_files).map((row, ordinal) => ({ position: ordinal + 1, ...row }));
  if (value.selected.length !== selected.length) fail('context_ranking_selection_changed');
  for (let i = 0; i < selected.length; i++) {
    check();
    const actual = value.selected[i], expected = selected[i];
    keys(actual, ['position', 'path_hex', 'blob', 'score_q16', 'contributions']);
    if (actual.position !== expected.position || actual.path_hex !== expected.path_hex ||
        oid(actual.blob, q.scope.object_format) !== expected.blob || actual.score_q16 !== expected.score_q16 ||
        !Array.isArray(actual.contributions) || actual.contributions.length !== expected.contributions.length) fail('context_ranking_selection_changed');
    for (let j = 0; j < expected.contributions.length; j++) {
      check();
      const contribution = actual.contributions[j];
      keys(contribution, ['channel', 'document_rank', 'weight', 'score_q16']);
      if (Object.keys(expected.contributions[j]).some(k => contribution[k] !== expected.contributions[j][k])) fail('context_ranking_contribution_changed');
    }
  }
  check();
  // Fresh, normalized data; no response-owned object can mutate the checked
  // ordering when a capture is projected into a private text export.
  return { profile: RANKING_PROFILE, rank_constant: 60, score_scale: 65536,
    input_order: 'raw-path-distinct-documents', tie_break: 'raw-path-ascending',
    ranked_over: 'returned-channel-hits', semantic_relevance: false, selected };
}

export function validate(reply, input, check = () => {}) {
  const q = query(input), limits = q.limits; check(); record(reply);
  if (reply.type !== 'source_context_initial' || reply.schema_version !== 1 || reply.profile !== 'source-initial-context-v1' ||
      reply.read_only !== true || reply.transaction_created !== false || reply.source_material_untrusted !== true ||
      reply.selection !== (q.selection ?? 'raw-path-prefix') ||
      (reply.selection === 'raw-path-prefix' && Object.hasOwn(reply, 'ranking')) || !Array.isArray(reply.files)) fail('unsupported_native_context');
  for (const k of ['context_max_files', 'context_radius_bytes', 'context_max_source_bytes', 'context_max_excerpt_bytes']) if (reply[k] !== limits[k]) fail('context_budget_echo_changed');
  const r = record(reply.retrieval), selected = source(r, q);
  const evidence = readLabels(r), labelled = evidence.state === 'labelled';
  if (r.type !== 'source_search_initial' || r.schema_version !== 1 || r.profile !== 'source-initial-retrieval-v1' || r.phase !== 'Initial' ||
      r.streaming !== false || r.semantic_refinement !== false || r.source_blobs_read !== 0 || r.source_bytes_read !== 0) fail('unsupported_context_retrieval');
  for (const k of ['max_results_per_channel', 'max_work', 'max_payload_bytes', 'max_result_bytes']) if (r[k] !== limits[k]) fail('context_query_budget_changed');
  keys(r.generation_vector, ['lexical', 'symbols']);
  const vector = r.generation_vector.lexical; keys(vector, ['index_token', 'index_number']);
  const generation = activation({ token: vector.index_token, number: vector.index_number });
  const contentCoverage = lexical(r.content, 'content', q, selected, generation, 0, check, evidence);
  const pathCoverage = lexical(r.path, 'path', q, selected, generation, 1, check, evidence);
  const symbol = symbols(r.symbols, r.generation_vector.symbols, q, selected, r.content.source_head, check, evidence);
  if (r.content.source_head !== r.path.source_head || r.content.indexed_documents !== r.path.indexed_documents ||
      r.content.indexed_source_bytes !== r.path.indexed_source_bytes || r.content.non_regular_entries !== r.path.non_regular_entries ||
      !same(r.content.omissions ?? [], r.path.omissions ?? [])) fail('context_lexical_corpus_changed');
  const contentHead = activation({ token: r.content.selected_index_token, number: r.content.selected_index_number });
  const pathHead = activation({ token: r.path.selected_index_token, number: r.path.selected_index_number });
  if (contentHead.number === pathHead.number && contentHead.token !== pathHead.token) fail('conflicting_context_index_heads');
  const checkpoint = BigInt(contentHead.number) >= BigInt(pathHead.number) ? contentHead : pathHead;
  let retained = symbol.retained + [r.content, r.path].reduce((n, channel) => n + channel.hits.reduce((sum, h) => sum + h.path_hex.length / 2 + h.spans.length * 24 + 64, 0)
    + (channel.omissions ?? []).reduce((sum, omission) => sum + omission.path_hex.length / 2 + 96, 0), 0);
  if (labelled) retained += (r.content.hits.length + r.path.hits.length + symbol.matches.length) * 192 + 768 + r.ref_hex.length / 2;
  if (count(r.retained_result_bytes, limits.max_result_bytes) !== retained) fail('context_retained_bytes_changed');
  if (r.completed_work_units !== r.content.work_units + r.path.work_units + symbol.work ||
      r.completed_payload_bytes_read !== r.content.payload_bytes_read + r.path.payload_bytes_read + symbol.payload ||
      r.complete !== (contentCoverage && pathCoverage && r.content.complete && r.path.complete && symbol.complete && symbol.coverage)) fail('context_retrieval_accounting_changed');
  const candidates = new Map(), documents = new Map(); let anchorCount = 0;
  for (const channel of ['content', 'path']) for (const hit of r[channel].hits) {
    check(); const blob = oid(hit.blob, q.scope.object_format), prior = candidates.get(hit.path_hex);
    const document = exact(hit.document_id);
    if (documents.has(document) && documents.get(document) !== hit.path_hex) fail('context_document_identity_conflict');
    documents.set(document, hit.path_hex);
    if (prior && (prior.document !== document || prior.blob !== blob || prior.size !== hit.content_bytes)) fail('context_file_identity_conflict');
    const row = prior ?? { blob, document, size: hit.content_bytes, anchors: [], witnesses: [], origins: [] };
    if (labelled && !row.origins.includes(hit.authorization_label)) row.origins.push(hit.authorization_label);
    hit.spans.forEach((s, i) => {
      row.anchors.push({ channel, byte_offset: s.byte_offset, byte_length: s.byte_length });
      row.witnesses.push({ channel, offset: s.byte_offset, word: Buffer.from(q.terms[i]),
        ...(labelled ? { authorization_label: hit.authorization_label } : {}) });
    }); candidates.set(hit.path_hex, row);
  }
  for (const hit of symbol.matches) {
    check(); const blob = oid(hit.blob, q.scope.object_format), prior = candidates.get(hit.path_hex);
    const minimum = hit.excerpt_offset + hit.excerpt_hex.length / 2;
    if (prior && (prior.blob !== blob || prior.size !== null && prior.size < minimum)) fail('context_file_identity_conflict');
    const row = prior ?? { blob, document: null, size: null, anchors: [], witnesses: [], origins: [] };
    if (labelled && !row.origins.includes(hit.authorization_label)) row.origins.push(hit.authorization_label);
    row.minimum = Math.max(row.minimum ?? 0, minimum);
    row.anchors.push({ channel: 'symbol', byte_offset: hit.byte_offset, byte_length: hit.match_length });
    row.witnesses.push({ channel: 'symbol', offset: hit.byte_offset, word: Buffer.from(hit.name_hex, 'hex'),
      raw: hit.raw_identifier, excerptOffset: hit.excerpt_offset, excerpt: Buffer.from(hit.excerpt_hex, 'hex'),
      ...(labelled ? { authorization_label: hit.authorization_label } : {}) });
    candidates.set(hit.path_hex, row);
  }
  const ranked = q.selection === RANKING_PROFILE
    ? ranking(reply.ranking, q, candidates, [['content', r.content.hits], ['path', r.path.hits], ['symbol', symbol.matches]], check) : null;
  const paths = ranked ? ranked.selected.map(row => row.path_hex).sort() : [...candidates.keys()].sort().slice(0, limits.context_max_files);
  const plans = new Map(); let lineageBytes = 0, maximumWindows = 0;
  for (const p of paths) {
    check(); const row = candidates.get(p);
    if ((anchorCount += row.witnesses.length) > LIMITS.anchors) fail('context_anchor_limit');
    const witnesses = plannedWitnesses(row); plans.set(p, witnesses);
    if (labelled) {
      lineageBytes += row.origins.length * 256 + witnesses.length * 256 + 1024;
      maximumWindows += Math.max(1, witnesses.filter(w => w.channel !== 'path').length);
    }
  }
  if (labelled) {
    lineageBytes += Math.min(maximumWindows, LIMITS.windows) * 192;
    if (count(reply.lineage_metadata_bytes, limits.max_result_bytes) !== lineageBytes || retained + lineageBytes > limits.max_result_bytes) fail('context_lineage_accounting_changed');
  } else if (Object.hasOwn(reply, 'lineage_metadata_bytes')) fail('undeclared_context_read_labels');
  const fileLimit = Math.min(LIMITS.file, Math.floor(limits.context_max_source_bytes / Math.max(1, paths.length)));
  if (!fileLimit || reply.source_file_limit !== fileLimit || reply.candidate_files !== candidates.size || reply.returned_files !== paths.length ||
      reply.files.length !== paths.length || reply.omitted_files !== candidates.size - paths.length || reply.source_blobs_read !== paths.length ||
      reply.complete !== (r.complete && paths.length === candidates.size)) fail('context_selection_or_completeness_changed');
  let sourceBytes = 0, symbolSourceBytes = 0, excerptBytes = 0, windows = 0; const fullBlobs = [];
  for (let i = 0; i < paths.length; i++) {
    check(); const file = record(reply.files[i]), expected = candidates.get(paths[i]);
    const anchors = plans.get(paths[i]).map(w => ({ channel: w.channel, byte_offset: w.offset, byte_length: w.word.length,
      ...(labelled ? { authorization_label: w.authorization_label, position_domain: positionDomain(w.channel) } : {}) }));
    if (labelled) {
      keys(file, ['path_hex', 'blob', 'source_bytes', 'anchors', 'excerpts', 'authorization_labels', 'lineage_commitment', 'position_domain']);
      resultLabel(file.lineage_commitment);
      if (file.position_domain !== 'source-blob-bytes' || !same(file.authorization_labels, expected.origins)) fail('context_lineage_origins_changed');
    } else if (['authorization_labels', 'lineage_commitment', 'position_domain'].some(k => Object.hasOwn(file, k))) fail('undeclared_context_read_labels');
    if (file.path_hex !== paths[i] || oid(file.blob, q.scope.object_format) !== expected.blob || (expected.size !== null && file.source_bytes !== expected.size) ||
        count(file.source_bytes, fileLimit, expected.minimum ?? 0) > fileLimit || !same(file.anchors, anchors) || !Array.isArray(file.excerpts)) fail('context_file_or_anchors_changed');
    if (expected.witnesses.some(w => w.channel === 'symbol')) {
      symbolSourceBytes += file.source_bytes;
      if (symbolSourceBytes > r.symbols.result.indexed_source_bytes) fail('context_symbol_source_accounting');
    }
    let ranges = anchors.filter(a => a.channel !== 'path').map(a => [Math.max(0, a.byte_offset - limits.context_radius_bytes),
      Math.min(file.source_bytes, a.byte_offset + a.byte_length + limits.context_radius_bytes)]);
    if (!ranges.length) ranges = [[0, Math.min(file.source_bytes, Math.max(1, limits.context_radius_bytes) * 2)]];
    ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]); const merged = [];
    for (const range of ranges) { const last = merged.at(-1); if (last && range[0] <= last[1]) last[1] = Math.max(last[1], range[1]); else merged.push([...range]); }
    if (file.excerpts.length !== merged.length || (windows += merged.length) > LIMITS.windows) fail('context_excerpt_windows_changed');
    const bytes = file.excerpts.map((excerpt, j) => {
      check(); keys(excerpt, ['byte_offset', 'untrusted_bytes_hex', ...(labelled ? ['lineage_commitment', 'position_domain'] : [])]);
      if (labelled && (excerpt.position_domain !== 'source-blob-bytes' || excerpt.lineage_commitment !== file.lineage_commitment)) fail('context_lineage_excerpt_changed');
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
    for (const witness of expected.witnesses.filter(w => w.channel === 'symbol')) {
      check();
      const index = merged.findIndex(([from, to]) => from <= witness.offset && to >= witness.offset + witness.word.length);
      if (index < 0 || !bytes[index].subarray(witness.offset - merged[index][0], witness.offset - merged[index][0] + witness.word.length).equals(witness.word)) fail('context_symbol_source_mismatch');
      for (let j = 0; j < merged.length; j++) {
        const [from, to] = merged[j], start = Math.max(from, witness.excerptOffset), end = Math.min(to, witness.excerptOffset + witness.excerpt.length);
        if (start < end && !bytes[j].subarray(start - from, end - from).equals(witness.excerpt.subarray(start - witness.excerptOffset, end - witness.excerptOffset))) fail('context_symbol_source_mismatch');
      }
      // r# was checked in the native row excerpt. A zero-radius hydration
      // may exclude it; no independent partial-blob hash proof is claimed.
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
    ...(labelled ? { authorization: evidence, lineage_metadata_bytes: lineageBytes } : {}),
    source_bytes_read: sourceBytes, excerpt_bytes: excerptBytes,
    ...(q.symbols ? { symbols: { state: symbol.state, ...(symbol.reason ? { reason: symbol.reason } : {}),
      generation: symbol.generation, coverage_complete: symbol.coverage, complete: symbol.complete } } : {}),
    ...(ranked ? { ranking: ranked } : {}) };
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
