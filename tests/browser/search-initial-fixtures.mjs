// Wire fixtures derived from source/retrieval.rs and its lexical/symbol renderers
// at b7a9aab44dc30e04f0a23fb10ad96514f844a67c. Not a native server or signed
// authority oracle. File identities are computed independently with Node crypto.
import { createHash, webcrypto } from 'node:crypto';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
export { webcrypto };
export const bytes = text => new TextEncoder().encode(text);
export const hex = value => Buffer.from(typeof value === 'string' ? bytes(value) : value).toString('hex');
export const token = character => `alg:2:${character.repeat(64)}`;
export const selected = format => ({ reference: 'refs/heads/main', format });
export const clone = value => structuredClone(value);
export function fixture({ format = 'sha1', limit = 2, symbols = 'available', policy = 'optional', maxWork = 997, maxPayloadBytes = 3001, maxResultBytes = 2097152 } = {}) {
  const files = [['src/needle.rs', 'pub fn Needle() {}\n', 7, 'function'], ['src/z/needle.rs', 'pub struct Needle;\n', 11, 'struct']].map(([path, text, at, kind], i) => {
    const data = bytes(text), blob = createHash(format).update(`blob ${data.length}\0`).update(data).digest('hex');
    return { path, pathHex: hex(path), bytes: data, blob, at, kind, id: i + 1 };
  });
  const width = format === 'sha1' ? 40 : 64;
  const source = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
    object_format: format, ref: 'refs/heads/main', ref_hex: hex('refs/heads/main'), source_head: 'head-one', snapshot_token: token('1'),
    source_rcr: 'rcr-one', source_commit: 'b'.repeat(width), root_tree: 'c'.repeat(width), read_only: true, transaction_created: false, published: false };
  const input = { mode: 'initial', termsHex: [hex('Needle')], prefixesHex: [hex('src')], maxMatches: limit, maxWork, maxPayloadBytes, maxResultBytes,
    ...(symbols === 'not_requested' ? {} : { symbol: { nameHex: hex('Needle'), match: 'exact', kinds: [], policy } }) };
  const sourceBytes = files.reduce((n, file) => n + file.bytes.length, 0), rows = files.slice(0, limit), complete = rows.length === files.length;
  const lexical = channel => ({ ...source, type: 'source_search_index', profile: 'ascii-word-postings-v1',
    index_token: token('a'), index_number: 7, selected_index_token: token('a'), selected_index_number: 7,
    channel, after: null, limit, returned_hits: rows.length, complete, next_after: complete ? null : rows.at(-1).id,
    indexed_documents: files.length, indexed_source_bytes: sourceBytes, non_regular_entries: 1,
    segments_read: 1, payload_bytes_read: channel === 'content' ? 120 : 140, generation_bytes_read: 100, work_units: channel === 'content' ? 20 : 30,
    terms_hex: [hex('needle')], path_prefix_hex: [hex('src')], hits: rows.map(file => ({ document_id: file.id, path_hex: file.pathHex,
      blob: file.blob, content_bytes: file.bytes.length, spans: [{ query_index: 0, byte_offset: channel === 'content' ? file.at : file.path.indexOf('needle'), byte_length: 6 }] })) });
  const symbol = { ...source, type: 'source_search_symbols_index', profile: 'rust-declaration-heads-v1', index_profile: 'rust-declaration-tables-v1',
    authority_class: 'deterministic-derived', compiler_resolved: false, macro_expansion: false, cfg_evaluated: false,
    index_token: token('d'), index_number: 4, source_blobs_read: 0, source_bytes_read: 0,
    name_hex: hex('Needle'), match: 'exact', complete, completion: complete ? 'complete' : 'match_limit', max_matches: limit,
    returned_matches: rows.length, indexed_files: files.length, indexed_declarations: files.length, indexed_source_bytes: sourceBytes,
    unsupported_language_files: 0, non_regular_entries: 1, tables_read: files.length, payload_bytes_read: 250,
    max_work: Math.floor(maxWork / 3), work_units: 40, kinds: [], path_prefix_hex: [hex('src')],
    matches: rows.map(file => ({ name_hex: hex('Needle'), kind: file.kind, raw_identifier: false, path_hex: file.pathHex,
      blob: file.blob, byte_offset: file.at, line: 1, byte_column: file.at + 1, match_length: 6,
      excerpt_hex: hex(file.bytes.subarray(0, file.bytes.length - 1)), excerpt_offset: 0, match_truncated_in_excerpt: false })) };
  const { published, source_head, ...outerSource } = source;
  const reply = { ...outerSource, type: 'source_search_initial', profile: 'source-initial-retrieval-v1', phase: 'Initial', streaming: false, semantic_refinement: false,
    source_blobs_read: 0, source_bytes_read: 0, complete: complete && ['available', 'not_requested'].includes(symbols),
    generation_vector: { lexical: { index_token: token('a'), index_number: 7 }, symbols: symbols === 'available' ? { index_token: token('d'), index_number: 4 } : null },
    max_results_per_channel: limit, max_work: maxWork, max_payload_bytes: maxPayloadBytes, max_result_bytes: maxResultBytes,
    retained_result_bytes: 0, completed_payload_bytes_read: symbols === 'available' ? 510 : 260,
    completed_work_units: symbols === 'available' ? 90 : 50, content: lexical('content'), path: lexical('path'),
    symbols: symbols === 'available' ? { state: 'available', result: symbol } : symbols === 'not_requested' ? { state: 'not_requested' } : { state: 'unavailable', reason: symbols, result: null } };
  reply.retained_result_bytes = 2 * rows.reduce((n, f) => n + f.path.length + 24 + 64, 0) +
    (symbols === 'available' ? rows.reduce((n, f) => n + f.path.length + 6 + f.bytes.length - 1 + 96, 0) : 0);
  return { format, files, input, reply, source };
}
export function response(value, status = 200) {
  const body = JSON.stringify(value);
  return new Response(body, { status, headers: { 'Content-Type': 'application/json', 'Content-Length': String(bytes(body).length) } });
}
export function fileReply(f, file, offset = 0) {
  const part = file.bytes.subarray(offset, offset + 65536), next = offset + part.length;
  return { ...f.source, type: 'source_blob', path_hex: file.pathHex, object_id: file.blob, offset,
    symlink_followed: false, kind: 'file', total_bytes: file.bytes.length, content_hex: hex(part), returned_bytes: part.length,
    next_offset: next < file.bytes.length ? next : null };
}
export function harness(f = fixture(), handler = null, options = {}) {
  const calls = [];
  const client = new CodeSearch({ href: 'https://forge.example/repo.git/ui/search/', cryptoImpl: webcrypto, ...options,
    fetchImpl: async (url, init) => {
      const call = { path: new URL(url).pathname.split('/api/v1/')[1], fields: new URLSearchParams(init.body), init }; calls.push(call);
      if (handler) { const result = await handler(call, calls.length); if (result !== undefined) return result; }
      if (call.path === 'source/search-initial') return response(f.reply);
      if (call.path === 'source/search-index') return response(f.reply.content);
      if (call.path === 'source/search-symbols-index') return response(f.reply.symbols.result);
      if (call.path === 'source/blob') {
        const file = f.files.find(file => file.pathHex === call.fields.get('path_hex'));
        if (!file) throw new Error('Unexpected file request');
        return response(fileReply(f, file, Number(call.fields.get('offset'))));
      }
      throw new Error('Unexpected request route');
    } });
  return { client, calls, connect: () => client.connect('a'.repeat(64), 'refs/heads/main', f.format) };
}
