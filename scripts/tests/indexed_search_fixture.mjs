// HTTP fixtures, not an index/server emulator. Tests use the real browser
// transport, query validator, source-page reader and native-identity verifier.
import { createHash, webcrypto } from 'node:crypto';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { hex, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { indexQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
export { CodeSearch, hex, utf8, webcrypto, indexQuery };
export const token = 'ab'.repeat(32), href = 'https://forge.example/repo.git/ui/search/';
export const head = `alg:1:${'12'.repeat(32)}`, indexToken = `alg:1:${'34'.repeat(32)}`;
export const native = (kind, bytes, algorithm = 'sha1') => createHash(algorithm).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
export const input = (extra = {}) => ({ mode: 'indexed', channel: 'content', termsHex: [hex(utf8.encode('Alpha')), hex(utf8.encode('BETA'))], ...extra });
export function source(algorithm = 'sha1') {
  return { schema_version: 1, tenant_id: 'tenant', repository_id: 'repository', repository_incarnation: 'incarnation',
    object_format: algorithm, ref: 'refs/heads/main', ref_hex: hex(utf8.encode('refs/heads/main')),
    source_head: 'head-identity', snapshot_token: head, source_rcr: 'rcr-identity',
    source_commit: '56'.repeat(algorithm === 'sha1' ? 20 : 32), root_tree: '78'.repeat(algorithm === 'sha1' ? 20 : 32),
    read_only: true, transaction_created: false, published: false };
}
export function document({ path = 'src/a.rs', bytes = utf8.encode('ALPHA alpha beta\n'), algorithm = 'sha1', id = 1,
  spans = [{ query_index: 0, byte_offset: 0, byte_length: 5 }, { query_index: 1, byte_offset: 12, byte_length: 4 }] } = {}) {
  return { raw: { document_id: id, path_hex: hex(utf8.encode(path)), blob: `${algorithm}:${native('blob', bytes, algorithm)}`,
    content_bytes: bytes.length, spans }, bytes, algorithm };
}
export function page(q, docs = [document()], extras = {}, algorithm = 'sha1') {
  return { ...source(algorithm), type: 'source_search_index', profile: 'ascii-word-postings-v1',
    index_token: indexToken, index_number: 2, selected_index_token: indexToken, selected_index_number: 2,
    channel: q.channel, terms_hex: [...q.termsHex], path_prefix_hex: [...q.prefixesHex], after: null, limit: q.maxMatches,
    returned_hits: docs.length, complete: true, next_after: null, indexed_documents: docs.length,
    indexed_source_bytes: docs.reduce((n, d) => n + d.bytes.length, 0), non_regular_entries: 0,
    segments_read: docs.length ? 1 : 0, payload_bytes_read: 256, generation_bytes_read: 128, work_units: 64,
    hits: docs.map(d => structuredClone(d.raw)), ...extras };
}
export function blobPage(doc, fields, extra = {}) {
  const offset = Number(fields.get('offset')), limit = Number(fields.get('limit'));
  const end = Math.min(doc.bytes.length, offset + limit), bytes = doc.bytes.subarray(offset, end);
  return { ...source(doc.algorithm), type: 'source_blob', path_hex: doc.raw.path_hex, object_id: doc.raw.blob,
    kind: 'file', symlink_followed: false, offset, total_bytes: doc.bytes.length, content_hex: hex(bytes),
    returned_bytes: bytes.length, next_offset: end < doc.bytes.length ? end : null, ...extra };
}
export function response(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}
export async function connected(respond, options = {}) {
  const requests = [];
  const client = new CodeSearch({ href, cryptoImpl: webcrypto, ...options, fetchImpl: async (url, init) => {
    const fields = new URLSearchParams(init.body), request = { path: url.pathname, fields, init };
    requests.push(request); return respond(request, requests.length);
  } });
  await client.connect(token, 'refs/heads/main', options.algorithm ?? 'sha1');
  return { client, requests };
}
