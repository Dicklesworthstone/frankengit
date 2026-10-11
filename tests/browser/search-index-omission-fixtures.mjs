// Lexical v2 wire fixtures, not a native index or authority implementation.
import { hex, nativeHash } from './search-index-fixtures.mjs';

export function omission(format = 'sha1', path = Buffer.from('vendor/oversized.bin')) {
  const bytes = Buffer.alloc(128, 97);
  return { path_hex: hex(path), blob: `${format}:${nativeHash(bytes, format)}`,
    source_bytes: bytes.length, reason: 'file_bytes', limit: 64 };
}
export function partialReply(reply, omissions = [omission(reply.object_format)]) {
  Object.assign(reply, { schema_version: 2, index_profile: 'ascii-word-postings-omissions-v1',
    coverage_complete: false, omitted_files: omissions.length,
    omitted_source_bytes: omissions.reduce((total, entry) => total + entry.source_bytes, 0),
    omissions: structuredClone(omissions) });
  return reply;
}
export function partialInitial(reply, omissions = [omission(reply.object_format)]) {
  partialReply(reply.content, omissions); partialReply(reply.path, omissions);
  reply.complete = false;
  reply.retained_result_bytes += 2 * omissions.reduce((total, entry) => total + entry.path_hex.length / 2 + 96, 0);
  return reply;
}
export function revalidatedReply(reply) {
  const fields = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref_hex',
    'source_head', 'snapshot_token', 'source_rcr', 'source_commit', 'root_tree'];
  const current = { ...Object.fromEntries(fields.map(field => [field, reply[field]])), forge_position_root: `alg:2:${'d'.repeat(64)}` };
  Object.assign(reply, { type: 'source_search_index_current', profile: 'source-lexical-revalidated-v1',
    source_mode: 'revalidated', distinct_provenance: true, current_source: current,
    indexed_source: { ...current, source_head: 'original-authority-head', snapshot_token: `alg:2:${'e'.repeat(64)}`,
      source_rcr: 'original-rcr', forge_position_root: `alg:2:${'f'.repeat(64)}` },
    index_number: '9007199254740993', selected_index_number: '9007199254740993',
    after: reply.after === null ? null : String(reply.after), next_after: reply.next_after === null ? null : String(reply.next_after) });
  for (const hit of reply.hits) hit.document_id = String(hit.document_id);
  return reply;
}
