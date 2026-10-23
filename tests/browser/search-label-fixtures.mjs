// Opaque native-schema label fixtures for structural/membership validation.
// These strings are not cryptographic, credential, authentication or live Rust
// evidence. Existing independent native Git blob identity fixtures stay intact.
import { fixture } from './search-initial-fixtures.mjs';
export function labelledInitialFixture(options = {}) {
  const f = fixture(options);
  f.reply.authorization = { profile: 'source-read-result-labels-v1', host: 'http-repository-read-credential',
    principal: '9'.repeat(32), scope: 'whole-repository', binding: 'a'.repeat(64), reusable_capability: false };
  let ordinal = 0;
  for (const [rows, domain] of [[f.reply.content.hits, 'source-blob-bytes'], [f.reply.path.hits, 'raw-path-bytes'],
    [f.reply.symbols.result?.matches ?? [], 'source-declaration-bytes']]) {
    for (const row of rows) Object.assign(row, { authorization_label: (++ordinal).toString(16).padStart(64, '0'), position_domain: domain });
  }
  f.reply.retained_result_bytes += ordinal * 192 + 768 + f.reply.ref_hex.length / 2;
  return f;
}
export function labelledContextFixture(options = {}) {
  const initial = labelledInitialFixture(options), file = initial.files[0], commitment = 'c'.repeat(64);
  const origins = [initial.reply.content.hits[0].authorization_label, initial.reply.path.hits[0].authorization_label,
    initial.reply.symbols.result.matches[0].authorization_label];
  const reply = { type: 'source_context_initial', schema_version: 1, profile: 'source-initial-context-v1', read_only: true,
    transaction_created: false, source_material_untrusted: true, complete: false, candidate_files: 2, returned_files: 1,
    omitted_files: 1, selection: 'raw-path-prefix', source_blobs_read: 1, source_bytes_read: file.bytes.length,
    excerpt_bytes: file.bytes.length, source_file_limit: 8 * 1024 * 1024,
    context_max_files: 1, context_radius_bytes: 128, context_max_source_bytes: 64 * 1024 * 1024,
    context_max_excerpt_bytes: 256 * 1024,
    // Three distinct origin rows, three deduped anchors, two possible source windows.
    lineage_metadata_bytes: 3 * 256 + 3 * 256 + 1024 + 2 * 192,
    retrieval: initial.reply, files: [{ path_hex: file.pathHex, blob: file.blob, source_bytes: file.bytes.length,
      position_domain: 'source-blob-bytes', lineage_commitment: commitment, authorization_labels: origins,
      anchors: ['content', 'path', 'symbol'].map((channel, i) => ({ channel,
        byte_offset: channel === 'path' ? file.path.indexOf('needle') : file.at, byte_length: 6,
        position_domain: channel === 'path' ? 'raw-path-bytes' : 'source-blob-bytes', authorization_label: origins[i] })),
      excerpts: [{ byte_offset: 0, untrusted_bytes_hex: Buffer.from(file.bytes).toString('hex'),
        position_domain: 'source-blob-bytes', lineage_commitment: commitment }] }] };
  return { initial, reply, limits: { maxFiles: 1 } };
}
