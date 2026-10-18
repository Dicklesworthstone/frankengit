// Native schema and prevalidated Initial result fixtures; not a live node.
import { createHash } from 'node:crypto';
import { CONTEXT_PROFILE, contextLimits, contextReply } from '../../crates/fgit-node/src/smart_http/server/browser/search-context.mjs';
export const hex = value => Buffer.from(value).toString('hex');
export const copy = value => structuredClone(value);
export const oid = (bytes, format) => createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
export function fixture(format = 'sha1') {
  const bytes = Buffer.from('pub struct Thing;\n'), pathHex = hex('src/thing.rs');
  const blob = oid(bytes, format), termsHex = [hex('thing')];
  const lexical = (channel, offset) => ({ query: { termsHex, channel },
    hits: [{ pathHex, blob, contentBytes: bytes.length, spans: [{ queryIndex: 0, offset, length: 5 }] }] });
  const retrieval = { query: { mode: 'initial' }, scope: { format }, pin: { commit: 'source-commit' },
    complete: true, content: lexical('content', 11), path: lexical('path', 4),
    symbols: { state: 'available', result: { hits: [{ pathHex, blob, offset: 11, length: 5,
      nameHex: hex('Thing'), rawIdentifier: false }] } }, vector: { lexical: { token: 'lexical', number: 3 }, symbols: { token: 'symbols', number: 7 } } };
  const wireRetrieval = { marker: 'the native Initial child, validated by initialReply in production' };
  const reply = { type: 'source_context_initial', schema_version: 1, profile: CONTEXT_PROFILE,
    read_only: true, transaction_created: false, source_material_untrusted: true, complete: true,
    candidate_files: 1, returned_files: 1, omitted_files: 0, selection: 'raw-path-prefix',
    source_blobs_read: 1, source_bytes_read: bytes.length, excerpt_bytes: bytes.length, source_file_limit: 8 * 1024 * 1024,
    context_max_files: 8, context_radius_bytes: 128, context_max_source_bytes: 64 * 1024 * 1024,
    context_max_excerpt_bytes: 256 * 1024, retrieval: wireRetrieval, files: [{ path_hex: pathHex, blob, source_bytes: bytes.length,
      anchors: [{ channel: 'content', byte_offset: 11, byte_length: 5 }, { channel: 'path', byte_offset: 4, byte_length: 5 },
        { channel: 'symbol', byte_offset: 11, byte_length: 5 }], excerpts: [{ byte_offset: 0, untrusted_bytes_hex: hex(bytes) }] }] };
  return { reply, retrieval, bytes };
}
export function check(f, limits = {}) { return contextReply(f.reply, f.retrieval, limits); }
export function limitsFor(f, input) {
  const limits = contextLimits(input);
  Object.assign(f.reply, { context_max_files: limits.maxFiles, context_radius_bytes: limits.radiusBytes,
    context_max_source_bytes: limits.maxSourceBytes, context_max_excerpt_bytes: limits.maxExcerptBytes,
    source_file_limit: Math.min(8 * 1024 * 1024, Math.floor(limits.maxSourceBytes / Math.max(1, f.reply.returned_files))) });
  return limits;
}
