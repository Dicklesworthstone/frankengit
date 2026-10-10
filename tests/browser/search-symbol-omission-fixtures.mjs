// Source-derived symbol v2 wire receipts. These are not executions of a native
// index builder or locally authenticated generation proofs.
import { createHash } from 'node:crypto';
import { hex } from './search-symbol-fixtures.mjs';
export function omission(format = 'sha1', path = Buffer.from('broken/ff\xff.rs', 'latin1')) {
  const body = Buffer.from('fn Discarded() {} fn Broken() {\n');
  return { path_hex: hex(path), blob: createHash(format).update(`blob ${body.length}\0`).update(body).digest('hex'),
    source_bytes: body.length, reason: 'unbalanced_delimiter', byte_offset: body.length, limit: null };
}
export function partialReply(reply, omissions = [omission(reply.object_format)]) {
  Object.assign(reply, { schema_version: 2, index_profile: 'rust-declaration-omissions-v1', coverage_complete: false,
    coverage_scope: 'recorded-rust-files', omitted_files: omissions.length,
    omitted_source_bytes: omissions.reduce((total, entry) => total + entry.source_bytes, 0), omissions: structuredClone(omissions) });
  return reply;
}
