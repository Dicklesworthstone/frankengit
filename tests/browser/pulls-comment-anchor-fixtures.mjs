import { hex, refFields } from './pulls-fixtures.mjs';

export function anchor(format = 'sha1', extra = {}) {
  const width = format === 'sha1' ? 40 : 64;
  return { profile: 'frankengit.source-comment.myers-lines.v1', pull_request_version: 1,
    source_ref_hex: refFields.source_ref_hex, target_ref_hex: refFields.target_ref_hex,
    source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width), compared_base: 'e'.repeat(width),
    comparison: 'merge_base', path_hex: hex('src/main.rs'), side: 'after', blob: 'd'.repeat(width),
    mode: '100644', byte_start: 0, byte_end: 5, line_start: 0, line_count: 2, ...extra };
}
