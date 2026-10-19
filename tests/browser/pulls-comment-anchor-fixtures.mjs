import { hex, refFields, ids, head } from './pulls-fixtures.mjs';

export function anchor(format = 'sha1', extra = {}) {
  const width = format === 'sha1' ? 40 : 64;
  return { profile: 'frankengit.source-comment.myers-lines.v1', pull_request_version: 1,
    source_ref_hex: refFields.source_ref_hex, target_ref_hex: refFields.target_ref_hex,
    source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width), compared_base: 'e'.repeat(width),
    comparison: 'merge_base', path_hex: hex('src/main.rs'), side: 'after', blob: 'd'.repeat(width),
    mode: '100644', byte_start: 0, byte_end: 5, line_start: 0, line_count: 2, ...extra };
}

export function sourceDiff(format = 'sha1', mode = 'merge-base', extra = {}) {
  const width = format === 'sha1' ? 40 : 64;
  return { ...ids, object_format: format, type: 'source_diff', profile: 'native-tree-review-v1',
    source_head: 'head-id', snapshot_token: head, mode, pull_request: { number: 1, version: 1 },
    read_only: true, transaction_created: false, published: false, approval_created: false, complete: true,
    line_origin: 0, context_lines: 3, before_ref_hex: refFields.target_ref_hex, after_ref_hex: refFields.source_ref_hex,
    requested_before: 'b'.repeat(width), requested_after: 'a'.repeat(width), compared_before: (mode === 'direct' ? 'b' : 'e').repeat(width),
    before_tree: 'f'.repeat(width), after_tree: '1'.repeat(width), entry_count: 1, path_prefixes_hex: [],
    entries: [{ path_hex: hex('src/main.rs'), kind: 'modified', before: { mode: '100644', object_id: 'c'.repeat(width) },
      after: { mode: '100644', object_id: 'd'.repeat(width) }, content: { kind: 'text', algorithm: 'Myers', additions: 1, deletions: 1,
        before_bytes: 5, after_bytes: 5, hunks: [{ old: { byte_start: 0, byte_end: 5, line_start: 0, line_count: 2 },
          new: { byte_start: 0, byte_end: 5, line_start: 0, line_count: 2 }, before_hex: '610d0aff62', after_hex: '610d0afe63' }] } }], ...extra };
}
