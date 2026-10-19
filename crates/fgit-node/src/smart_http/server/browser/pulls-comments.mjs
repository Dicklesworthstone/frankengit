// A canonical conversation has its own contiguous sequence and exact retry
// input. A comment grants no approval, PR metadata change, or actor identity.
import { binding, fail, integer, keys, oid, pinned, principal, snapshot, text, unhex } from './pulls-core.mjs';
import { checkedPath } from './pulls-candidate.mjs';

export const SOURCE_COMMENT_PROFILE = 'frankengit.source-comment.myers-lines.v1';
export const SOURCE_COMMENT_FIELDS = Object.freeze(['pull_request_version', 'source_ref_hex', 'target_ref_hex',
  'source_tip', 'target_tip', 'compared_base', 'comparison', 'path_hex', 'side', 'blob', 'mode',
  'byte_start', 'byte_end', 'line_start', 'line_count']);
export const SOURCE_COMMENT_LIMITS = Object.freeze({ lines: 128, spanBytes: 64 * 1024, blobBytes: 1024 * 1024 });

// This checks the closed protocol shape. Only native admission can authenticate
// a path/blob and whole-line range against the recorded PR trees.
export function sourceCommentAnchor(value, algorithm) {
  keys(value, ['profile', ...SOURCE_COMMENT_FIELDS]);
  if (value.profile !== SOURCE_COMMENT_PROFILE || SOURCE_COMMENT_FIELDS.some(name => !Object.hasOwn(value, name))) fail('Incomplete or unsupported source comment anchor.');
  const result = { profile: SOURCE_COMMENT_PROFILE,
    pull_request_version: integer(value.pull_request_version, 'anchored PR version', 1, Number.MAX_SAFE_INTEGER - 1) };
  for (const name of ['source_ref_hex', 'target_ref_hex']) {
    const bytes = unhex(value[name], 1024);
    const raw = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
    if (!raw.startsWith('refs/heads/') || raw.length === 11 || /[\x00-\x20\x7f~^:?*\[\\]/.test(raw) ||
        raw.includes('..') || raw.includes('@{') || raw.endsWith('.') ||
        raw.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) fail('Invalid anchored ref bytes.');
    result[name] = value[name];
  }
  if (result.source_ref_hex === result.target_ref_hex) fail('Anchored source and target refs must differ.');
  for (const name of ['source_tip', 'target_tip', 'compared_base']) result[name] = oid(value[name], algorithm);
  if (!['direct', 'merge_base'].includes(value.comparison) ||
      (value.comparison === 'direct' && result.compared_base !== result.target_tip)) fail('Invalid source comment comparison.');
  result.comparison = value.comparison;
  checkedPath(value.path_hex);
  if (unhex(value.path_hex).filter(byte => byte === 47).length >= 64) fail('Source comment path has too many components.');
  result.path_hex = value.path_hex;
  if (!['before', 'after'].includes(value.side) || !['100644', '100755', '120000'].includes(value.mode)) fail('Invalid anchored source side or mode.');
  result.side = value.side; result.blob = oid(value.blob, algorithm); result.mode = value.mode;
  result.byte_start = integer(value.byte_start, 'source comment byte start', 0, SOURCE_COMMENT_LIMITS.blobBytes - 1);
  result.byte_end = integer(value.byte_end, 'source comment byte end', result.byte_start + 1, SOURCE_COMMENT_LIMITS.blobBytes);
  result.line_start = integer(value.line_start, 'source comment line start', 0, result.byte_start);
  result.line_count = integer(value.line_count, 'source comment line count', 1, SOURCE_COMMENT_LIMITS.lines);
  const bytes = result.byte_end - result.byte_start;
  if (bytes > SOURCE_COMMENT_LIMITS.spanBytes || result.line_count > bytes ||
      (result.byte_start === 0) !== (result.line_start === 0)) fail('Invalid source comment range.');
  return result;
}

export function sourceCommentFields(anchor) {
  return Object.fromEntries(SOURCE_COMMENT_FIELDS.map(name => [`anchor_${name}`, anchor[name]]));
}

// Select one complete before/after text span from a validated, snapshot-bound
// PR diff. Candidate inspections and imported reports are not source selectors.
export function sourceCommentSelection(diff, entryIndex, hunkIndex, side) {
  const reply = diff?.reply;
  if (reply?.type !== 'source_diff' || reply.profile !== 'native-tree-review-v1' ||
      reply.complete !== true || reply.read_only !== true || reply.transaction_created !== false ||
      reply.published !== false || reply.approval_created !== false || reply.line_origin !== 0 ||
      reply.context_lines !== 3 || !['direct', 'merge-base'].includes(reply.mode) ||
      !['before', 'after'].includes(side)) fail('Select a source comment from the complete recorded PR comparison.');
  const selected = pinned(reply, diff.binding, diff.head);
  snapshot(selected.head); integer(reply.pull_request?.number, 'source comment PR number', 1);
  integer(entryIndex, 'source comment entry'); integer(hunkIndex, 'source comment hunk');
  const entry = diff.comparison?.entries?.[entryIndex], content = entry?.content, hunk = content?.hunks?.[hunkIndex];
  if (content?.type !== 'text' || content.algorithm !== 'Myers' || !hunk || !entry[side]) fail('Select a nonempty native text span.');
  const bytes = unhex(hunk[`${side}_hex`], SOURCE_COMMENT_LIMITS.spanBytes), span = hunk[side === 'before' ? 'old' : 'new'];
  const total = integer(content[`${side}_bytes`], 'source comment blob bytes', 1, SOURCE_COMMENT_LIMITS.blobBytes);
  if (!bytes.length || bytes.includes(0) || span.byte_end - span.byte_start !== bytes.length || span.byte_end > total ||
      (span.byte_end < total && bytes.at(-1) !== 10)) fail('Source comments require complete nonbinary lines.');
  let lines = bytes.at(-1) === 10 ? 0 : 1;
  for (const byte of bytes) if (byte === 10) lines += 1;
  if (span.line_count !== lines) fail('Source comment bytes and line count disagree.');
  const anchor = sourceCommentAnchor({ profile: SOURCE_COMMENT_PROFILE,
    pull_request_version: reply.pull_request.version, source_ref_hex: reply.after_ref_hex, target_ref_hex: reply.before_ref_hex,
    source_tip: reply.requested_after, target_tip: reply.requested_before, compared_base: reply.compared_before,
    comparison: reply.mode === 'merge-base' ? 'merge_base' : 'direct', path_hex: entry.path_hex,
    side, blob: entry[side].oid, mode: entry[side].mode.toString(8), ...span }, selected.binding.format);
  return { number: reply.pull_request.number, head: selected.head, anchor, excerpt_hex: hunk[`${side}_hex`] };
}

export function commentsReply(reply, number, { after = 0, limit = 20, head = null, scope = null } = {}) {
  integer(number, 'PR number', 1); integer(after, 'comment cursor'); integer(limit, 'page size', 1, 100);
  keys(reply, ['schema_version', 'type', 'tenant_id', 'repository_id', 'repository_incarnation',
    'object_format', 'number', 'found', 'source_head', 'snapshot_token', 'discussion_version',
    'after', 'limit', 'next_after', 'complete', 'merge_permission', 'transaction_created', 'comments']);
  const selectedBinding = binding(reply, scope);
  if (reply.type !== 'pull_request_comments' || reply.number !== number || typeof reply.found !== 'boolean' ||
      reply.after !== after || reply.limit !== limit || reply.merge_permission !== null || reply.transaction_created !== false ||
      typeof reply.complete !== 'boolean' || reply.complete !== (reply.next_after === null) ||
      !Array.isArray(reply.comments) || reply.comments.length > limit) fail('Invalid conversation page.');
  if (!reply.found) {
    if (reply.comments.length || reply.next_after !== null || reply.source_head !== null ||
        reply.snapshot_token !== null || reply.discussion_version !== null) fail('Unavailable conversation disclosed data.');
    return { binding: selectedBinding, head: null, reply };
  }
  const selected = pinned(reply, selectedBinding, head);
  const high = integer(reply.discussion_version, 'conversation version');
  if (reply.comments.length !== Math.min(Math.max(high - after, 0), limit)) fail('Conversation page omitted a committed position.');
  let previous = after;
  for (const row of reply.comments) {
    keys(row, ['version', 'actor', 'body', 'body_rendered', 'anchor', 'anchor_status']);
    if (integer(row.version, 'comment version', 1) !== previous + 1 || row.version > high) fail('Conversation positions are not contiguous.');
    previous = row.version; principal(row.actor); text(row.body, 64 * 1024, 'comment body');
    if (!row.body.trim()) fail('Empty canonical comment.');
    if (Object.hasOwn(row, 'anchor') !== Object.hasOwn(row, 'anchor_status')) fail('Incomplete source comment status.');
    if (Object.hasOwn(row, 'anchor')) {
      sourceCommentAnchor(row.anchor, selected.binding.format);
      if (!['exact', 'outdated'].includes(row.anchor_status)) fail('Unsupported source comment status.');
    }
  }
  if (reply.next_after !== (previous < high ? previous : null)) fail('Conversation cursor disagrees with its high water.');
  return { ...selected, reply };
}
