// A canonical conversation has its own contiguous sequence and exact retry
// input. A comment grants no approval, PR metadata change, or actor identity.
import { binding, fail, integer, keys, pinned, principal, text } from './pulls-core.mjs';

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
    keys(row, ['version', 'actor', 'body', 'body_rendered']);
    if (integer(row.version, 'comment version', 1) !== previous + 1 || row.version > high) fail('Conversation positions are not contiguous.');
    previous = row.version; principal(row.actor); text(row.body, 64 * 1024, 'comment body');
    if (!row.body.trim()) fail('Empty canonical comment.');
  }
  if (reply.next_after !== (previous < high ? previous : null)) fail('Conversation cursor disagrees with its high water.');
  return { ...selected, reply };
}
