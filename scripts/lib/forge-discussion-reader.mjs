// Bounded, snapshot-pinned discussion reads through the shipped public client.
// These are authenticated server observations, not independent authority proofs.
import { DiscussionClient } from '../../crates/fgit-node/src/smart_http/server/browser/discussions.mjs';
import { natural, snapshotToken } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { issueConnectionOptions, connectIssueToken, issueOperatorFetch } from './forge-issue-operator.mjs';
import { operatorError, operatorJson } from './forge-operator-io.mjs';

const fail = code => { throw operatorError(code); };
export function discussionReadOptions(raw) {
  const keys = ['operation', 'href', 'tenant', 'repository', 'tokenFile', 'timeoutMs', 'signal', 'onProgress',
    'number', 'after', 'head', 'limit', 'maxPages', 'maxOutputBytes'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(key => !keys.includes(key))) fail('discussion_read_options');
  const o = issueConnectionOptions(raw, 'discussion');
  if (!['list', 'show'].includes(o.operation)) fail('discussion_read_operation');
  o.after = natural(raw.after ?? 0, 'cursor');
  o.limit = natural(raw.limit ?? 20, 'page size', 1, 100);
  o.maxPages = natural(raw.maxPages ?? 1, 'page budget', 1, 100);
  o.maxOutputBytes = natural(raw.maxOutputBytes ?? 8 * 1024 * 1024, 'output budget', 1, 8 * 1024 * 1024);
  o.head = raw.head ?? null;
  if (o.head !== null) snapshotToken(o.head);
  if (o.after && o.head === null) fail('discussion_read_snapshot_required');
  if (o.operation === 'show') natural(o.number, 'discussion number', 1);
  else if (raw.number !== undefined) fail('discussion_read_number_inapplicable');
  return o;
}

// Return only fields checked by DiscussionClient. Unknown response extensions,
// rendered HTML and any other server-provided properties are not CLI data.
function checkedPage(reply, operation) {
  const row = value => value === null ? null : Object.fromEntries([
    'number', 'version', 'title', 'body', 'state', 'locked', 'opened_by', 'last_actor', 'comments',
  ].map(key => [key, value[key]]));
  const common = { type: reply.type, schema_version: reply.schema_version, scope: reply.scope,
    tenant_id: reply.tenant_id, repository_id: reply.repository_id,
    snapshot_token: reply.snapshot_token, limit: reply.limit };
  if (operation === 'list') return { ...common, after: reply.after,
    discussions: reply.discussions.map(row), next_after: reply.next_after };
  return { ...common, found: reply.found, discussion: row(reply.discussion), after_version: reply.after_version,
    events: reply.events.map(event => ({ version: event.version, actor: event.actor,
      action: Object.fromEntries(['name', 'title', 'body'].filter(key => Object.hasOwn(event.action, key))
        .map(key => [key, event.action[key]])) })), next_after_version: reply.next_after_version };
}

export async function runDiscussionRead(raw) {
  const o = discussionReadOptions(raw), stop = new AbortController();
  const signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const check = () => { if (signal.aborted) fail('discussion_read_cancelled_or_deadline'); };
  const timer = setTimeout(() => stop.abort(), o.timeoutMs);
  const client = new DiscussionClient({ href: o.href, timeoutMs: o.timeoutMs,
    fetchImpl: (url, init) => issueOperatorFetch(url, init, signal) });
  const pages = []; let head = o.head, after = o.after, next = null, retained = 0;
  try {
    check(); await connectIssueToken(client, o, check);
    while (pages.length < o.maxPages) {
      check();
      const page = await client.read(o.operation === 'show' ? o.number : null, { after, limit: o.limit, head });
      check();
      if (page.binding.tenant !== o.tenant || page.binding.repository !== o.repository) fail('discussion_operator_repository_mismatch');
      if (head !== null && page.head !== head) fail('discussion_read_snapshot_moved');
      head = page.head;
      next = o.operation === 'show' ? page.reply.next_after_version : page.reply.next_after;
      if (next !== null && (!Number.isSafeInteger(next) || next <= after)) fail('discussion_read_cursor_stalled');
      const reply = checkedPage(page.reply, o.operation);
      retained += Buffer.byteLength(operatorJson(reply));
      if (retained > o.maxOutputBytes) fail('discussion_read_output_limit');
      pages.push(reply);
      o.onProgress(Object.freeze({ phase: 'page_checked', pages: pages.length, next_after: next })); check();
      if (next === null) break;
      after = next;
    }
    const continuation = next === null ? null : { operation: o.operation, expected_head: head, after: next,
      ...(o.operation === 'show' ? { number: o.number } : {}), limit: o.limit };
    const result = { type: 'forge_discussion_operator_read', schema_version: 1, operation: o.operation, href: o.href,
      tenant_id: o.tenant, repository_id: o.repository, snapshot_token: head, initial_after: o.after,
      page_count: pages.length, complete: next === null, stop_reason: next === null ? 'exhausted' : 'page_budget',
      read_only: true, mutation_submitted: false, continuation, pages };
    if (Buffer.byteLength(operatorJson(result)) > o.maxOutputBytes) fail('discussion_read_output_limit');
    check(); return result;
  } catch (cause) {
    const error = cause instanceof Error ? cause : operatorError('discussion_read_failed');
    error.operator_state = 'read_incomplete';
    // A failed later page never turns the saved prefix into a successful read.
    throw error;
  } finally { clearTimeout(timer); client.disconnect(); }
}
