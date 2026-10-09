// Bounded read-only terminal workflow using the same native issue client.
// Cursor progression follows examined candidates, not the number of matches.
import { IssueClient, natural, snapshotToken, issueSearchQuery } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { issueConnectionOptions, connectIssueToken } from './forge-issue-operator.mjs';
import { operatorError, operatorJson } from './forge-operator-io.mjs';
const fail = code => { throw operatorError(code); };
export function issueReadOptions(raw) {
  const keys = ['operation', 'href', 'tenant', 'repository', 'tokenFile', 'timeoutMs', 'signal', 'onProgress',
    'number', 'after', 'head', 'limit', 'maxPages', 'maxOutputBytes', 'maxScan', 'query'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !keys.includes(k))) fail('issue_read_options');
  const o = issueConnectionOptions(raw);
  if (!['list', 'show', 'search'].includes(o.operation)) fail('issue_read_operation');
  o.after = natural(raw.after ?? 0, 'cursor');
  o.limit = natural(raw.limit ?? 20, 'page size', 1, 100);
  o.maxPages = natural(raw.maxPages ?? 1, 'page budget', 1, 100);
  o.maxOutputBytes = natural(raw.maxOutputBytes ?? 8 * 1024 * 1024, 'output budget', 1, 8 * 1024 * 1024);
  o.head = raw.head ?? null;
  if (o.head !== null) snapshotToken(o.head);
  if (o.after && o.head === null) fail('issue_read_snapshot_required');
  if (o.operation === 'show') natural(o.number, 'issue number', 1);
  else if (raw.number !== undefined) fail('issue_read_number_inapplicable');
  if (o.operation === 'search') {
    o.query = issueSearchQuery(raw.query ?? {});
    o.maxScan = natural(raw.maxScan ?? 200, 'scan budget', 1, 1000);
  } else if (raw.query !== undefined || raw.maxScan !== undefined) fail('issue_read_search_inapplicable');
  return o;
}
export async function runIssueRead(raw) {
  const o = issueReadOptions(raw), stop = new AbortController();
  const signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const check = () => { if (signal.aborted) fail('issue_read_cancelled_or_deadline'); };
  const timer = setTimeout(() => stop.abort(), o.timeoutMs);
  const client = new IssueClient({ href: o.href, timeoutMs: o.timeoutMs,
    fetchImpl: (url, init) => fetch(url, { ...init, signal: AbortSignal.any([signal, init.signal]) }) });
  const pages = []; let head = o.head, after = o.after, next = null, retained = 0;
  try {
    check(); await connectIssueToken(client, o, check);
    while (pages.length < o.maxPages) {
      check();
      const parameters = { after, limit: o.limit, head };
      const page = o.operation === 'search'
        ? await client.search(o.query, { ...parameters, maxScan: o.maxScan })
        : await client.read(o.operation === 'show' ? o.number : null, parameters);
      check();
      if (page.binding.tenant !== o.tenant || page.binding.repository !== o.repository) fail('issue_operator_repository_mismatch');
      if (head !== null && page.head !== head) fail('issue_read_snapshot_moved');
      head = page.head;
      next = o.operation === 'show' ? page.reply.next_after_version : page.reply.next_after;
      if (next !== null && (!Number.isSafeInteger(next) || next <= after)) fail('issue_read_cursor_stalled');
      retained += Buffer.byteLength(operatorJson(page.reply));
      if (retained > o.maxOutputBytes) fail('issue_read_output_limit');
      pages.push(page.reply);
      o.onProgress(Object.freeze({ phase: 'page_checked', pages: pages.length, next_after: next })); check();
      if (next === null) break;
      after = next; // Even a zero-hit search page can advance the scan cursor.
    }
    const continuation = next === null ? null : { operation: o.operation, expected_head: head, after: next,
      ...(o.operation === 'show' ? { number: o.number } : {}),
      ...(o.operation === 'search' ? { query: o.query, max_scan: o.maxScan } : {}), limit: o.limit };
    const result = { type: 'forge_issue_operator_read', operation: o.operation, href: o.href,
      tenant_id: o.tenant, repository_id: o.repository, snapshot_token: head, initial_after: o.after,
      page_count: pages.length, complete: next === null, stop_reason: next === null ? 'exhausted' : 'page_budget',
      read_only: true, mutation_submitted: false, continuation, pages };
    // Include the actual envelope/escaping overhead in the final output budget.
    if (Buffer.byteLength(operatorJson(result)) > o.maxOutputBytes) fail('issue_read_output_limit');
    check(); return result;
  } catch (cause) {
    const error = cause instanceof Error ? cause : operatorError('issue_read_failed');
    error.operator_state = 'read_incomplete';
    // Do not return an apparently complete prefix after a later failed page.
    throw error;
  } finally { clearTimeout(timer); client.disconnect(); }
}
