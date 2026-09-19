// Native-API contract doubles only: these do not attest a live Rust node.
export const token = 'c'.repeat(64);
export const head = `alg:1:${'b'.repeat(64)}`;
export const actor = 'd'.repeat(32);
export const identity = { schema_version: 1, tenant_id: 'tenant', repository_id: 'repo',
  object_format: 'sha1', source_head: 'authority-head', snapshot_token: head };
export const issue = (number = 1, extra = {}) => ({ number, version: 1,
  title: 'Fix HTTP', body: 'native issue body', labels: ['bug'], state: 'open',
  opened_by: actor, last_actor: actor, comments: 0, ...extra });
export const predicate = extra => ({ state: null, opened_by: null, labels: [],
  text: null, case_sensitive: false, ...extra });
export function searchPage(extra = {}, query = {}) {
  const issues = extra.issues ?? [issue()];
  return { ...identity, type: 'issue_search_page', scope: 'repository_issues',
    query: { ...predicate(query), text_scope: 'title_or_body' },
    after: 0, limit: 20, max_scan: 200, scanned: issues.length, count: issues.length,
    complete: true, stop_reason: 'exhausted', has_more_candidates: false,
    next_after: null, refs_changed: false, transaction_created: false, issues, ...extra };
}
export const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
});
export const terminal = { ...identity, type: 'issue_publication', principal_id: actor,
  number: 1, expected_version: 1, action: 'comment', tx_id: 'tx', outcome: 'committed',
  decision_sequence: 2, repository_commit_id: 'rcr', refusal_record_id: null,
  refusal_code: null, delivery_acknowledged: null };
export function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}
