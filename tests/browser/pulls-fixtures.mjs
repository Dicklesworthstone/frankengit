import { webcrypto } from 'node:crypto';
export { webcrypto };
export const token = 'c'.repeat(64), actor = '3'.repeat(32), reviewer = '4'.repeat(32);
export const head = `alg:1:${'b'.repeat(64)}`;
export const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '5'.repeat(32), object_format: 'sha1' };
export const scope = { tenant: ids.tenant_id, repository: ids.repository_id, incarnation: ids.repository_incarnation, format: ids.object_format };
export const hex = s => Buffer.from(s).toString('hex');
export const refFields = { source_ref: 'refs/heads/topic', source_ref_hex: hex('refs/heads/topic'), target_ref: 'refs/heads/main', target_ref_hex: hex('refs/heads/main') };
export const data = (extra = {}) => ({ ...refFields, object_format: 'sha1', source_tip: 'a'.repeat(40), target_tip: 'b'.repeat(40), title: 'Title 🦀', body: '<script>inert</script>', ...extra });
export const row = (number = 1, extra = {}) => ({ number, version: 1, state: 'open', data: data(), opened_by: actor, last_metadata_actor: actor, merge_only: false, merge: null, ...extra });
export const page = (extra = {}) => ({ ...ids, type: 'pull_request_page', snapshot_token: head, source_head: 'head-id', after: 0, limit: 20, next_after: null, pull_requests: [row()], ...extra });
export const show = (extra = {}) => ({ ...ids, type: 'pull_request', snapshot_token: head, source_head: 'head-id', number: 1, found: true, pull_request: row(), ...extra });
export const subject = (extra = {}) => ({ object_format: 'sha1', pull_request_version: 1, policy_epoch: 1, source_ref: refFields.source_ref, target_ref: refFields.target_ref,
  source_tip: 'a'.repeat(40), target_tip: 'b'.repeat(40), ...extra });
export const rawSubject = (extra = {}) => { const { object_format: _, ...rest } = subject(); return { number: 1, ...rest, ...refFields, ...extra }; };
export const reviewRow = (extra = {}) => ({ reviewer, version: 1, subject: rawSubject(), candidate: { merge_base: 'e'.repeat(40), candidate_commit: 'd'.repeat(40) }, decision: 'approve', reason: 'Exact candidate', freshness: 'current', reviewer_is_opener: false, ...extra });
export const reviews = (extra = {}) => ({ ...ids, type: 'review_page', number: 1, found: true, source_head: 'head-id', snapshot_token: head,
  pull_request_version: 1, policy_epoch: 1, after: null, limit: 20, next_after: null, merge_authorized: false, reviews: [reviewRow()], ...extra });
export const metadata = (extra = {}) => { const { source_ref_hex: _, target_ref_hex: __, ...rest } = data(); return { expected_version: 1, ...rest, ...extra }; };
export const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
export const options = fetchImpl => ({ href: 'https://forge.example/team/repo.git/ui/pulls/', fetchImpl, cryptoImpl: webcrypto });
export const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
