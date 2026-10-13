// Full capture validators and unchanged sender preparation; no substituted modules.
import test from 'node:test';
import assert from 'node:assert/strict';
import { draftCandidateReview } from '../../scripts/operator/pull_candidate_draft.mjs';
import { preparePull, pullEnvelope, validatePullIntent } from '../../scripts/operator/pull_command.mjs';
import { capturePullCandidate } from '../../scripts/operator/pull_candidate_capture.mjs';
import { localCapture } from './pull_candidate_package_fixture.mjs';
import { candidatePeer, TOKEN, REVIEWER } from './pull_candidate_fixture.mjs';

const ACTOR = 'e'.repeat(32);
function choice(value, action = 'approve', actor = REVIEWER) {
  const raw = value.capture.preparation.candidate?.commit?.split(':')[1] ?? 'a'.repeat(40);
  return { action, principal_id: actor, candidate_commit: raw, ...(action === 'merge'
    ? { method: value.capture.request.method, required_reviewers: [REVIEWER] } : { reason: 'Inspect this exact candidate.\n🦀' }) };
}
for (const algorithm of ['sha1', 'sha256']) for (const method of ['merge-commit', 'squash']) for (const action of ['approve', 'request-changes', 'merge']) {
  test(`${algorithm} ${method} ${action}: exact inspected coordinates enter the unchanged preparer`, async () => {
    const value = await localCapture(algorithm, method), selected = choice(value, action, action === 'merge' ? ACTOR : REVIEWER);
    const draft = await draftCandidateReview(value.capture, value.bundle, selected);
    assert.equal(draft.fields.candidate_commit, selected.candidate_commit); assert.equal(draft.fields.pull_request_version, '9');
    assert.equal(draft.fields.policy_epoch, '3'); assert.equal(draft.fields.source_ref, 'refs/heads/source');
    assert.equal(draft.fields.target_tip, value.capture.inspection.subject.target_tip.split(':')[1]);
    if (action === 'merge') { assert.equal(draft.fields.method, method); assert.deepEqual(draft.fields.required_reviewers, [REVIEWER]); }
    else assert.equal(draft.fields.expected_version, '2');
    assert.equal(Object.hasOwn(draft, 'key'), false); assert.equal(Object.hasOwn(draft, 'bundle'), false);
    const intent = preparePull(draft, TOKEN, value.bundle), original = JSON.stringify(intent), envelope = pullEnvelope(intent, value.bundle);
    assert.deepEqual(validatePullIntent(intent), intent); assert.equal(intent.scope.principal_id, selected.principal_id);
    assert.equal(intent.body.includes('principal'), false); assert.ok(envelope.body.includes(value.bundle));
    draft.fields.policy_epoch = '99'; selected.principal_id = 'f'.repeat(32);
    assert.equal(JSON.stringify(intent), original);
  });
}
for (const row of ['second-page', 'absent', 'stale']) test(`review predecessor selection: ${row}`, async t => {
  const p = await candidatePeer(t, { reviewCount: 51 });
  const actor = row === 'absent' ? ACTOR : (51).toString(16).padStart(32, '0');
  if (row === 'stale') { p.reviews[50].freshness = 'source_moved'; p.reviews[50].subject.source_tip = 'sha1:' + '1'.repeat(40); p.reviews[50].version = 17; }
  const value = await capturePullCandidate(p.input, TOKEN), count = p.requests.length;
  const result = await draftCandidateReview(value.capture, value.bundle, choice(value, 'approve', actor));
  assert.equal(result.fields.expected_version, row === 'absent' ? '0' : row === 'stale' ? '17' : '2');
  assert.equal(result.fields.source_tip, p.fixture.source); assert.equal(p.requests.length, count);
});
for (const state of ['conflicted', 'already_up_to_date']) test(`${state} cannot become a draft`, async () => {
  const value = await localCapture('sha1', 'merge-commit', state);
  await assert.rejects(draftCandidateReview(value.capture, value.bundle, choice(value)), { code: 'candidate_draft_requires_clean_inspection' });
});
const corrupt = [
  c => c.candidate_commit = '0'.repeat(40), c => c.candidate_commit = 'sha1:' + c.candidate_commit,
  c => c.principal_id = 'invalid', c => c.reason = '', c => c.reason = 'x'.repeat(4097), c => c.reason = '\uD800',
  c => c.reason = '\0', c => c.action = 'withdraw', c => c.action = 'fast-forward', c => c.action = '../apply',
  c => c.endpoint = 'https://foreign.invalid/repo.git', c => c.expected_version = '99', c => c.policy_epoch = '99',
  c => c.method = 'squash', c => c.required_reviewers = [REVIEWER], c => delete c.candidate_commit,
];
for (const edit of corrupt) test(`closed review choices refuse: ${edit}`, async () => {
  const v = await localCapture(), c = choice(v); edit(c);
  await assert.rejects(draftCandidateReview(v.capture, v.bundle, c));
});
for (const edit of [c => c.method = 'squash', c => c.required_reviewers = [], c => c.required_reviewers = [ACTOR],
  c => c.required_reviewers = [REVIEWER, REVIEWER], c => c.required_reviewers = ['bad'], c => c.required_reviewers = Array(33).fill(REVIEWER),
  c => c.reason = 'not applicable', c => delete c.method]) test(`explicit merge requirements refuse: ${edit}`, async () => {
  const v = await localCapture(), c = choice(v, 'merge', ACTOR); edit(c);
  await assert.rejects(draftCandidateReview(v.capture, v.bundle, c));
});
test('merge requirements are explicit, not inferred from current approval labels', async () => {
  const v = await localCapture(), c = choice(v, 'merge', ACTOR);
  c.required_reviewers = ['d'.repeat(32), REVIEWER];
  const d = await draftCandidateReview(v.capture, v.bundle, c);
  assert.deepEqual(d.fields.required_reviewers, [REVIEWER, 'd'.repeat(32)]);
  assert.equal(v.capture.review_pages[0].reviews[0].decision, 'request-changes');
  assert.equal(Object.hasOwn(d, 'merge_authorized'), false);
});
test('corrupt bundle, incomplete reviewers and altered inspection refuse even for valid choices', async () => {
  const v = await localCapture(), c = choice(v), bytes = Buffer.from(v.bundle); bytes[0] ^= 1;
  await assert.rejects(draftCandidateReview(v.capture, bytes, c));
  await assert.rejects(draftCandidateReview(v.capture, null, c));
  for (const edit of [r => r.review_pages = [], r => r.review_pages[0].next_after = REVIEWER,
    r => r.inspection = null, r => r.inspection.candidate_commit_body_hex += '20']) {
    const copy = structuredClone(v.capture); edit(copy); await assert.rejects(draftCandidateReview(copy, v.bundle, c));
  }
});
test('choice, reports, and bundle mutations during the first digest do not change a draft', async () => {
  const v = await localCapture(), c = choice(v), candidate = c.candidate_commit;
  const promise = draftCandidateReview(v.capture, v.bundle, c);
  c.reason = 'replaced'; c.candidate_commit = '0'.repeat(40); v.capture.request.number = '8'; v.bundle.fill(0);
  const result = await promise;
  assert.equal(result.fields.candidate_commit, candidate); assert.equal(result.number, '7');
  assert.equal(result.fields.reason, 'Inspect this exact candidate.\n🦀');
});
test('cancellation, unknown options, and shared mutable bundle bytes refuse', async () => {
  const v = await localCapture(), c = choice(v), controller = new AbortController(); controller.abort();
  await assert.rejects(draftCandidateReview(v.capture, v.bundle, c, { signal: controller.signal }), { code: 'candidate_cancelled' });
  await assert.rejects(draftCandidateReview(v.capture, v.bundle, c, { force: true }));
  await assert.rejects(draftCandidateReview(v.capture, new Uint8Array(new SharedArrayBuffer(10)), c), { code: 'candidate_shared_bundle_refused' });
});
