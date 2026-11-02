import test from 'node:test';
import assert from 'node:assert/strict';
import { policy, prepareIntent, validateIntent, canonical } from '../../scripts/operator/review_protection.mjs';
import { intentSummary } from '../../scripts/fg_protection_admin.mjs';
import { TOKEN, ACTOR, SCOPE, POLICY, NEXT, ref, state } from './protection_fixtures.mjs';
const plan = extra => prepareIntent({ endpoint: 'https://forge.example/team/repo.git', token: TOKEN, principal_id: ACTOR,
  expectedScope: SCOPE, snapshot: state(), replacement: NEXT, nonce: 'e'.repeat(32), ...extra });
const check = (job = 'test:日本語') => ({ publisher: '55'.repeat(16), graph_root: '66'.repeat(32), job });
const selected = () => ({ administrators: [ACTOR], branches: [{
  reference_hex: ref('refs/heads/main'), required_reviewers: [], required_candidate_checks: [check()],
}] });

test('omitted and empty candidate selectors preserve existing operator intent bytes', () => {
  const before = structuredClone(POLICY), after = structuredClone(NEXT);
  before.branches[0].required_candidate_checks = []; after.branches[0].required_candidate_checks = [];
  assert.deepEqual(plan({ snapshot: state({ policy: before }), replacement: after }), plan());
});

test('candidate-only policy retains exact form and recovery identity and shows removals explicitly', () => {
  const replacement = selected(), intent = plan({ replacement });
  const expected = ref('refs/heads/main') + ':' + check().publisher + ':' + check().graph_root + ':' + Buffer.from(check().job).toString('hex');
  assert.deepEqual(new URLSearchParams(intent.request.body).getAll('required_candidate_check'), [expected]);
  assert.equal(new URLSearchParams(intent.request.body).has('required_check'), false);
  assert.deepEqual(validateIntent(JSON.parse(canonical(intent))), intent);
  assert.deepEqual(intentSummary(intent).branches[0].candidate_checks_added, [check()]);
  const removed = plan({ snapshot: state({ policy: replacement }), replacement: { administrators: [ACTOR], branches: [] }, clear: true });
  assert.deepEqual(intentSummary(removed).branches[0].candidate_checks_removed, [check()]);
  for (const place of ['source', 'replacement']) {
    const withSource = plan({ snapshot: state({ policy: replacement }), replacement });
    const changed = structuredClone(withSource);
    (place === 'source' ? changed.source.policy : changed.replacement).branches[0].required_candidate_checks[0].job = 'changed';
    assert.throws(() => validateIntent(changed));
  }
});

test('closed selectors reject authority/source substitution and enforce the shared count bound', () => {
  const row = selected().branches[0];
  for (const required_candidate_checks of [null, '[]', [null], [check('')], [check('bad\njob')],
    [check(), check()], [{ ...check(), source_ref_hex: ref('refs/heads/ci') }], [{ ...check(), actor: ACTOR }]]) {
    assert.throws(() => policy({ administrators: [ACTOR], branches: [{ ...row, required_candidate_checks }] }));
  }
  const candidate = Array.from({ length: 31 }, (_, i) => check('job-' + String(i).padStart(2, '0')));
  const ordinary = { ...check('ordinary'), source_ref_hex: ref('refs/heads/ci') };
  const value = { administrators: [ACTOR], branches: [{ ...row, required_checks: [ordinary], required_candidate_checks: candidate }] };
  assert.equal(policy(value).branches[0].required_candidate_checks.length, 31);
  value.branches[0].required_candidate_checks.push(check('overflow'));
  assert.throws(() => policy(value), /invalid_required_check_count/);
});
