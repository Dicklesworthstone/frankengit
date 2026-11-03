// Controlled outcome records; these are not native Rust authority receipts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareIntent, outcomeReply, observation, extendsObservation } from '../../scripts/operator/review_protection.mjs';
import { TOKEN, ACTOR, SCOPE, NEXT, state } from './protection_fixtures.mjs';
const intent = prepareIntent({ endpoint: 'https://forge.example/team/repo.git', token: TOKEN, principal_id: ACTOR,
  expectedScope: SCOPE, snapshot: state(), replacement: NEXT, nonce: 'e'.repeat(32) });
const receipt = (status = 'committed') => ({ type: 'transaction_outcome', schema_version: 1,
  tenant_id: intent.scope.tenant_id, repository_id: intent.scope.repository_id, repository_incarnation: intent.scope.repository_incarnation,
  principal_id: ACTOR, selector: 'transaction', command_index: null, state: status, terminal: status === 'committed',
  transaction: status === 'key_not_observed' ? null : { tx_id: 'tx-original', seal_id: 'seal-original', request_schema: 'native-protection',
    canonical_request_digest: { algorithm: 2, hex: '5'.repeat(64) } },
  decision: status === 'committed' ? { kind: status, decision_sequence: '9007199254740993', repository_commit_id: 'rcr-original' } : null,
  read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false });
const annotated = (authentication = 'http_token') => ({ ...receipt(), principal_provenance: {
  state: authentication === null ? 'legacy_unknown' : 'recorded', principal_id: ACTOR, authentication, agent_provenance: null }, provenance_error: null });
for (const method of ['http_token', 'ssh_deploy_key', 'operator_assertion', null]) {
  test(`protection operator retains native optional ${method} evidence without changing the decision`, () => {
    const value = annotated(method), observed = observation(intent, 'outcome', 200, value);
    assert.deepEqual(observed.summary, outcomeReply(receipt(), intent));
    assert.deepEqual(observed.record.reply, value);
    extendsObservation(observed, observation(intent, 'outcome', 200, receipt()));
  });
}
test('protection operator accepts optional evidence unavailability and exact nonterminal shape', () => {
  for (const error of ['original_principal_evidence_unavailable', 'response_limit']) {
    const value = { ...receipt(), principal_provenance: { state: 'unavailable' }, provenance_error: error };
    assert.deepEqual(outcomeReply(value, intent), outcomeReply(receipt(), intent));
  }
  const value = { ...receipt('key_not_observed'), principal_provenance: { state: 'not_terminal' }, provenance_error: null };
  assert.equal(outcomeReply(value, intent).terminal, false);
});
test('protection operator refuses partial, mismatched or changed original evidence', () => {
  const good = annotated(); assert.equal(outcomeReply(good, intent).terminal, true);
  for (const mutate of [v => { delete v.provenance_error; }, v => { v.extra = true; },
    v => { v.principal_provenance.principal_id = '9'.repeat(32); },
    v => { v.principal_provenance.authentication = 'human'; },
    v => { v.principal_provenance.agent_provenance = {}; },
    v => { v.principal_provenance.extra = true; }]) {
    const bad = structuredClone(good); mutate(bad); assert.throws(() => outcomeReply(bad, intent));
  }
  assert.throws(() => extendsObservation(observation(intent, 'outcome', 200, annotated('ssh_deploy_key')),
    observation(intent, 'outcome', 200, good)));
});
