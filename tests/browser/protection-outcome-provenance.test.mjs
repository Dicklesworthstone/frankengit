// Actual shared client and WebCrypto with controlled Response streams.
// No live native server or real-browser qualification is implied.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { ProtectionClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { protectionClientHref } from '../../crates/fgit-node/src/smart_http/server/browser/protection-view.mjs';
import { actor, reviewer, token, snapshot, hex } from './protection-standalone-fixture.mjs';
const selected = snapshot(), scope = selected.scope;
const ordinary = (method = 'http_token') => ({ state: method === null ? 'legacy_unknown' : 'recorded',
  principal_id: actor, authentication: method, agent_provenance: null });
function receipt(terminal = true) {
  return { type: 'transaction_outcome', schema_version: 1, tenant_id: scope.tenant, repository_id: scope.repository,
    repository_incarnation: scope.incarnation, principal_id: actor, selector: 'transaction', command_index: null,
    state: terminal ? 'committed' : 'undecided', terminal,
    transaction: { tx_id: 'tx:protection', seal_id: 'seal:protection', request_schema: 'native-protection',
      canonical_request_digest: { algorithm: 2, hex: 'ab'.repeat(32) } },
    decision: terminal ? { kind: 'committed', decision_sequence: 7, repository_commit_id: 'rcr:protection' } : null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
async function staged(value) {
  const requests = [];
  const client = new ProtectionClient({ href: protectionClientHref('https://forge.example/team/repo.git/ui/protection/'), cryptoImpl: webcrypto,
    fetchImpl: async (url, options) => {
      requests.push({ url: url.href, ...options });
      const body = options.method === 'GET' ? { type: 'repository_review_protection', schema_version: 1,
        tenant_id: scope.tenant, repository_id: scope.repository, repository_incarnation: scope.incarnation, object_format: scope.format,
        source_head: selected.head, version: selected.version, policy_epoch: selected.epoch, installed: true, enabled: true,
        policy: selected.policy, complete: true, transaction_created: false, published: false } : value;
      return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
    } });
  await client.connect(token, actor); await client.load();
  await client.stage({ administrators: [actor], branches: [{ reference_hex: hex('refs/heads/topic'), required_reviewers: [reviewer] }] });
  return { client, requests, original: structuredClone(client.pending.intent) };
}
for (const method of ['http_token', 'ssh_deploy_key', 'operator_assertion', null]) {
  test(`browser protection recovers native optional ${method} evidence with the original key`, async () => {
    const value = { ...receipt(), principal_provenance: ordinary(method), provenance_error: null };
    const { client, requests, original } = await staged(value);
    const result = await client.recover(); assert.equal(result.outcome, 'committed');
    assert.deepEqual(result.principalProvenance, value.principal_provenance); assert.equal(result.provenanceError, null);
    assert.equal(result.tx, value.transaction.tx_id); assert.equal(client.pending, null);
    assert.equal(requests.at(-1).headers['Idempotency-Key'], original.key);
    assert.equal(requests.at(-1).body, undefined);
  });
}
test('browser protection keeps a nonterminal request and accepts optional evidence unavailability', async () => {
  const value = { ...receipt(false), principal_provenance: { state: 'not_terminal' }, provenance_error: null };
  const h = await staged(value); assert.equal((await h.client.recover()).terminal, false);
  assert.deepEqual(h.client.pending.intent, h.original);
  for (const error of ['original_principal_evidence_unavailable', 'response_limit']) {
    const h = await staged({ ...receipt(), principal_provenance: { state: 'unavailable' }, provenance_error: error });
    assert.equal((await h.client.recover()).terminal, true);
  }
});
test('browser protection refuses malformed evidence and retains the exact pending intent', async () => {
  for (const mutate of [v => { delete v.provenance_error; }, v => { v.extra = true; },
    v => { v.principal_provenance.principal_id = reviewer; }, v => { v.principal_provenance.authentication = 'agent_credential'; },
    v => { v.principal_provenance.agent_provenance = {}; }, v => { v.principal_provenance.extra = true; }]) {
    const value = { ...receipt(), principal_provenance: ordinary(), provenance_error: null }; mutate(value);
    const h = await staged(value); await assert.rejects(h.client.recover()); assert.deepEqual(h.client.pending.intent, h.original);
  }
});
