// Native-schema HTTP fixtures, not a Rust node or proof of policy authorization.
import { webcrypto } from 'node:crypto';
import { ProtectionClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
export { webcrypto };
export const TOKEN = '1'.repeat(64), ROTATED = '2'.repeat(64), ADMIN = 'a'.repeat(32), REVIEWER = 'b'.repeat(32), OTHER = 'c'.repeat(32);
export const HREF = 'https://forge.example/team/repo.git/ui/pulls/';
export const hex = value => Buffer.from(value).toString('hex');
export const policy = () => ({ administrators: [ADMIN], branches: [{ reference_hex: hex('refs/heads/main'), required_reviewers: [REVIEWER] }] });
// Opaque native-schema transport fixture, not a compiled-policy proof.
export const refPolicy = (profile = 'reference_facts_v1') => ({ snapshot_id: `frankengit/policy-snapshot/v1/v1.0/alg:2/${'d'.repeat(64)}`,
  profile, mode: 'enforce', frame_hex: '000102ff' });
export function snapshot(format = 'sha1', patch = {}) {
  return { type: 'repository_review_protection', schema_version: 1, tenant_id: '3'.repeat(32), repository_id: '4'.repeat(32),
    repository_incarnation: '5'.repeat(32), object_format: format, source_head: `alg:2:${'6'.repeat(64)}`,
    policy_epoch: '9007199254740993', version: '9007199254740992', installed: true, enabled: true,
    policy: policy(), complete: true, transaction_created: false, published: false, ...patch };
}
export function terminal(pending, outcome = 'committed', patch = {}) {
  const i = pending.intent, s = i.source.scope;
  return { type: 'review_protection_publication', schema_version: 1, tenant_id: s.tenant, repository_id: s.repository,
    repository_incarnation: s.incarnation, object_format: s.format, principal_id: i.principal,
    expected_version: i.source.version, expected_epoch: i.source.epoch,
    resulting_epoch: outcome === 'committed' ? String(BigInt(i.source.epoch) + 1n) : null,
    tx_id: 'fixture-tx', outcome, decision_sequence: '18446744073709551615',
    repository_commit_id: outcome === 'committed' ? 'fixture-rcr' : null, refusal_record_id: outcome === 'refused' ? 'fixture-refusal' : null,
    refusal_code: outcome === 'refused' ? 'EvidenceStale' : null, refusal_code_point: outcome === 'refused' ? 1 : null,
    delivery_acknowledged: null, ...patch };
}
export function recovered(pending, state = 'committed', patch = {}) {
  const i = pending.intent, s = i.source.scope, present = !['key_not_observed', 'seal_not_observed'].includes(state);
  return { type: 'transaction_outcome', schema_version: 1, tenant_id: s.tenant, repository_id: s.repository,
    repository_incarnation: s.incarnation, principal_id: i.principal, selector: 'transaction', command_index: null, state,
    terminal: ['committed', 'refused'].includes(state), transaction: present ? { tx_id: 'fixture-tx', seal_id: 'fixture-seal',
      request_schema: 'fixture-schema', canonical_request_digest: { algorithm: 2, hex: 'd'.repeat(64) } } : null,
    decision: state === 'committed' ? { kind: state, decision_sequence: '18446744073709551615', repository_commit_id: 'fixture-rcr' }
      : state === 'refused' ? { kind: state, decision_sequence: '7', code: 'EvidenceStale', code_point: 1, refusal_record_id: 'fixture-refusal' } : null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false, ...patch };
}
export const response = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
export function harness({ format = 'sha1', respond = () => null, ...options } = {}) {
  const calls = [];
  let client;
  client = new ProtectionClient({ href: HREF, cryptoImpl: webcrypto, ...options, fetchImpl: async (url, request) => {
    const call = { url, ...request }; calls.push(call);
    const result = await respond(call, client);
    if (result !== null && result !== undefined) return result;
    if (request.method === 'GET') return response(snapshot(format));
    if (url.pathname.endsWith('/outcomes')) return response(recovered(client.pending));
    return response(terminal(client.pending));
  } });
  const ready = async () => { await client.connect(TOKEN, ADMIN); await client.load(); };
  return { client, calls, ready };
}
export function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { resolve, reject, promise }; }
