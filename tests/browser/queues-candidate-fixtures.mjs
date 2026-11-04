// Transport fixtures only: the native queue/candidate owners are doubled.
// The shared fixture independently computes actual Git commit-body hashes.
import { fixture } from './pulls-candidate-fixtures.mjs';
import { actor, hex } from './pulls-fixtures.mjs';
export function queueFixture(algorithm = 'sha1', raw = false) {
  const f = fixture(algorithm), scope = f.artifact.scope;
  const refs = raw ? { source_ref: null, source_ref_hex: `${hex('refs/heads/topic')}ff`,
    target_ref: null, target_ref_hex: `${hex('refs/heads/main')}fe` } : {
    source_ref: 'refs/heads/topic', source_ref_hex: hex('refs/heads/topic'), target_ref: 'refs/heads/main', target_ref_hex: hex('refs/heads/main') };
  const subject = { ...f.metadata.subject, ...refs, pull_request_version: 4 };
  const fields = { expected_version: 3, target_ref_hex: refs.target_ref_hex, pull_request: 1, expected_pull_request_version: 4,
    source_ref_hex: refs.source_ref_hex, expected_source_tip: f.fields.source_tip, expected_target_tip: f.fields.target_tip, expected_policy_epoch: 1 };
  const landingFields = { ...fields, merge_base: f.fields.merge_base, expected_commit: f.fields.candidate_commit };
  const commandForm = new URLSearchParams({ expected_incarnation: scope.incarnation, object_format: algorithm,
    expected_version: '3', pull_request: '1', expected_pull_request_version: '4', expected_policy_epoch: '1',
    source_ref_hex: refs.source_ref_hex, target_ref_hex: refs.target_ref_hex, expected_source_tip: f.fields.source_tip,
    expected_target_tip: f.fields.target_tip, merge_base: f.fields.merge_base, expected_commit: f.fields.candidate_commit }).toString();
  const metadata = { ...f.metadata, type: 'queue_merge_preparation', method: 'merge-commit', subject,
    queue: { number: 7, expected_version: 3 }, landing: { api_path: '/api/v1/queues/7/land-candidate', command_form: commandForm } };
  const inspection = { ...f.inspection, subject };
  const queue = { number: 7, target_ref: refs.target_ref, target_ref_hex: refs.target_ref_hex, version: 3,
    entries: [{ pull_request: 1, source_ref: refs.source_ref, source_ref_hex: refs.source_ref_hex, head_tip: f.fields.source_tip,
      enqueued_by: actor, priority: 10, enqueued_version: 1 }], order: [1], active_batch: null };
  const identity = Object.fromEntries(['schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'source_head', 'snapshot_token'].map(k => [k, metadata[k]]));
  const page = { ...identity, type: 'merge_queue_page', after: 0, limit: 20, next_after: null, queues: [queue], complete: true };
  const show = { ...identity, type: 'merge_queue', number: 7, found: true, version: 3, queue, complete: true };
  const mixed = (meta = metadata, bundle = f.bundle) => f.mixed(meta, bundle);
  const prepared = (meta = metadata, bundle = f.bundle) => new Response(mixed(meta, bundle), { status: 200, headers: { 'Content-Type': f.type } });
  const commitMetadata = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 1, message: 'Exact candidate\n' };
  return { ...f, scope, metadata, inspection, refs, fields, landingFields, commandForm, page, show, queue, mixed, prepared, commitMetadata };
}
export function candidatePublication(pending, committed = true) {
  const f = pending.fields, s = pending.scope;
  const ref = (name, value) => {
    let decoded = null; try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(value, 'hex')); } catch { /* Native byte ref. */ }
    return { [name]: decoded, [`${name}_hex`]: value };
  };
  return { type: 'merge_queue_publication', schema_version: 1, tenant_id: s.tenant, repository_id: s.repository,
    repository_incarnation: s.incarnation, object_format: s.format, principal_id: actor, number: pending.number,
    ...ref('target_ref', f.target_ref_hex), expected_version: f.expected_version,
    proposed_action: { name: 'land-candidate', pull_request: f.pull_request, expected_pull_request_version: f.expected_pull_request_version,
      ...ref('source_ref', f.source_ref_hex), expected_source_tip: f.expected_source_tip, expected_target_tip: f.expected_target_tip,
      method: 'merge-commit', expected_policy_epoch: f.expected_policy_epoch, merge_base: f.merge_base, expected_commit: f.expected_commit },
    tx_id: 'queue-candidate-original', decision_sequence: 8, outcome: committed ? 'committed' : 'refused', committed,
    repository_commit_id: committed ? 'queue-candidate-rcr' : null, refusal_record_id: committed ? null : 'queue-candidate-refusal',
    refusal_code: committed ? null : 'PolicyDenied', refs_changed: committed, delivery_acknowledged: null, historical_outcome: true, complete: true };
}
