// Bundle bytes exercise transport integrity only. The native verifier is a test
// double here; the commit body and its Git object hash are computed independently.
import { createHash } from 'node:crypto';
import { ids, scope, subject, rawSubject, refFields, actor, head } from './pulls-fixtures.mjs';
export function fixture(algorithm = 'sha1') {
  const length = algorithm === 'sha1' ? 40 : 64, sha = bytes => createHash('sha256').update(bytes).digest('hex');
  const selected = subject({ object_format: algorithm, source_tip: 'a'.repeat(length), target_tip: 'b'.repeat(length) });
  const commitBody = Buffer.from(`tree ${'f'.repeat(length)}\nparent ${selected.target_tip}\nparent ${selected.source_tip}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nExact candidate\n`);
  const commit = createHash(algorithm).update(`commit ${commitBody.length}\0`).update(commitBody).digest('hex');
  const bundle = new Uint8Array(Buffer.concat([Buffer.from(`# ${algorithm === 'sha1' ? 'v2' : 'v3'} git bundle\n${commit} refs/heads/candidate\n\nPACK`), Buffer.from([0, 255, 13, 10])]));
  const fields = { ...selected, merge_base: 'e'.repeat(length), candidate_commit: commit };
  const observedSubject = { ...rawSubject(), ...refFields, ...selected, pull_request: 1 }; delete observedSubject.number; delete observedSubject.object_format;
  const identity = { ...ids, object_format: algorithm, source_head: 'head-id', snapshot_token: head };
  const flags = { read_only: true, objects_staged: false, transaction_created: false, published: false, merge_authorized: false };
  const metadata = { ...identity, ...flags, type: 'merge_preparation', profile: 'path-merge-v1', subject: observedSubject, state: 'clean',
    candidate: { merge_base: fields.merge_base, commit, tree: 'f'.repeat(length), new_object_count: 1 }, bundle: { bytes: bundle.length, sha256: sha(bundle) }, conflicts: [] };
  const inspection = { ...identity, ...flags, type: 'candidate_inspection', all_changed_paths: true, binary_bodies_included: false,
    comparison_profile: 'full-tree-direct-path-myers-v1', context_lines: 3, subject: observedSubject, merge_base: fields.merge_base, candidate_commit: commit,
    parents: [selected.target_tip, selected.source_tip], prerequisites: [selected.target_tip], candidate_commit_body_hex: commitBody.toString('hex'),
    bundle: { bytes: bundle.length, sha256: sha(bundle), pack_bytes: 6, pack_objects: 1, expanded_bytes: commitBody.length, closure_objects: 1, transport_only_objects: 0 },
    comparison: { mode: 'direct', before: selected.target_tip, after: commit, before_tree: 'd'.repeat(length), after_tree: 'f'.repeat(length), entry_count: 0, entries: [] } };
  const artifact = { number: 1, scope: { ...scope, format: algorithm }, fields, bundle, sha256: sha(bundle) };
  const boundary = `fg-prepare-${sha(bundle).slice(0, 48)}-0`;
  const mixed = (meta = metadata, bytes = bundle) => new Uint8Array(Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n${JSON.stringify(meta)}\r\n--${boundary}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`),
    bytes, Buffer.from(`\r\n--${boundary}--\r\n`)]));
  return { selected, fields, bundle, artifact, metadata, inspection, mixed, type: `multipart/mixed; boundary=${boundary}`, commitBody };
}
export function terminal(pending, extra = {}) {
  const shared = { ...ids, object_format: pending.scope.format, principal_id: actor, action: pending.action, tx_id: 'transaction-1', outcome: 'committed', decision_sequence: 2,
    repository_commit_id: 'rcr-1', refusal_record_id: null, refusal_code: null, refusal_code_point: null, delivery_acknowledged: null };
  if (['open', 'update', 'close'].includes(pending.action)) return { ...shared, type: 'pull_request_publication', number: pending.number, expected_version: pending.fields.expected_version, ...extra };
  const fields = pending.fields, merge = pending.action === 'merge';
  return { ...shared, type: merge ? 'reviewed_merge_publication' : 'candidate_review_publication', review_expected_version: merge ? null : fields.expected_version,
    subject: { ...rawSubject(), number: pending.number, ...Object.fromEntries(Object.entries(fields).filter(([k]) => ['pull_request_version', 'policy_epoch', 'source_ref', 'target_ref', 'source_tip', 'target_tip'].includes(k))) },
    merge_base: fields.merge_base, candidate_commit: fields.candidate_commit, required_reviewers: merge ? fields.required_reviewer : null, ...extra };
}
export const recovered = (extra = {}) => ({ ...ids, type: 'transaction_outcome', principal_id: actor, selector: 'transaction', command_index: null, state: 'undecided', terminal: false,
  transaction: { tx_id: 'transaction-1', seal_id: 'seal-1', request_schema: 'native-command-v1', canonical_request_digest: { algorithm: 1, hex: 'a'.repeat(64) } }, decision: null,
  read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false, ...extra });
