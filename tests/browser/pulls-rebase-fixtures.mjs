// Shared controlled HTTP peer fixture. Native commit hashes are real; bundle
// and admission responses are test doubles, not native Git evidence.
import { createHash } from 'node:crypto';
import { fixture } from './pulls-candidate-fixtures.mjs';
import { rebasePreparationCommand } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-rebase.mjs';

export const metadata = { committer: 'Maintainer <maintainer@example.invalid>', timestamp: 7, empty: 'stop' };
export function sample(algorithm = 'sha1') {
  const old = fixture(algorithm), width = algorithm === 'sha1' ? 40 : 64;
  const hash = (kind, bytes) => createHash(algorithm).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
  const firstTree = '8'.repeat(width), lastTree = '9'.repeat(width), initialTree = '7'.repeat(width);
  const body = (parent, tree, message) => Buffer.from(`tree ${tree}\nparent ${parent}\nauthor Author <author@example.invalid> 1 +0000\ncommitter ${metadata.committer} 7 +0000\n\n${message}\n`);
  const firstBody = body(old.selected.target_tip, firstTree, 'Add protected configuration'), first = hash('commit', firstBody);
  const lastBody = body(first, lastTree, 'Remove temporary configuration'), last = hash('commit', lastBody);
  const blob = Buffer.from('secret\n'), blobId = hash('blob', blob), path_hex = Buffer.from('protected/settings').toString('hex');
  const entry = added => ({ path_hex, kind: added ? 'added' : 'deleted', before: added ? null : { mode: 0o100644, oid: blobId },
    after: added ? { mode: 0o100644, oid: blobId } : null, content: { type: 'text', algorithm: 'myers-v1',
      before_bytes: added ? 0 : blob.length, after_bytes: added ? blob.length : 0, additions: added ? 1 : 0, deletions: added ? 0 : 1,
      hunks: [{ old: { byte_start: 0, byte_end: added ? 0 : blob.length, line_start: 0, line_count: added ? 0 : 1 },
        new: { byte_start: 0, byte_end: added ? blob.length : 0, line_start: 0, line_count: added ? 1 : 0 },
        before_hex: added ? '' : blob.toString('hex'), after_hex: added ? blob.toString('hex') : '' }] } });
  const comparison = (before, after, before_tree, after_tree, entries) => ({ mode: 'direct', before, after, before_tree, after_tree, entry_count: entries.length, entries });
  const bundle = new Uint8Array(Buffer.concat([Buffer.from(`rebase-fixture:${algorithm}:${last}\n`), Buffer.from([0, 255, 13, 10])]));
  const sha256 = createHash('sha256').update(bundle).digest('hex');
  const fields = { ...old.fields, candidate_commit: last }, command = rebasePreparationCommand(old.selected, { ...metadata, upstream: fields.merge_base });
  const preparation = { ...old.metadata, type: 'pull_request_rebase_preparation', profile: 'path-v1', method: 'rebase',
    candidate_commit: last, root_tree: lastTree, merge_base: fields.merge_base, committer: metadata.committer, timestamp: metadata.timestamp,
    empty_policy: metadata.empty, stopped_commit: null, step_count: 2, series_complete: true, provisional_steps: false,
    steps: [{ original: '6'.repeat(width), rewritten: first, tree: firstTree, kind: 'replayed' },
      { original: fields.source_tip, rewritten: last, tree: lastTree, kind: 'replayed' }], bundle: { bytes: bundle.length, sha256 } };
  delete preparation.candidate;
  const inspection = { ...old.inspection, type: 'pull_request_rebase_inspection', profile: 'verified-linear-series-v1', method: 'rebase',
    scope: 'all_paths_all_commits', complete: true, all_rewritten_commits: true, replay_equivalence_verified: false,
    candidate_commit: last, commit_count: 2,
    bundle: { ...old.inspection.bundle, bytes: bundle.length, sha256, pack_objects: 4, expanded_bytes: firstBody.length + lastBody.length },
    source_comparison: comparison(fields.source_tip, last, lastTree, lastTree, []),
    commits: [{ commit: first, parent: fields.target_tip, tree: firstTree, commit_hex: firstBody.toString('hex'),
      comparison: comparison(fields.target_tip, first, initialTree, firstTree, [entry(true)]) },
    { commit: last, parent: first, tree: lastTree, commit_hex: lastBody.toString('hex'),
      comparison: comparison(first, last, firstTree, lastTree, [entry(false)]) }] };
  for (const field of ['comparison', 'parents', 'candidate_commit_body_hex']) delete inspection[field];
  const artifact = { ...old.artifact, method: 'rebase', fields, bundle, sha256 };
  return { ...old, fields, command, artifact, bundle, metadata: preparation, inspection,
    mixed: (meta = preparation) => old.mixed(meta, bundle) };
}
