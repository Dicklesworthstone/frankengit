// Independently framed Git commitments and explicit inspection-schema rows.
// These are local validator contracts, not native admission or pack evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { changeFixture, intent, replace, hexPath, objectId } from '../../scripts/tests/source_changes_fixture.mjs';
import { buildSourceChanges, canonical, sha256 } from '../../scripts/operator/source_changes.mjs';
import { verifySourceChangeCandidate } from '../../scripts/operator/source_changes_prepare.mjs';
import { validateSourceEdit } from '../../scripts/operator/source_edit_candidate.mjs';

async function fixture(format, unchangedChild = false) {
  const source = changeFixture(format, [{ path: 'dir/edit', bytes: 'before\n' }, { path: 'dir/drop', bytes: 'drop\n' },
    { path: 'keep', bytes: 'unchanged\n' }, ...(unchangedChild ? [{ path: 'dir/retained', bytes: 'not a changed effect' }] : [])]);
  const changes = intent([replace('dir/edit', 'after\n'), { path_hex: hexPath('dir/drop'), operation: 'delete' },
    { path_hex: hexPath('new/created'), operation: 'create', content_utf8: 'created\n', executable: true }]);
  const draft = await buildSourceChanges(source.bytes, source.expected, changes);
  const scope = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format };
  const metadata = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 2, message: 'edit\n' };
  const request = { endpoint: 'http://127.0.0.1:1/repository.git', scope, ref: 'refs/heads/main', expected_commit: source.commit,
    metadata, paths_hex: draft.manifest.effects.map(e => e.path_hex), expected_result_tree: draft.tree.afterTree, patch_profile: 'exact-tree-v1' };
  const body = Buffer.from(`tree ${draft.tree.afterTree}\nparent ${source.commit}\nauthor ${metadata.author} 2 +0000\ncommitter ${metadata.committer} 2 +0000\n\n${metadata.message}`);
  const candidate = objectId('commit', body, format);
  // The report-only validator never claims to decode this transport. The real
  // native campaign separately verifies every object in the returned pack.
  const bundle = Buffer.from(format === 'sha1' ? '# v2 git bundle\nvalidator-contract' : '# v3 git bundle\nvalidator-contract');
  const bundleHash = createHash('sha256').update(bundle).digest('hex');
  const sizes = new Map(source.files.map(f => [f.id, f.bytes.length]));
  for (const text of ['after\n', 'created\n']) sizes.set(objectId('blob', Buffer.from(text), format), Buffer.byteLength(text));
  const entries = draft.manifest.effects.map(e => ({ path_hex: e.path_hex,
    kind: e.old_blob === null ? 'added' : e.new_blob === null ? 'deleted' : e.old_mode !== e.new_mode ? 'mode_changed' : 'modified',
    before: e.old_blob === null ? null : { mode: e.old_mode, oid: e.old_blob },
    after: e.new_blob === null ? null : { mode: e.new_mode, oid: e.new_blob },
    content: { type: 'binary', before_bytes: e.old_blob === null ? 0 : sizes.get(e.old_blob),
      after_bytes: e.new_blob === null ? 0 : sizes.get(e.new_blob), body_included: false } }));
  for (const tree of draft.tree.rewrittenTrees.filter(t => t.pathHex !== null)) entries.push({ path_hex: tree.pathHex,
    kind: tree.beforeTree === null ? 'added' : tree.afterTree === null ? 'deleted' : 'modified',
    before: tree.beforeTree === null ? null : { mode: 0o40000, oid: tree.beforeTree },
    after: tree.afterTree === null ? null : { mode: 0o40000, oid: tree.afterTree }, content: { type: 'object_only', content_read: false } });
  entries.sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
  const common = { schema_version: 1, ...scope, ref: request.ref, ref_hex: hexPath(request.ref), read_only: true,
    objects_staged: false, transaction_created: false, published: false, publication_authorized: false };
  const preparation = { type: 'source_preparation', ...common, source_commit: source.commit, source_rcr: 'schema-rcr', candidate_commit: candidate,
    root_tree: draft.tree.afterTree, patch_profile: request.patch_profile, expected_result_tree: draft.tree.afterTree,
    patch_sha256: draft.manifest.patch_sha256, object_count: 5, bundle: { bytes: bundle.length, sha256: bundleHash },
    paths: draft.manifest.effects.map(e => ({ path_hex: e.path_hex, old_blob: e.old_blob, new_blob: e.new_blob, new_mode: e.new_mode, hunks: e.hunks })) };
  const inspection = { type: 'source_inspection', ...common, source_head: 'schema-head', snapshot_token: `alg:2:${'4'.repeat(64)}`,
    expected_commit: source.commit, candidate_commit: candidate, parents: [source.commit], bundle_bytes: bundle.length, bundle_sha256: bundleHash,
    all_changed_paths: true, binary_bodies_included: false, candidate_commit_body_hex: body.toString('hex'),
    comparison: { mode: 'direct', before_tree: source.tree, after_tree: draft.tree.afterTree, entry_count: entries.length, entries } };
  const capture = { schema: 'frankengit-source-edit-capture-v3', request, patch_sha256: draft.manifest.patch_sha256,
    patch_bytes: draft.manifest.patch_bytes, preparation, inspection };
  const check = (value = capture) => verifySourceChangeCandidate(source.bytes, source.expected, changes, value, bundle,
    { confirmDraftSha256: sha256(canonical(draft.manifest)) });
  return { capture, bundle, draft, check };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: complete modified and created parent trees bind to exact intended file effects`, async () => {
    const f = await fixture(format), result = await f.check();
    assert.equal(result.binding.effect_count, 3);
    assert.equal(result.binding.candidate_root_matches_exact_effects, true);
    assert.equal(result.binding.bundle_objects_independently_verified, false);
    assert.equal(result.capture.inspection.comparison.entries.length, 5);
    assert.deepEqual(result.capture, f.capture);
  });
  for (const [name, change] of [
    ['wrong before tree', r => r.find(e => e.path_hex === hexPath('dir')).before.oid = 'e'.repeat(format === 'sha1' ? 40 : 64)],
    ['wrong after tree', r => r.find(e => e.path_hex === hexPath('dir')).after.oid = 'e'.repeat(format === 'sha1' ? 40 : 64)],
    ['missing deletion', r => r.splice(r.findIndex(e => e.path_hex === hexPath('dir/drop')), 1)],
    ['unproved empty directory', r => r.push({ path_hex: hexPath('zzz'), kind: 'added', before: null,
      after: { mode: 0o40000, oid: 'e'.repeat(format === 'sha1' ? 40 : 64) }, content: { type: 'object_only', content_read: false } })],
    ['extra directory field', r => r.find(e => e.path_hex === hexPath('dir')).trusted = true],
  ]) test(`${format}: ${name} cannot disappear through file-effect matching`, async () => {
    const f = await fixture(format), altered = structuredClone(f.capture);
    change(altered.inspection.comparison.entries);
    altered.inspection.comparison.entry_count = altered.inspection.comparison.entries.length;
    await assert.rejects(f.check(altered));
    assert.equal((await f.check()).binding.effect_count, 3);
  });
  test(`${format}: an unreported unchanged child remains an explicit structural refusal`, async () => {
    const f = await fixture(format, true);
    await assert.rejects(f.check(), /structural_identity/);
  });
  test(`${format}: older captures cannot acquire structural support by dropping the profile`, async () => {
    const f = await fixture(format), changed = structuredClone(f.capture);
    changed.schema = 'frankengit-source-edit-capture-v1';
    delete changed.request.patch_profile; delete changed.request.expected_result_tree;
    delete changed.preparation.patch_profile; delete changed.preparation.expected_result_tree;
    assert.throws(() => validateSourceEdit(changed, f.bundle));
  });
}
