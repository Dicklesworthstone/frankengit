import test from 'node:test';
import assert from 'node:assert/strict';
import { bindVerifiedEditSource, validateSourceEditEvidence, captureVerifiedSourceEdit,
  SOURCE_CREATION_EVIDENCE_PROFILE } from '../../scripts/operator/source_edit_from_package.mjs';
import { validateSourceEdit } from '../../scripts/operator/source_edit_candidate.mjs';
import { creationFixture, creationPeer, material, TOKEN, hex } from './source_edit_creation_fixture.mjs';
import { evidenceFixture, material as oldMaterial } from './source_edit_evidence_fixture.mjs';
const verify = (f, evidence = material(f), check) => validateSourceEditEvidence(f.capture, Buffer.from(f.bundle, 'hex'), evidence, check);
for (const format of ['sha1', 'sha256']) {
  for (const scenario of ['root', 'parent', 'nested', 'raw', 'empty', 'executable', 'mixed', 'binary']) {
    test(`${format}/${scenario}: explicit absence and native before/after commitments bind creation`, async () => {
      const f = creationFixture(format, scenario), before = structuredClone(f), r = await verify(f);
      const v = r.source_verification;
      assert.equal(v.profile, SOURCE_CREATION_EVIDENCE_PROFILE);
      assert.equal(v.path_absence_verified, true); assert.deepEqual(v.created_paths_hex, [f.target]);
      assert.equal(v.commit, f.base); assert.equal(v.before_tree, f.beforeTree); assert.equal(v.after_tree, f.afterTree);
      assert.equal(v.verified_paths, scenario === 'mixed' ? 2 : 1);
      assert.equal(v.replayed_text_files, scenario === 'binary' ? 0 : scenario === 'mixed' ? 2 : 1);
      assert.deepEqual(v.unverified_after_paths_hex, scenario === 'binary' ? [f.target] : []);
      assert.equal(v.absence.paths[0].pathHex, f.target);
      assert.equal(v.absence.paths[0].parentTree, scenario === 'parent' ? f.package.membership.trees[1].oid : f.beforeTree);
      assert.equal(v.absence.paths[0].absentPrefixHex, scenario === 'nested' ? hex('new') : scenario === 'raw' ? 'ff' : f.target);
      for (const key of ['patch_application_verified', 'bundle_objects_independently_verified', 'authority_verified', 'freshness_verified', 'publication_authorized']) assert.equal(v[key], false);
      assert.deepEqual((await validateSourceEditEvidence(r.capture, r.bundle, r.source_evidence)).source_verification, v);
      assert.deepEqual(f, before);
    });
  }
  test(`${format}: real prepare/inspect receives only the original patch and bundle`, async t => {
    const f = await creationPeer(t, format, 'parent');
    const result = await captureVerifiedSourceEdit(f.request, f.patchBytes, TOKEN, f.evidence);
    assert.equal(result.candidate_commit, f.candidate); assert.equal(result.source_verification.path_absence_verified, true);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
    assert.ok(f.calls[0].body.includes(f.patchBytes)); assert.ok(f.calls[1].body.includes(f.bundleBytes));
    for (const call of f.calls) assert.equal(call.headers['idempotency-key'], undefined);
  });
  test(`${format}: genuinely hashed candidate cannot hide an extra creation`, async () => {
    const f = creationFixture(format, 'hidden');
    assert.doesNotThrow(() => validateSourceEdit(f.capture, Buffer.from(f.bundle, 'hex')));
    await assert.rejects(verify(f), /source_edit_unreported_tree_effect/);
  });
}
for (const [path, reason] of [
  ['sibling', /already exists/], ['src', /creation_collision/], ['hidden/new', /parent tree is not proved/],
  ['hidden/secret', /parent tree is not proved/], ['link/new', /ancestor is not a directory/],
  ['submodule/new', /ancestor is not a directory/], ['src/base.rs/new', /creation_collision/],
]) test(`missing package member does not prove ${path} absent`, async t => {
  const f = await creationPeer(t), evidence = material(f), request = structuredClone(f.request);
  evidence.expected.create_paths_hex = request.paths_hex = [hex(path)];
  await assert.rejects(captureVerifiedSourceEdit(request, f.patchBytes, TOKEN, evidence), reason);
  assert.equal(f.calls.length, 0, 'preflight refuses without a native source request');
});
for (const [name, change] of Object.entries({
  'unknown schema': e => { e.schema += '-other'; },
  'unknown field': e => { e.force = true; },
  'no creates': e => { e.create_paths_hex = []; },
  'too many creates': e => { e.create_paths_hex = Array.from({length: 33}, (_,i) => hex(`f${i}`)).sort(); },
  'duplicate path': e => { e.create_paths_hex.push(e.create_paths_hex[0]); },
  'unordered paths': e => { e.create_paths_hex = [hex('z'), hex('a')]; },
  'dot traversal': e => { e.create_paths_hex = [hex('../new')]; },
  'empty component': e => { e.create_paths_hex = [hex('new//file')]; },
  'nul name': e => { e.create_paths_hex = ['00']; },
  'uppercase bytes': e => { e.create_paths_hex = ['FF']; },
  'excess depth': e => { e.create_paths_hex = [hex(Array(65).fill('d').join('/'))]; },
  'source collision': e => { e.create_paths_hex = [e.source.files[0].pathHex]; },
  'unused creation': e => { e.create_paths_hex = [hex('different')]; },
  'wrong root': e => { e.source.commit = 'f'.repeat(40); },
})) test(`closed creation selection refuses ${name} before native I/O`, async t => {
  const f = await creationPeer(t), e = material(f); change(e.expected);
  await assert.rejects(captureVerifiedSourceEdit(f.request, f.patchBytes, TOKEN, e)); assert.equal(f.calls.length, 0);
});
test('creation is never inferred from an ordinary positive selection', async t => {
  const f = await creationPeer(t), e = material(f); e.expected = e.expected.source;
  await assert.rejects(captureVerifiedSourceEdit(f.request, f.patchBytes, TOKEN, e), /package_path/); assert.equal(f.calls.length, 0);
});
test('new path cannot smuggle an existing preimage into a consistent native report', async () => {
  const f = creationFixture(), base = f.expected.source.files[0].blob;
  f.capture.preparation.paths[0].old_blob = base;
  Object.assign(f.capture.inspection.comparison.entries[0], { kind: 'modified', before: { mode: 0o100644, oid: base } });
  assert.doesNotThrow(() => validateSourceEdit(f.capture, Buffer.from(f.bundle, 'hex')));
  await assert.rejects(verify(f), /creation_effect/);
});
for (const [name, change] of Object.entries({
  'nonzero preimage size': c => { c.before_bytes = 1; },
  'invented original line': c => { c.hunks[0].old.line_start = 1; },
  'invented output line': c => { c.hunks[0].new.line_start = 1; },
  'wrong output bytes': c => { c.hunks[0].after_hex = hex('BAD\r\nlast'); },
  'omitted bytes': c => { c.hunks = []; },
})) test(`new text rejects ${name} despite valid native receipt shape`, async () => {
  const f = creationFixture(); change(f.capture.inspection.comparison.entries[0].content);
  assert.doesNotThrow(() => validateSourceEdit(f.capture, Buffer.from(f.bundle, 'hex')));
  await assert.rejects(verify(f));
});
test('all caller-owned creation evidence is captured before asynchronous verification', async () => {
  const f = creationFixture('sha256', 'nested'), e = material(f), bundle = Buffer.from(f.bundle, 'hex');
  const pending = validateSourceEditEvidence(f.capture, bundle, e);
  e.expected.create_paths_hex.length = 0; e.expected.source.files.length = 0; e.package_bytes.fill(0);
  f.capture.inspection.comparison.entries.length = 0; bundle.fill(0);
  const result = await pending; assert.deepEqual(result.source_verification.created_paths_hex, [f.target]);
  assert.equal(result.source_evidence.expected.source.files.length, 1);
});
test('cancellation throughout input and absence preflight never reaches native preparation', async t => {
  const f = await creationPeer(t), stop = new AbortController(); stop.abort();
  await assert.rejects(captureVerifiedSourceEdit(f.request, f.patchBytes, TOKEN, f.evidence, { signal: stop.signal }), /cancelled/);
  let total = 0;
  await bindVerifiedEditSource(f.evidence.package_bytes, f.evidence.expected, f.request, () => { total++; });
  for (const at of [1, 10, Math.floor(total / 2), total - 1, total]) {
    let n = 0;
    await assert.rejects(bindVerifiedEditSource(f.evidence.package_bytes, f.evidence.expected, f.request,
      () => { if (++n === at) throw new Error('cancel preflight'); }), /cancel preflight/);
  }
  assert.equal(f.calls.length, 0);
});
test('existing v1 evidence results and normalization do not acquire creation semantics', async () => {
  const f = evidenceFixture(), result = await validateSourceEditEvidence(f.capture, Buffer.from(f.bundle, 'hex'), oldMaterial(f));
  assert.equal(result.source_verification.profile, 'frankengit-source-edit-evidence-v1');
  assert.equal(Object.hasOwn(result.source_verification, 'path_absence_verified'), false);
  assert.deepEqual(result.source_evidence.expected, f.expected);
});
