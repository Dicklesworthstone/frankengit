import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { validateSourceEdit, captureSourceEdit } from '../../scripts/operator/source_edit_candidate.mjs';
import { bindVerifiedEditSource, validateSourceEditEvidence, captureVerifiedSourceEdit } from '../../scripts/operator/source_edit_from_package.mjs';
import { evidenceFixture, evidencePeer, material, TOKEN } from './source_edit_evidence_fixture.mjs';
const verify = (f, evidence = material(f), check) => validateSourceEditEvidence(f.capture, Buffer.from(f.bundle, 'hex'), evidence, check);
const clone = value => structuredClone(value);
for (const format of ['sha1', 'sha256']) {
  for (const scenario of ['text', 'raw', 'empty', 'delete', 'nested-delete', 'mode', 'binary']) {
    test(`${format}/${scenario}: replay native inspection against actual Git basis and trees`, async () => {
      const f = evidenceFixture(format, scenario), original = clone(f);
      const result = await verify(f), r = result.source_verification;
      assert.equal(r.commit, f.base); assert.equal(r.before_tree, f.beforeTree); assert.equal(r.after_tree, f.afterTree);
      assert.equal(r.preimages_verified, true); assert.equal(r.exact_tree_effects_verified, true);
      assert.equal(r.unrelated_entries_preserved, true); assert.equal(r.verified_paths, 1);
      assert.deepEqual(r.unverified_after_paths_hex, scenario === 'binary' ? [f.pathHex] : []);
      assert.equal(r.replayed_text_files, ['mode', 'binary'].includes(scenario) ? 0 : 1);
      for (const name of ['patch_application_verified', 'bundle_objects_independently_verified', 'authority_verified', 'freshness_verified', 'publication_authorized']) assert.equal(r[name], false);
      assert.deepEqual(f, original);
      assert.deepEqual((await validateSourceEditEvidence(result.capture, result.bundle, result.source_evidence)).source_verification, r);
    });
  }
  test(`${format}: hidden edits outside the declared path set cannot enter a verified candidate`, async () => {
    const f = evidenceFixture(format, 'hidden');
    assert.doesNotThrow(() => validateSourceEdit(f.capture, Buffer.from(f.bundle, 'hex')));
    await assert.rejects(verify(f), /source_edit_unreported_tree_effect/);
  });
  test(`${format}: production acquisition keeps the exact independently checked candidate`, async t => {
    const f = await evidencePeer(t, format);
    const captured = await captureVerifiedSourceEdit(f.request, f.patchBytes, TOKEN, f.evidence);
    assert.equal(captured.candidate_commit, f.candidate);
    assert.equal(captured.source_verification.before_tree, f.beforeTree);
    assert.equal(captured.source_verification.after_tree, f.afterTree);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
    assert.equal(captured.metrics.requests, 2);
    for (const call of f.calls) assert.equal(call.headers['idempotency-key'], undefined);
    assert.ok(f.calls[0].body.includes(f.patchBytes)); assert.ok(f.calls[1].body.includes(f.bundleBytes));
  });
}
const alterations = {
  'wrong base tree': f => { f.capture.inspection.comparison.before_tree = 'f'.repeat(40); },
  'substituted old blob': f => {
    f.capture.preparation.paths[0].old_blob = 'f'.repeat(40);
    f.capture.inspection.comparison.entries[0].before.oid = 'f'.repeat(40);
  },
  'wrong old executable bit': f => { const row = f.capture.inspection.comparison.entries[0]; row.before.mode = 0o100755; row.kind = 'mode_changed'; },
  'invented old length': f => { f.capture.inspection.comparison.entries[0].content.before_bytes++; },
  'same-sized different preimage': f => { f.capture.inspection.comparison.entries[0].content.hunks[0].before_hex = Buffer.from('BAD\r\n').toString('hex'); },
  'invented old line': f => { f.capture.inspection.comparison.entries[0].content.hunks[0].old.line_start++; },
  'invented new line': f => { f.capture.inspection.comparison.entries[0].content.hunks[0].new.line_start++; },
  'changed new blob bytes': f => { f.capture.inspection.comparison.entries[0].content.hunks[0].after_hex = Buffer.from('BAD\r\n').toString('hex'); },
  'dropped real change': f => { f.capture.inspection.comparison.entries[0].content.hunks = []; },
  'wrong new location and total': f => { const c = f.capture.inspection.comparison.entries[0].content; c.hunks[0].new.byte_start++; c.hunks[0].new.byte_end++; c.after_bytes++; },
  'opaque ordinary-file effect': f => { f.capture.inspection.comparison.entries[0].content = { type: 'object_only', content_read: false }; },
};
for (const [name, alter] of Object.entries(alterations)) test(`self-consistent native report still refuses ${name}`, async () => {
  const f = evidenceFixture(); alter(f);
  assert.doesNotThrow(() => validateSourceEdit(f.capture, Buffer.from(f.bundle, 'hex')), 'target the additional source-evidence check');
  await assert.rejects(verify(f));
});
test('same-size old hash substitutions cannot be disguised as a mode-only change', async () => {
  const f = evidenceFixture('sha1', 'mode'); f.capture.preparation.paths[0].old_blob = 'f'.repeat(40);
  f.capture.preparation.paths[0].new_blob = 'f'.repeat(40);
  const row = f.capture.inspection.comparison.entries[0]; row.before.oid = row.after.oid = 'f'.repeat(40);
  assert.doesNotThrow(() => validateSourceEdit(f.capture, Buffer.from(f.bundle, 'hex')));
  await assert.rejects(verify(f), /preimage_identity/);
});
test('binary preimages retain their exact byte count despite an omitted after body', async () => {
  const f = evidenceFixture('sha1', 'binary'); f.capture.inspection.comparison.entries[0].content.before_bytes++;
  await assert.rejects(verify(f), /preimage_size/);
});
test('input package, independent expectation and edit paths must agree before network I/O', async t => {
  const f = await evidencePeer(t);
  for (const alter of [e => { e.expected.commit = 'f'.repeat(40); }, e => { e.package_bytes.fill(0); },
    e => { e.expected.files[0].blob = 'f'.repeat(40); }]) {
    const evidence = { package_bytes: Buffer.from(f.evidence.package_bytes), expected: clone(f.evidence.expected) }; alter(evidence);
    await assert.rejects(captureVerifiedSourceEdit(f.request, f.patchBytes, TOKEN, evidence));
  }
  const request = clone(f.request); request.paths_hex = [Buffer.from('untouched').toString('hex')];
  await assert.rejects(captureVerifiedSourceEdit(request, f.patchBytes, TOKEN, f.evidence), /package_path/);
  assert.equal(f.calls.length, 0);
});
test('input preflight remains usable but does not attest to candidate effects', async () => {
  const f = evidenceFixture(), evidence = material(f);
  const r = await bindVerifiedEditSource(evidence.package_bytes, evidence.expected, f.capture.request);
  assert.equal(r.verified_commit, f.base); assert.equal(r.source_package_verified, true);
  assert.equal(r.verified_paths[0].blob, f.oldId); assert.equal(r.publication_authorized, false);
  assert.equal(Object.hasOwn(r, 'exact_tree_effects_verified'), false);
});
test('offline verification owns capture, bundle and evidence before asynchronous hashing', async () => {
  const f = evidenceFixture(), evidence = material(f), bundle = Buffer.from(f.bundle, 'hex');
  const pending = validateSourceEditEvidence(f.capture, bundle, evidence);
  f.capture.request.paths_hex.length = 0; f.capture.inspection.comparison.entries.length = 0;
  evidence.package_bytes.fill(0); evidence.expected.files.length = 0; bundle.fill(0);
  const result = await pending;
  assert.equal(result.source_verification.verified_paths, 1);
  assert.notEqual(result.bundle[0], 0); assert.equal(result.source_evidence.expected.files.length, 1);
});
test('acquisition owns patch and selection before package verification yields', async t => {
  const f = await evidencePeer(t), originalHash = createHash('sha256').update(f.patchBytes).digest('hex');
  const request = clone(f.request), patch = Buffer.from(f.patchBytes), evidence = material(f);
  const pending = captureVerifiedSourceEdit(request, patch, TOKEN, evidence);
  request.expected_commit = 'f'.repeat(40); patch.fill(0); evidence.package_bytes.fill(0); evidence.expected.files.length = 0;
  const result = await pending;
  assert.equal(result.capture.patch_sha256, originalHash); assert.equal(result.source_verification.commit, f.base);
});
test('cancellation and malformed evidence fail closed, never granting another route', async t => {
  const f = await evidencePeer(t), stop = new AbortController(); stop.abort();
  await assert.rejects(captureVerifiedSourceEdit(f.request, f.patchBytes, TOKEN, f.evidence, { signal: stop.signal }), /cancelled/);
  assert.equal(f.calls.length, 0);
  for (const evidence of [{ ...f.evidence, verified: true }, { package_bytes: f.evidence.package_bytes }, null]) {
    await assert.rejects(validateSourceEditEvidence(f.capture, f.bundleBytes, evidence));
  }
  let n = 0;
  await assert.rejects(verify(f, material(f), () => { if (++n === 9) throw new Error('stopped'); }), /stopped/);
});
test('ordinary prepare remains distinct from independently verified native effects', async t => {
  const f = await evidencePeer(t, 'sha1', 'hidden');
  const ordinary = await captureSourceEdit(f.request, f.patchBytes, TOKEN);
  assert.equal(ordinary.candidate_commit, f.candidate); assert.equal(ordinary.source_evidence, undefined);
  await assert.rejects(captureVerifiedSourceEdit(f.request, f.patchBytes, TOKEN, f.evidence), /unreported_tree_effect/);
  assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect', 'prepare', 'inspect']);
});
