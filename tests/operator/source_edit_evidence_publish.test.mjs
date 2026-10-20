// Actual private-file custody and native-schema sockets. No substituted owner,
// serializer or source verifier; fixtures use installed Git only for evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, readdir, access, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { saveSourceEdit, saveVerifiedSourceEdit, loadSourceEdit, stageSourceApply,
  dispatchSourceApply, recoverSourceApply, inspectSourceApply } from '../../scripts/operator/source_edit_publish.mjs';
import { canonical } from '../../scripts/operator/source_edit_candidate.mjs';
import { hash } from '../../scripts/operator/source_edit_wire.mjs';
import { evidenceFixture, evidencePeer, material, TOKEN, PRINCIPAL } from './source_edit_evidence_fixture.mjs';
async function local(t, format = 'sha1', scenario = 'text') {
  const f = await evidencePeer(t, format, scenario), dir = await mkdtemp(join(tmpdir(), 'fg-evidence-custody-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const candidate = join(dir, 'candidate'), journal = join(dir, 'journal');
  const save = () => saveVerifiedSourceEdit(candidate, f.capture, f.bundleBytes, f.evidence);
  const stage = async () => {
    const saved = await save();
    const staged = await stageSourceApply(journal, candidate, saved.manifest_sha256, PRINCIPAL);
    return { saved, staged };
  };
  return { ...f, dir, candidatePath: candidate, journal, save, stage };
}
export function terminal(f) {
  return { type: 'source_publication', schema_version: 1, ...f.request.scope, principal_id: PRINCIPAL,
    ref: f.request.ref, ref_hex: Buffer.from(f.request.ref).toString('hex'), expected_commit: f.base, candidate_commit: f.candidate,
    tx_id: 'evidence-tx', outcome: 'committed', decision_sequence: 7, decision_record: 'evidence-rcr', refusal_code: null, delivery_acknowledged: null };
}
export function outcome(f) {
  return { type: 'transaction_outcome', schema_version: 1, tenant_id: f.request.scope.tenant_id, repository_id: f.request.scope.repository_id,
    repository_incarnation: f.request.scope.repository_incarnation, principal_id: PRINCIPAL, selector: 'transaction', command_index: null,
    state: 'committed', terminal: true, transaction: { tx_id: 'evidence-tx', seal_id: 'evidence-seal', request_schema: 'evidence-request',
      canonical_request_digest: { algorithm: 2, hex: '6'.repeat(64) } },
    decision: { kind: 'committed', decision_sequence: 7, repository_commit_id: 'evidence-rcr' }, read_only: true, request_reexecuted: false,
    absence_proves_non_commit: false, session_completeness_established: false };
}
export const send = (res, value) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
for (const format of ['sha1', 'sha256']) {
  test(`${format}: source evidence is manifest-bound and freshly verified on offline load`, async t => {
    const f = await local(t, format), saved = await f.save();
    const manifest = await readFile(join(f.candidatePath, 'manifest.json'));
    assert.equal(hash(manifest), saved.manifest_sha256);
    const root = JSON.parse(manifest);
    assert.equal(root.schema, 'frankengit-source-edit-files-v2');
    assert.deepEqual(await readFile(join(f.candidatePath, 'source-package.json')), f.evidence.package_bytes);
    assert.deepEqual(await readFile(join(f.candidatePath, 'source-expected.json')), canonical(f.expected));
    assert.equal(root.source_evidence.package_sha256, hash(f.evidence.package_bytes));
    assert.equal(root.source_evidence.expected_sha256, hash(canonical(f.expected)));
    const loaded = await loadSourceEdit(f.candidatePath, saved.manifest_sha256);
    assert.deepEqual(loaded.source_verification, saved.source_verification);
    assert.deepEqual(loaded.source_evidence.package_bytes, f.evidence.package_bytes);
    assert.equal(f.calls.length, 0);
    loaded.source_evidence.package_bytes.fill(0);
    assert.equal((await loadSourceEdit(f.candidatePath, saved.manifest_sha256)).source_verification.preimages_verified, true);
  });
  test(`${format}: staging, apply and terminal replay preserve self-contained evidence and original key`, async t => {
    const f = await local(t, format), { saved, staged } = await f.stage();
    assert.equal(staged.source_verification.package_sha256, saved.source_verification.package_sha256);
    const copied = await loadSourceEdit(join(f.journal, 'candidate'), saved.manifest_sha256);
    assert.deepEqual(copied.source_verification, saved.source_verification);
    await rm(f.candidatePath, { recursive: true });
    f.control.handler = (_req, res, call) => {
      assert.equal(call.operation, 'apply'); assert.equal(call.headers['idempotency-key'], staged.key);
      assert.ok(call.body.includes(f.bundleBytes)); send(res, terminal(f));
    };
    const applied = await dispatchSourceApply(f.journal, staged.request_sha256, TOKEN);
    assert.equal(applied.decision.outcome, 'committed'); assert.equal(applied.source_verification.exact_tree_effects_verified, true);
    const status = await inspectSourceApply(f.journal, staged.request_sha256);
    assert.deepEqual(status.source_verification, applied.source_verification);
    assert.deepEqual((await recoverSourceApply(f.journal, staged.request_sha256, TOKEN)).decision, applied.decision);
    assert.equal(f.calls.length, 1);
  });
}
for (const name of ['source-package.json', 'source-expected.json']) {
  for (const action of ['change', 'remove', 'symlink', 'public']) test(`${action} ${name} refuses before dispatch or recovery I/O`, async t => {
    const f = await local(t), { staged } = await f.stage(), path = join(f.journal, 'candidate', name);
    if (action === 'change') await writeFile(path, '{}\n');
    else if (action === 'remove') await rm(path);
    else if (action === 'public') await chmod(path, 0o644);
    else { await rm(path); await symlink(join(f.candidatePath, name), path); }
    await assert.rejects(inspectSourceApply(f.journal, staged.request_sha256));
    await assert.rejects(dispatchSourceApply(f.journal, staged.request_sha256, TOKEN));
    await assert.rejects(recoverSourceApply(f.journal, staged.request_sha256, TOKEN));
    await assert.rejects(access(join(f.journal, 'dispatch'))); assert.equal(f.calls.length, 0);
  });
}
test('evidence-root downgrade cannot reuse a separately retained manifest hash', async t => {
  const f = await local(t), saved = await f.save(), path = join(f.candidatePath, 'manifest.json');
  const root = JSON.parse(await readFile(path)); root.schema = 'frankengit-source-edit-files-v1'; delete root.source_evidence;
  await writeFile(path, canonical(root));
  await assert.rejects(loadSourceEdit(f.candidatePath, saved.manifest_sha256), /manifest_changed/);
});
test('even newly pinned local hashes cannot bless a source-inconsistent native report', async t => {
  const f = await local(t), saved = await f.save();
  const path = join(f.candidatePath, 'capture.json'), capture = JSON.parse(await readFile(path));
  capture.inspection.comparison.entries[0].content.hunks[0].before_hex = Buffer.from('BAD\r\n').toString('hex');
  const data = canonical(capture); await writeFile(path, data);
  const rootPath = join(f.candidatePath, 'manifest.json'), root = JSON.parse(await readFile(rootPath));
  root.capture_sha256 = hash(data); root.capture_bytes = data.length;
  const newRoot = canonical(root); await writeFile(rootPath, newRoot);
  assert.notEqual(hash(newRoot), saved.manifest_sha256);
  await assert.rejects(loadSourceEdit(f.candidatePath, hash(newRoot)), /preimage_span/);
});
test('ordinary v1 serialization stays exact and does not claim independent evidence', async t => {
  const f = await local(t), saved = await saveSourceEdit(f.candidatePath, f.capture, f.bundleBytes);
  const root = { schema: 'frankengit-source-edit-files-v1', capture_sha256: hash(canonical(f.capture)), capture_bytes: canonical(f.capture).length,
    bundle_sha256: hash(f.bundleBytes), bundle_bytes: f.bundleBytes.length };
  assert.deepEqual(await readFile(join(f.candidatePath, 'manifest.json')), canonical(root));
  assert.equal(saved.manifest_sha256, hash(canonical(root)));
  assert.deepEqual((await readdir(f.candidatePath)).sort(), ['candidate.bundle', 'capture.json', 'manifest.json']);
  assert.equal((await loadSourceEdit(f.candidatePath, saved.manifest_sha256)).source_verification, undefined);
});
test('a genuine hidden sibling edit cannot be saved through the verified writer', async t => {
  const f = await local(t, 'sha256', 'hidden'); await assert.rejects(f.save(), /unreported_tree_effect/);
  await assert.rejects(access(f.candidatePath));
});
test('saved binary evidence never upgrades omitted after bodies into verified bytes', async t => {
  const f = await local(t, 'sha256', 'binary'), saved = await f.save();
  const loaded = await loadSourceEdit(f.candidatePath, saved.manifest_sha256);
  assert.deepEqual(loaded.source_verification.unverified_after_paths_hex, [f.pathHex]);
  assert.equal(loaded.source_verification.replayed_text_files, 0);
  assert.equal(loaded.source_verification.patch_application_verified, false);
});
test('one destination has one winner and losing exporter cannot replace evidence', async t => {
  const f = await local(t), results = await Promise.allSettled([f.save(), f.save()]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const saved = results.find(r => r.status === 'fulfilled').value;
  await loadSourceEdit(f.candidatePath, saved.manifest_sha256);
});
test('saving owns native capture and evidence before asynchronous checks', async t => {
  const f = await local(t), capture = structuredClone(f.capture), bundle = Buffer.from(f.bundleBytes), evidence = material(f);
  const pending = saveVerifiedSourceEdit(f.candidatePath, capture, bundle, evidence);
  capture.request.paths_hex.length = 0; bundle.fill(0); evidence.expected.files.length = 0; evidence.package_bytes.fill(0);
  const saved = await pending; const loaded = await loadSourceEdit(f.candidatePath, saved.manifest_sha256);
  assert.equal(loaded.source_verification.verified_paths, 1); assert.equal(loaded.candidate_commit, f.candidate);
});
test('prepublication cancellation refuses without claiming a candidate directory', async t => {
  const f = await local(t), stop = new AbortController(); stop.abort();
  await assert.rejects(saveVerifiedSourceEdit(f.candidatePath, f.capture, f.bundleBytes, f.evidence, { signal: stop.signal }), /cancelled/);
  await assert.rejects(access(f.candidatePath));
});
test('uncertain apply keeps evidence, never permits resend, and recovery sends only original key', async t => {
  const f = await local(t), { saved, staged } = await f.stage();
  f.control.handler = (_req, res, call) => {
    if (call.operation === 'apply') { res.destroy(); return; }
    assert.equal(call.operation, 'outcomes'); assert.equal(call.body.length, 0); assert.equal(call.headers['idempotency-key'], staged.key);
    send(res, outcome(f));
  };
  await assert.rejects(dispatchSourceApply(f.journal, staged.request_sha256, TOKEN), e => e.retained_request?.source_verification.preimages_verified === true);
  await assert.rejects(dispatchSourceApply(f.journal, staged.request_sha256, TOKEN), /already_dispatched/);
  const source = join(f.journal, 'candidate', 'source-package.json');
  const bytes = await readFile(source); await writeFile(source, '{}');
  const count = f.calls.length;
  await assert.rejects(recoverSourceApply(f.journal, staged.request_sha256, TOKEN));
  assert.equal(f.calls.length, count); await access(join(f.journal, 'dispatch', 'started.json'));
  // Restore the ORIGINAL pinned bytes, not a replacement base/evidence selection.
  await writeFile(source, bytes);
  const terminal = await recoverSourceApply(f.journal, staged.request_sha256, TOKEN);
  assert.equal(terminal.decision.outcome, 'committed');
  assert.equal(terminal.source_verification.package_sha256, saved.source_verification.package_sha256);
  assert.deepEqual(f.calls.map(c => c.operation), ['apply', 'outcomes']);
});
