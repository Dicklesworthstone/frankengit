import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, access, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical, hash } from '../../scripts/operator/source_edit_candidate.mjs';
import { saveSourceEdit, saveVerifiedSourceEdit, loadSourceEdit, stageSourceApply,
  dispatchSourceApply, recoverSourceApply, inspectSourceApply } from '../../scripts/operator/source_edit_publish.mjs';
import { creationPeer, TOKEN, PRINCIPAL } from './source_edit_creation_fixture.mjs';
import { evidenceFixture, material as oldMaterial } from './source_edit_evidence_fixture.mjs';
async function setup(t, format = 'sha1') {
  const f = await creationPeer(t, format, 'nested'), directory = await mkdtemp(join(tmpdir(), 'fg-create-custody-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const candidate = join(directory, 'candidate'), journal = join(directory, 'journal');
  const saved = await saveVerifiedSourceEdit(candidate, f.capture, f.bundleBytes, f.evidence);
  const staged = await stageSourceApply(journal, candidate, saved.manifest_sha256, PRINCIPAL);
  const outcome = { type: 'transaction_outcome', schema_version: 1,
    tenant_id: f.request.scope.tenant_id, repository_id: f.request.scope.repository_id,
    repository_incarnation: f.request.scope.repository_incarnation, principal_id: PRINCIPAL,
    selector: 'transaction', command_index: null, state: 'committed', terminal: true,
    transaction: { tx_id: 'create-tx', seal_id: 'create-seal', request_schema: 'source-edit',
      canonical_request_digest: { algorithm: 2, hex: '6'.repeat(64) } },
    decision: { kind: 'committed', decision_sequence: '18446744073709551615', repository_commit_id: 'create-rcr' },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
  const publication = { type: 'source_publication', schema_version: 1, ...f.request.scope, principal_id: PRINCIPAL,
    ref: f.request.ref, ref_hex: Buffer.from(f.request.ref).toString('hex'), expected_commit: f.base, candidate_commit: f.candidate,
    tx_id: 'create-tx', outcome: 'committed', decision_sequence: '18446744073709551615', decision_record: 'create-rcr',
    refusal_code: null, delivery_acknowledged: null };
  const send = (res, value) => { res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(value).replace(/"decision_sequence":"([0-9]+)"/g, '"decision_sequence":$1')); };
  return { ...f, directory, candidatePath: candidate, journal, saved, staged, publication, outcome, send };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: v3 owns absence intent and source evidence through staging and one-shot apply`, async t => {
    const f = await setup(t, format), root = JSON.parse(await readFile(join(f.candidatePath, 'manifest.json')));
    assert.equal(root.schema, 'frankengit-source-edit-files-v3');
    assert.equal(root.source_evidence.profile, 'frankengit-source-edit-evidence-v2');
    const expectedBytes = await readFile(join(f.candidatePath, 'source-expected.json'));
    assert.equal(hash(expectedBytes), root.source_evidence.expected_sha256);
    assert.deepEqual(JSON.parse(expectedBytes), f.expected);
    assert.equal((await loadSourceEdit(f.candidatePath, f.saved.manifest_sha256)).source_verification.path_absence_verified, true);
    await rm(f.candidatePath, { recursive: true });
    f.control.handler = async (_req, res, call) => {
      assert.equal(call.operation, 'apply'); assert.equal(call.headers['idempotency-key'], f.staged.key);
      assert.deepEqual(await readFile(join(f.journal, 'candidate', 'source-expected.json')), expectedBytes);
      const start = JSON.parse(await readFile(join(f.journal, 'dispatch', 'started.json')));
      assert.equal(start.request_sha256, f.staged.request_sha256);
      f.send(res, f.publication);
    };
    const result = await dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN);
    assert.equal(result.decision.decision_sequence, '18446744073709551615');
    assert.equal(result.source_verification.path_absence_verified, true);
    const status = await inspectSourceApply(f.journal, f.staged.request_sha256);
    assert.equal(status.state, 'terminal'); assert.deepEqual(status.source_verification, result.source_verification);
    await recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN);
    assert.equal(f.calls.length, 1);
  });
  test(`${format}: loss after transmission preserves the original creation request and outcome lookup`, async t => {
    const f = await setup(t, format);
    f.control.handler = (_req, res, call) => {
      if (call.operation === 'apply') { res.destroy(); return; }
      assert.equal(call.operation, 'outcomes'); assert.equal(call.body.length, 0);
      assert.equal(call.headers['idempotency-key'], f.staged.key); f.send(res, f.outcome);
    };
    await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN), e => !!e.retained_request);
    await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN), /already_dispatched/);
    const result = await recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN);
    assert.equal(result.source_verification.path_absence_verified, true);
    assert.deepEqual(f.calls.map(c => c.operation), ['apply', 'outcomes']);
  });
}
for (const name of ['source-package.json', 'source-expected.json']) {
  test(`missing ${name} cannot downgrade a creation or acquire dispatch ownership`, async t => {
    const f = await setup(t), selected = join(f.journal, 'candidate', name);
    const original = await readFile(selected); await rm(selected);
    await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN));
    await assert.rejects(access(join(f.journal, 'dispatch'))); assert.equal(f.calls.length, 0);
    await writeFile(selected, original, { mode: 0o600 });
    assert.equal((await inspectSourceApply(f.journal, f.staged.request_sha256)).state, 'not_dispatched');
  });
  test(`altered ${name} after an uncertain apply cannot permit recovery or another apply`, async t => {
    const f = await setup(t); f.control.handler = (_req, res) => res.destroy();
    await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN));
    await writeFile(join(f.journal, 'candidate', name), 'changed');
    await assert.rejects(recoverSourceApply(f.journal, f.staged.request_sha256, TOKEN));
    await assert.rejects(dispatchSourceApply(f.journal, f.staged.request_sha256, TOKEN));
    await access(join(f.journal, 'dispatch', 'started.json')); assert.equal(f.calls.length, 1);
  });
}
for (const [schema, profile] of [
  ['frankengit-source-edit-files-v2', 'frankengit-source-edit-evidence-v1'],
  ['frankengit-source-edit-files-v3', 'frankengit-source-edit-evidence-v1'],
  ['frankengit-source-edit-files-v2', 'frankengit-source-edit-evidence-v2'],
]) test(`creation intent cannot be relabeled ${schema}/${profile}`, async t => {
  const f = await setup(t), path = join(f.candidatePath, 'manifest.json');
  const root = JSON.parse(await readFile(path)); root.schema = schema; root.source_evidence.profile = profile;
  const bytes = canonical(root); await writeFile(path, bytes);
  await assert.rejects(loadSourceEdit(f.candidatePath, hash(bytes)), /evidence_profile/);
});
test('v1 and v2 serialization stays byte-identical for ordinary and positive-evidence candidates', async t => {
  const f = await setup(t), old = evidenceFixture(), bundle = Buffer.from(old.bundle, 'hex'), capture = canonical(old.capture);
  const root = { schema: 'frankengit-source-edit-files-v1', capture_sha256: hash(capture), capture_bytes: capture.length,
    bundle_sha256: hash(bundle), bundle_bytes: bundle.length };
  const plain = join(f.directory, 'ordinary'), positive = join(f.directory, 'positive');
  const a = await saveSourceEdit(plain, old.capture, bundle);
  assert.deepEqual(await readFile(join(plain, 'manifest.json')), canonical(root)); assert.equal(a.manifest_sha256, hash(canonical(root)));
  const evidence = oldMaterial(old), expectedBytes = canonical(evidence.expected);
  root.schema = 'frankengit-source-edit-files-v2'; root.source_evidence = { profile: 'frankengit-source-edit-evidence-v1',
    package_sha256: hash(evidence.package_bytes), package_bytes: evidence.package_bytes.length,
    expected_sha256: hash(expectedBytes), expected_bytes: expectedBytes.length };
  const b = await saveVerifiedSourceEdit(positive, old.capture, bundle, evidence);
  assert.deepEqual(await readFile(join(positive, 'manifest.json')), canonical(root)); assert.equal(b.manifest_sha256, hash(canonical(root)));
  assert.equal((await loadSourceEdit(positive, b.manifest_sha256)).source_verification.profile, 'frankengit-source-edit-evidence-v1');
  root.schema = 'frankengit-source-edit-files-v3'; root.source_evidence.profile = 'frankengit-source-edit-evidence-v2';
  await writeFile(join(positive, 'manifest.json'), canonical(root));
  await assert.rejects(loadSourceEdit(positive, hash(canonical(root))), /evidence_profile/);
});
test('create-only evidence publication preserves competing writers and cancellation-before-claim', async t => {
  const f = await setup(t), path = join(f.directory, 'race');
  const results = await Promise.allSettled([saveVerifiedSourceEdit(path, f.capture, f.bundleBytes, f.evidence),
    saveVerifiedSourceEdit(path, f.capture, f.bundleBytes, f.evidence)]);
  assert.equal(results.filter(v => v.status === 'fulfilled').length, 1);
  await loadSourceEdit(path, f.saved.manifest_sha256);
  const stop = new AbortController(); stop.abort(); const absent = join(f.directory, 'cancel');
  await assert.rejects(saveVerifiedSourceEdit(absent, f.capture, f.bundleBytes, f.evidence, { signal: stop.signal }));
  await assert.rejects(access(absent));
});
test('private evidence checks reject public files and symbolic aliases', async t => {
  const f = await setup(t), name = join(f.candidatePath, 'source-expected.json'), original = await readFile(name);
  await chmod(name, 0o644); await assert.rejects(loadSourceEdit(f.candidatePath, f.saved.manifest_sha256));
  await chmod(name, 0o600); await rm(name);
  const alternative = join(f.directory, 'alternate'); await writeFile(alternative, original, { mode: 0o600 }); await symlink(alternative, name);
  await assert.rejects(loadSourceEdit(f.candidatePath, f.saved.manifest_sha256)); assert.equal(f.calls.length, 0);
});
