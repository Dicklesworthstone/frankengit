// Real fragments, signatures and files. The invoked native-schema peer is NOT fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile, unlink, readdir, lstat, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { recoverRepositoryBackup, repositoryBackupRecoveryOptions } from '../lib/repository-backup-recovery.mjs';
import { catalogRepositoryBackupChunks, BACKUP_CHUNK_BYTES as C } from '../lib/repository-backup-chunks.mjs';
import { withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { recoveryFixture, digest } from './backup-recovery-fixture.mjs';

const DATA = Buffer.concat([Buffer.alloc(C, 0x41), Buffer.alloc(C, 0x42)]);
const sha = b => createHash('sha256').update(b).digest();
const absent = path => assert.rejects(lstat(path), { code: 'ENOENT' });
async function fixture(t, format = 'sha256') {
  const f = await recoveryFixture(t, format);
  const signed = await f.sign(DATA);
  const catalog = join(f.root, 'chunks.catalog'), a = join(f.root, 'a-damaged'), b = join(f.root, 'b-damaged');
  await catalogRepositoryBackupChunks({ input: f.local, output: catalog, approval: f.approval, trustKey: f.trustKey,
    policy: f.options.policy, maximumBytes: DATA.length });
  const first = Buffer.from(DATA), second = Buffer.from(DATA); first[0] ^= 1; second[C] ^= 1;
  await writeFile(a, first); await writeFile(b, second); await unlink(f.local);
  const { sourceFile, caFile, ...base } = f.verifyOptions();
  const options = { ...base, repairCatalog: catalog, repairReplicas: [b, a], maximumBytes: DATA.length,
    maximumAcquisitionBytes: DATA.length * 4 + C, timeoutMs: 20000 };
  const cached = join(f.destination, `archive-sha256-${digest(DATA)}.fgbackup`);
  const restore = () => ({ ...options, operation: 'restore', destination: f.options.destination,
    destinationInstance: '12', approvalRecord: f.options.approvalRecord });
  return { ...f, catalog, a, b, first, second, signed, options, cached, restore };
}
const cleanFailure = async f => {
  assert.deepEqual(await f.events(), []); assert.deepEqual(f.requests, []);
  assert.deepEqual(await readdir(f.destination), []); await absent(f.options.approvalRecord ?? f.restore().approvalRecord);
};
for (const format of ['sha1', 'sha256']) test(`${format}: complementary corrupt replicas reach signed native preflight with no intact copy`, async t => {
  const f = await fixture(t, format); await absent(f.local);
  const r = await recoverRepositoryBackup(f.options);
  assert.equal(r.state, 'complete'); assert.equal(r.acquisition.mode, 'reconstructed');
  assert.equal(r.acquisition.reconstruction.original_archive_authenticated, true);
  assert.equal(r.acquisition.reconstruction.catalog_is_authority, false);
  assert.equal(r.acquisition.streaming.total_payload_bytes_read, String(DATA.length * 4 + C));
  assert.deepEqual(r.acquisition.reconstruction.replicas.map(x => x.chunks_used), [1, 1]);
  assert.deepEqual(await readFile(r.candidate.input), DATA);
  assert.deepEqual(await readFile(r.candidate.approval), await readFile(f.approval));
  assert.deepEqual(await readFile(f.a), f.first); assert.deepEqual(await readFile(f.b), f.second);
  assert.deepEqual(f.requests, []); assert.deepEqual((await f.events()).map(x => x.operation), ['verify']);
  assert.equal(r.native.native.signature_verified, true); assert.equal(r.complete_capsule_restored, false);
});
test('lost restore response resumes offline from the reconstructed cache under the original pin', async t => {
  const f = await fixture(t); await f.configure({ mode: 'lose_restore_response' }); let pin;
  await assert.rejects(recoverRepositoryBackup(f.restore()), e => {
    assert.equal(e.state, 'restore_attempted_unknown'); pin = e.recovery.checkpoint;
    assert.equal(e.recovery.acquisition.mode, 'reconstructed'); return true;
  });
  const before = await lstat(f.cached); await unlink(f.a); await unlink(f.b); await unlink(f.catalog);
  await unlink(f.sourceFile); await unlink(f.caFile);
  const { repairCatalog, repairReplicas, ...options } = f.restore();
  const r = await recoverRepositoryBackup({ ...options, resume: true, checkpoint: pin });
  assert.equal(r.native.native.already_published, true); assert.equal(r.acquisition.mode, 'cached');
  assert.equal((await lstat(f.cached)).ino, before.ino); assert.deepEqual(f.requests, []);
  assert.deepEqual((await f.events()).map(x => x.operation), ['verify', 'restore', 'verify', 'restore']);
});
test('cache hit authenticates original bytes without reading obsolete repair inputs', async t => {
  const f = await fixture(t); const first = await recoverRepositoryBackup(f.options);
  await unlink(f.catalog); await unlink(f.a); await unlink(f.b);
  const r = await recoverRepositoryBackup({ ...f.options, checkpoint: first.checkpoint });
  assert.equal(r.acquisition.mode, 'cached'); assert.deepEqual(f.requests, []);
});
test('truncated and corrupt replicas combine only complete authenticated chunks', async t => {
  const f = await fixture(t); await writeFile(f.a, DATA.subarray(0, C));
  const b = Buffer.from(DATA); b[0] ^= 1; await writeFile(f.b, b);
  const r = await recoverRepositoryBackup(f.options);
  assert.equal(r.acquisition.streaming.total_payload_bytes_read, String(DATA.length * 4));
  assert.deepEqual(await readFile(f.cached), DATA);
});
test('missing explicit replica does not prevent reconstruction from remaining fragments', async t => {
  const f = await fixture(t);
  const r = await recoverRepositoryBackup({ ...f.options, repairReplicas: [join(f.root, '0-absent'), f.a, f.b] });
  assert.equal(r.acquisition.reconstruction.replicas[0].unavailable, 'ENOENT');
  assert.deepEqual(await readFile(f.cached), DATA);
});
test('one unrecoverable range refuses before cache approval or native invocation', async t => {
  const f = await fixture(t); await writeFile(f.b, f.first);
  await assert.rejects(recoverRepositoryBackup(f.options), e => {
    assert.equal(e.code, 'backup_chunk_unrecoverable'); assert.equal(e.chunk_index, 0); return true;
  });
  await cleanFailure(f);
});
test('self-consistent forged chunk hints cannot override the original signed whole-archive digest', async t => {
  const f = await fixture(t); await writeFile(f.b, f.first);
  const catalog = await readFile(f.catalog);
  sha(f.first.subarray(0, C)).copy(catalog, 56);
  sha(catalog.subarray(0, -32)).copy(catalog, catalog.length - 32); await writeFile(f.catalog, catalog);
  await assert.rejects(recoverRepositoryBackup(f.options), { code: 'backup_chunk_readback_mismatch' });
  await cleanFailure(f);
});
test('repair shares exact payload budget with cache authentication and approval publication', async t => {
  const f = await fixture(t);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, maximumAcquisitionBytes: DATA.length * 4 + C - 1 }),
    { code: 'backup_chunk_read_budget' });
  await cleanFailure(f);
  const r = await recoverRepositoryBackup(f.options);
  assert.equal(r.acquisition.streaming.total_payload_bytes_read, String(f.options.maximumAcquisitionBytes));
});
test('less than minimum repair plus publication work refuses before staging', async t => {
  const f = await fixture(t);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, maximumAcquisitionBytes: DATA.length * 4 - 1 }),
    { code: 'backup_recovery_acquisition_budget' });
  await cleanFailure(f);
});
test('invalid signature is refused without reconstructing or ratcheting witness evidence', async t => {
  const f = await fixture(t), e = JSON.parse(await readFile(f.approval)); e.signatures[0].sig = Buffer.alloc(64).toString('base64');
  await writeFile(f.approval, JSON.stringify(e));
  await assert.rejects(recoverRepositoryBackup(f.options), { code: 'backup_invalid_signature' });
  await cleanFailure(f);
  const view = await withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, {}, w => w.snapshot());
  assert.equal(view.highest_observed_generation, null);
});
test('an unavailable newer checkpoint remains constraining after failed reconstruction', async t => {
  const f = await fixture(t), old = await readFile(f.approval);
  await f.sign(DATA, { head_generation: '9007199254740994' }); await writeFile(f.b, f.first);
  await assert.rejects(recoverRepositoryBackup(f.options), { code: 'backup_chunk_unrecoverable' });
  await writeFile(f.approval, old); await writeFile(f.b, f.second);
  await assert.rejects(recoverRepositoryBackup(f.options), { code: 'backup_below_witness' }); await cleanFailure(f);
});
test('a substituted valid approval cannot retarget the repaired-byte publisher', async t => {
  const f = await fixture(t);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, async onProgress(e) {
    if (e.phase === 'reconstruction_complete') await f.sign(DATA, { head_generation: '9007199254740994' });
  } }), { code: 'backup_replication_checkpoint_mismatch' });
  assert.deepEqual(await readFile(f.cached), DATA); assert.equal((await readdir(f.destination)).length, 1);
  assert.deepEqual(await f.events(), []);
});
test('corruption after reconstruction is caught before approval publication or native execution', async t => {
  const f = await fixture(t);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, async onProgress(e) {
    if (e.phase === 'reconstruction_complete') await writeFile(f.cached, f.first);
  } }), { code: 'backup_artifact_mismatch' });
  assert.deepEqual(await f.events(), []); assert.equal((await readdir(f.destination)).length, 1);
});
test('completed reconstruction survives observer failure and is reused on explicit retry', async t => {
  const f = await fixture(t);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, onProgress(e) {
    if (e.phase === 'reconstruction_complete') throw Object.assign(Error('stop'), { code: 'observer_stop' });
  } }), e => { assert.equal(e.recovery.reconstruction.state, 'complete'); return e.code === 'observer_stop'; });
  const before = await lstat(f.cached); await unlink(f.catalog);
  const r = await recoverRepositoryBackup(f.options); assert.equal(r.acquisition.mode, 'cached');
  assert.equal((await lstat(f.cached)).ino, before.ino);
});
test('cancellation during repair drains files without starting native work', async t => {
  const f = await fixture(t), controller = new AbortController();
  await assert.rejects(recoverRepositoryBackup({ ...f.options, signal: controller.signal, onProgress(e) {
    if (e.phase === 'repair_read') controller.abort();
  } }), e => e.code === 'backup_chunk_observer_failed' && e.cause.code === 'backup_cancelled');
  await cleanFailure(f); await absent(join(f.witness, '.witness-lock'));
  assert.equal((await recoverRepositoryBackup(f.options)).state, 'complete');
});
test('repair replica list is snapshotted before any observer runs', async t => {
  const f = await fixture(t), raw = { ...f.options, repairReplicas: [...f.options.repairReplicas] };
  raw.onProgress = e => { if (e.phase === 'checkpoint_pinned') raw.repairReplicas.fill(f.approval); };
  assert.equal((await recoverRepositoryBackup(raw)).state, 'complete');
});
test('physical repair-input aliases into the private cache are refused before reconstruction', async t => {
  const f = await fixture(t), alias = join(f.root, 'alias'); await symlink(f.destination, alias);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, repairReplicas: [join(alias, 'not-present'), f.a, f.b] }),
    { code: 'backup_recovery_separate_paths_required' }); await cleanFailure(f);
});
test('native refusal preserves repaired cache and never activates network fallback', async t => {
  const f = await fixture(t); await f.configure({ mode: 'refuse_verify' });
  await assert.rejects(recoverRepositoryBackup(f.options), { code: 'backup_native_refused' });
  assert.deepEqual(await readFile(f.cached), DATA); assert.deepEqual(f.requests, []);
  await f.configure({}); assert.equal((await recoverRepositoryBackup(f.options)).acquisition.mode, 'cached');
});
for (const kind of ['catalog-only', 'replicas-only', 'empty', 'too-many', 'duplicate', 'mixed-network', 'output-overlap']) {
  test(`invalid repair selection ${kind} refuses synchronously`, async t => {
    const f = await fixture(t), o = { ...f.options };
    if (kind === 'catalog-only') delete o.repairReplicas;
    if (kind === 'replicas-only') delete o.repairCatalog;
    if (kind === 'empty') o.repairReplicas = [];
    if (kind === 'too-many') o.repairReplicas = Array.from({ length: 65 }, (_, i) => join(f.root, String(i)));
    if (kind === 'duplicate') o.repairReplicas = [f.a, f.a];
    if (kind === 'mixed-network') o.sourceFile = f.sourceFile;
    if (kind === 'output-overlap') o.repairReplicas = [f.cached];
    assert.throws(() => repositoryBackupRecoveryOptions(o)); await cleanFailure(f);
  });
}
