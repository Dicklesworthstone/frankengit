// Real files, TLS and child processes; the native peer is NOT Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile, readdir, unlink, lstat, mkdir, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { recoverRepositoryBackup, repositoryBackupRecoveryOptions } from '../lib/repository-backup-recovery.mjs';
import { withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { catalogRepositoryBackupChunks, BACKUP_CHUNK_BYTES as C } from '../lib/repository-backup-chunks.mjs';
import { recoveryFixture, DATA, digest } from './backup-recovery-fixture.mjs';
const code = expected => e => e.code === expected;
const missing = path => assert.rejects(lstat(path), { code: 'ENOENT' });
function setOptions(f, candidates, extra = {}) {
  const { approval, sourceFile, caFile, ...base } = f.verifyOptions();
  return { ...base, candidates, ...extra };
}
async function row(f, name, generation, data = DATA, meta = {}) {
  const signed = await f.sign(data, { head_generation: generation, ...meta });
  const approval = join(f.root, name + '.approval'); await writeFile(approval, signed.envelope);
  return { approval, sourceFile: f.sourceFile, caFile: f.caFile };
}
const snapshot = f => withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, {}, w => w.snapshot());
const noEffects = async f => {
  assert.deepEqual(await f.events(), []); assert.deepEqual(f.requests, []);
  assert.deepEqual(await readdir(f.destination), []); await missing(f.options.approvalRecord);
};
for (const format of ['sha1', 'sha256']) for (const reverse of [false, true]) test(`${format}: highest full-width checkpoint wins, reversed=${reverse}`, async t => {
  const f = await recoveryFixture(t, format), a = await row(f, 'old', '9007199254740992'), b = await row(f, 'new', '9007199254740993');
  const r = await recoverRepositoryBackup(setOptions(f, reverse ? [b, a] : [a, b]));
  assert.equal(String(r.native.native.head_generation), '9007199254740993');
  assert.equal(r.checkpoint_selection.selected.approval, b.approval); assert.equal(r.checkpoint_selection.selected_index, reverse ? 0 : 1);
  assert.equal(r.checkpoint_selection.all_supplied_approvals_authenticated, true);
  assert.equal(r.checkpoint_selection.payloads_read, false); // Selection phase only.
  assert.equal(r.checkpoint_selection.newest_checkpoint_verified, false);
  assert.equal(r.checkpoint_selection.candidate_set_completeness_verified, false);
  assert.equal(r.recovery_witness.highest_observed_generation, '9007199254740993');
  assert.equal(f.requests.length, 1); assert.deepEqual((await f.events()).map(e => e.operation), ['verify']);
});
test('unselected acquisition files and their absent parents are never resolved/opened', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'old', '1'), b = await row(f, 'new', '2');
  const r = await recoverRepositoryBackup(setOptions(f, [
    { approval: a.approval, sourceFile: join(f.root, 'absent', 'urls'), caFile: join(f.root, 'absent', 'ca') },
    { approval: a.approval, repairCatalog: join(f.root, 'absent', 'catalog'), repairReplicas: [join(f.root, 'absent', 'replica')] }, b]));
  assert.equal(r.checkpoint_selection.selected_index, 2); assert.equal(f.requests.length, 1);
});
test('invalid lower approval refuses before payload/network/native work', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'old', '1'), b = await row(f, 'new', '2');
  const bad = JSON.parse(await readFile(a.approval)); bad.signatures[0].sig = Buffer.alloc(64).toString('base64');
  await writeFile(a.approval, JSON.stringify(bad));
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [b, a])), code('backup_invalid_signature'));
  await noEffects(f); assert.equal((await snapshot(f)).highest_observed_generation, '2');
});
test('missing higher payload never falls back to an intact cached lower checkpoint', async t => {
  const f = await recoveryFixture(t), low = await row(f, 'old', '1');
  await recoverRepositoryBackup(setOptions(f, [low]));
  const high = await row(f, 'new', '2', Buffer.alloc(DATA.length, 0x42)); high.sourceFile = join(f.root, 'missing-urls');
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [low, high])), { code: 'ENOENT' });
  assert.equal(f.requests.length, 1); assert.equal((await f.events()).length, 1);
  assert.equal((await snapshot(f)).highest_observed_generation, '2');
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [low])), code('backup_below_witness'));
});
for (const defect of ['expired', 'future', 'oversized']) test(`${defect} highest approval is retained before refusal`, async t => {
  const f = await recoveryFixture(t), low = await row(f, 'old', '1');
  const time = n => new Date(Math.floor(n / 1000) * 1000).toISOString().replace('.000Z', 'Z');
  const meta = defect === 'expired' ? { issued_at: time(Date.now() - 7200000), expires_at: time(Date.now() - 3600000) }
    : defect === 'future' ? { issued_at: time(Date.now() + 3600000), expires_at: time(Date.now() + 7200000) } : {};
  // Sign future evidence at its own issuance instant, then restore the real
  // clock before exercising recovery. No production verifier clock is injected.
  const clock = defect === 'future' ? t.mock.method(Date, 'now', () => Date.parse(meta.issued_at) + 1000) : null;
  let high;
  try { high = await row(f, 'new', '18446744073709551615', defect === 'oversized' ? Buffer.alloc(DATA.length + 1) : DATA, meta); }
  finally { clock?.mock.restore(); }
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [low, high])));
  await noEffects(f); assert.equal((await snapshot(f)).highest_observed_generation, '18446744073709551615');
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [low])), code('backup_below_witness'));
});
test('conflicting highest statements persist across omitted-candidate restart', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '2'), b = await row(f, 'b', '2', Buffer.alloc(DATA.length, 0x42));
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [a, b])), code('backup_checkpoint_ambiguous'));
  await noEffects(f); assert.equal((await snapshot(f)).conflicting_statements, true);
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [a])), code('backup_witness_checkpoint_ambiguous'));
});
test('equivalent envelopes obey ordering; original pin selects its exact highest serialization', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '2'), b = { ...a, approval: join(f.root, 'b.approval') };
  await writeFile(b.approval, JSON.stringify(JSON.parse(await readFile(a.approval)), null, 2));
  const first = await recoverRepositoryBackup(setOptions(f, [a, b]));
  const next = await recoverRepositoryBackup(setOptions(f, [b, a], { checkpoint: first.checkpoint }));
  assert.equal(next.checkpoint_selection.selected_index, 1); assert.deepEqual(next.checkpoint, first.checkpoint);
  assert.equal(next.acquisition.mode, 'cached'); assert.equal(f.requests.length, 1);
  assert.equal(next.checkpoint_selection.original_checkpoint_pin_enforced, true);
  const unpinned = await recoverRepositoryBackup(setOptions(f, [b, a]));
  assert.equal(unpinned.checkpoint_selection.selected_index, 0); assert.equal(unpinned.checkpoint.approval_sha256, digest(await readFile(b.approval)));
});
test('an old exact pin cannot override a newer checkpoint', async t => {
  const f = await recoveryFixture(t), low = await row(f, 'a', '1');
  const first = await recoverRepositoryBackup(setOptions(f, [low])); const high = await row(f, 'b', '2');
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [low, high], { checkpoint: first.checkpoint })), code('backup_recovery_checkpoint_mismatch'));
  assert.equal(f.requests.length, 1); assert.equal((await f.events()).length, 1); assert.equal((await snapshot(f)).highest_observed_generation, '2');
});
test('wrong trusted-key equality pin refuses without acquisition', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '2');
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [a], { checkpoint: {
    approval_sha256: digest(await readFile(a.approval)), trusted_key_id: 'sha256:' + '0'.repeat(64) } })), code('backup_recovery_checkpoint_mismatch'));
  await noEffects(f);
});
test('selected cache-only plan refuses a miss instead of implicitly trying a different plan', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '2');
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [{ approval: a.approval }, a])), code('backup_recovery_sources_required'));
  await noEffects(f);
});
test('lost native response resumes offline with reordered approvals and original pin', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '2'), b = { approval: join(f.root, 'b.approval') };
  await writeFile(b.approval, JSON.stringify(JSON.parse(await readFile(a.approval)), null, 2));
  await f.configure({ mode: 'lose_restore_response' }); let pin, cached;
  const restore = { operation: 'restore', destination: f.options.destination, destinationInstance: '12', approvalRecord: f.options.approvalRecord };
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [a, b], restore)), e => {
    assert.equal(e.state, 'restore_attempted_unknown'); pin = e.recovery.checkpoint; cached = e.recovery.candidate.input;
    assert.equal(e.recovery.checkpoint_selection.selected_index, 0); return true;
  });
  const inode = (await lstat(cached)).ino; await unlink(f.sourceFile); await unlink(f.caFile);
  const r = await recoverRepositoryBackup(setOptions(f, [b, { approval: a.approval }], { ...restore, resume: true, checkpoint: pin }));
  assert.equal(r.native.native.already_published, true); assert.equal(r.acquisition.mode, 'cached');
  assert.equal((await lstat(cached)).ino, inode); assert.equal(f.requests.length, 1);
  assert.deepEqual((await f.events()).map(e => e.operation), ['verify', 'restore', 'verify', 'restore']);
});
test('mutable caller rows cannot retarget selection after the first await', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '1'), b = await row(f, 'b', '2');
  const candidates = [a, b], options = setOptions(f, candidates); let changed = false;
  options.onProgress = e => { if (e.stage === 'selection' && !changed) {
    changed = true; b.approval = a.approval; b.sourceFile = '/nonexistent'; candidates.reverse(); candidates.push({});
  } };
  const r = await recoverRepositoryBackup(options); assert(changed);
  assert.equal(r.checkpoint_selection.selected.head_generation, '2'); assert.equal(r.checkpoint_selection.candidates.length, 2);
});
test('selection cancellation retains newer observation with no payload work', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '2'), b = await row(f, 'b', '1'), controller = new AbortController();
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [a, b], { signal: controller.signal,
    onProgress(e) { if (e.stage === 'selection') controller.abort(); } })), code('backup_cancelled'));
  await noEffects(f); assert.equal((await snapshot(f)).highest_observed_generation, '2'); await missing(join(f.witness, '.witness-lock'));
});
test('same witness lease spans every approval and both native operations', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '1'), b = await row(f, 'b', '2'); let checks = 0;
  await recoverRepositoryBackup(setOptions(f, [a, b], { operation: 'restore', destination: f.options.destination,
    destinationInstance: '12', approvalRecord: f.options.approvalRecord, async onProgress(e) {
      if (['selection', 'native'].includes(e.stage)) { await assert.rejects(snapshot(f), code('backup_witness_locked')); checks++; }
    } }));
  assert(checks >= 4); await missing(join(f.witness, '.witness-lock'));
});
test('selection observer cannot redirect native output through a parent alias', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '2');
  const one = join(f.root, 'one'), two = join(f.root, 'two'), alias = join(f.root, 'alias');
  await mkdir(one, { mode: 0o700 }); await mkdir(two, { mode: 0o700 }); await symlink(one, alias); let moved = false;
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [a], { operation: 'restore',
    destination: join(alias, 'restored'), destinationInstance: '12', approvalRecord: f.options.approvalRecord,
    async onProgress(e) { if (e.stage === 'selection' && !moved) { moved = true; await unlink(alias); await symlink(two, alias); } }
  })), code('backup_recovery_path_changed'));
  await noEffects(f); assert(moved);
});
test('native refusal preserves chosen set without another checkpoint or acquisition attempt', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '1'), b = await row(f, 'b', '2'); await f.configure({ mode: 'refuse_verify' });
  await assert.rejects(recoverRepositoryBackup(setOptions(f, [a, b])), e => {
    assert.equal(e.code, 'backup_native_refused'); assert.equal(e.recovery.checkpoint_selection.selected.approval, b.approval); return true;
  });
  assert.equal(f.requests.length, 1); assert.equal((await f.events()).length, 1);
});
test('highest checkpoint selects complementary damaged replicas without intact input or network', async t => {
  const f = await recoveryFixture(t), low = await row(f, 'old', '1'), data = Buffer.concat([Buffer.alloc(C, 0x41), Buffer.alloc(C, 0x42)]);
  const high = await row(f, 'new', '2', data), catalog = join(f.root, 'catalog'), a = join(f.root, 'a'), b = join(f.root, 'b');
  await catalogRepositoryBackupChunks({ input: f.local, output: catalog, approval: high.approval, trustKey: f.trustKey,
    policy: f.options.policy, maximumBytes: data.length });
  const x = Buffer.from(data), y = Buffer.from(data); x[0] ^= 1; y[C] ^= 1; await writeFile(a, x); await writeFile(b, y); await unlink(f.local);
  const r = await recoverRepositoryBackup(setOptions(f, [low, { approval: high.approval, repairCatalog: catalog, repairReplicas: [a, b] }],
    { maximumBytes: data.length, maximumAcquisitionBytes: 4 * data.length + C, timeoutMs: 20000 }));
  assert.equal(r.acquisition.mode, 'reconstructed'); assert.equal(r.checkpoint_selection.selected_index, 1);
  assert.deepEqual(await readFile(r.candidate.input), data); assert.deepEqual(f.requests, []);
});
test('bounded grammar validates and snapshots all candidate inputs without I/O', async t => {
  const f = await recoveryFixture(t), a = { approval: f.approval };
  for (const candidates of [[], Array(65).fill(a), [null], [{ ...a, endpoint: 'x' }]]) assert.throws(() => repositoryBackupRecoveryOptions(setOptions(f, candidates)));
  assert.throws(() => repositoryBackupRecoveryOptions({ ...f.verifyOptions(), candidates: [a] }), code('backup_recovery_mixed_candidates'));
  assert.throws(() => repositoryBackupRecoveryOptions(setOptions(f, [{ ...a, sourceFile: f.sourceFile, repairCatalog: '/c', repairReplicas: ['/a'] }])));
  const paths = ['/a'], o = repositoryBackupRecoveryOptions(setOptions(f, [{ ...a, repairCatalog: '/c', repairReplicas: paths }]));
  paths.push('/b'); assert.deepEqual(o.candidates[0].repairReplicas, ['/a']); assert(Object.isFrozen(o.candidates[0]));
  const many = Array.from({ length: 64 }, (_, i) => ({ approval: '/' + 'a'.repeat(4090) + i, sourceFile: '/' + 'b'.repeat(4090) }));
  assert.throws(() => repositoryBackupRecoveryOptions(setOptions(f, many)), code('backup_candidate_path_limit')); await noEffects(f);
});
test('64 explicit duplicate approvals remain bounded and usable', async t => {
  const f = await recoveryFixture(t), a = await row(f, 'a', '2');
  const r = await recoverRepositoryBackup(setOptions(f, Array(64).fill(a), { timeoutMs: 20000 }));
  assert.equal(r.checkpoint_selection.candidates.length, 64); assert.equal(r.checkpoint_selection.highest_indices.length, 64); assert.equal(f.requests.length, 1);
});
