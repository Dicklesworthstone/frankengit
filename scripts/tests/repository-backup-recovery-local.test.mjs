// Real local files, signatures, TLS peers and native-schema child processes.
// Opaque bytes and the fixture executable are NOT native fg recovery evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, chmod, lstat, unlink, readdir, mkdir, symlink, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { recoverRepositoryBackup, repositoryBackupRecoveryOptions } from '../lib/repository-backup-recovery.mjs';
import { withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { recoveryFixture, DATA, digest } from './backup-recovery-fixture.mjs';

function local(f, inputs = [f.local], restore = false, extra = {}) {
  const { sourceFile, caFile, ...base } = restore ? f.options : f.verifyOptions();
  return { ...base, localInputs: inputs, ...extra };
}
const absent = path => assert.rejects(lstat(path), { code: 'ENOENT' });
const noNative = async f => { assert.deepEqual(await f.events(), []); assert.deepEqual(f.requests, []); };
const snapshot = f => withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, {}, w => w.snapshot());
async function signed(f, name, generation, data = DATA) {
  const approval = join(f.root, name + '.approval');
  await writeFile(approval, (await f.sign(data, { head_generation: generation })).envelope);
  return approval;
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: readonly local media enters signed native restore within 3N`, async t => {
    const f = await recoveryFixture(t, format);
    await chmod(f.local, 0o444); const before = await lstat(f.local);
    const result = await recoverRepositoryBackup(local(f, [f.local], true, { maximumAcquisitionBytes: 3 * DATA.length }));
    assert.equal(result.acquisition.mode, 'local');
    assert.equal(result.acquisition.receipt.source.input, f.local);
    assert.equal(result.acquisition.receipt.streaming.total_payload_bytes_read, String(3 * DATA.length));
    assert.equal(result.acquisition.receipt.streaming.maximum_read_bytes, 65536);
    assert.deepEqual(await readFile(result.candidate.input), DATA);
    assert.equal((await lstat(f.local)).ino, before.ino);
    assert.equal((await lstat(f.local)).mode, before.mode);
    assert.deepEqual(await readFile(f.local), DATA);
    assert.deepEqual((await f.events()).map(e => e.operation), ['verify', 'restore']);
    assert.deepEqual(f.requests, []);
    assert.equal(result.native.native.signature_verified, true);
    assert.equal(result.complete_capsule_restored, false);
  });
}
test('explicit local verification never submits native restore', async t => {
  const f = await recoveryFixture(t);
  const result = await recoverRepositoryBackup(local(f));
  assert.equal(result.state, 'complete'); assert.equal(result.acquisition.mode, 'local');
  assert.deepEqual((await f.events()).map(e => e.operation), ['verify']);
  await absent(f.options.destination); await absent(f.options.approvalRecord);
  assert.deepEqual(f.requests, []);
});
test('missing media parent and corrupt copy yield only to a healthy identical replica', async t => {
  const f = await recoveryFixture(t), corrupt = join(f.root, 'b-corrupt'), good = join(f.root, 'z-good');
  await writeFile(corrupt, Buffer.alloc(DATA.length, 1)); await writeFile(good, DATA);
  const result = await recoverRepositoryBackup(local(f, [good, join(f.root, 'a-absent-media', 'copy'), corrupt],
    false, { maximumAcquisitionBytes: 4 * DATA.length }));
  assert.equal(result.acquisition.receipt.source.input, good);
  assert.equal(result.acquisition.receipt.streaming.total_payload_bytes_read, String(4 * DATA.length));
  assert.deepEqual(await readFile(corrupt), Buffer.alloc(DATA.length, 1));
  assert.deepEqual(f.requests, []); assert.deepEqual((await f.events()).map(e => e.operation), ['verify']);
});
test('all damaged copies retain bounded replica diagnostics and never publish cache approval', async t => {
  const f = await recoveryFixture(t), a = join(f.root, 'a-bad'), b = join(f.root, 'b-bad');
  await writeFile(a, Buffer.alloc(DATA.length, 1)); await writeFile(b, Buffer.alloc(DATA.length, 2));
  await assert.rejects(recoverRepositoryBackup(local(f, [a, b])), error => {
    assert.equal(error.local_acquisition.replica_attempts.length, 2);
    assert(error.local_acquisition.replica_attempts.every(row => row.outcome === 'unavailable'));
    assert.equal(error.local_acquisition.streaming.total_payload_bytes_read, String(2 * DATA.length));
    assert.equal(error.recovery.acquisition, null); return true;
  });
  assert.deepEqual(await readdir(f.destination), []); await noNative(f);
});
test('3N-1 refuses before local payload callbacks or cache staging', async t => {
  const f = await recoveryFixture(t); let payloadProgress = 0;
  await assert.rejects(recoverRepositoryBackup(local(f, [f.local], false, {
    maximumAcquisitionBytes: 3 * DATA.length - 1, onProgress(e) { if (e.stage === 'local') payloadProgress++; },
  })), { code: 'backup_recovery_acquisition_budget' });
  assert.equal(payloadProgress, 0); assert.deepEqual(await readdir(f.destination), []);
  assert.equal((await snapshot(f)).highest_observed_generation, '9007199254740993'); await noNative(f);
});
test('a failed probe consumes the same acquisition budget as successful copy/readback', async t => {
  const f = await recoveryFixture(t), bad = join(f.root, 'a-bad'), good = join(f.root, 'b-good');
  await writeFile(bad, Buffer.alloc(DATA.length, 1)); await writeFile(good, DATA);
  await assert.rejects(recoverRepositoryBackup(local(f, [bad, good], false,
    { maximumAcquisitionBytes: 4 * DATA.length - 1 })), { code: 'backup_replication_read_budget' });
  assert.deepEqual(await readdir(f.destination), []); await noNative(f);
});
test('local acquisition cannot widen the individual signed archive ceiling', async t => {
  const f = await recoveryFixture(t);
  await assert.rejects(recoverRepositoryBackup(local(f, [f.local], false, {
    maximumBytes: DATA.length - 1, maximumAcquisitionBytes: DATA.length * 8,
  })), { code: 'backup_selected_archive_limit' });
  await noNative(f); assert.deepEqual(await readdir(f.destination), []);
});
test('source changes after selection refuse without another local-copy attempt', async t => {
  const f = await recoveryFixture(t); let changed = false;
  await assert.rejects(recoverRepositoryBackup(local(f, [f.local], false, { async onProgress(e) {
    if (e.stage === 'local' && e.phase === 'selection_complete') {
      changed = true; await writeFile(f.local, Buffer.alloc(DATA.length, 9));
    }
  } })), { code: 'backup_replica_digest_mismatch' });
  assert(changed); await noNative(f); assert.deepEqual(await readdir(f.destination), []);
});
test('observer ENOENT is a failure, not permission to fail over', async t => {
  const f = await recoveryFixture(t), second = join(f.root, 'z-other'); await writeFile(second, DATA);
  const raised = Object.assign(new Error('observer'), { code: 'ENOENT' }); let calls = 0;
  await assert.rejects(recoverRepositoryBackup(local(f, [f.local, second], false, { onProgress(e) {
    if (e.stage === 'local') { calls++; throw raised; }
  } })), e => e === raised);
  assert.equal(calls, 1); await noNative(f); assert.deepEqual(await readdir(f.destination), []);
});
test('copy cancellation drains its quarantine and releases the witness before a permitted retry', async t => {
  const f = await recoveryFixture(t), controller = new AbortController(); let copying = false;
  await assert.rejects(recoverRepositoryBackup(local(f, [f.local], false, { signal: controller.signal, onProgress(e) {
    if (e.stage === 'local' && e.phase === 'copy_archive') { copying = true; controller.abort(); }
  } })), { code: 'backup_cancelled' });
  assert(copying); await noNative(f); assert.deepEqual(await readdir(f.destination), []);
  await absent(join(f.witness, '.witness-lock'));
  assert.equal((await recoverRepositoryBackup(local(f))).state, 'complete');
});
test('one deadline includes local-copy observers and cleanup', async t => {
  const f = await recoveryFixture(t); let copying = false;
  await assert.rejects(recoverRepositoryBackup(local(f, [f.local], false, { timeoutMs: 1500, async onProgress(e) {
    if (e.stage === 'local' && e.phase === 'copy_archive' && !copying) { copying = true; await delay(1600); }
  } })), { code: 'backup_deadline' });
  assert(copying); await noNative(f); await absent(join(f.witness, '.witness-lock'));
  assert.deepEqual(await readdir(f.destination), []);
});
test('confirmed copied cache survives an observer failure and can continue after media removal', async t => {
  const f = await recoveryFixture(t); let retained;
  await assert.rejects(recoverRepositoryBackup(local(f, [f.local], false, { onProgress(e) {
    if (e.phase === 'acquisition_complete') throw Object.assign(new Error('delivery failed'), { code: 'TEST_STOP' });
  } })), e => {
    assert.equal(e.code, 'TEST_STOP'); retained = e.recovery.acquisition;
    assert.equal(retained.mode, 'local'); assert.equal(retained.receipt.state, 'complete'); return true;
  });
  const inode = (await lstat(retained.receipt.candidate.input)).ino; await unlink(f.local);
  const { localInputs, ...offline } = local(f);
  const result = await recoverRepositoryBackup(offline);
  assert.equal(result.acquisition.mode, 'cached'); assert.equal((await lstat(result.candidate.input)).ino, inode);
  assert.deepEqual(f.requests, []); assert.deepEqual((await f.events()).map(e => e.operation), ['verify']);
});
test('lost restore response resumes offline with original intent and no source media', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'lose_restore_response' }); let checkpoint;
  await assert.rejects(recoverRepositoryBackup(local(f, [f.local], true)), e => {
    assert.equal(e.state, 'restore_attempted_unknown'); checkpoint = e.recovery.checkpoint;
    assert.equal(e.recovery.acquisition.mode, 'local'); return true;
  });
  await unlink(f.local);
  const { localInputs, ...offline } = local(f, [], true);
  const result = await recoverRepositoryBackup({ ...offline, checkpoint, resume: true });
  assert.equal(result.native.native.already_published, true); assert.equal(result.acquisition.mode, 'cached');
  assert.deepEqual((await f.events()).map(e => e.operation), ['verify', 'restore', 'verify', 'restore']);
  assert.deepEqual(f.requests, []);
});
test('all local-copy/native phases retain one exclusive witness', async t => {
  const f = await recoveryFixture(t); const stages = new Set();
  await recoverRepositoryBackup(local(f, [f.local], true, { async onProgress(e) {
    if (!['local', 'native'].includes(e.stage) || stages.has(e.stage)) return;
    stages.add(e.stage); await assert.rejects(snapshot(f), { code: 'backup_witness_locked' });
  } }));
  assert.deepEqual([...stages], ['local', 'native']); await absent(join(f.witness, '.witness-lock'));
});
test('unavailable newer local checkpoint blocks intact older media and remains remembered', async t => {
  const f = await recoveryFixture(t), oldData = Buffer.alloc(DATA.length, 1);
  const low = await signed(f, 'low', '1', oldData), old = join(f.root, 'old-archive');
  await writeFile(old, oldData);
  const high = await signed(f, 'high', '2');
  const { approval, localInputs, ...common } = local(f);
  await assert.rejects(recoverRepositoryBackup({ ...common, candidates: [
    { approval: low, localInputs: [old] },
    { approval: high, localInputs: [join(f.root, 'absent-media', 'archive')] },
  ] }), { code: 'ENOENT' });
  assert.equal((await snapshot(f)).highest_observed_generation, '2');
  await assert.rejects(recoverRepositoryBackup({ ...common, candidates: [{ approval: low, localInputs: [old] }] }),
    { code: 'backup_below_witness' }); await noNative(f);
  assert.deepEqual(await readdir(f.destination), []);
});
test('losing local media paths and parents are not resolved by checkpoint selection', async t => {
  const f = await recoveryFixture(t), low = await signed(f, 'low', '1'), high = await signed(f, 'high', '2');
  const dangling = join(f.root, 'dangling'); await symlink(join(f.root, 'absent-target'), dangling);
  const { approval, localInputs, ...common } = local(f);
  const result = await recoverRepositoryBackup({ ...common, candidates: [
    { approval: low, localInputs: [join(dangling, 'archive')] },
    { approval: high, localInputs: [f.local] },
  ] });
  assert.equal(result.checkpoint_selection.selected_index, 1);
  assert.equal(result.acquisition.mode, 'local'); assert.deepEqual(f.requests, []);
});
test('selected dangling parent cannot be guessed as a missing mount', async t => {
  const f = await recoveryFixture(t), dangling = join(f.root, 'dangling');
  await symlink(join(f.root, 'missing-target'), dangling);
  await assert.rejects(recoverRepositoryBackup(local(f, [join(dangling, 'archive'), f.local])),
    { code: 'backup_recovery_local_path_unresolved' }); await noNative(f);
});
test('local source aliases into the cache refuse without changing either file', async t => {
  const f = await recoveryFixture(t), inside = join(f.destination, 'original'), alias = join(f.root, 'alias');
  await writeFile(inside, DATA); await symlink(f.destination, alias);
  await assert.rejects(recoverRepositoryBackup(local(f, [join(alias, 'original')])),
    { code: 'backup_recovery_separate_paths_required' });
  assert.deepEqual(await readFile(inside), DATA); await noNative(f);
});
test('source approval substitution after local acquisition cannot reach native verification', async t => {
  const f = await recoveryFixture(t), original = await readFile(f.approval);
  const other = await f.sign(DATA, { head_generation: '9007199254740994' });
  await writeFile(f.approval, original);
  await assert.rejects(recoverRepositoryBackup(local(f, [f.local], false, { async onProgress(e) {
    if (e.phase === 'acquisition_complete') await writeFile(e.candidate.approval, other.envelope);
  } })), { code: 'backup_selected_approval_changed' }); await noNative(f);
});
test('local input array is owned before any asynchronous observation', async t => {
  const f = await recoveryFixture(t), inputs = [f.local], options = local(f, inputs);
  const running = recoverRepositoryBackup(options);
  inputs[0] = '/different'; inputs.push('/another'); options.localInputs = [];
  const result = await running; assert.equal(result.acquisition.receipt.source.input, f.local); assert.deepEqual(f.requests, []);
});
test('local grammar refuses mixed mechanisms, duplicates, holes and excess input count before I/O', async t => {
  const f = await recoveryFixture(t);
  for (const localInputs of [[], [undefined], new Array(2), 'wrong', Array(65).fill(f.local), [f.local, f.local]]) {
    assert.throws(() => repositoryBackupRecoveryOptions(local(f, localInputs)));
  }
  for (const extra of [{ sourceFile: f.sourceFile }, { caFile: f.caFile }, { repairCatalog: 'catalog' }, { repairReplicas: [f.local] }]) {
    assert.throws(() => repositoryBackupRecoveryOptions(local(f, [f.local], false, extra)), { code: 'backup_recovery_mixed_acquisition' });
  }
  assert.throws(() => repositoryBackupRecoveryOptions({ ...local(f), candidates: [{ approval: f.approval }] }),
    { code: 'backup_recovery_mixed_candidates' });
  await noNative(f);
});
test('the complete bounded 64-copy set permits absent copies without consuming payload budget', async t => {
  const f = await recoveryFixture(t), inputs = Array.from({ length: 63 }, (_, i) => join(f.root, `a-missing-${i}`));
  inputs.push(f.local);
  const result = await recoverRepositoryBackup(local(f, inputs, false, { maximumAcquisitionBytes: 3 * DATA.length, timeoutMs: 20000 }));
  assert.equal(result.acquisition.receipt.source.input, f.local);
  assert.equal(result.acquisition.receipt.streaming.total_payload_bytes_read, String(3 * DATA.length));
  assert.deepEqual(f.requests, []);
});
