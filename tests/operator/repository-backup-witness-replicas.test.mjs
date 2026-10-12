// Real signature/filesystem integration of the witness with replica selection.
// Opaque artifacts: no native Rust archive or authority execution is implied.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtemp, writeFile, readFile, unlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signRepositoryBackupFile } from '../../scripts/lib/repository-backup-approval.mjs';
import { initializeRepositoryBackupWitness, withRepositoryBackupWitness } from '../../scripts/lib/repository-backup-witness.mjs';
import { selectRepositoryBackup } from '../../scripts/lib/repository-backup-selection.mjs';

async function fixture(t, object_format = 'sha256') {
  const root = await mkdtemp(join(tmpdir(), 'fg-witness-replicas-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const pair = generateKeyPairSync('ed25519'), key = join(root, 'key'), directory = join(root, 'witness');
  const secret = Buffer.from(pair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  await writeFile(key, pair.publicKey.export({ format: 'pem', type: 'spki' }));
  const policy = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16),
    object_format, minimum_head_generation: '1' };
  await initializeRepositoryBackupWitness(directory, key, policy);
  async function candidate(name, generation, bytes = 'checkpoint') {
    const input = join(root, name), approval = input + '.dsse';
    await writeFile(input, bytes);
    const { minimum_head_generation, ...identity } = policy;
    const signed = await signRepositoryBackupFile(input, secret,
      { ...identity, head_generation: generation, issued_at: '2026-10-08T11:00:00Z' });
    await writeFile(approval, signed.envelope); return { input, approval };
  }
  const select = (rows, options = {}) => withRepositoryBackupWitness(directory, key, policy, options,
    witness => selectRepositoryBackup(rows, key, policy, options, witness));
  return { candidate, select, snapshot: () => withRepositoryBackupWitness(directory, key, policy, {}, w => w.snapshot()) };
}
for (const format of ['sha1', 'sha256']) test(`${format}: available exact-checkpoint replica preserves retained generation and its own approval pin`, async t => {
  const f = await fixture(t, format), low = await f.candidate('low', '8');
  const a = await f.candidate('a', '9'), b = await f.candidate('b', '9');
  // Cosmetic envelope bytes may differ, while original signed statements agree.
  await writeFile(b.approval, JSON.stringify(JSON.parse(await readFile(b.approval)), null, 2));
  await unlink(a.input);
  const { report } = await f.select([b, low, a]);
  assert.equal(report.selected.input, b.input);
  assert.equal(report.checkpoint.approval_sha256, createHash('sha256').update(await readFile(b.approval)).digest('hex'));
  assert.equal(report.replica_attempts.length, 2);
  assert.equal(report.recovery_witness.highest_observed_generation, '9');
  assert.equal(report.highest_retained_generation_enforced, true);
  await assert.rejects(f.select([low]), { code: 'backup_below_witness' });
  assert.equal((await f.select([b])).report.selected.input, b.input);
});
test('a exhausted aggregate replica budget retains the newer checkpoint; an explicit adequate budget permits the exact twin', async t => {
  const f = await fixture(t), low = await f.candidate('low', '8');
  const a = await f.candidate('a', '9', 'abc'), b = await f.candidate('b', '9', 'abc');
  await writeFile(a.input, 'xyz');
  await assert.rejects(f.select([a, b], { maximumBytes: 3 }), { code: 'backup_replica_read_budget' });
  assert.equal((await f.snapshot()).highest_observed_generation, '9');
  await assert.rejects(f.select([low]), { code: 'backup_below_witness' });
  const { report } = await f.select([a, b], { maximumBytes: 6 });
  assert.equal(report.selected.input, b.input); assert.equal(report.streaming.total_payload_bytes_read, '6');
});
test('loss of every newer replica never permits an older archive, even on the next invocation', async t => {
  const f = await fixture(t), low = await f.candidate('low', '8');
  const a = await f.candidate('a', '9'), b = await f.candidate('b', '9');
  await unlink(a.input); await unlink(b.input);
  await assert.rejects(f.select([low, a, b]), error => error.code === 'ENOENT' && error.replica_attempts.length === 2);
  await assert.rejects(f.select([low]), { code: 'backup_below_witness' });
  await writeFile(b.input, 'checkpoint'); assert.equal((await f.select([b])).report.selected.input, b.input);
});
test('an observer failure is not an unavailable replica and does not erase witnessed evidence', async t => {
  const f = await fixture(t), a = await f.candidate('a', '9'), b = await f.candidate('b', '9');
  const failure = Object.assign(new Error('observer failed'), { code: 'ENOENT' }); let reads = 0;
  await assert.rejects(f.select([a, b], { onProgress(e) { if (e.bytes_read) { reads++; throw failure; } } }), error => error === failure);
  assert.equal(reads, 1); assert.equal((await f.snapshot()).highest_observed_generation, '9');
  assert.equal((await f.select([b])).report.selected.input, b.input);
});
