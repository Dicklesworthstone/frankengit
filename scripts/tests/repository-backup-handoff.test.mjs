// Actual files and Ed25519; operator bytes, not native archive fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, unlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { replenishRepositoryBackups } from '../lib/repository-backup-replenishment.mjs';

test('verified source handoff survives loss of original archive and approval after first copy', async t => {
  const root = await mkdtemp(join(tmpdir(), 'fg-handoff-')); t.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, 'original'), approval = join(root, 'original.approval'), trustKey = join(root, 'trust.pem');
  const data = Buffer.alloc(65553, 0x61); await writeFile(input, data, { mode: 0o600 });
  const pair = generateKeyPairSync('ed25519');
  await writeFile(trustKey, pair.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  const identity = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: 'sha256' };
  const now = Math.floor(Date.now() / 1000) * 1000;
  const signed = await signRepositoryBackupFile(input, Buffer.from(pair.privateKey.export({ type: 'pkcs8', format: 'pem' })), {
    ...identity, head_generation: '9007199254740993', issued_at: new Date(now - 60000).toISOString().replace('.000Z', 'Z'),
    expires_at: new Date(now + 86400000).toISOString().replace('.000Z', 'Z'),
  });
  await writeFile(approval, signed.envelope, { mode: 0o600 });
  const destinations = [join(root, 'copy-a'), join(root, 'copy-b'), join(root, 'copy-c')];
  for (const path of destinations) await mkdir(path, { mode: 0o700 });
  const report = await replenishRepositoryBackups({ candidates: [{ input, approval }], destinations, trustKey,
    policy: { ...identity, minimum_head_generation: '1' }, maximumBytes: data.length,
    sourceHandoff: true,
    async onProgress(event) {
      if (event.phase === 'replica_complete' && event.completed_destinations === 1) { await unlink(input); await unlink(approval); }
    } });
  assert.equal(report.state, 'complete'); assert.equal(report.completed_replicas.length, 3);
  for (const { receipt } of report.completed_replicas) assert.deepEqual(await readFile(receipt.candidate.input), data);
  assert.equal(report.completed_replicas[1].receipt.source.input, report.completed_replicas[0].receipt.candidate.input);
  assert.equal(report.completed_replicas[2].receipt.source.input, report.completed_replicas[1].receipt.candidate.input);
});
