// Exercise the distinct archive ceiling and aggregate work budget at their
// exact boundaries using signed bytes and the real replication/selection path.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { BACKUP_LIMITS } from '../lib/repository-backup-io.mjs';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { selectRepositoryBackup, MAX_BACKUP_CANDIDATES } from '../lib/repository-backup-selection.mjs';
import { replicateRepositoryBackup } from '../lib/repository-backup-replication.mjs';

const DATA = Buffer.alloc(65553, 0x61);
const NOW = Date.parse('2026-10-11T12:00:00Z');
const ID = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
  incarnation_id: '3'.repeat(32), object_format: 'sha256' };
const POLICY = { ...ID, minimum_head_generation: '7' };
async function fixture(t, corrupt = true) {
  const root = await mkdtemp(join(tmpdir(), 'fg-replica-budgets-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = join(root, 'replicas');
  await mkdir(destination, { mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const trustKey = join(root, 'trust.pem');
  await writeFile(trustKey, publicKey.export({ format: 'pem', type: 'spki' }));
  const first = { input: join(root, 'a.archive'), approval: join(root, 'a.approval') };
  const second = { input: join(root, 'b.archive'), approval: join(root, 'b.approval') };
  await writeFile(first.input, DATA);
  const signed = await signRepositoryBackupFile(first.input,
    Buffer.from(privateKey.export({ format: 'pem', type: 'pkcs8' })),
    { ...ID, head_generation: '7', issued_at: '2026-10-11T11:00:00Z', expires_at: null }, { now: NOW });
  await writeFile(first.approval, signed.envelope);
  await writeFile(second.input, DATA); await writeFile(second.approval, signed.envelope);
  if (corrupt) await writeFile(first.input, Buffer.alloc(DATA.length, 0x62));
  const candidates = [first, second];
  return { destination, first, second,
    select: options => selectRepositoryBackup(candidates, trustKey, POLICY,
      { now: NOW, maximumBytes: DATA.length, ...options }),
    replicate: options => replicateRepositoryBackup({ candidates, trustKey, policy: POLICY,
      destination, now: NOW, maximumBytes: DATA.length, ...options }) };
}

test('explicit replica budget permits failover without increasing the archive ceiling', async t => {
  const f = await fixture(t);
  const result = await f.select({ maximumReplicaBytes: DATA.length * 2 });
  assert.equal(result.report.selected.input, f.second.input);
  assert.equal(result.report.streaming.total_payload_bytes_read, String(DATA.length * 2));
  assert.equal(result.report.streaming.replica_payload_byte_budget, String(DATA.length * 2));
});

test('legacy default keeps the original one-archive-sized aggregate read budget', async t => {
  const f = await fixture(t);
  await assert.rejects(f.select({}), { code: 'backup_replica_read_budget' });
});

test('larger replica budget never widens the signed per-archive ceiling', async t => {
  const f = await fixture(t, false); let reads = 0;
  await assert.rejects(f.select({ maximumBytes: DATA.length - 1,
    maximumReplicaBytes: DATA.length * 2,
    onProgress(e) { if (typeof e.bytes_read === 'number') reads++; } }),
  { code: 'backup_selected_archive_limit' });
  assert.equal(reads, 0);
});

test('insufficient replica budget refuses before opening even the first archive', async t => {
  const f = await fixture(t, false); let reads = 0;
  await assert.rejects(f.select({ maximumReplicaBytes: DATA.length - 1,
    onProgress(e) { if (typeof e.bytes_read === 'number') reads++; } }),
  { code: 'backup_replica_read_budget' });
  assert.equal(reads, 0);
});

test('invalid replica budgets and unknown options refuse rather than widening bounds', async t => {
  const f = await fixture(t, false);
  for (const maximumReplicaBytes of [0, -1, 1.5, '1', NaN, Infinity,
    Number.MAX_SAFE_INTEGER, BACKUP_LIMITS.maximumArchiveBytes * MAX_BACKUP_CANDIDATES + 1]) {
    await assert.rejects(f.select({ maximumReplicaBytes }), { code: 'backup_invalid_options' });
  }
  await assert.rejects(f.select({ maximumReplicaBytes: DATA.length, unrecognized: true }),
    { code: 'backup_invalid_options' });
});

test('replication uses all four budgeted reads after a corrupt full-size source', async t => {
  const f = await fixture(t);
  const result = await f.replicate({ maximumTotalBytes: DATA.length * 4 });
  assert.equal(result.state, 'complete'); assert.equal(result.source.input, f.second.input);
  assert.equal(result.streaming.total_payload_bytes_read, String(DATA.length * 4));
  assert.deepEqual(await readFile(result.candidate.input), DATA);
  assert.equal(result.native_content_verified, false);
});

test('one byte below four-read budget refuses before replica publication', async t => {
  const f = await fixture(t);
  await assert.rejects(f.replicate({ maximumTotalBytes: DATA.length * 4 - 1 }),
    { code: 'backup_replication_read_budget' });
  assert.deepEqual(await readdir(f.destination), []);
});

test('replication still enforces its archive ceiling before any payload read', async t => {
  const f = await fixture(t, false); let reads = 0;
  await assert.rejects(f.replicate({ maximumBytes: DATA.length - 1,
    maximumTotalBytes: DATA.length * 4,
    onProgress(e) { if (typeof e.bytes_read === 'number') reads++; } }),
  { code: 'backup_selected_archive_limit' });
  assert.equal(reads, 0); assert.deepEqual(await readdir(f.destination), []);
});
