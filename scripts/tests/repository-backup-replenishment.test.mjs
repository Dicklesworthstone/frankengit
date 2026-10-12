// Real files and Ed25519 approvals. Opaque payloads are NOT native fg archives.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, readdir, lstat, unlink, rm, symlink, chmod, rename, link, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { replenishRepositoryBackups, repositoryBackupReplenishmentOptions } from '../lib/repository-backup-replenishment.mjs';
import { replicateRepositoryBackup, repositoryBackupReplicationCheckpoint } from '../lib/repository-backup-replication.mjs';
import { selectRepositoryBackup } from '../lib/repository-backup-selection.mjs';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';

const NOW = Date.parse('2026-10-11T12:00:00Z'), DATA = Buffer.alloc(65559, 97), N = DATA.length;
const hash = value => createHash('sha256').update(value).digest('hex');
const code = expected => error => { assert.equal(error.code, expected); return true; };
async function absent(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
async function fixture(t, format = 'sha256', count = 2) {
  const root = await mkdtemp(join(tmpdir(), 'fg-replenish-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const identity = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: format };
  const policy = { ...identity, minimum_head_generation: '1' };
  const pair = generateKeyPairSync('ed25519'), privatePem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
  const trustKey = join(root, 'trust.pem'); await writeFile(trustKey, pair.publicKey.export({ format: 'pem', type: 'spki' }), { mode: 0o600 });
  async function signed(name, generation = '9007199254740993', bytes = DATA, extra = {}, pem = privatePem) {
    const input = join(root, name + '.backup'), approval = join(root, name + '.approval');
    await writeFile(input, bytes, { mode: 0o600 });
    const s = await signRepositoryBackupFile(input, Buffer.from(pem), { ...identity, head_generation: generation,
      issued_at: '2026-10-11T11:00:00Z', expires_at: '2026-10-12T12:00:00Z', ...extra }, { now: NOW });
    await writeFile(approval, s.envelope, { mode: 0o600 }); return { input, approval };
  }
  const row = await signed('source'), envelope = await readFile(row.approval);
  const destinations = [];
  for (let i = 0; i < count; i++) { const p = join(root, `copy-${i}`); await mkdir(p, { mode: 0o700 }); destinations.push(p); }
  const paths = destinations.map(d => ({ input: join(d, `archive-sha256-${hash(DATA)}.fgbackup`),
    approval: join(d, `checkpoint-sha256-${hash(envelope)}.approval.json`) }));
  const checkpoint = { approval_sha256: hash(envelope), trusted_key_id: JSON.parse(envelope).signatures[0].keyid };
  const options = { candidates: [row], destinations, trustKey, policy, maximumBytes: N, maximumTotalBytes: (1 + 4 * count) * N, now: NOW };
  return { root, row, envelope, identity, policy, destinations, paths, checkpoint, options, signed,
    run: extra => replenishRepositoryBackups({ ...options, ...extra }) };
}
async function emptyTargets(f) { for (const d of f.destinations) assert.deepEqual(await readdir(d), []); }

for (const format of ['sha1', 'sha256']) test(`${format}: replenish and independently scrub all explicit copies`, async t => {
  const f = await fixture(t, format); let removed = false;
  const result = await f.run({ async onProgress(e) {
    if (e.phase === 'replica_complete' && e.completed_destinations === 2) {
      await unlink(f.row.input); await unlink(f.row.approval); removed = true;
    }
  } });
  assert(removed); assert.equal(result.state, 'complete'); assert.equal(result.all_destinations_verified, true);
  assert.equal(result.final_scrub.distinct_authenticated_files, 2); assert.equal(result.final_scrub.all_replicas_authenticated, true);
  assert.equal(result.streaming.total_payload_bytes_read, String(9 * N));
  assert.equal(result.completed_replicas.length, 2); assert.deepEqual(result.checkpoint, f.checkpoint);
  for (const entry of result.completed_replicas) {
    assert.deepEqual(await readFile(entry.receipt.candidate.input), DATA);
    assert.deepEqual(await readFile(entry.receipt.candidate.approval), f.envelope);
    assert.equal(entry.receipt.disposition.archive, 'created');
  }
  const source = result.completed_replicas[1].receipt.candidate;
  const verified = await selectRepositoryBackup([source], f.options.trustKey, f.policy, { now: NOW });
  assert.deepEqual(verified.report.checkpoint, result.checkpoint);
  assert.equal(result.failure_domain_independence_verified, false); assert.equal(result.atomic_publication, false);
  assert.equal(result.native_content_verified, false); assert.equal(result.complete_capsule_verified, false);
});

test('exact restart reuses every completed file and still scrubs the output set', async t => {
  const f = await fixture(t); const first = await f.run();
  const ids = await Promise.all(f.paths.flatMap(p => [p.input, p.approval]).map(p => lstat(p, { bigint: true })));
  const second = await f.run({ checkpoint: first.checkpoint });
  assert(second.completed_replicas.every(r => r.receipt.disposition.archive === 'reused' && r.receipt.disposition.approval === 'reused'));
  assert.equal(second.streaming.total_payload_bytes_read, String(7 * N));
  const after = await Promise.all(f.paths.flatMap(p => [p.input, p.approval]).map(p => lstat(p, { bigint: true })));
  assert.deepEqual(after.map(s => s.ino), ids.map(s => s.ino));
});

test('cancellation between destinations retains a resumable exact-checkpoint receipt', async t => {
  const f = await fixture(t), controller = new AbortController(); let partial;
  await assert.rejects(f.run({ signal: controller.signal, onProgress(e) {
    if (e.phase === 'replica_complete') controller.abort();
  } }), error => { assert.equal(error.code, 'backup_cancelled'); partial = error.replenishment; return true; });
  assert.equal(partial.completed_replicas.length, 1); assert.equal(partial.all_destinations_verified, false);
  assert.deepEqual(partial.checkpoint, f.checkpoint); await absent(f.paths[1].approval);
  const inode = (await lstat(f.paths[0].input)).ino;
  const resumed = await f.run({ checkpoint: partial.checkpoint });
  assert.equal(resumed.state, 'complete'); assert.equal((await lstat(f.paths[0].input)).ino, inode);
  assert.equal(resumed.completed_replicas[0].receipt.disposition.archive, 'reused');
});

test('a conflicting output refuses without deleting it or losing earlier completions', async t => {
  const f = await fixture(t, 'sha256', 3); await writeFile(f.paths[1].input, Buffer.alloc(N, 98), { mode: 0o600 });
  await assert.rejects(f.run(), error => {
    assert.equal(error.code, 'backup_replica_digest_mismatch');
    assert.equal(error.replenishment.completed_replicas.length, 1);
    assert.equal(error.replenishment.active_destination, f.destinations[1]); return true;
  });
  assert.deepEqual(await readFile(f.paths[0].input), DATA);
  assert.deepEqual(await readFile(f.paths[1].input), Buffer.alloc(N, 98));
  await absent(f.paths[1].approval); await absent(f.paths[2].input);
});

test('a different valid checkpoint cannot replace the pinned source between copies', async t => {
  const f = await fixture(t), next = await f.signed('newer', '9007199254740994', Buffer.alloc(N, 98));
  await assert.rejects(f.run({ async onProgress(e) {
    if (e.phase === 'replica_complete') { await copyFile(next.input, f.row.input); await copyFile(next.approval, f.row.approval); }
  } }), error => { assert.equal(error.code, 'backup_replication_checkpoint_mismatch');
    assert.equal(error.replenishment.completed_replicas.length, 1); assert.deepEqual(error.replenishment.checkpoint, f.checkpoint); return true; });
  assert.deepEqual(await readFile(f.paths[0].input), DATA); assert.deepEqual(await readdir(f.destinations[1]), []);
});

test('envelope formatting cannot change a pinned intent between destinations', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ async onProgress(e) {
    if (e.phase === 'replica_complete') await writeFile(f.row.approval, JSON.stringify(JSON.parse(f.envelope), null, 2));
  } }), code('backup_replication_checkpoint_mismatch'));
  assert.deepEqual(await readdir(f.destinations[1]), []);
});

test('key and valid-signature substitution cannot retarget later copies', async t => {
  const f = await fixture(t), pair = generateKeyPairSync('ed25519');
  const next = await f.signed('rotated', '9007199254740993', DATA, {}, pair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  await assert.rejects(f.run({ async onProgress(e) {
    if (e.phase === 'replica_complete') {
      await writeFile(f.options.trustKey, pair.publicKey.export({ format: 'pem', type: 'spki' }));
      await copyFile(next.approval, f.row.approval);
    }
  } }), code('backup_replication_checkpoint_mismatch'));
  assert.deepEqual(await readdir(f.destinations[1]), []);
});

test('a supplied restart pin refuses a newer checkpoint before output publication', async t => {
  const f = await fixture(t), next = await f.signed('newer', '18446744073709551615');
  await assert.rejects(f.run({ candidates: [next], checkpoint: f.checkpoint }), code('backup_replication_checkpoint_mismatch'));
  await emptyTargets(f);
});

test('final scrub catches corruption of an earlier completed copy', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ async onProgress(e) {
    if (e.phase === 'replica_complete' && e.completed_destinations === 2) await writeFile(f.paths[0].input, Buffer.alloc(N, 99));
  } }), error => {
    assert.equal(error.code, 'backup_replenishment_verification_failed');
    assert.equal(error.replenishment.completed_replicas.length, 2);
    assert.equal(error.replenishment.final_scrub.unavailable_candidates, 1);
    assert.equal(error.replenishment.all_destinations_verified, false); return true;
  });
  assert.deepEqual(await readFile(f.paths[1].input), DATA);
});

test('final scrub requires original approval bytes, not only the signed statement', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ async onProgress(e) {
    if (e.phase === 'replica_complete' && e.completed_destinations === 2) await writeFile(f.paths[0].approval, JSON.stringify(JSON.parse(f.envelope), null, 2));
  } }), code('backup_replenishment_verification_failed'));
});

test('hard-link aliases cannot satisfy the final distinct-output count', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ async onProgress(e) {
    if (e.phase === 'replica_complete' && e.completed_destinations === 2) {
      await unlink(f.paths[1].input); await link(f.paths[0].input, f.paths[1].input);
    }
  } }), error => { assert.equal(error.code, 'backup_replenishment_verification_failed');
    assert.equal(error.replenishment.final_scrub.distinct_authenticated_files, 1); return true; });
});

test('one aggregate byte ceiling includes selection, all copying and final scrub', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ maximumTotalBytes: 9 * N - 1 }), code('backup_replenishment_read_budget'));
  await emptyTargets(f);
  const ok = await f.run({ maximumTotalBytes: 9 * N });
  assert.equal(ok.streaming.total_payload_bytes_read, String(9 * N));
});

test('a corrupt source replica consumes the same operation-wide read allowance', async t => {
  const f = await fixture(t), bad = await f.signed('a-corrupt'); await writeFile(bad.input, Buffer.alloc(N, 0));
  await assert.rejects(f.run({ candidates: [bad, f.row], maximumTotalBytes: 10 * N - 1 }), code('backup_replenishment_read_budget'));
  await emptyTargets(f);
  const ok = await f.run({ candidates: [bad, f.row], maximumTotalBytes: 10 * N });
  assert.equal(ok.streaming.total_payload_bytes_read, String(10 * N));
});

test('a large aggregate budget never widens the single-archive size limit', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ maximumBytes: N - 1 }), code('backup_selected_archive_limit')); await emptyTargets(f);
});

test('all destinations are checked before any copy is published', async t => {
  const f = await fixture(t); await chmod(f.destinations[1], 0o755);
  await assert.rejects(f.run(), code('backup_replenishment_private_directory_required')); await emptyTargets(f);
});

test('destination aliases and nested directories are refused before writes', async t => {
  const f = await fixture(t), alias = join(f.root, 'alias'); await symlink(f.root, alias);
  await assert.rejects(f.run({ destinations: [f.destinations[0], join(alias, 'copy-0')] }), code('backup_replenishment_destination_overlap'));
  await assert.rejects(f.run({ destinations: [f.destinations[0], join(f.destinations[0], 'nested')] }), code('backup_replenishment_destination_overlap'));
  await emptyTargets(f);
});

test('a destination final-component symlink is not followed', async t => {
  const f = await fixture(t), alias = join(f.root, 'symlink'); await symlink(f.destinations[1], alias);
  await assert.rejects(f.run({ destinations: [f.destinations[0], alias] }), code('backup_replenishment_private_directory_required')); await emptyTargets(f);
});

test('renaming a destination during the operation cannot redirect later publication', async t => {
  const f = await fixture(t); let changed = false;
  await assert.rejects(f.run({ async onProgress(e) {
    if (e.phase === 'replica_complete' && !changed) {
      changed = true; await rename(f.destinations[1], join(f.root, 'old')); await mkdir(f.destinations[1], { mode: 0o700 });
    }
  } }), error => { assert.equal(error.code, 'backup_replenishment_directory_changed'); assert.equal(error.replenishment.completed_replicas.length, 1); return true; });
  assert.deepEqual(await readdir(f.destinations[1]), []);
});

test('callback ENOENT is fatal, not a reason to silently continue with other targets', async t => {
  const f = await fixture(t), sentinel = Object.assign(new Error('observer'), { code: 'ENOENT' });
  await assert.rejects(f.run({ onProgress(e) { if (e.phase === 'copy_archive') throw sentinel; } }), error => error === sentinel);
  await emptyTargets(f);
});

test('primitive observer failure preserves prior completion evidence', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ onProgress(e) { if (e.phase === 'replica_complete') throw 'stop'; } }), error => {
    assert.equal(error.code, 'backup_replenishment_observer_failed'); assert.equal(error.replenishment.completed_replicas.length, 1); return true;
  });
  assert.deepEqual(await readFile(f.paths[0].input), DATA); await absent(f.paths[1].approval);
});

test('whole-operation deadline is not reset for the next destination', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ timeoutMs: 3000, async onProgress(e) {
    if (e.phase === 'replica_complete') await delay(3100);
  } }), error => { assert.equal(error.code, 'backup_deadline'); assert.equal(error.replenishment.completed_replicas.length, 1); return true; });
  await absent(f.paths[1].approval);
});

test('arguments and checkpoint pins are snapshotted before asynchronous work', async t => {
  const f = await fixture(t), candidates = f.options.candidates.map(r => ({ ...r })), destinations = [...f.destinations], pin = { ...f.checkpoint };
  const promise = f.run({ candidates, destinations, checkpoint: pin });
  candidates[0].input = '/not-a-source'; destinations[0] = '/not-a-destination'; pin.approval_sha256 = '0'.repeat(64);
  const result = await promise; assert.deepEqual(result.checkpoint, f.checkpoint); assert.deepEqual(result.destinations, f.destinations);
  assert(Object.isFrozen(result.completed_replicas)); assert(Object.isFrozen(result.checkpoint));
});

test('an unavailable highest full-u64 checkpoint blocks all lower material', async t => {
  const f = await fixture(t), higher = await f.signed('higher', '18446744073709551615'); await unlink(higher.input);
  await assert.rejects(f.run({ candidates: [f.row, higher] }), code('ENOENT')); await emptyTargets(f);
});

test('equal-generation conflicting signed statements block replenishment', async t => {
  const f = await fixture(t), fork = await f.signed('fork', '9007199254740993', Buffer.alloc(N, 98));
  await assert.rejects(f.run({ candidates: [f.row, fork] }), code('backup_checkpoint_ambiguous')); await emptyTargets(f);
});

test('expired higher evidence does not select a lower working checkpoint', async t => {
  const f = await fixture(t), expired = await f.signed('expired', '18446744073709551615', DATA, { expires_at: '2026-10-11T13:00:00Z' });
  await assert.rejects(f.run({ candidates: [f.row, expired], now: NOW + 7200000 }), code('backup_approval_expired')); await emptyTargets(f);
});

test('checkpoint and resource option validation is bounded and fail-closed', async t => {
  const f = await fixture(t);
  for (const pin of [null, {}, { ...f.checkpoint, extra: true }, { ...f.checkpoint, trusted_key_id: 'f'.repeat(64) }, { ...f.checkpoint, approval_sha256: 'F'.repeat(64) }]) {
    assert.throws(() => repositoryBackupReplicationCheckpoint(pin), code('backup_replication_invalid_checkpoint'));
  }
  for (const extra of [{ destinations: [] }, { destinations: Array(17).fill(f.destinations[0]) }, { maximumTotalBytes: 0 }, { maximumTotalBytes: Number.MAX_SAFE_INTEGER }, { signingKey: 'forbidden' }]) {
    assert.throws(() => repositoryBackupReplenishmentOptions({ ...f.options, ...extra }));
  }
  await emptyTargets(f);
});

test('single-destination publisher accepts exact pins and reports monotonic work', async t => {
  const f = await fixture(t); const seen = [];
  const result = await replicateRepositoryBackup({ candidates: [f.row], destination: f.destinations[0], trustKey: f.options.trustKey,
    policy: f.policy, now: NOW, maximumBytes: N, checkpoint: f.checkpoint,
    onProgress(e) { seen.push(Number(e.total_payload_bytes_read)); } });
  assert(seen.every((n, i) => Number.isSafeInteger(n) && (!i || n >= seen[i - 1])));
  assert.equal(seen.at(-1), Number(result.streaming.total_payload_bytes_read));
  await assert.rejects(replicateRepositoryBackup({ candidates: [f.row], destination: f.destinations[1], trustKey: f.options.trustKey,
    policy: f.policy, now: NOW, checkpoint: { ...f.checkpoint, approval_sha256: '0'.repeat(64) } }), error => {
    assert.equal(error.code, 'backup_replication_checkpoint_mismatch'); assert.equal(error.streaming.total_payload_bytes_read, String(N)); return true;
  });
  assert.deepEqual(await readdir(f.destinations[1]), []);
});

test('all sixteen permitted destinations fit the declared bounded work model', async t => {
  const f = await fixture(t, 'sha256', 16), result = await f.run();
  assert.equal(result.completed_replicas.length, 16); assert.equal(result.final_scrub.distinct_authenticated_files, 16);
  assert.equal(result.streaming.total_payload_bytes_read, String(65 * N));
  assert.deepEqual(result.destinations, [...f.destinations].sort());
});
