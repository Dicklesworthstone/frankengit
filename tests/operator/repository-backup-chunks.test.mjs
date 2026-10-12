// Real filesystem reads, hashes, Ed25519 approvals and byte reconstruction.
// Opaque artifacts are not native fg archives; no native engine is substituted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, readdir, access, chmod, symlink, link, truncate, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { catalogRepositoryBackupChunks, reconstructRepositoryBackup, BACKUP_CHUNK_BYTES as CHUNK,
  MAX_BACKUP_CHUNK_CATALOG_BYTES } from '../../scripts/lib/repository-backup-chunks.mjs';
import { signRepositoryBackupFile, authenticateRepositoryBackupFile } from '../../scripts/lib/repository-backup-approval.mjs';

const policy = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16),
  object_format: 'sha1', minimum_head_generation: '9007199254740993' };
const keys = generateKeyPairSync('ed25519');
const privatePem = Buffer.from(keys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
const publicPem = Buffer.from(keys.publicKey.export({ type: 'spki', format: 'pem' }));
const hash = b => createHash('sha256').update(b).digest();
const code = expected => error => error.code === expected;
async function exists(path) { try { await access(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
async function scratch(t, size = 2 * CHUNK + 137, format = 'sha1', extra = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-chunk-repair-')); t.after(() => rm(root, { recursive: true, force: true }));
  const original = Buffer.alloc(size); for (let i = 0; i < size; i++) original[i] = (i * 17 + (i >>> 17)) & 255;
  const input = join(root, 'source'), approval = join(root, 'approval'), trustKey = join(root, 'public'), catalog = join(root, 'catalog');
  await writeFile(input, original); await writeFile(trustKey, publicPem);
  const expected = { ...policy, object_format: format };
  const { minimum_head_generation, ...identity } = expected;
  const signed = await signRepositoryBackupFile(input, privatePem, { ...identity, head_generation: minimum_head_generation, ...extra });
  await writeFile(approval, signed.envelope);
  const common = { approval, trustKey, policy: expected, maximumBytes: size };
  const output = join(root, 'reconstructed');
  const make = overrides => catalogRepositoryBackupChunks({ ...common, input, output: catalog, ...overrides });
  const repair = (replicas, overrides) => reconstructRepositoryBackup({ ...common, replicas, catalog, output, ...overrides });
  async function replica(name, offsets = []) {
    const bytes = Buffer.from(original); for (const offset of offsets) bytes[offset] ^= 0x5a;
    const path = join(root, name); await writeFile(path, bytes); return path;
  }
  async function clean() {
    assert.equal(await exists(output), false);
    assert.deepEqual((await readdir(root)).filter(p => p.startsWith('.fg-backup-chunks-')), []);
  }
  return { root, original, input, approval, trustKey, catalog, common, output, signed, make, repair, replica, clean };
}

for (const format of ['sha1', 'sha256']) test(`reconstruct ${format} original with NO intact replica and unchanged signature`, async t => {
  const f = await scratch(t, 2 * CHUNK + 137, format), receipt = await f.make();
  assert.equal(receipt.original_archive_authenticated, true); assert.equal(receipt.chunks, 3);
  const a = await f.replica('a', [1]), b = await f.replica('b', [CHUNK + 1]);
  assert.notEqual(hash(await readFile(a)).toString('hex'), f.signed.statement.artifact.sha256);
  assert.notEqual(hash(await readFile(b)).toString('hex'), f.signed.statement.artifact.sha256);
  await rm(f.input);
  const signedBefore = await readFile(f.approval);
  const restored = await f.repair([b, a], { maximumReadBytes: 2 * f.original.length + CHUNK });
  assert.equal(restored.state, 'complete'); assert.deepEqual(await readFile(f.output), f.original);
  assert.equal(restored.sha256, f.signed.statement.artifact.sha256);
  assert.deepEqual(restored.replicas.map(v => v.chunks_used), [2, 1]);
  assert.equal(restored.streaming.payload_bytes_read, String(2 * f.original.length + CHUNK));
  assert.equal(restored.authentication.statement.head_generation, '9007199254740993');
  for (const flag of ['catalog_is_authority', 'native_content_verified', 'repository_changed', 'complete_capsule_restored', 'newest_checkpoint_verified']) assert.equal(restored[flag], false);
  assert.deepEqual(await readFile(f.approval), signedBefore);
  await authenticateRepositoryBackupFile(f.output, signedBefore, publicPem, f.common.policy);
});

for (const size of [1, 65535, 65536, CHUNK, CHUNK + 1]) test(`catalog is deterministic and repairs exact ${size}-byte boundaries`, async t => {
  const f = await scratch(t, size); const first = await f.make();
  const again = join(f.root, 'catalog2'); const second = await f.make({ output: again });
  assert.deepEqual(await readFile(again), await readFile(f.catalog)); assert.equal(first.sha256, second.sha256);
  assert.equal(first.bytes, 88 + 32 * Math.ceil(size / CHUNK));
  assert.ok(first.bytes <= MAX_BACKUP_CHUNK_CATALOG_BYTES);
  const result = await f.repair([f.input], { maximumReadBytes: 2 * size });
  assert.deepEqual(await readFile(f.output), f.original); assert.equal(result.streaming.payload_bytes_read, String(2 * size));
});

test('one-byte-short source work budget refuses before any staged publication', async t => {
  const f = await scratch(t); await f.make();
  const a = await f.replica('a', [0]), b = await f.replica('b', [CHUNK]);
  await assert.rejects(f.repair([a, b], { maximumReadBytes: 2 * f.original.length + CHUNK - 1 }), code('backup_chunk_read_budget'));
  await f.clean();
  assert.equal((await f.repair([a, b], { maximumReadBytes: 2 * f.original.length + CHUNK })).state, 'complete');
});

test('incomplete, symlinked and missing copies contribute no fake coverage', async t => {
  const f = await scratch(t); await f.make();
  const a = await f.replica('a'); await truncate(a, CHUNK);
  const b = await f.replica('b', [0]); const alias = join(f.root, 'alias'); await symlink(b, alias);
  const result = await f.repair([join(f.root, 'missing'), alias, b, a]);
  assert.deepEqual(await readFile(f.output), f.original);
  assert.equal(result.replicas.find(v => v.input === a).chunks_used, 1);
  assert.equal(result.replicas.find(v => v.input === b).chunks_used, 2);
  assert.equal(result.replicas.find(v => v.input === alias).unavailable, 'ELOOP');
});

test('uncovered chunk refuses and removes only this attempt’s staging file', async t => {
  const f = await scratch(t); await f.make();
  const a = await f.replica('a', [CHUNK + 9]), b = await f.replica('b', [CHUNK + 12]);
  const originalA = await readFile(a), originalB = await readFile(b);
  await assert.rejects(f.repair([a, b]), error => error.code === 'backup_chunk_unrecoverable' && error.chunk_index === 1);
  await f.clean(); assert.deepEqual(await readFile(a), originalA); assert.deepEqual(await readFile(b), originalB);
});

test('a self-consistent forged catalog NEVER replaces the original signed archive digest', async t => {
  const f = await scratch(t, 131072); await f.make();
  const bad = await f.replica('bad', [17]); const bytes = await readFile(f.catalog);
  hash(await readFile(bad)).copy(bytes, 56); hash(bytes.subarray(0, -32)).copy(bytes, bytes.length - 32);
  await writeFile(f.catalog, bytes);
  await assert.rejects(f.repair([bad]), code('backup_chunk_readback_mismatch')); await f.clean();
});

for (const defect of ['trailer', 'magic', 'length', 'count', 'chunk-size', 'artifact', 'trailing']) test(`malformed ${defect} catalog refuses without output`, async t => {
  const f = await scratch(t, 128); await f.make(); let bytes = await readFile(f.catalog);
  if (defect === 'trailer') bytes[bytes.length - 1] ^= 1;
  if (defect === 'magic') bytes[0] ^= 1;
  if (defect === 'length') bytes.writeBigUInt64BE(129n, 8);
  if (defect === 'count') bytes.writeUInt32BE(0xffffffff, 52);
  if (defect === 'chunk-size') bytes.writeUInt32BE(1, 48);
  if (defect === 'artifact') bytes[16] ^= 1;
  if (defect === 'trailing') bytes = Buffer.concat([bytes, Buffer.from([0])]);
  if (!['trailer', 'trailing'].includes(defect)) hash(bytes.subarray(0, -32)).copy(bytes, bytes.length - 32);
  await writeFile(f.catalog, bytes); await assert.rejects(f.repair([f.input]), code('backup_chunk_catalog_mismatch')); await f.clean();
});

test('invalid signature, namespace and independent floor refuse before catalog or replica access', async t => {
  const f = await scratch(t, 128); const saved = await readFile(f.approval); const envelope = JSON.parse(saved);
  const signature = Buffer.from(envelope.signatures[0].sig, 'base64'); signature[0] ^= 1;
  envelope.signatures[0].sig = signature.toString('base64'); await writeFile(f.approval, JSON.stringify(envelope));
  await assert.rejects(f.repair([f.input]), code('backup_invalid_signature'));
  await writeFile(f.approval, saved);
  await assert.rejects(f.repair([f.input], { policy: { ...f.common.policy, tenant_id: '99'.repeat(16) } }), code('backup_approval_identity_mismatch'));
  await assert.rejects(f.repair([f.input], { policy: { ...f.common.policy, minimum_head_generation: '9007199254740994' } }), code('backup_approval_below_floor'));
  await f.clean();
});

test('wrong source commitment cannot produce a trusted catalog', async t => {
  const f = await scratch(t, 128); await writeFile(f.input, Buffer.alloc(128));
  await assert.rejects(f.make(), code('backup_artifact_mismatch')); assert.equal(await exists(f.catalog), false); await f.clean();
});

test('cancel, elapsed time and observer failures are fatal, not replica-unavailability hints', async t => {
  const f = await scratch(t, 262144); await f.make(); const other = await f.replica('other');
  const controller = new AbortController();
  await assert.rejects(f.repair([f.input, other], { signal: controller.signal, onProgress(event) { if (event.phase === 'repair_read') controller.abort(); } }), code('backup_cancelled'));
  await f.clean();
  await assert.rejects(f.repair([f.input, other], { onProgress() { const e = Error('observer, not filesystem'); e.code = 'ENOENT'; throw e; } }), code('backup_chunk_observer_failed')); await f.clean();
  await assert.rejects(f.repair([f.input, other], { timeoutMs: 50, async onProgress() { await new Promise(r => setTimeout(r, 60)); } }), code('backup_deadline')); await f.clean();
  assert.equal((await f.repair([f.input, other])).state, 'complete');
});

test('production approval expiry is rechecked through the publication boundary', async t => {
  const clock = Date.parse('2026-10-12T08:00:00Z'); let now = clock; t.mock.method(Date, 'now', () => now);
  const f = await scratch(t, 128, 'sha1', { issued_at: '2026-10-12T07:59:00Z', expires_at: '2026-10-12T08:01:00Z' });
  await f.make();
  await assert.rejects(f.repair([f.input], { onProgress(event) { if (event.phase === 'before_publication') now += 120000; } }), code('backup_approval_expired'));
  await f.clean(); now = clock; assert.equal((await f.repair([f.input])).state, 'complete');
});

test('mutation during a chunk is not accepted using an earlier good hash', async t => {
  const f = await scratch(t, 262144); await f.make(); let changed = false;
  await assert.rejects(f.repair([f.input], { async onProgress(event) {
    if (event.phase === 'repair_read' && !changed) { changed = true; await writeFile(f.input, Buffer.alloc(f.original.length, 9)); }
  } }), code('backup_chunk_unrecoverable')); await f.clean();
});

test('the output is create-only and never destroys existing data or hard-link aliases', async t => {
  const f = await scratch(t, 128); await f.make(); await writeFile(f.output, 'valuable existing data');
  await assert.rejects(f.repair([f.input]), code('backup_chunk_output_exists')); assert.equal(await readFile(f.output, 'utf8'), 'valuable existing data');
  await rm(f.output); await link(f.input, f.output);
  await assert.rejects(f.repair([f.input]), code('backup_chunk_output_exists')); assert.deepEqual(await readFile(f.input), f.original);
});

test('concurrent publishers cannot replace the winning output', async t => {
  const f = await scratch(t, 128); await f.make();
  const result = await Promise.allSettled([f.repair([f.input]), f.repair([f.input])]);
  assert.equal(result.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(result.filter(r => r.status === 'rejected').length, 1);
  assert.deepEqual(await readFile(f.output), f.original);
  assert.deepEqual((await readdir(f.root)).filter(p => p.startsWith('.fg-backup-chunks-')), []);
});

test('private destination parent and file-mode changes are enforced', async t => {
  const f = await scratch(t, 128); await f.make(); await chmod(f.root, 0o755);
  await assert.rejects(f.repair([f.input]), code('backup_chunk_private_parent_required')); await chmod(f.root, 0o700);
  await assert.rejects(f.repair([f.input], { async onProgress(event) {
    if (event.phase === 'before_publication') {
      const temp = (await readdir(f.root)).find(p => p.startsWith('.fg-backup-chunks-')); await chmod(join(f.root, temp), 0o666);
    }
  } }), code('backup_chunk_temporary_changed')); await f.clean();
});

test('all paths and limits are copied and validated before asynchronous I/O', async t => {
  const f = await scratch(t, 128); await f.make(); const replicas = [f.input], p = { ...f.common.policy };
  const pending = f.repair(replicas, { policy: p }); replicas[0] = '/missing'; p.tenant_id = 'ff'.repeat(16);
  assert.equal((await pending).state, 'complete');
  for (const overrides of [{ replicas: [] }, { replicas: new Array(2) }, { replicas: Array(65).fill(f.input) },
    { replicas: [f.input, f.input] }, { maximumReadBytes: 0 }, { maximumReadBytes: Number.MAX_SAFE_INTEGER },
    { maximumBytes: 0 }, { output: f.input }, { input: f.input }, { unknown: true }]) {
    await assert.rejects(f.repair([f.input], overrides));
  }
});

test('witness-to-repair equality pins cannot skip verification or accept changed approval bytes', async t => {
  const f = await scratch(t, 128); await f.make();
  const checkpoint = { approval_sha256: hash(await readFile(f.approval)).toString('hex'), trusted_key_id: f.signed.trusted_key_id };
  await assert.rejects(f.repair([f.input], { checkpoint: { ...checkpoint, trusted_key_id: 'sha256:' + '0'.repeat(64) } }), code('backup_chunk_signer_changed'));
  await writeFile(f.approval, Buffer.concat([await readFile(f.approval), Buffer.from('\n')]));
  await assert.rejects(f.repair([f.input], { checkpoint }), code('backup_chunk_approval_changed')); await f.clean();
  await writeFile(f.approval, f.signed.envelope);
  assert.equal((await f.repair([f.input], { checkpoint })).state, 'complete');
});
