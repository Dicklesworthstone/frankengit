// Real filesystem and cryptographic inputs; no native Rust execution claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, lstat, readdir, rm, rename, symlink, chmod, unlink } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { backupLifetime } from '../../scripts/lib/repository-backup-io.mjs';
import { signRepositoryBackupFile, verifyRepositoryBackupApproval } from '../../scripts/lib/repository-backup-approval.mjs';
import { nativeBackupApprovalBinding, stageNativeBackupApproval, assertNativeBackupApproval } from '../../scripts/lib/repository-backup-native-approval.mjs';
const policy = Object.freeze({ tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16),
  object_format: 'sha1', minimum_head_generation: '18446744073709551615' });
const publicPem = Buffer.from('-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n');
const code = value => error => error.code === value;
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-approval-bridge-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, 'source'); await writeFile(input, 'opaque archive; no native graph claim');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const key = Buffer.from(publicKey.export({ type: 'spki', format: 'pem' }));
  const { minimum_head_generation, ...identity } = policy;
  const { envelope } = await signRepositoryBackupFile(input, Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' })),
    { ...identity, head_generation: minimum_head_generation });
  const { authentication } = await verifyRepositoryBackupApproval(envelope, key, policy);
  const session = await stageNativeBackupApproval(envelope, key, authentication, backupLifetime());
  t.after(async () => { try { await session.close(); } finally { await rm(session.directory, { recursive: true, force: true }); } });
  return { root, envelope, key, authentication, session, path: session.args[1] };
}

// Fixed preimages independently assembled with Python hashlib. They encode the
// native approval.rs::binding wire layout, not the output of this JS function.
for (const [object_format, expected] of [
  ['sha1', '0f2b3a8ddca6a3277db495c42b472c289ed9d2ec76f6863df1bae95b51171829'], ['sha256', '3f6680b1eae7a95ca55afd00dad790ef8bba06b45f2998cd9cd9e49b367bd03d'],
]) test(`native ${object_format} ownership preimage golden preserves full-width generation`, () => {
  assert.equal(nativeBackupApprovalBinding(Buffer.from('test\n'), publicPem, { ...policy, object_format }).binding_sha256, expected);
});

test('binding covers original envelope bytes and every independent policy field', () => {
  const original = nativeBackupApprovalBinding(Buffer.from('test\n'), publicPem, policy).binding_sha256;
  assert.notEqual(nativeBackupApprovalBinding(Buffer.from('test'), publicPem, policy).binding_sha256, original);
  for (const field of ['tenant_id', 'repository_id', 'incarnation_id']) {
    assert.notEqual(nativeBackupApprovalBinding(Buffer.from('test\n'), publicPem, { ...policy, [field]: '44'.repeat(16) }).binding_sha256, original);
  }
  assert.notEqual(nativeBackupApprovalBinding(Buffer.from('test\n'), publicPem, { ...policy, minimum_head_generation: '1' }).binding_sha256, original);
});

test('native control snapshots are private, byte-exact and independent of caller buffers', async t => {
  const f = await fixture(t); f.envelope.fill(0); f.key.fill(0);
  assert.equal((await lstat(f.session.directory)).mode & 0o777, 0o700);
  for (const path of [f.session.args[1], f.session.args[3]]) {
    const stat = await lstat(path); assert.equal(stat.mode & 0o777, 0o600); assert.equal(stat.nlink, 1);
  }
  await f.session.check();
  const signed = JSON.parse(await readFile(f.path));
  assert.deepEqual(JSON.parse(Buffer.from(signed.payload, 'base64')), f.authentication.statement);
  assert.deepEqual(f.session.args.slice(4), ['--tenant-id', policy.tenant_id, '--repository-id', policy.repository_id,
    '--incarnation-id', policy.incarnation_id, '--object-format', 'sha1', '--minimum-head-generation', policy.minimum_head_generation]);
  assertNativeBackupApproval(structuredClone(f.session.expected), f.session.expected);
  await Promise.all([f.session.close(), f.session.close()]);
  await assert.rejects(lstat(f.session.directory), code('ENOENT'));
  await assert.rejects(f.session.check(), code('backup_native_approval_closed'));
});

test('receipt equality refuses unsigned, missing, surplus and rebound approval fields', async t => {
  const { session } = await fixture(t);
  for (const mutation of [
    v => { v.signature_verified = false; }, v => { delete v.binding_sha256; }, v => { v.extra = false; },
    v => { v.binding_sha256 = '00'.repeat(32); }, v => { v.trusted_key_id = 'sha256:' + '00'.repeat(32); },
    v => { v.minimum_head_generation = '1'; }, v => { v.statement.artifact.sha256 = '00'.repeat(32); },
    v => { v.newest_checkpoint_verified = true; }, v => { v.complete_capsule_verified = true; },
  ]) {
    const actual = structuredClone(session.expected); mutation(actual);
    assert.throws(() => assertNativeBackupApproval(actual, session.expected), code('backup_native_approval_mismatch'));
    assertNativeBackupApproval(structuredClone(session.expected), session.expected);
  }
});

for (const mutation of ['bytes', 'mode', 'replacement', 'symlink']) {
  test(`${mutation} mutation is refused before native use, without deleting a replacement`, async t => {
    const f = await fixture(t), original = await readFile(f.path), parked = join(f.root, 'parked');
    if (mutation === 'bytes') await writeFile(f.path, Buffer.alloc(original.length, 120));
    if (mutation === 'mode') await chmod(f.path, 0o644);
    if (['replacement', 'symlink'].includes(mutation)) {
      await rename(f.path, parked);
      if (mutation === 'replacement') await writeFile(f.path, original, { mode: 0o600 });
      else await symlink(parked, f.path);
    }
    await assert.rejects(f.session.check());
    // Restore the exact owned resource so test cleanup does not hide refusal.
    if (mutation === 'bytes') await writeFile(f.path, original);
    if (mutation === 'mode') await chmod(f.path, 0o600);
    if (['replacement', 'symlink'].includes(mutation)) { await unlink(f.path); await rename(parked, f.path); }
    await f.session.check();
  });
}

test('pre-cancellation and oversized inputs refuse without staging', async t => {
  const f = await fixture(t), controller = new AbortController(); controller.abort();
  const live = backupLifetime(); live.check = () => { throw Object.assign(Error('cancelled'), { code: 'cancelled' }); };
  await assert.rejects(stageNativeBackupApproval(f.envelope, f.key, f.authentication, live), code('cancelled'));
  await assert.rejects(stageNativeBackupApproval(Buffer.alloc(16385), f.key, f.authentication, backupLifetime()), code('backup_approval_byte_limit'));
  await assert.rejects(stageNativeBackupApproval(f.envelope, Buffer.alloc(8193), f.authentication, backupLifetime()), code('backup_approval_byte_limit'));
  await f.session.check();
});
