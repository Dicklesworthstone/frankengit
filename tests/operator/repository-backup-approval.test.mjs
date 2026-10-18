import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign, createPublicKey, verify } from 'node:crypto';
import { mkdtemp, writeFile, readFile, chmod, rm, symlink, link, readdir, lstat, rename, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { BACKUP_LIMITS, backupLifetime, readBackupControl, hashRepositoryBackup, publishBackupControl } from '../../scripts/lib/repository-backup-io.mjs';
import { REPOSITORY_BACKUP_TYPE, repositoryBackupPAE, backupPolicy, backupDecimal,
  signRepositoryBackupFile, verifyRepositoryBackupApproval, authenticateRepositoryBackupFile } from '../../scripts/lib/repository-backup-approval.mjs';
import { runApprovalCommand, approvalArguments } from '../../scripts/attest_repository_backup.mjs';

const NOW = Date.parse('2026-10-08T12:00:00Z');
const data = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16),
  object_format: 'sha1', head_generation: '18446744073709551615', issued_at: '2026-10-08T12:00:00Z', expires_at: '2026-10-09T12:00:00Z' };
const policy = { tenant_id: data.tenant_id, repository_id: data.repository_id, incarnation_id: data.incarnation_id,
  object_format: data.object_format, minimum_head_generation: data.head_generation };
function keys() {
  const pair = generateKeyPairSync('ed25519');
  return { privatePem: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }), publicPem: pair.publicKey.export({ format: 'pem', type: 'spki' }) };
}
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-backup-approval-')); t.after(() => rm(root, { recursive: true, force: true }));
  const pair = keys(), path = join(root, 'archive'); await writeFile(path, 'opaque native archive fixture\n');
  const signed = await signRepositoryBackupFile(path, Buffer.from(pair.privatePem), data, { now: NOW });
  return { root, path, ...pair, signed };
}
async function verifyApproval(f, expected = policy, options = {}) {
  return verifyRepositoryBackupApproval(f.signed.envelope, Buffer.from(f.publicPem), expected, { now: NOW, ...options });
}
const code = value => error => error.code === value;

test('real Ed25519 binds exact streamed bytes, native identity, and full-width floor', async t => {
  const f = await fixture(t), authenticated = await authenticateRepositoryBackupFile(f.path, f.signed.envelope, Buffer.from(f.publicPem), policy, { now: NOW });
  assert.equal(authenticated.authentication.signature_verified, true);
  assert.equal(authenticated.authentication.statement.head_generation, '18446744073709551615');
  assert.equal(authenticated.authentication.statement.artifact.sha256, createHash('sha256').update(await readFile(f.path)).digest('hex'));
  assert.equal(authenticated.authentication.native_content_verified, false);
  assert.equal(authenticated.authentication.complete_capsule_verified, false);
  assert.equal(authenticated.authentication.newest_checkpoint_verified, false);
  assert.ok(Object.isFrozen(authenticated.authentication.statement.artifact));
  const envelope = JSON.parse(f.signed.envelope), payload = Buffer.from(envelope.payload, 'base64'), type = Buffer.from(REPOSITORY_BACKUP_TYPE);
  // Independent assembly of the DSSE preimage, not a second call to the helper.
  const pae = Buffer.concat([Buffer.from('DSSEv1 ' + type.length + ' '), type, Buffer.from(' ' + payload.length + ' '), payload]);
  assert.ok(verify(null, pae, createPublicKey(f.publicPem), Buffer.from(envelope.signatures[0].sig, 'base64')));
});
for (const key of ['tenant_id', 'repository_id', 'incarnation_id', 'object_format']) {
  test('foreign ' + key + ' refuses before archive I/O', async t => {
    const f = await fixture(t), wrong = { ...policy, [key]: key === 'object_format' ? 'sha256' : '44'.repeat(16) };
    await assert.rejects(authenticateRepositoryBackupFile(join(f.root, 'missing'), f.signed.envelope, Buffer.from(f.publicPem), wrong, { now: NOW }), code('backup_approval_identity_mismatch'));
    assert.ok((await verifyApproval(f)).authentication.signature_verified);
  });
}
test('wrong key and tampering refuse without opening even a missing archive', async t => {
  const f = await fixture(t), other = keys();
  await assert.rejects(authenticateRepositoryBackupFile('/does/not/exist', f.signed.envelope, Buffer.from(other.publicPem), policy, { now: NOW }), code('backup_untrusted_signer'));
  const changed = JSON.parse(f.signed.envelope); const payload = JSON.parse(Buffer.from(changed.payload, 'base64'));
  payload.artifact.sha256 = '0'.repeat(64); changed.payload = Buffer.from(JSON.stringify(payload)).toString('base64');
  await assert.rejects(verifyRepositoryBackupApproval(Buffer.from(JSON.stringify(changed)), Buffer.from(f.publicPem), policy, { now: NOW }), code('backup_invalid_signature'));
  await writeFile(f.path, 'wrong archive');
  await assert.rejects(authenticateRepositoryBackupFile(f.path, f.signed.envelope, Buffer.from(f.publicPem), policy, { now: NOW }), code('backup_artifact_mismatch'));
});
test('signed metadata cannot lower an externally retained generation floor', async t => {
  const f = await fixture(t);
  f.signed = await signRepositoryBackupFile(f.path, Buffer.from(f.privatePem), { ...data, head_generation: '9007199254740992' }, { now: NOW });
  await assert.rejects(verifyApproval(f, { ...policy, minimum_head_generation: '9007199254740993' }), code('backup_approval_below_floor'));
  assert.ok((await verifyApproval(f, { ...policy, minimum_head_generation: '9007199254740992' })).authentication.signature_verified);
});
test('future, expired and invalid approval lifetimes refuse with permitted twins', async t => {
  const f = await fixture(t);
  await assert.rejects(verifyApproval(f, policy, { now: Date.parse(data.expires_at) }), code('backup_approval_expired'));
  await assert.rejects(verifyApproval(f, policy, { now: NOW - 300001 }), code('backup_approval_in_future'));
  assert.ok((await verifyApproval(f, policy, { now: NOW - 300000 })).authentication.signature_verified);
  for (const expires_at of ['2026-02-30T00:00:00Z', 'invalid', data.issued_at]) {
    await assert.rejects(signRepositoryBackupFile(f.path, Buffer.from(f.privatePem), { ...data, expires_at }, { now: NOW }));
  }
});
test('portable source approval and altered DSSE payload types cannot cross into repository backups', async t => {
  const f = await fixture(t), envelope = JSON.parse(f.signed.envelope);
  envelope.payloadType = 'application/vnd.frankengit.source-backup-attestation.v1+json';
  await assert.rejects(verifyRepositoryBackupApproval(Buffer.from(JSON.stringify(envelope)), Buffer.from(f.publicPem), policy, { now: NOW }), code('backup_invalid_envelope'));
  const payload = Buffer.from(envelope.payload, 'base64'), type = Buffer.from(envelope.payloadType);
  const sig = sign(null, Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type, Buffer.from(` ${payload.length} `), payload]), f.privatePem);
  envelope.payloadType = REPOSITORY_BACKUP_TYPE; envelope.signatures[0].sig = sig.toString('base64');
  await assert.rejects(verifyRepositoryBackupApproval(Buffer.from(JSON.stringify(envelope)), Buffer.from(f.publicPem), policy, { now: NOW }), code('backup_invalid_signature'));
});
test('signed but noncanonical, duplicate-field and unsupported-scope payloads refuse', async t => {
  const f = await fixture(t), original = JSON.parse(f.signed.envelope), signed = JSON.parse(Buffer.from(original.payload, 'base64'));
  for (const text of [JSON.stringify(signed, null, 2), JSON.stringify(signed).replace('"type":', '"type":"ignored","type":'),
    JSON.stringify({ ...signed, scope: 'full-capsule' }), JSON.stringify({ ...signed, extra: true })]) {
    const payload = Buffer.from(text), envelope = { ...original, payload: payload.toString('base64'),
      signatures: [{ ...original.signatures[0], sig: sign(null, repositoryBackupPAE(payload), f.privatePem).toString('base64') }] };
    await assert.rejects(verifyRepositoryBackupApproval(Buffer.from(JSON.stringify(envelope)), Buffer.from(f.publicPem), policy, { now: NOW }));
  }
  assert.ok((await verifyApproval(f)).authentication.signature_verified);
});
test('bounded canonical PEM/base64/metadata rejects ambiguous and unsupported keys', async t => {
  const f = await fixture(t);
  for (const key of [f.privatePem, f.publicPem + 'garbage', '', f.publicPem.repeat(200)]) {
    await assert.rejects(verifyRepositoryBackupApproval(f.signed.envelope, Buffer.from(key), policy, { now: NOW }));
  }
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'pem' });
  await assert.rejects(verifyRepositoryBackupApproval(f.signed.envelope, Buffer.from(rsa), policy, { now: NOW }), code('backup_ed25519_required'));
  for (const value of ['', '01', '+1', '0', '18446744073709551616', 123]) assert.throws(() => backupDecimal(value));
  assert.throws(() => backupPolicy({ ...policy, inferred_trust: true }));
  const envelope = JSON.parse(f.signed.envelope); envelope.signatures[0].sig += '=';
  await assert.rejects(verifyRepositoryBackupApproval(Buffer.from(JSON.stringify(envelope)), Buffer.from(f.publicPem), policy, { now: NOW }), code('backup_invalid_base64'));
});
test('mutable input and policy are captured before an async verifier yields', async t => {
  const f = await fixture(t), encoded = Buffer.from(f.signed.envelope), key = Buffer.from(f.publicPem), expected = { ...policy };
  const pending = verifyRepositoryBackupApproval(encoded, key, expected, { now: NOW });
  encoded.fill(0); key.fill(0); expected.minimum_head_generation = '1'; expected.tenant_id = '99'.repeat(16);
  const result = await pending; assert.deepEqual(result.authentication.policy, policy);
  assert.throws(() => { result.authentication.statement.expires_at = null; }); result.checkCurrent();
});
test('streaming hashes an over-16-MiB archive without returning its bytes', async t => {
  const f = await fixture(t), large = await open(f.path, 'w'); await large.truncate(17 * 1024 * 1024 + 7); await large.close();
  const signed = await signRepositoryBackupFile(f.path, Buffer.from(f.privatePem), data, { now: NOW, maximumBytes: 18 * 1024 * 1024 });
  assert.equal(signed.statement.artifact.bytes, String(17 * 1024 * 1024 + 7)); assert.ok(signed.streaming.read_calls > 256);
  const approved = await authenticateRepositoryBackupFile(f.path, signed.envelope, Buffer.from(f.publicPem), policy, { now: NOW, maximumBytes: 18 * 1024 * 1024 });
  assert.equal(approved.bytes, undefined);
  await assert.rejects(verifyRepositoryBackupApproval(signed.envelope, Buffer.from(f.publicPem), policy, { now: NOW, maximumBytes: 16 * 1024 * 1024 }), code('backup_invalid_decimal'));
});
test('path substitution, links, file growth, cancellation and deadline cannot authenticate an unstable archive', async t => {
  const f = await fixture(t);
  await symlink(f.path, join(f.root, 'alias')); await assert.rejects(hashRepositoryBackup(join(f.root, 'alias'), backupLifetime()));
  for (const change of ['replace', 'grow', 'cancel']) {
    await writeFile(f.path, Buffer.alloc(100000)); const controller = new AbortController(); let acted = false;
    const live = backupLifetime({ signal: controller.signal, onProgress: async () => {
      if (acted) return; acted = true;
      if (change === 'cancel') controller.abort();
      else if (change === 'replace') { await writeFile(join(f.root, 'new'), Buffer.alloc(100000)); await rename(join(f.root, 'new'), f.path); }
      else { const h = await open(f.path, 'a'); await h.write('more'); await h.close(); }
    } });
    await assert.rejects(hashRepositoryBackup(f.path, live)); assert.ok(acted);
  }
  await assert.rejects(hashRepositoryBackup(f.path, backupLifetime({ timeoutMs: 1, onProgress: () => new Promise(r => setTimeout(r, 5)) })), code('backup_deadline'));
});
test('private-key reads refuse group permissions and hard links', async t => {
  const f = await fixture(t), p = join(f.root, 'key'); await writeFile(p, f.privatePem, { mode: 0o600 });
  assert.equal((await readBackupControl(p, 8192, backupLifetime(), true)).toString(), f.privatePem);
  await chmod(p, 0o640); await assert.rejects(readBackupControl(p, 8192, backupLifetime(), true), code('backup_private_owner_required'));
  await chmod(p, 0o600); await link(p, join(f.root, 'key-link'));
  await assert.rejects(readBackupControl(p, 8192, backupLifetime(), true), code('backup_private_key_links'));
});
test('control publication is private, no-replace and leaves no successful temporary files', async t => {
  const f = await fixture(t), path = join(f.root, 'approval');
  const result = await publishBackupControl(path, f.signed.envelope, backupLifetime()); assert.equal(result.state, 'complete');
  assert.deepEqual(await readFile(path), f.signed.envelope); assert.equal((await lstat(path)).mode & 0o777, 0o600);
  await assert.rejects(publishBackupControl(path, Buffer.from('different'), backupLifetime()), code('EEXIST'));
  assert.deepEqual(await readFile(path), f.signed.envelope); assert.ok(!(await readdir(f.root)).some(n => n.endsWith('.tmp')));
});
test('real CLI sign/check round trip, help and malformed grammar never contact a native engine', async t => {
  const f = await fixture(t), key = join(f.root, 'private.pem'), publicKey = join(f.root, 'public.pem'), approval = join(f.root, 'approval.json');
  await writeFile(key, f.privatePem, { mode: 0o600 }); await writeFile(publicKey, f.publicPem, { mode: 0o600 });
  const common = ['--tenant-id', data.tenant_id, '--repository-id', data.repository_id, '--incarnation-id', data.incarnation_id, '--object-format', 'sha1'];
  const script = resolve('scripts/attest_repository_backup.mjs');
  const signed = spawnSync(process.execPath, [script, 'sign', f.path, approval, ...common, '--private-key', key, '--head-generation', data.head_generation], { encoding: 'utf8' });
  assert.equal(signed.status, 0, signed.stderr); assert.equal(JSON.parse(signed.stdout).native_content_verified, false);
  const checked = spawnSync(process.execPath, [script, 'check', f.path, approval, ...common, '--trust-key', publicKey, '--minimum-head-generation', data.head_generation], { encoding: 'utf8' });
  assert.equal(checked.status, 0, checked.stderr); assert.equal(JSON.parse(checked.stdout).archive_bytes_authenticated, true);
  assert.match(await runApprovalCommand(['--help']), /operator/i);
  for (const args of [[], ['check'], ['sign', 'x', 'y', '--unknown', 'z'], ['check', 'x', 'y', '--trust-key', 'x', '--trust-key', 'y']]) assert.throws(() => approvalArguments(args));
  const signAgain = spawnSync(process.execPath, [script, 'sign', f.path, approval, ...common, '--private-key', key, '--head-generation', '2'], { encoding: 'utf8' });
  assert.equal(signAgain.status, 1); assert.equal(JSON.parse(signAgain.stderr).code, 'EEXIST');
});
