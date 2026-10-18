// Bridge already authenticated operator inputs to the native signed-mode CLI.
// This owns only two bounded, private control files, never a restore directory.
import { createHash, createPublicKey } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdtemp, open, lstat, unlink, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { BACKUP_LIMITS, backupError, readBackupControl } from './repository-backup-io.mjs';
import { backupPolicy } from './repository-backup-approval.mjs';

const fail = code => { throw backupError(code); };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
function copy(value, maximum) {
  if (!(value instanceof Uint8Array) || value.buffer instanceof SharedArrayBuffer
    || !value.length || value.length > maximum) fail('backup_approval_byte_limit');
  return Buffer.from(value);
}
function u64(value) { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); return bytes; }

// Exact local ownership preimage in native repository/approval.rs::binding.
// Not a signature, repository identity, or alternative source of authority.
export function nativeBackupApprovalBinding(encoded, publicPem, rawPolicy) {
  const envelope = copy(encoded, BACKUP_LIMITS.envelopeBytes), keyBytes = copy(publicPem, BACKUP_LIMITS.keyBytes);
  const policy = backupPolicy(rawPolicy);
  const key = createPublicKey({ key: keyBytes, format: 'pem', type: 'spki' });
  if (key.asymmetricKeyType !== 'ed25519') fail('backup_ed25519_required');
  const der = key.export({ format: 'der', type: 'spki' });
  if (der.length !== 44 || der.subarray(0, 12).toString('hex') !== '302a300506032b6570032100') fail('backup_noncanonical_key');
  const hash = createHash('sha256').update('repository_backup_restore_approval_v1\0')
    .update(u64(envelope.length)).update(envelope).update(der);
  for (const name of ['tenant_id', 'repository_id', 'incarnation_id']) hash.update(Buffer.from(policy[name], 'hex'));
  const binding = hash.update(Buffer.from([policy.object_format === 'sha1' ? 1 : 2]))
    .update(u64(policy.minimum_head_generation)).digest('hex');
  return Object.freeze({ binding_sha256: binding, trusted_key_id: 'sha256:' + sha256(der) });
}

export function assertNativeBackupApproval(actual, expected) {
  if (!expected || !isDeepStrictEqual(actual, expected)) fail('backup_native_approval_mismatch');
}

// Call only after independent signature/artifact authentication. The native
// process independently verifies these ORIGINAL bytes, policy and archive again.
// Snapshot before the first await; neither caller mutations nor path replacement
// can substitute a different valid approval/key between preflight and restore.
export async function stageNativeBackupApproval(encoded, publicPem, authentication, live) {
  const envelope = copy(encoded, BACKUP_LIMITS.envelopeBytes), key = copy(publicPem, BACKUP_LIMITS.keyBytes);
  const policy = backupPolicy(authentication.policy), pins = nativeBackupApprovalBinding(envelope, key, policy);
  if (authentication.signature_verified !== true || pins.trusted_key_id !== authentication.trusted_key_id) fail('backup_untrusted_signer');
  const statement = structuredClone(authentication.statement);
  Object.freeze(statement.artifact); Object.freeze(statement);
  const expected = Object.freeze({ type: 'repository_backup_approval_authentication', signature_verified: true,
    ...pins, minimum_head_generation: policy.minimum_head_generation, statement,
    newest_checkpoint_verified: false, complete_capsule_verified: false });
  if (constants.O_NOFOLLOW === undefined || constants.O_DIRECTORY === undefined || typeof process.getuid !== 'function') fail('backup_unsupported_filesystem');
  live.check();
  const root = await mkdtemp(join(tmpdir(), 'fg-backup-native-approval-'));
  const files = []; let directory, identity, closing;
  async function checkDirectory() {
    const named = await lstat(root, { bigint: true }), opened = await directory.stat({ bigint: true });
    if (!named.isDirectory() || !same(named, opened) || !same(opened, identity)
      || named.uid !== BigInt(process.getuid()) || (named.mode & 0o077n)) fail('backup_native_approval_changed');
  }
  async function cleanup(retain = false) {
    let problem;
    try {
      if (!retain) {
        if (directory) await checkDirectory();
        for (const entry of files) {
          const named = await lstat(entry.path, { bigint: true });
          if (!named.isFile() || !same(named, entry.identity)) fail('backup_native_approval_changed');
          await unlink(entry.path);
        }
        if (directory) { await directory.sync(); await checkDirectory(); }
        // Unknown children, including native diagnostic state, are not removed.
        await rmdir(root);
      }
    } catch (error) { problem = error; }
    for (const handle of [...files.map(entry => entry.file), directory]) {
      try { await handle?.close(); } catch (error) { problem ??= error; }
    }
    if (problem) {
      const error = backupError('backup_native_approval_cleanup_failed');
      error.approval_scratch = root; error.cause = problem; throw error;
    }
  }
  const close = () => (closing ??= cleanup());
  // A failed-containment caller cannot delete resources a child may still read.
  // Finalization still closes our own file descriptors; it is idempotent and
  // cannot be followed by a close() that silently removes retained evidence.
  const retain = () => (closing ??= cleanup(true));
  try {
    directory = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    identity = await directory.stat({ bigint: true }); await checkDirectory(); live.check();
    for (const [name, bytes] of [['approval.dsse.json', envelope], ['trusted-public.pem', key]]) {
      await checkDirectory(); live.check();
      const path = join(root, name), file = await open(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      // Record ownership immediately, even when writing or synchronizing fails.
      const entry = { path, file, bytes, identity: null }; files.push(entry);
      entry.identity = await file.stat({ bigint: true });
      await file.writeFile(bytes); await file.sync(); live.check();
    }
    await directory.sync();
    const check = async () => {
      if (closing) fail('backup_native_approval_closed');
      live.check(); await checkDirectory();
      for (const entry of files) {
        const named = await lstat(entry.path, { bigint: true });
        if (!named.isFile() || !same(named, entry.identity)) fail('backup_native_approval_changed');
        const bytes = await readBackupControl(entry.path, entry.bytes.length, live, true);
        if (!bytes.equals(entry.bytes)) fail('backup_native_approval_changed');
      }
      await checkDirectory(); live.check();
    };
    await check();
    const args = Object.freeze(['--approval', files[0].path, '--trust-key', files[1].path,
      '--tenant-id', policy.tenant_id, '--repository-id', policy.repository_id, '--incarnation-id', policy.incarnation_id,
      '--object-format', policy.object_format, '--minimum-head-generation', policy.minimum_head_generation]);
    return Object.freeze({ args, expected, directory: root, check, close, retain });
  } catch (caught) {
    const error = caught instanceof Error ? caught : backupError('backup_native_approval_staging_failed');
    try { await close(); } catch (cleanup) { error.cleanup_error = cleanup.code; error.approval_scratch = root; }
    throw error;
  }
}
