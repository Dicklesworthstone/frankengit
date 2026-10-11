// Native verification gates publication of an ordinary detached backup approval.
// The operator adapter neither decodes an archive nor publishes repository state.
import { constants } from 'node:fs';
import { mkdtemp, open, lstat, realpath, rmdir } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { runImportProcess } from './native-import-process.mjs';
import { repositoryBackupReceipt } from './repository-backup-native.mjs';
import { backupDecimal, repositoryBackupDeclarations, signRepositoryBackupFile } from './repository-backup-approval.mjs';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, hashRepositoryBackup,
  readBackupControl, publishBackupControl } from './repository-backup-io.mjs';

function fail(code) { throw backupError(code); }
async function absent(path) {
  try { await lstat(path); fail('backup_existing_path'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;

/** Verify exact archive bytes and declared identity before publishing an approval.
 * The caller explicitly trusts the local fg executable, NOT the archive. Only
 * `backup verify` runs; neither restore nor export is inferred or retried. The
 * private key is read only after native verification closes and is never sent
 * to the child. A final signing pass must match the digest verified by fg.
 *
 * This does not change the DSSE v1 statement or assert a complete Capsule. The
 * native receipt is an operation result, not a signed verification certificate;
 * restore consumers must still independently verify signatures and native data.
 */
export async function approveVerifiedRepositoryBackup(raw) {
  const keys = ['fg', 'input', 'output', 'privateKey', 'declarations', 'verificationInstance',
    'trustedLocal', 'maximumBytes', 'timeoutMs', 'signal'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !keys.includes(k))
    || raw.trustedLocal !== true) fail('backup_explicit_local_operation_required');
  const options = { ...raw };
  for (const field of ['fg', 'input', 'output', 'privateKey']) options[field] = backupPath(options[field]);
  if (!isAbsolute(options.fg)) fail('backup_absolute_fg_required');
  for (const field of ['input', 'output', 'privateKey']) options[field] = resolve(options[field]);
  const instance = backupDecimal(options.verificationInstance, 9223372036854775807n);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal: options.signal });
  const declarations = Object.freeze(repositoryBackupDeclarations(options.declarations, live.now()));
  const current = () => {
    live.check();
    if (Date.parse(declarations.issued_at) > live.now() + 300000) fail('backup_approval_in_future');
    if (declarations.expires_at !== null && Date.parse(declarations.expires_at) <= live.now()) fail('backup_approval_expired');
  };
  current();
  let scratch = null, key;
  try {
    // Reject existing outputs before running a verifier. Publication independently
    // repeats parent/ownership checks and uses a no-replace hard link.
    const parent = await realpath(dirname(options.output));
    const owner = await lstat(parent, { bigint: true });
    if (!owner.isDirectory() || typeof process.getuid !== 'function'
      || owner.uid !== BigInt(process.getuid()) || (owner.mode & 0o077n)) fail('backup_private_parent_required');
    options.output = join(parent, basename(options.output));
    await absent(options.output); current();
    const artifact = await hashRepositoryBackup(options.input, live); current();
    const statement = { ...declarations, artifact: { bytes: artifact.bytes, sha256: artifact.sha256 } };
    scratch = await mkdtemp(join(tmpdir(), 'fg-verify-sign-'));
    const directory = await open(scratch, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    let native;
    try {
      const identity = await directory.stat({ bigint: true });
      if (!identity.isDirectory() || identity.uid !== BigInt(process.getuid()) || (identity.mode & 0o077n)) fail('backup_private_parent_required');
      const path = join(scratch, 'native'); current();
      const args = ['backup', 'verify', options.input, path, '--trusted-local', '--expected-sha256', artifact.sha256,
        '--verification-instance', instance, '--max-archive-bytes', String(live.maximumBytes),
        '--timeout-secs', String(Math.ceil(live.remaining() / 1000))];
      native = repositoryBackupReceipt(await runImportProcess(options.fg, args, live), 'verify', statement, instance);
      // Do not believe a scratch_removed flag without checking the filesystem.
      // Never recursively remove unknown native files, even on a failed run.
      await absent(path);
      const named = await lstat(scratch, { bigint: true });
      if (!named.isDirectory() || !same(named, identity)) fail('backup_scratch_changed');
      await rmdir(scratch); scratch = null;
    } finally { await directory.close(); }
    current();
    key = await readBackupControl(options.privateKey, BACKUP_LIMITS.keyBytes, live, true);
    const signed = await signRepositoryBackupFile(options.input, key, declarations,
      { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal });
    // The archive may have been replaced while fg was running. Never publish an
    // approval for bytes different from the independently verified digest.
    if (signed.statement.artifact.sha256 !== artifact.sha256 || signed.statement.artifact.bytes !== artifact.bytes) fail('backup_artifact_changed_after_verification');
    current();
    const output = await publishBackupControl(options.output, signed.envelope, { ...live, check: current });
    return { type: 'repository_backup_approval_created', ...output, statement: signed.statement,
      trusted_key_id: signed.trusted_key_id, native_content_verified: true, signed_identity_matched_native: true,
      native, complete_capsule_verified: false, newest_checkpoint_verified: false,
      streaming: { initial: { read_calls: artifact.read_calls, maximum_read_bytes: artifact.maximum_read_bytes }, signing: signed.streaming } };
  } catch (error) {
    error.verification_scratch = scratch;
    // A failed output publication can already be visible: preserve the I/O
    // owner's precise state instead of relabelling it as unconditionally absent.
    error.publication_state ??= 'not_created';
    throw error;
  } finally { key?.fill(0); }
}
