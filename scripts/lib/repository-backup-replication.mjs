// Trusted-local signed archive replication, not a repository authority backend.
// Stream original bytes, synchronize/read back the body, publish approval last.
// Destination names are content-addressed and every publication is create-only.
import { constants } from 'node:fs';
import { open, lstat, realpath, link, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, readBackupControl,
  publishBackupControl } from './repository-backup-io.mjs';
import { backupPolicy, verifyRepositoryBackupApproval } from './repository-backup-approval.mjs';
import { repositoryBackupCandidates, selectRepositoryBackup } from './repository-backup-selection.mjs';

const CHUNK = 65536;
const fields = ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs'];
const sameInode = (a, b) => a.dev === b.dev && a.ino === b.ino;
const sameFile = (a, b) => fields.every(key => a[key] === b[key]);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw backupError(code); };

export function repositoryBackupReplicationOptions(value) {
  const keys = ['candidates', 'trustKey', 'policy', 'destination', 'maximumBytes',
    'maximumTotalBytes', 'timeoutMs', 'signal', 'onProgress', 'now'];
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some(key => !keys.includes(key))) fail('backup_invalid_replication_options');
  const candidates = repositoryBackupCandidates(value.candidates), policy = backupPolicy(value.policy);
  const trustKey = resolve(backupPath(value.trustKey)), destination = resolve(backupPath(value.destination));
  backupPath(trustKey); backupPath(destination);
  const live = backupLifetime({ maximumBytes: value.maximumBytes, timeoutMs: value.timeoutMs,
    signal: value.signal, onProgress: value.onProgress, now: value.now });
  // Separate the archive size ceiling from all selection/copy/readback payload
  // reads. Controls and one-byte EOF probes have their own fixed small bounds.
  const maximumTotalBytes = value.maximumTotalBytes ?? live.maximumBytes * 4;
  if (!Number.isSafeInteger(maximumTotalBytes) || maximumTotalBytes < 1
    || maximumTotalBytes > BACKUP_LIMITS.maximumArchiveBytes * 4) fail('backup_replication_read_limit');
  return Object.freeze({ candidates, policy, trustKey, destination,
    maximumBytes: live.maximumBytes, maximumTotalBytes, timeoutMs: value.timeoutMs,
    signal: live.signal, onProgress: live.onProgress, now: value.now });
}

/** Publish a byte-for-byte replica in an EXISTING private local directory.
 * No signing key, native mutation, bucket listing, root replacement, or deletion
 * of previously published files is involved. The result is a new candidate for
 * the existing selector/approved native restore path, NOT native verification.
 * The selected signed intent is pinned before the destination is touched.
 */
export async function replicateRepositoryBackup(raw) {
  const options = repositoryBackupReplicationOptions(raw);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs,
    signal: options.signal, now: options.now });
  const controlLive = () => ({ ...live, onProgress: () => {} });
  let totalBytes = 0, readCalls = 0, selectionOffset = 0;
  let selected, verified, directory, directoryIdentity, canonical, temporary, temporaryIdentity;
  let source, staging, target, state = 'not_started', candidate, completed, failure;
  let archiveDisposition = 'reused', approvalDisposition = 'reused', existingApproval = false;
  const gate = () => { live.check(); selected?.checkCurrent(); verified?.checkCurrent(); };
  const budget = bytes => {
    if (bytes > options.maximumTotalBytes - totalBytes) fail('backup_replication_read_budget');
  };
  const charge = bytes => { budget(bytes); totalBytes += bytes; readCalls++; };
  const progress = async (phase, details = {}) => {
    await options.onProgress(Object.freeze({ phase, ...details, publication_state: state }));
    gate();
  };
  function privateDirectory(stat) {
    if (!stat.isDirectory() || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_replica_private_directory_required');
  }
  function privateReplica(stat) {
    if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n) || stat.nlink !== 1n) fail('backup_replica_private_file_required');
  }
  async function checkDirectory() {
    const named = await lstat(canonical, { bigint: true }), opened = await directory.stat({ bigint: true });
    const requested = await lstat(options.destination, { bigint: true });
    privateDirectory(named); privateDirectory(opened); privateDirectory(requested);
    if (!sameInode(named, opened) || !sameInode(opened, directoryIdentity)
      || !sameInode(requested, opened)) fail('backup_replica_directory_changed');
  }
  async function absentOrFile(path) {
    try { return await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async function unchanged(handle, path, before) {
    const after = await handle.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    if (!named.isFile() || !sameFile(before, after) || !sameFile(after, named)) fail('backup_replica_file_changed');
  }
  function archiveStat(stat, expected) {
    if (!stat.isFile() || stat.size !== BigInt(expected.bytes)) fail('backup_replica_archive_size_or_type');
  }
  // One bounded scan of an already-owned descriptor, optionally streaming to
  // an exclusively-created destination. Explicit offsets and partial-write
  // handling avoid ever assembling an archive-sized Buffer in memory.
  async function scan(handle, path, expected, phase, output = null) {
    gate(); budget(Number(expected.bytes));
    const before = await handle.stat({ bigint: true }); archiveStat(before, expected);
    const hash = createHash('sha256'), scratch = Buffer.alloc(CHUNK);
    let offset = 0;
    try {
      while (offset < Number(expected.bytes)) {
        gate();
        const length = Math.min(CHUNK, Number(expected.bytes) - offset);
        const { bytesRead } = await handle.read(scratch, 0, length, offset);
        if (!bytesRead) fail('backup_replica_file_changed');
        charge(bytesRead); hash.update(scratch.subarray(0, bytesRead)); gate();
        if (output) {
          let written = 0;
          while (written < bytesRead) {
            gate();
            const { bytesWritten } = await output.write(scratch, written, bytesRead - written, offset + written);
            if (!bytesWritten) fail('backup_replica_write_incomplete');
            written += bytesWritten;
          }
        }
        offset += bytesRead;
        await progress(phase, { bytes_read: offset, total_bytes: Number(expected.bytes) });
      }
      if ((await handle.read(scratch, 0, 1, offset)).bytesRead) fail('backup_replica_file_changed');
      await unchanged(handle, path, before); gate();
      if (hash.digest('hex') !== expected.sha256) fail('backup_replica_digest_mismatch');
      return before;
    } finally { scratch.fill(0); }
  }
  async function removeTemporary() {
    if (!temporaryIdentity) return;
    await checkDirectory();
    const named = await lstat(temporary, { bigint: true });
    if (!named.isFile() || !sameInode(named, temporaryIdentity)) fail('backup_replica_temporary_changed');
    await unlink(temporary); temporaryIdentity = null;
    await directory.sync();
  }
  async function checkExistingApproval(bytes) {
    let file;
    try {
      file = await absentOrFile(candidate.approval);
      if (!file) return false;
      const stat = await file.stat({ bigint: true });
      if (!stat.isFile() || stat.size !== BigInt(bytes.length)) fail('backup_replica_approval_conflict');
      const existing = await readBackupControl(candidate.approval, BACKUP_LIMITS.envelopeBytes, controlLive());
      if (!bytes.equals(existing)) fail('backup_replica_approval_conflict');
      privateReplica(stat);
      await unchanged(file, candidate.approval, stat); gate();
      await file.sync(); await directory.sync(); await checkDirectory();
      return true;
    } finally { await file?.close(); }
  }
  try {
    if (constants.O_NOFOLLOW === undefined || constants.O_NONBLOCK === undefined
      || constants.O_DIRECTORY === undefined || typeof process.getuid !== 'function') fail('backup_unsupported_filesystem');
    selected = await selectRepositoryBackup(options.candidates, options.trustKey, options.policy, {
      maximumBytes: Math.min(live.maximumBytes, options.maximumTotalBytes),
      maximumReplicaBytes: options.maximumTotalBytes, timeoutMs: live.remaining(),
      signal: live.signal, ...(options.now === undefined ? {} : { now: options.now }),
      async onProgress(event) {
        if (typeof event.bytes_read === 'number') {
          const delta = event.bytes_read - selectionOffset;
          if (delta <= 0) fail('backup_replication_invalid_progress');
          charge(delta); selectionOffset = event.bytes_read;
        } else if (event.phase === 'replica_unavailable') selectionOffset = 0;
        await progress('selection', event);
      },
    });
    await progress('selection_complete');
    // Reopen control paths only with the exact selected approval/key pins.
    // A different valid signature, key, or formatting cannot substitute intent.
    const envelope = await readBackupControl(selected.report.selected.approval, BACKUP_LIMITS.envelopeBytes, controlLive());
    if (digest(envelope) !== selected.report.checkpoint.approval_sha256) fail('backup_replica_approval_changed');
    const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, controlLive());
    verified = await verifyRepositoryBackupApproval(envelope, key, options.policy, {
      maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal,
      ...(options.now === undefined ? {} : { now: options.now }),
    });
    if (verified.authentication.trusted_key_id !== selected.report.checkpoint.trusted_key_id) fail('backup_replica_key_changed');
    const artifact = verified.authentication.statement.artifact;
    gate();
    // Do not follow a symlink at the configured directory. Ancestors resolve
    // once, then the opened and named directory identity is checked at effects.
    privateDirectory(await lstat(options.destination, { bigint: true }));
    canonical = await realpath(options.destination);
    directory = await open(canonical, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    directoryIdentity = await directory.stat({ bigint: true }); await checkDirectory(); gate();
    candidate = Object.freeze({ input: join(canonical, `archive-sha256-${artifact.sha256}.fgbackup`),
      approval: join(canonical, `checkpoint-sha256-${digest(envelope)}.approval.json`) });
    existingApproval = await checkExistingApproval(envelope);
    if (existingApproval) state = 'approval_visible';
    await progress('destination_checked');
    await checkDirectory(); gate();
    target = await absentOrFile(candidate.input);
    let stableTarget;
    if (target) {
      stableTarget = await scan(target, candidate.input, artifact, 'verify_existing_archive');
    } else {
      // Reserve copy AND readback work before staging anything. A refused work
      // budget cannot leave a partially-created archive as its ordinary result.
      budget(Number(artifact.bytes) * 2);
      source = await open(selected.report.selected.input, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      archiveStat(await source.stat({ bigint: true }), artifact); gate(); await checkDirectory();
      temporary = join(canonical, `.fg-backup-replica-${randomBytes(16).toString('hex')}.tmp`);
      staging = await open(temporary, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      if (!existingApproval) state = 'staging';
      temporaryIdentity = await staging.stat({ bigint: true });
      await scan(source, selected.report.selected.input, artifact, 'copy_archive', staging);
      await staging.sync(); gate();
      const stagedIdentity = await staging.stat({ bigint: true });
      await progress('archive_staged'); await checkDirectory();
      await unchanged(staging, temporary, stagedIdentity); gate();
      if (!existingApproval) state = 'archive_publication_unknown';
      try {
        await link(temporary, candidate.input); archiveDisposition = 'created';
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        // A concurrent winner must have the exact same committed bytes. Never
        // rename over a winner, including a corrupt file or a symbolic link.
        if (!existingApproval) state = 'archive_visible';
        target = await absentOrFile(candidate.input);
        if (!target) fail('backup_replica_archive_disappeared');
        stableTarget = await scan(target, candidate.input, artifact, 'verify_concurrent_archive');
      }
      if (!existingApproval) state = 'archive_visible';
      await directory.sync(); await removeTemporary();
      if (!target) {
        target = staging; staging = null;
        stableTarget = await scan(target, candidate.input, artifact, 'verify_published_archive');
      }
    }
    // Even an identical retry synchronizes the exact existing file and its
    // directory. It cannot call object existence a completed durability epoch.
    privateReplica(stableTarget);
    await target.sync(); await directory.sync(); await checkDirectory();
    await unchanged(target, candidate.input, stableTarget); gate();
    if (!existingApproval) state = 'archive_durable';
    await progress('archive_durable');
    // Recheck after the observer/any await and immediately before root-last
    // publication. A caller cancellation here leaves only an unadvertised body.
    await checkDirectory(); await unchanged(target, candidate.input, stableTarget); gate();
    if (existingApproval) {
      // An existing root is not a permanently valid receipt: validate it again
      // after copy/readback and every observer before acknowledging a retry.
      if (!await checkExistingApproval(envelope)) fail('backup_replica_approval_disappeared');
    } else {
      state = 'approval_publication_unknown';
      try {
        await publishBackupControl(candidate.approval, envelope, { ...controlLive(), check: gate });
        approvalDisposition = 'created';
      } catch (error) {
        if (error.publication_state === 'published' || error.publication_state === 'complete') state = 'approval_visible';
        if (error.code !== 'EEXIST' || error.cleanup_error) throw error;
        // The root already exists: resume only its EXACT original envelope.
        if (!await checkExistingApproval(envelope)) fail('backup_replica_approval_disappeared');
      }
    }
    // Publication is acknowledged only after the helper's sync/readback. Do
    // not turn a late cancellation into an inference that publication failed.
    state = 'complete';
    completed = Object.freeze({ type: 'repository_backup_replication', schema_version: 1, state,
      candidate, checkpoint: selected.report.checkpoint, authentication: verified.authentication,
      source: selected.report.selected, artifact,
      disposition: Object.freeze({ archive: archiveDisposition, approval: approvalDisposition }),
      archive_readback_verified: true, body_before_approval: true, files_and_directory_synced: true,
      native_content_verified: false, newest_checkpoint_verified: false, complete_capsule_verified: false,
      streaming: Object.freeze({ total_payload_bytes_read: String(totalBytes), read_calls: readCalls,
        maximum_read_bytes: CHUNK, total_payload_byte_budget: String(options.maximumTotalBytes) }) });
    return completed;
  } catch (caught) {
    failure = caught instanceof Error ? caught : backupError('backup_replication_observer_failed');
    failure.publication_state = state; failure.replica = candidate ?? null;
    failure.selection = selected?.report ?? null;
    throw failure;
  } finally {
    let cleanup;
    try { await removeTemporary(); } catch (error) { cleanup = error; }
    for (const handle of new Set([source, staging, target, directory])) {
      try { await handle?.close(); } catch (error) { cleanup ??= error; }
    }
    if (cleanup) {
      if (failure) {
        failure.cleanup_error = 'backup_replication_cleanup_failed'; failure.retained_temporary = temporaryIdentity ? temporary : null;
      } else {
        cleanup.publication_state = state; cleanup.replica = candidate ?? null;
        cleanup.completed_result = completed; throw cleanup;
      }
    }
  }
}
