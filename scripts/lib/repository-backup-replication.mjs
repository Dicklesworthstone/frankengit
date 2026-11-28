// Trusted-local signed archive replication, not a repository authority backend.
// Stream original bytes, synchronize/read back the body, publish approval last.
// Destination names are content-addressed and every publication is create-only.
import { constants } from 'node:fs';
import { open, lstat, realpath, link, unlink } from 'node:fs/promises';
import { join, resolve, isAbsolute, sep } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, readBackupControl,
  publishBackupControl, exact } from './repository-backup-io.mjs';
import { backupDecimal, backupPolicy, verifyRepositoryBackupApproval } from './repository-backup-approval.mjs';
import { repositoryBackupCandidates, selectRepositoryBackup } from './repository-backup-selection.mjs';
import { runApprovedRepositoryBackup } from './repository-backup-native.mjs';
import { backupLfsSha256, checkBackupLfsArtifact } from './repository-backup-lfs.mjs';

const CHUNK = 65536;
const fields = ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs'];
const sameInode = (a, b) => a.dev === b.dev && a.ino === b.ino;
const sameFile = (a, b) => fields.every(key => a[key] === b[key]);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw backupError(code); };

// A pin restricts the selected intent; it is never a substitute for signature,
// independent trust, freshness, artifact or destination verification.
export function repositoryBackupReplicationCheckpoint(value) {
  if (value === undefined) return undefined;
  if (!exact(value, ['approval_sha256', 'trusted_key_id'])
    || typeof value.approval_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.approval_sha256)
    || typeof value.trusted_key_id !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value.trusted_key_id)) fail('backup_replication_invalid_checkpoint');
  return Object.freeze({ approval_sha256: value.approval_sha256, trusted_key_id: value.trusted_key_id });
}

export function repositoryBackupReplicationOptions(value) {
  const keys = ['candidates', 'trustKey', 'policy', 'destination', 'maximumBytes',
    'maximumTotalBytes', 'timeoutMs', 'signal', 'onProgress', 'now', 'checkpoint',
    'lfsArchive', 'expectedLfsSha256', 'fg', 'verificationInstance', 'trustedLocal'];
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some(key => !keys.includes(key))) fail('backup_invalid_replication_options');
  const checkpoint = repositoryBackupReplicationCheckpoint(value.checkpoint);
  const candidates = repositoryBackupCandidates(value.candidates), policy = backupPolicy(value.policy);
  const trustKey = resolve(backupPath(value.trustKey)), destination = resolve(backupPath(value.destination));
  backupPath(trustKey); backupPath(destination);
  if ((value.lfsArchive !== undefined) !== (value.expectedLfsSha256 !== undefined)) fail('backup_lfs_pair_required');
  let companion;
  if (value.lfsArchive !== undefined) {
    if (value.trustedLocal !== true) fail('backup_explicit_local_operation_required');
    const fg = backupPath(value.fg);
    if (!isAbsolute(fg)) fail('backup_absolute_fg_required');
    companion = { lfsArchive: resolve(backupPath(value.lfsArchive)),
      expectedLfsSha256: backupLfsSha256(value.expectedLfsSha256), fg,
      verificationInstance: backupDecimal(value.verificationInstance, 9223372036854775807n), trustedLocal: true };
  } else if (['fg', 'verificationInstance', 'trustedLocal'].some(key => value[key] !== undefined)) {
    fail('backup_replication_inapplicable_native_option');
  }
  const live = backupLifetime({ maximumBytes: value.maximumBytes, timeoutMs: value.timeoutMs,
    signal: value.signal, onProgress: value.onProgress, now: value.now });
  // Separate the archive size ceiling from all selection/copy/readback payload
  // reads. Controls and one-byte EOF probes have their own fixed small bounds.
  const multiplier = companion ? 8 : 4;
  const maximumTotalBytes = value.maximumTotalBytes ?? live.maximumBytes * multiplier;
  if (!Number.isSafeInteger(maximumTotalBytes) || maximumTotalBytes < 1
    || maximumTotalBytes > BACKUP_LIMITS.maximumArchiveBytes * multiplier) fail('backup_replication_read_limit');
  return Object.freeze({ candidates, policy, trustKey, destination, checkpoint,
    maximumBytes: live.maximumBytes, maximumTotalBytes, timeoutMs: value.timeoutMs,
    signal: live.signal, onProgress: live.onProgress, now: value.now, ...companion });
}

/** Publish a byte-for-byte replica in an EXISTING private local directory.
 * No signing key, native mutation, bucket listing, root replacement, or deletion
 * of previously published files is involved. The result is a new candidate for
 * the existing selector/approved native restore path. Source-only publication
 * is NOT native verification.
 * The selected signed intent is pinned before the destination is touched.
 * An explicit LFS pair additionally requires signed native verify before
 * either body is published; its ordinary source approval remains unchanged.
 */
export async function replicateRepositoryBackup(raw) {
  const options = repositoryBackupReplicationOptions(raw);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs,
    signal: options.signal, now: options.now });
  const controlLive = () => ({ ...live, onProgress: () => {} });
  let totalBytes = 0, readCalls = 0, selectionOffset = 0;
  let selected, verified, directory, directoryIdentity, canonical, temporary, temporaryIdentity;
  let state = 'not_started', candidate, completed, failure;
  const handles = new Set(), bodies = [];
  let source, lfsSource, sourceIdentity, lfsIdentity, lfsPath, lfsReceipt, native;
  let lfsDisposition = 'reused', lfsState = options.lfsArchive ? 'not_started' : null;
  let archiveDisposition = 'reused', approvalDisposition = 'reused', existingApproval = false;
  const gate = () => { live.check(); selected?.checkCurrent(); verified?.checkCurrent(); };
  const budget = bytes => {
    if (bytes > options.maximumTotalBytes - totalBytes) fail('backup_replication_read_budget');
  };
  const charge = bytes => { budget(bytes); totalBytes += bytes; readCalls++; };
  const accounting = () => Object.freeze({ total_payload_bytes_read: String(totalBytes), read_calls: readCalls,
    maximum_read_bytes: CHUNK, total_payload_byte_budget: String(options.maximumTotalBytes),
    ...(options.lfsArchive ? { byte_budget_scope: 'selection_and_replica_publication',
      native_preflight_metered: false, native_preflight_maximum_archive_bytes: String(live.maximumBytes) } : {}) });
  const progress = async (phase, details = {}) => {
    await options.onProgress(Object.freeze({ phase, ...details, publication_state: state,
      total_payload_bytes_read: String(totalBytes) }));
    gate();
    await checkPairInputs();
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
  async function checkPairInputs() {
    if (!lfsSource) return;
    await unchanged(source, selected.report.selected.input, sourceIdentity);
    await unchanged(lfsSource, options.lfsArchive, lfsIdentity);
    gate();
  }
  async function checkPairSeparation() {
    if (!options.lfsArchive) return;
    // The companion cannot alias a source/control or any intended output,
    // including through a parent symlink or a hard link. Pair inputs stay
    // outside this writable directory; no output may be its own source.
    const inputs = [selected.report.selected.input, options.lfsArchive,
      selected.report.selected.approval, options.trustKey, options.fg];
    const identities = [];
    for (const path of inputs) {
      gate(); const physical = await realpath(path), stat = await lstat(physical, { bigint: true });
      if (physical === canonical || physical.startsWith(canonical + sep)) fail('backup_lfs_separate_path_required');
      identities.push(stat);
    }
    if (identities.some((stat, index) => index !== 1 && sameInode(stat, identities[1]))) fail('backup_lfs_separate_path_required');
    for (const path of [candidate.input, candidate.approval, lfsPath]) {
      let stat;
      try { stat = await lstat(path, { bigint: true }); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (stat && identities.some(input => sameInode(input, stat))) fail('backup_lfs_separate_path_required');
    }
    gate();
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
  async function publishBody(kind, path, artifact, input, pinned = null) {
    const mark = value => {
      if (kind === 'lfs') lfsState = value;
      if (!existingApproval) state = value;
    };
    let target = await absentOrFile(path), stableTarget, disposition = 'reused';
    if (target) {
      handles.add(target);
      stableTarget = await scan(target, path, artifact, `verify_existing_${kind}`);
    } else {
      budget(Number(artifact.bytes) * 2);
      const inputFile = pinned ?? await open(input, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      handles.add(inputFile);
      archiveStat(await inputFile.stat({ bigint: true }), artifact); gate(); await checkDirectory();
      temporary = join(canonical, `.fg-backup-replica-${randomBytes(16).toString('hex')}.tmp`);
      const staging = await open(temporary, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      handles.add(staging);
      mark(kind === 'archive' ? 'staging' : 'lfs_staging');
      temporaryIdentity = await staging.stat({ bigint: true });
      await scan(inputFile, input, artifact, `copy_${kind}`, staging);
      await staging.sync(); gate();
      const stagedIdentity = await staging.stat({ bigint: true });
      await progress(`${kind}_staged`); await checkDirectory();
      await unchanged(staging, temporary, stagedIdentity); gate();
      mark(`${kind}_publication_unknown`);
      try {
        await link(temporary, path); disposition = 'created';
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        mark(`${kind}_visible`);
        target = await absentOrFile(path);
        if (!target) fail('backup_replica_archive_disappeared');
        handles.add(target);
        stableTarget = await scan(target, path, artifact, `verify_concurrent_${kind}`);
      }
      mark(`${kind}_visible`);
      await directory.sync(); await removeTemporary();
      if (!target) {
        target = staging;
        stableTarget = await scan(target, path, artifact, `verify_published_${kind}`);
      }
    }
    privateReplica(stableTarget);
    await target.sync(); await directory.sync(); await checkDirectory();
    await unchanged(target, path, stableTarget); gate();
    mark(`${kind}_durable`);
    bodies.push({ handle: target, path, identity: stableTarget });
    await progress(`${kind}_durable`);
    return disposition;
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
    if (options.checkpoint && (options.checkpoint.approval_sha256 !== selected.report.checkpoint.approval_sha256
      || options.checkpoint.trusted_key_id !== selected.report.checkpoint.trusted_key_id)) fail('backup_replication_checkpoint_mismatch');
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
    if (options.lfsArchive) {
      lfsPath = join(canonical, `lfs-sha256-${options.expectedLfsSha256}.fglf`);
      await checkPairSeparation();
      source = await open(selected.report.selected.input, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      handles.add(source); sourceIdentity = await source.stat({ bigint: true }); archiveStat(sourceIdentity, artifact);
      lfsSource = await open(options.lfsArchive, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      handles.add(lfsSource); lfsIdentity = await lfsSource.stat({ bigint: true });
      if (!lfsIdentity.isFile() || lfsIdentity.size < 1n || lfsIdentity.size > BigInt(live.maximumBytes)) fail('backup_lfs_archive_size_or_type');
      await checkPairInputs();
      // Reserve both fresh-copy/readback passes before a verifier or stage.
      // The native adapter's archive/object/deadline bounds remain independent:
      // its internal reads are not observable in this JavaScript byte ledger.
      budget(2 * (Number(artifact.bytes) + Number(lfsIdentity.size)));
      state = 'native_verification';
      const preflight = await runApprovedRepositoryBackup({ operation: 'verify', fg: options.fg,
        input: selected.report.selected.input, approval: selected.report.selected.approval,
        trustKey: options.trustKey, policy: options.policy, verificationInstance: options.verificationInstance,
        trustedLocal: true, lfsArchive: options.lfsArchive, expectedLfsSha256: options.expectedLfsSha256,
        checkpoint: selected.report.checkpoint, maximumBytes: live.maximumBytes,
        timeoutMs: live.remaining(), signal: live.signal,
        async onProgress(event) { await progress('native_preflight', { event }); } });
      native = preflight.native; lfsReceipt = native.lfs_companion;
      checkBackupLfsArtifact({ sha256: options.expectedLfsSha256, bytes: String(lfsIdentity.size) }, lfsReceipt);
      await checkPairInputs(); await checkPairSeparation(); await checkDirectory(); gate();
      state = 'native_verified';
      await progress('native_verified');
    }
    existingApproval = await checkExistingApproval(envelope);
    if (existingApproval) state = 'approval_visible';
    await progress('destination_checked');
    await checkDirectory(); gate();
    archiveDisposition = await publishBody('archive', candidate.input, artifact, selected.report.selected.input, source);
    if (lfsReceipt) lfsDisposition = await publishBody('lfs', lfsPath, lfsReceipt, options.lfsArchive, lfsSource);
    // Recheck after the observer/any await and immediately before root-last
    // publication. A caller cancellation here leaves only an unadvertised body.
    await checkDirectory();
    for (const body of bodies) await unchanged(body.handle, body.path, body.identity);
    await checkPairInputs(); await checkPairSeparation(); gate();
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
      disposition: Object.freeze({ archive: archiveDisposition, approval: approvalDisposition,
        ...(lfsReceipt ? { lfs: lfsDisposition } : {}) }),
      archive_readback_verified: true, body_before_approval: true, files_and_directory_synced: true,
      native_content_verified: Boolean(native), newest_checkpoint_verified: false, complete_capsule_verified: false,
      ...(lfsReceipt ? { lfs_archive: lfsPath, lfs_companion: lfsReceipt, lfs_companion_signed: false,
        lfs_payloads_verified: true, lfs_readback_verified: true,
        lfs_before_approval: approvalDisposition === 'created', lfs_durable_before_acknowledgement: true, native } : {}),
      streaming: accounting() });
    return completed;
  } catch (caught) {
    failure = caught instanceof Error ? caught : backupError('backup_replication_observer_failed');
    failure.publication_state = state; failure.replica = candidate ?? null;
    if (options.lfsArchive) { failure.lfs_archive = lfsPath ?? null; failure.lfs_publication_state = lfsState; }
    failure.selection = selected?.report ?? null; failure.streaming = accounting();
    throw failure;
  } finally {
    let cleanup;
    try { await removeTemporary(); } catch (error) { cleanup = error; }
    for (const handle of new Set([...handles, directory])) {
      try { await handle?.close(); } catch (error) { cleanup ??= error; }
    }
    if (cleanup) {
      if (failure) {
        failure.cleanup_error = 'backup_replication_cleanup_failed'; failure.retained_temporary = temporaryIdentity ? temporary : null;
      } else {
        cleanup.publication_state = state; cleanup.replica = candidate ?? null;
        if (options.lfsArchive) { cleanup.lfs_archive = lfsPath ?? null; cleanup.lfs_publication_state = lfsState; }
        cleanup.completed_result = completed; cleanup.streaming = accounting(); throw cleanup;
      }
    }
  }
}
