// One owned offsite-acquisition -> signed-native-verify/restore lifetime.
// Reuse the existing engines; a cached byte replica is never restore authority.
import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { resolve, dirname, basename, join, sep, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupPath, backupLifetime, readBackupControl } from './repository-backup-io.mjs';
import { backupDecimal, backupPolicy, inspectRepositoryBackupApproval } from './repository-backup-approval.mjs';
import { MAX_DOWNLOAD_SOURCES, downloadRepositoryBackup, repositoryBackupDownloadOptions } from './repository-backup-download.mjs';
import { replicateRepositoryBackup, repositoryBackupReplicationCheckpoint } from './repository-backup-replication.mjs';
import { repositoryBackupOptions, runApprovedRepositoryBackup } from './repository-backup-native.mjs';
import { withRepositoryBackupWitness } from './repository-backup-witness.mjs';

const fail = code => { throw backupError(code); };
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const overlap = (a, b) => a === b || a.startsWith(b + sep) || b.startsWith(a + sep);
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
export const MAX_RECOVERY_ACQUISITION_BYTES = (MAX_DOWNLOAD_SOURCES + 3) * BACKUP_LIMITS.maximumArchiveBytes;

function separated(paths) {
  const writes = ['witness', 'cacheDirectory', 'destination', 'approvalRecord'].filter(k => paths[k] !== undefined);
  const reads = ['fg', 'approval', 'trustKey', 'sourceFile', 'caFile'].filter(k => paths[k] !== undefined);
  for (let i = 0; i < writes.length; i++) {
    if (writes.slice(i + 1).some(k => overlap(paths[writes[i]], paths[k]))
      || reads.some(k => overlap(paths[writes[i]], paths[k]))) fail('backup_recovery_separate_paths_required');
  }
}

/** All arguments are snapshotted before the first await. Restore is explicit;
 * resume additionally requires the original independent checkpoint equality pin.
 * There is no arbitrary callback/native implementation injection or clock override.
 */
export function repositoryBackupRecoveryOptions(raw) {
  const keys = ['operation', 'cacheDirectory', 'sourceFile', 'approval', 'trustKey', 'policy', 'witness',
    'fg', 'verificationInstance', 'destination', 'destinationInstance', 'approvalRecord', 'resume', 'trustedLocal',
    'checkpoint', 'maximumBytes', 'maximumAcquisitionBytes', 'timeoutMs', 'signal', 'onProgress', 'caFile'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !keys.includes(k))
    || !['verify', 'restore'].includes(raw.operation) || raw.trustedLocal !== true) fail('backup_explicit_recovery_required');
  const result = { ...raw, policy: backupPolicy(raw.policy), resume: raw.resume ?? false,
    checkpoint: repositoryBackupReplicationCheckpoint(raw.checkpoint) };
  if (typeof result.resume !== 'boolean') fail('backup_invalid_options');
  if (result.resume && !result.checkpoint) fail('backup_recovery_resume_checkpoint_required');
  if (!isAbsolute(backupPath(raw.fg))) fail('backup_absolute_fg_required');
  for (const k of ['fg', 'cacheDirectory', 'witness', 'approval', 'trustKey']) result[k] = resolve(backupPath(raw[k]));
  for (const k of ['sourceFile', 'caFile']) if (raw[k] !== undefined) result[k] = resolve(backupPath(raw[k]));
  result.verificationInstance = backupDecimal(raw.verificationInstance, 9223372036854775807n);
  if (raw.operation === 'restore') {
    for (const k of ['destination', 'approvalRecord']) result[k] = resolve(backupPath(raw[k]));
    result.destinationInstance = backupDecimal(raw.destinationInstance, 9223372036854775807n);
  } else if (result.resume || ['destination', 'destinationInstance', 'approvalRecord'].some(k => raw[k] !== undefined)) {
    fail('backup_inapplicable_restore_option');
  }
  for (const k of ['cacheDirectory', 'witness', 'destination', 'approvalRecord']) {
    if (result[k] !== undefined && dirname(result[k]) === result[k]) fail('backup_recovery_separate_paths_required');
  }
  separated(result);
  const live = backupLifetime({ maximumBytes: raw.maximumBytes, timeoutMs: raw.timeoutMs,
    signal: raw.signal, onProgress: raw.onProgress });
  result.maximumBytes = live.maximumBytes; result.onProgress = live.onProgress;
  result.maximumAcquisitionBytes = raw.maximumAcquisitionBytes ?? 4 * live.maximumBytes;
  if (!Number.isSafeInteger(result.maximumAcquisitionBytes) || result.maximumAcquisitionBytes < 1
    || result.maximumAcquisitionBytes > MAX_RECOVERY_ACQUISITION_BYTES) fail('backup_recovery_acquisition_limit');
  return Object.freeze(result);
}

async function physicalPaths(options, live) {
  const paths = {};
  for (const k of ['witness', 'cacheDirectory', 'destination', 'approvalRecord', 'fg', 'approval', 'trustKey', 'sourceFile', 'caFile']) {
    if (options[k] === undefined) continue;
    live.check();
    try { paths[k] = await realpath(options[k]); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      // Missing capability files are allowed for offline cache reuse. Their
      // existing parent must still be separate from witness/cache/native output.
      paths[k] = join(await realpath(dirname(options[k])), basename(options[k]));
    }
  }
  separated(paths); live.check(); return paths;
}
function privateDirectory(stat) {
  if (!stat.isDirectory() || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_recovery_private_cache_required');
}

/** The witness owns network drain, cached-byte publication, native preflight,
 * native restore/resume, and child/control cleanup as ONE operation. Cache reuse
 * reauthenticates and synchronizes through the existing publisher; no directory
 * listing, remote re-selection, automatic native retry or alternate engine.
 */
export async function recoverRepositoryBackup(raw) {
  const options = repositoryBackupRecoveryOptions(raw);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal: options.signal });
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined || constants.O_DIRECTORY === undefined) fail('backup_unsupported_filesystem');
  let phase = 'validating', checkpoint = null, candidate = null, acquisition = null, native = null, complete = null;
  const knowledge = () => Object.freeze({ phase, checkpoint, candidate, acquisition, native,
    operation: options.operation, resume_requested: options.resume });
  try {
    await physicalPaths(options, live);
    return await withRepositoryBackupWitness(options.witness, options.trustKey, options.policy,
      { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal }, async witness => {
        phase = 'authenticating';
        const envelope = await readBackupControl(options.approval, BACKUP_LIMITS.envelopeBytes, live);
        const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, live);
        const inspected = await inspectRepositoryBackupApproval(envelope, key, options.policy, {
          maximumBytes: BACKUP_LIMITS.maximumArchiveBytes, timeoutMs: live.remaining(), signal: live.signal,
        });
        // Signed higher/conflicting evidence survives later size, expiry, I/O and
        // native failures. Neither a cache hit nor a supplied resume pin bypasses it.
        await witness.observe(envelope);
        const statement = inspected.checkpoint.statement;
        checkpoint = Object.freeze({ approval_sha256: digest(envelope), trusted_key_id: inspected.checkpoint.trusted_key_id });
        witness.require(statement);
        if (options.checkpoint && (options.checkpoint.approval_sha256 !== checkpoint.approval_sha256
          || options.checkpoint.trusted_key_id !== checkpoint.trusted_key_id)) fail('backup_recovery_checkpoint_mismatch');
        const gate = () => { live.check(); inspected.checkCurrent(); witness.require(statement); };
        gate();
        if (BigInt(statement.artifact.bytes) > BigInt(live.maximumBytes)) fail('backup_selected_archive_limit');
        const paths = await physicalPaths(options, live);
        privateDirectory(await lstat(options.cacheDirectory, { bigint: true }));
        const directory = await open(paths.cacheDirectory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
        let identity, problem;
        async function checkPaths() {
          const current = await physicalPaths(options, live);
          if (current.witness !== witness.snapshot().directory || current.cacheDirectory !== paths.cacheDirectory) fail('backup_recovery_path_changed');
          // Native output must not be redirected between acquisition and submission.
          for (const k of ['destination', 'approvalRecord', 'fg']) if (current[k] !== paths[k]) fail('backup_recovery_path_changed');
          const named = await lstat(options.cacheDirectory, { bigint: true }), opened = await directory.stat({ bigint: true });
          privateDirectory(named); privateDirectory(opened);
          if (!same(named, identity) || !same(opened, identity)) fail('backup_recovery_cache_changed');
          gate();
        }
        const progress = async (stage, event) => {
          gate(); await options.onProgress(Object.freeze({ stage, ...event, checkpoint }));
          await checkPaths(); gate();
        };
        try {
          identity = await directory.stat({ bigint: true }); privateDirectory(identity);
          candidate = Object.freeze({ input: join(paths.cacheDirectory, `archive-sha256-${statement.artifact.sha256}.fgbackup`),
            approval: join(paths.cacheDirectory, `checkpoint-sha256-${checkpoint.approval_sha256}.approval.json`) });
          // Validate the ACTUAL content-addressed paths and complete native grammar
          // before opening a remote connection, not invented placeholder paths.
          const nativeOptions = repositoryBackupOptions({ operation: options.operation, fg: options.fg,
            input: candidate.input, approval: candidate.approval, trustKey: options.trustKey, policy: options.policy,
            verificationInstance: options.verificationInstance, trustedLocal: true,
            ...(options.operation === 'restore' ? { destination: paths.destination, approvalRecord: paths.approvalRecord,
              destinationInstance: options.destinationInstance, resume: options.resume } : {}),
            checkpoint, maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal });
          await progress('recovery', { phase: 'checkpoint_pinned' });
          phase = 'acquiring';
          let cached;
          try { await lstat(candidate.input); cached = true; }
          catch (error) { if (error.code !== 'ENOENT') throw error; cached = false; }
          let receipt;
          if (cached) {
            // Existing wrong bytes/symlinks/refused permissions are fatal, not
            // permission to overwrite the cache or try a different checkpoint.
            receipt = await replicateRepositoryBackup({ candidates: [{ input: candidate.input, approval: options.approval }],
              trustKey: options.trustKey, policy: options.policy, destination: paths.cacheDirectory, checkpoint,
              maximumBytes: live.maximumBytes, maximumTotalBytes: Math.min(options.maximumAcquisitionBytes, 4 * BACKUP_LIMITS.maximumArchiveBytes),
              timeoutMs: live.remaining(), signal: live.signal, onProgress: event => progress('cache', event) });
          } else {
            if (!options.sourceFile) fail('backup_recovery_sources_required');
            let sources;
            const bytes = await readBackupControl(options.sourceFile, BACKUP_LIMITS.envelopeBytes, live, true);
            try { sources = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
            catch { fail('backup_recovery_invalid_sources'); }
            const download = { sources, approval: options.approval, trustKey: options.trustKey, policy: options.policy,
              destination: paths.cacheDirectory, checkpoint, maximumBytes: live.maximumBytes,
              maximumTotalBytes: options.maximumAcquisitionBytes, timeoutMs: live.remaining(), signal: live.signal,
              ...(options.caFile === undefined ? {} : { caFile: options.caFile }), onProgress: event => progress('download', event) };
            repositoryBackupDownloadOptions(download); // No raw URL escapes on refusal.
            receipt = await downloadRepositoryBackup(download);
          }
          // Record confirmed acquisition before observers; cancellation cannot
          // turn these independently reusable bytes into a claim of rollback.
          acquisition = Object.freeze({ mode: cached ? 'cached' : 'downloaded', receipt });
          if (receipt.candidate.input !== candidate.input || receipt.candidate.approval !== candidate.approval
            || receipt.checkpoint.approval_sha256 !== checkpoint.approval_sha256
            || receipt.checkpoint.trusted_key_id !== checkpoint.trusted_key_id) fail('backup_recovery_handoff_mismatch');
          phase = 'acquired'; await progress('recovery', { phase: 'acquisition_complete', candidate });
          phase = 'native';
          native = await runApprovedRepositoryBackup({ ...nativeOptions, timeoutMs: live.remaining(),
            onProgress: event => progress('native', event) });
          // The native adapter and its process owner have drained. Do not add an
          // expiry/cancellation check after a confirmed native publication.
          phase = 'complete';
          complete = Object.freeze({ type: `remote_repository_backup_${options.operation}`, schema_version: 1, state: 'complete',
            checkpoint, candidate, acquisition, native, recovery_witness: witness.snapshot(),
            highest_retained_generation_enforced: true, complete_capsule_restored: false, external_effects_replayed: false });
          return complete;
        } catch (error) { problem = error; throw error; }
        finally {
          try { await directory.close(); }
          catch (error) {
            if (problem) problem.recovery_cleanup_error = error.code ?? 'backup_recovery_cache_close_failed';
            else { error.completed_result = complete; error.state = native?.state ?? 'not_started'; throw error; }
          }
        }
      });
  } catch (caught) {
    const error = caught instanceof Error ? caught : backupError('backup_recovery_observer_failed');
    error.state ??= native?.state ?? (options.resume ? 'existing_unknown' : 'not_started');
    error.recovery = knowledge();
    throw error;
  }
}
