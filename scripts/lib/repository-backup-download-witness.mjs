// Compose independent recovery memory with the existing HTTPS byte acquisition.
// The witness is not repository authority, endpoint discovery or a freshness oracle.
import { resolve, dirname, basename, join, sep } from 'node:path';
import { realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, readBackupControl } from './repository-backup-io.mjs';
import { inspectRepositoryBackupApproval } from './repository-backup-approval.mjs';
import { downloadRepositoryBackup, repositoryBackupDownloadOptions } from './repository-backup-download.mjs';
import { withRepositoryBackupWitness } from './repository-backup-witness.mjs';

const overlap = (a, b) => a === b || a.startsWith(b + sep) || b.startsWith(a + sep);
const fail = code => { throw backupError(code); };

/** Optional owned witness. No witness preserves the original single-approval
 * acquisition behavior. With one, retain authenticated observations before time,
 * archive-size, network or output checks. Hold its lease through socket drain and
 * publication cleanup; do not perform a new cancellation gate after completion.
 * sourceFile is an optional local capability-file path used ONLY for separation.
 */
export async function downloadRepositoryBackupWithWitness(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('backup_invalid_download_options');
  const { witness: requested, sourceFile, ...rest } = raw;
  const options = repositoryBackupDownloadOptions(rest);
  const owned = { ...options, sources: options.sources.map(source => source.url) };
  if (requested === undefined) {
    if (sourceFile !== undefined) backupPath(sourceFile);
    return downloadRepositoryBackup(owned);
  }
  const directory = resolve(backupPath(requested)); backupPath(directory);
  const paths = [options.approval, options.trustKey, options.destination, options.caFile,
    sourceFile === undefined ? undefined : resolve(backupPath(sourceFile))].filter(path => path !== undefined);
  if (paths.some(path => overlap(directory, path))) fail('backup_witness_separate_path_required');
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs,
    signal: options.signal, now: options.now });
  async function separated(root) {
    // Resolve parent aliases before effects and after trusted observers. A final
    // absent destination is still compared through its existing parent. Stable,
    // owner-controlled ancestors remain required, as in the native operator.
    for (const path of paths) {
      live.check(); let physical;
      try { physical = await realpath(path); }
      catch (error) {
        if (error.code !== 'ENOENT') throw error;
        physical = join(await realpath(dirname(path)), basename(path));
      }
      if (overlap(root, physical)) fail('backup_witness_separate_path_required');
    }
    live.check();
  }
  await separated(await realpath(directory));
  try {
    return await withRepositoryBackupWitness(directory, options.trustKey, options.policy,
      { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal, now: options.now }, async witness => {
        await separated(witness.snapshot().directory);
        const envelope = await readBackupControl(options.approval, BACKUP_LIMITS.envelopeBytes, live);
        const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, live);
        const inspected = await inspectRepositoryBackupApproval(envelope, key, options.policy, {
          maximumBytes: BACKUP_LIMITS.maximumArchiveBytes, timeoutMs: live.remaining(), signal: live.signal,
          ...(options.now === undefined ? {} : { now: options.now }),
        });
        // Authentication is not approval to restore. In particular, expired or
        // oversized newer evidence must remain constraining after a failed fetch.
        await witness.observe(envelope);
        const statement = inspected.checkpoint.statement;
        witness.require(statement);
        const checkpoint = Object.freeze({ approval_sha256: createHash('sha256').update(envelope).digest('hex'),
          trusted_key_id: inspected.checkpoint.trusted_key_id });
        if (options.checkpoint && (options.checkpoint.approval_sha256 !== checkpoint.approval_sha256
          || options.checkpoint.trusted_key_id !== checkpoint.trusted_key_id)) fail('backup_download_checkpoint_mismatch');
        inspected.checkCurrent(); live.check();
        const result = await downloadRepositoryBackup({ ...owned, checkpoint, timeoutMs: live.remaining(),
          onProgress: async event => {
            witness.require(statement);
            await options.onProgress(event);
            await separated(witness.snapshot().directory);
            witness.require(statement);
          } });
        // The downloader has drained its sockets and owned files. Preserve a
        // confirmed publication through late witness-cleanup or output failures.
        return Object.freeze({ ...result, recovery_witness: witness.snapshot(), highest_retained_generation_enforced: true });
      });
  } catch (error) {
    error.download_state ??= error.completed_result?.state === 'complete' ? 'complete' : 'not_started';
    throw error;
  }
}
