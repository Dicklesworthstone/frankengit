// Replenish explicit backup locations, not canonical repository placements.
// One signed intent, one bounded lifetime, independently resumable publications.
import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { BACKUP_LIMITS, backupError, backupPath, backupLifetime } from './repository-backup-io.mjs';
import { backupPolicy } from './repository-backup-approval.mjs';
import { MAX_BACKUP_CANDIDATES, repositoryBackupCandidates, selectRepositoryBackup,
  scrubRepositoryBackups } from './repository-backup-selection.mjs';
import { replicateRepositoryBackup, repositoryBackupReplicationCheckpoint } from './repository-backup-replication.mjs';

export const MAX_REPLENISHMENT_DESTINATIONS = 16;
export const MAX_REPLENISHMENT_READ_BYTES = BACKUP_LIMITS.maximumArchiveBytes
  * (MAX_BACKUP_CANDIDATES + 4 * MAX_REPLENISHMENT_DESTINATIONS);
const fail = code => { throw backupError(code); };
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const overlaps = (a, b) => a === b || a.startsWith(b + sep) || b.startsWith(a + sep);

export function repositoryBackupReplenishmentOptions(value) {
  const keys = ['candidates', 'destinations', 'trustKey', 'policy', 'checkpoint',
    'maximumBytes', 'maximumTotalBytes', 'timeoutMs', 'signal', 'onProgress', 'now'];
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some(key => !keys.includes(key))) fail('backup_invalid_replenishment_options');
  const candidates = repositoryBackupCandidates(value.candidates), policy = backupPolicy(value.policy);
  const checkpoint = repositoryBackupReplicationCheckpoint(value.checkpoint);
  const trustKey = resolve(backupPath(value.trustKey)); backupPath(trustKey);
  if (!Array.isArray(value.destinations) || !value.destinations.length
    || value.destinations.length > MAX_REPLENISHMENT_DESTINATIONS) fail('backup_replenishment_destination_limit');
  const destinations = value.destinations.map(path => { const p = resolve(backupPath(path)); backupPath(p); return p; }).sort();
  if (destinations.some((path, i) => destinations.slice(0, i).some(other => overlaps(path, other)))) fail('backup_replenishment_destination_overlap');
  const live = backupLifetime({ maximumBytes: value.maximumBytes, timeoutMs: value.timeoutMs,
    signal: value.signal, onProgress: value.onProgress, now: value.now });
  const maximumTotalBytes = value.maximumTotalBytes ?? live.maximumBytes * (1 + 4 * destinations.length);
  if (!Number.isSafeInteger(maximumTotalBytes) || maximumTotalBytes < 1
    || maximumTotalBytes > MAX_REPLENISHMENT_READ_BYTES) fail('backup_replenishment_read_limit');
  return Object.freeze({ candidates, destinations: Object.freeze(destinations), policy, checkpoint,
    trustKey, maximumBytes: live.maximumBytes, maximumTotalBytes, timeoutMs: value.timeoutMs,
    signal: live.signal, onProgress: live.onProgress, now: value.now });
}

/** Copy one highest uniquely signed checkpoint to every explicit destination,
 * then scrub the complete output set. Bad originals and existing conflicting
 * outputs are never overwritten or deleted. Retry exact paths with the returned
 * checkpoint pin; completed replicas remain useful after partial failure.
 * An optional witness is an ALREADY OWNED lease, held by the caller until return.
 * This is trusted-local file redundancy, not independent failure-domain evidence,
 * a native archive parser, canonical repair, routing publication or an atomic job.
 */
export async function replenishRepositoryBackups(raw, witness = null) {
  const options = repositoryBackupReplenishmentOptions(raw);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs,
    signal: options.signal, now: options.now });
  const targets = [], replicas = [];
  let selected, checkpoint = options.checkpoint ?? null, totalBytes = 0, active = null;
  let state = 'not_started', finalScrub = null, completed = null, problem;
  const remaining = () => options.maximumTotalBytes - totalBytes;
  const gate = () => { live.check(); selected?.checkCurrent(); };
  const snapshot = () => Object.freeze({ type: 'repository_backup_replenishment', schema_version: 1,
    state, checkpoint, destinations: options.destinations, active_destination: active,
    completed_replicas: Object.freeze(replicas.slice()), final_scrub: finalScrub,
    source_selection: selected?.report ?? null,
    all_destinations_verified: state === 'complete', atomic_publication: false,
    native_content_verified: false, newest_checkpoint_verified: false, complete_capsule_verified: false,
    failure_domain_independence_verified: false, simultaneous_availability_verified: false,
    streaming: Object.freeze({ total_payload_bytes_read: String(totalBytes),
      total_payload_byte_budget: String(options.maximumTotalBytes) }) });
  function privateDirectory(stat) {
    if (typeof process.getuid !== 'function' || !stat.isDirectory()
      || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_replenishment_private_directory_required');
  }
  async function checkTargets() {
    for (const target of targets) {
      gate();
      const named = await lstat(target.path, { bigint: true }), opened = await target.handle.stat({ bigint: true });
      privateDirectory(named); privateDirectory(opened);
      if (!same(named, target.identity) || !same(opened, target.identity)
        || await realpath(target.requested) !== target.path) fail('backup_replenishment_directory_changed');
    }
  }
  async function progress(stage, event) {
    await options.onProgress(Object.freeze({ ...event, stage, active_destination: active,
      completed_destinations: replicas.length, replenishment_bytes_read: String(totalBytes) }));
    gate(); await checkTargets();
  }
  // Select/scrub expose per-copy progress; reset only at their explicit boundary.
  // Every child also has a hard remaining-byte limit independent of observers.
  async function evaluate(method, candidates, stage) {
    gate();
    if (remaining() < 1) fail('backup_replenishment_read_budget');
    const base = totalBytes; let offset = 0;
    try {
      return await method(candidates, options.trustKey, options.policy, {
        maximumBytes: live.maximumBytes,
        maximumReplicaBytes: Math.min(remaining(), BACKUP_LIMITS.maximumArchiveBytes * MAX_BACKUP_CANDIDATES),
        timeoutMs: live.remaining(), signal: live.signal, now: options.now,
        async onProgress(event) {
          if (typeof event.bytes_read === 'number') {
            totalBytes += event.bytes_read - offset; offset = event.bytes_read;
          } else if (event.phase === 'replica_unavailable' || event.phase === 'replica_scrubbed') offset = 0;
          await progress(stage, event);
        },
      }, witness);
    } catch (error) {
      // The scanner may fail between a completed read and a progress callback.
      if (error.replica_bytes_read !== undefined) totalBytes = base + Number(error.replica_bytes_read);
      throw error;
    }
  }
  try {
    if (constants.O_DIRECTORY === undefined || constants.O_NOFOLLOW === undefined) fail('backup_unsupported_filesystem');
    // Validate every destination before the first publication. Retain descriptor
    // identities so parent aliases or renamed directories cannot invent copies.
    for (const requested of options.destinations) {
      gate(); privateDirectory(await lstat(requested, { bigint: true }));
      const path = await realpath(requested), handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      const target = { requested, path, handle }; targets.push(target);
      target.identity = await handle.stat({ bigint: true }); privateDirectory(target.identity);
      if (targets.slice(0, -1).some(other => same(other.identity, target.identity) || overlaps(other.path, path))) fail('backup_replenishment_destination_overlap');
      if (witness && overlaps(path, witness.snapshot().directory)) fail('backup_witness_separate_path_required');
    }
    await checkTargets();
    selected = await evaluate(selectRepositoryBackup, options.candidates, 'selection');
    if (checkpoint && (checkpoint.approval_sha256 !== selected.report.checkpoint.approval_sha256
      || checkpoint.trusted_key_id !== selected.report.checkpoint.trusted_key_id)) fail('backup_replication_checkpoint_mismatch');
    checkpoint = selected.report.checkpoint;
    const bytes = Number(selected.report.authentication.statement.artifact.bytes);
    // Reserve fresh-copy worst case for ALL destinations plus the final scrub.
    // Known insufficient work refuses before any target is staged, even on retry.
    if (bytes * 4 * targets.length > remaining()) fail('backup_replenishment_read_budget');
    state = 'publishing';
    await progress('replenishment', { phase: 'checkpoint_pinned', checkpoint });
    const source = { input: selected.report.selected.input, approval: selected.report.selected.approval };
    for (const target of targets) {
      gate(); await checkTargets(); active = target.path;
      const base = totalBytes;
      try {
        const receipt = await replicateRepositoryBackup({ candidates: [source], trustKey: options.trustKey,
          policy: options.policy, checkpoint, destination: target.path, maximumBytes: live.maximumBytes,
          maximumTotalBytes: Math.min(remaining(), BACKUP_LIMITS.maximumArchiveBytes * 4),
          timeoutMs: live.remaining(), signal: live.signal, now: options.now,
          async onProgress(event) {
            totalBytes = base + Number(event.total_payload_bytes_read);
            await progress('publication', event);
          } });
        totalBytes = base + Number(receipt.streaming.total_payload_bytes_read);
        // Record confirmed completion BEFORE invoking an observer or next gate.
        replicas.push(Object.freeze({ destination: target.path, receipt }));
      } catch (error) {
        if (error.streaming) totalBytes = base + Number(error.streaming.total_payload_bytes_read);
        if (error.completed_result) replicas.push(Object.freeze({ destination: target.path, receipt: error.completed_result }));
        throw error;
      }
      await progress('replenishment', { phase: 'replica_complete', candidate: replicas.at(-1).receipt.candidate });
    }
    active = null; state = 'verifying';
    const scrubbed = await evaluate(scrubRepositoryBackups, replicas.map(row => row.receipt.candidate), 'verification');
    finalScrub = scrubbed.report;
    scrubbed.checkCurrent(); gate(); await checkTargets();
    if (!finalScrub.all_replicas_authenticated || finalScrub.distinct_authenticated_files !== targets.length
      || finalScrub.authentication.trusted_key_id !== checkpoint.trusted_key_id
      || finalScrub.candidates.some(row => row.approval_sha256 !== checkpoint.approval_sha256)) fail('backup_replenishment_verification_failed');
    state = 'complete'; completed = snapshot();
    // No new cancellation/freshness interpretation after confirmed completion.
    return completed;
  } catch (caught) {
    problem = caught instanceof Error ? caught : backupError('backup_replenishment_observer_failed');
    problem.replenishment = snapshot();
    throw problem;
  } finally {
    let cleanup;
    for (const target of targets) {
      try { await target.handle.close(); } catch (error) { cleanup ??= error; }
    }
    if (cleanup) {
      if (problem) problem.replenishment_cleanup_error = cleanup.code ?? 'backup_replenishment_close_failed';
      else { cleanup.replenishment = snapshot(); cleanup.completed_result = completed; throw cleanup; }
    }
  }
}
