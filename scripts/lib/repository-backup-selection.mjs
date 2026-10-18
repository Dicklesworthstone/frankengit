// Highest uniquely signed checkpoint from an EXPLICIT bounded candidate set.
// No bucket/directory listing, filename/mtime ranking, or root publication.
// Only byte-identical signed checkpoint statements may share replica failover.
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { BACKUP_LIMITS, backupError, backupPath, backupLifetime, exact, hashRepositoryBackup } from './repository-backup-io.mjs';
import { MAX_BACKUP_APPROVALS, selectRepositoryBackupApprovals } from './repository-backup-checkpoints.mjs';

export const MAX_BACKUP_CANDIDATES = MAX_BACKUP_APPROVALS;
const hash = value => createHash('sha256').update(value).digest('hex');
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const fail = code => { throw backupError(code); };

// Copy and bound every descriptor BEFORE the first await. Paths only locate
// bytes: neither their order nor their spelling conveys checkpoint authority.
export function repositoryBackupCandidates(value) {
  if (!Array.isArray(value) || !value.length || value.length > MAX_BACKUP_CANDIDATES) fail('backup_candidate_limit');
  let pathBytes = 0;
  const seen = new Set(), rows = value.map(row => {
    if (!exact(row, ['input', 'approval'])) fail('backup_invalid_candidate');
    const input = resolve(backupPath(row.input)), approval = resolve(backupPath(row.approval));
    backupPath(input); backupPath(approval);
    pathBytes += Buffer.byteLength(input) + Buffer.byteLength(approval);
    if (pathBytes > 256 * 1024) fail('backup_candidate_path_limit');
    const key = JSON.stringify([input, approval]);
    if (seen.has(key)) fail('backup_duplicate_candidate');
    seen.add(key); return Object.freeze({ input, approval });
  });
  rows.sort((a, b) => compare(a.input, b.input) || compare(a.approval, b.approval));
  return Object.freeze(rows);
}

// Only path-local absence, access/type refusal, or failed byte authentication
// permits trying an alias. Unknown I/O failures (including descriptor exhaustion
// and close failures), observer exceptions, deadlines, and cancellation are fatal.
// Approval/signature/policy failures occur outside this loop and are never hidden.
const REPLICA_UNAVAILABLE = new Set([
  'ENOENT', 'ENOTDIR', 'ELOOP', 'EACCES', 'EPERM',
  'backup_file_size_or_type', 'backup_file_changed', 'backup_artifact_mismatch',
]);

async function readCheckpointReplicas(highest, statement, live, payloadBudget, scrub = false) {
  const expectedBytes = Number(statement.artifact.bytes), attempts = [];
  let totalBytes = 0, totalReads = 0, maximumRead = 0, firstFailure, active = null;
  const explain = caught => {
    const error = caught instanceof Error ? caught : backupError('backup_scrub_observer_failed');
    error.replica_attempts = Object.freeze(attempts.slice());
    error.replica_bytes_read = String(totalBytes);
    error.selected_head_generation = statement.head_generation;
    if (scrub) { error.scrub_complete = false; error.active_replica = active; }
    return error;
  };
  try {
    for (const [index, candidate] of highest.entries()) {
      active = candidate.observation;
      live.check(); candidate.verified.checkCurrent();
      // Reserve a full signed payload before opening the next replica. The
      // aggregate ceiling never widens the per-file size or absolute deadline.
      if (expectedBytes > payloadBudget - totalBytes) {
        const error = backupError('backup_replica_read_budget');
        error.cause = firstFailure; throw error;
      }
      let bytesRead = 0, readCalls = 0, observerFailed = false;
      const attempt = (code, identity) => Object.freeze({ input: candidate.observation.input,
        approval: candidate.observation.approval, outcome: code === null ? 'authenticated' : 'unavailable',
        code, bytes_read: String(bytesRead), read_calls: readCalls,
        ...(scrub ? { file_identity: identity ?? null } : {}) });
      try {
        const artifact = await hashRepositoryBackup(candidate.observation.input, {
          ...live, maximumBytes: expectedBytes,
          async onProgress(event) {
            const read = event.bytes_read - bytesRead;
            totalBytes += read; maximumRead = Math.max(maximumRead, read);
            bytesRead = event.bytes_read; readCalls++; totalReads++;
            try { await live.onProgress(event); }
            catch (error) { observerFailed = true; throw error; }
          },
        });
        live.check();
        const authentication = candidate.verified.checkCurrent();
        if (artifact.sha256 !== statement.artifact.sha256 || artifact.bytes !== statement.artifact.bytes) fail('backup_artifact_mismatch');
        attempts.push(attempt(null, artifact.file_identity));
        if (!scrub) return { winner: candidate, authentication, artifact,
          attempts: Object.freeze(attempts), totalBytes, totalReads };
      } catch (error) {
        // Error origin matters: a trusted observer throwing ENOENT is not a
        // missing replica. Cancellation, time, policy and unknown I/O are fatal.
        if (observerFailed) throw error;
        live.check(); candidate.verified.checkCurrent();
        if (!REPLICA_UNAVAILABLE.has(error?.code)) throw error;
        attempts.push(attempt(error.code)); firstFailure ??= error;
        await live.onProgress(Object.freeze({ phase: 'replica_unavailable',
          head_generation: statement.head_generation, replica_index: index + 1,
          replicas: highest.length, code: error.code }));
        live.check(); candidate.verified.checkCurrent();
      }
      if (scrub) {
        await live.onProgress(Object.freeze({ phase: 'replica_scrubbed', replica_index: index + 1,
          replicas: highest.length, outcome: attempts.at(-1).outcome }));
        live.check(); candidate.verified.checkCurrent();
      }
    }
    active = null;
    if (scrub) return { attempts: Object.freeze(attempts), totalBytes, totalReads, maximumRead };
    // No lower-generation fallback, even when all highest replicas fail.
    throw firstFailure;
  } catch (error) { throw explain(error); }
}

/** Read-only without a witness; witnessed selection also retains signed observations. Every supplied approval must authenticate in the exact
 * external namespace. Compare full u64 generations BEFORE testing winner expiry,
 * floor, size or availability. Never substitute a lower generation after failure.
 * Missing/corrupt copies may fail over only within that exact signed statement,
 * in canonical path order and within one shared read/time budget. maximumBytes
 * always caps a single archive; optional maximumReplicaBytes caps aggregate
 * replica reads (default: maximumBytes, preserving the existing strict bound).
 * Returned paths are not pinned handles; downstream consumers must reauthenticate
 * and enforce `checkpoint`, and still perform native archive/authority checks.
 */
export function selectRepositoryBackup(candidates, trustKey, expected, options = {}, witness = null) {
  return evaluateRepositoryBackups(candidates, trustKey, expected, options, witness, false);
}

/** Authenticate EVERY supplied replica of the highest uniquely signed checkpoint.
 * Unavailable copies produce a complete degraded report, not early success after
 * the first healthy copy. Fatal errors carry only partial read evidence. Lower
 * checkpoints are never opened. This is byte scrubbing, NOT native verification.
 * Same-inode aliases count once; even distinct inodes do not prove independent
 * failure domains or simultaneous availability after this sequential scan.
 */
export function scrubRepositoryBackups(candidates, trustKey, expected, options = {}, witness = null) {
  return evaluateRepositoryBackups(candidates, trustKey, expected, options, witness, true);
}

async function evaluateRepositoryBackups(candidates, trustKey, expected, options, witness, scrub) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail('backup_invalid_options');
  const { maximumReplicaBytes, ...lifetimeOptions } = options;
  const live = backupLifetime(lifetimeOptions), rows = repositoryBackupCandidates(candidates);
  const payloadBudget = maximumReplicaBytes ?? live.maximumBytes;
  if (!Number.isSafeInteger(payloadBudget) || payloadBudget < 1
    || payloadBudget > BACKUP_LIMITS.maximumArchiveBytes * MAX_BACKUP_CANDIDATES) fail('backup_invalid_options');
  const checkpointSelection = await selectRepositoryBackupApprovals(rows.map(row => row.approval), trustKey, expected, {
    ...lifetimeOptions, maximumBytes: live.maximumBytes, timeoutMs: live.remaining(),
  }, witness);
  live.check();
  // Preserve canonical input-path replica ordering, exact envelope pins and each
  // verified approval lifetime while sharing the pre-payload checkpoint gate.
  const inspected = checkpointSelection.inspected.map((row, index) => Object.freeze({ ...row,
    observation: Object.freeze({ ...rows[index], ...row.observation }) }));
  const observations = inspected.map(row => row.observation);
  let winner = inspected[checkpointSelection.report.selected_index];
  const highest = checkpointSelection.report.highest_indices.map(index => inspected[index]);
  const { policy, statement } = checkpointSelection.checkCurrent();
  await live.onProgress(Object.freeze({ phase: 'checkpoint_selected', head_generation: statement.head_generation }));
  live.check(); winner.verified.checkCurrent();
  // First choose the signed checkpoint, then its available byte replica. Lower
  // artifacts are NEVER opened. Successful hashing is not native verification;
  // the consumer must reauthenticate the selected replica's own approval pin.
  const replica = await readCheckpointReplicas(highest, statement, live, payloadBudget, scrub);
  if (scrub) {
    live.check(); const authentication = winner.verified.checkCurrent();
    if (witness) witness.require(statement);
    const healthy = replica.attempts.filter(row => row.outcome === 'authenticated');
    const distinct = new Set(healthy.map(row => JSON.stringify(row.file_identity)));
    const report = Object.freeze({ type: 'repository_backup_scrub', schema_version: 1,
      head_generation: statement.head_generation, authentication,
      candidates: Object.freeze(observations), replica_attempts: replica.attempts,
      candidate_set_sha256: hash(JSON.stringify({ policy, trusted_key_id: authentication.trusted_key_id, candidates: observations })),
      scrub_complete: true, all_replicas_authenticated: healthy.length === highest.length,
      authenticated_candidates: healthy.length, distinct_authenticated_files: distinct.size,
      unavailable_candidates: highest.length - healthy.length,
      identical_statement_candidates: highest.length, lower_checkpoint_candidates_not_scrubbed: rows.length - highest.length,
      highest_supplied_generation_selected: true, read_only: witness === null,
      ...(witness ? { recovery_witness: witness.snapshot(), highest_retained_generation_enforced: true } : {}),
      native_content_verified: false, newest_checkpoint_verified: false, candidate_set_completeness_verified: false,
      failure_domain_independence_verified: false, simultaneous_availability_verified: false,
      streaming: Object.freeze({ total_payload_bytes_read: String(replica.totalBytes),
        total_payload_read_calls: replica.totalReads, maximum_read_bytes: replica.maximumRead,
        replica_payload_byte_budget: String(payloadBudget) }) });
    return Object.freeze({ report, checkCurrent() { live.check(); winner.verified.checkCurrent();
      if (witness) witness.require(statement); } });
  }
  winner = replica.winner;
  const { authentication, artifact } = replica, selected = winner.observation;
  const checkpoint = Object.freeze({ approval_sha256: selected.approval_sha256, trusted_key_id: authentication.trusted_key_id });
  const report = Object.freeze({ type: 'repository_backup_selection', schema_version: 1,
    selected, checkpoint, authentication, candidates: Object.freeze(observations),
    candidate_set_sha256: hash(JSON.stringify({ policy, trusted_key_id: authentication.trusted_key_id, candidates: observations })),
    highest_supplied_generation_selected: true, selected_artifact_authenticated: true,
    identical_statement_candidates: highest.length, read_only: witness === null,
    ...(witness ? { recovery_witness: witness.snapshot(), highest_retained_generation_enforced: true } : {}),
    replica_attempts: replica.attempts,
    native_content_verified: false, newest_checkpoint_verified: false, candidate_set_completeness_verified: false,
    streaming: Object.freeze({ read_calls: artifact.read_calls, maximum_read_bytes: artifact.maximum_read_bytes,
      total_payload_bytes_read: String(replica.totalBytes), total_payload_read_calls: replica.totalReads,
      replica_payload_byte_budget: String(payloadBudget) }) });
  return Object.freeze({ report, checkCurrent() { live.check(); winner.verified.checkCurrent(); if (witness) witness.require(statement); } });
}
