// Highest uniquely signed checkpoint from an EXPLICIT bounded candidate set.
// No bucket/directory listing, filename/mtime ranking, or root publication.
// Only byte-identical signed checkpoint statements may share replica failover.
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { BACKUP_LIMITS, backupError, backupPath, backupLifetime, exact,
  readBackupControl, hashRepositoryBackup } from './repository-backup-io.mjs';
import { backupPolicy, inspectRepositoryBackupApproval } from './repository-backup-approval.mjs';

export const MAX_BACKUP_CANDIDATES = 64;
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

async function readCheckpointReplicas(highest, statement, live) {
  const expectedBytes = Number(statement.artifact.bytes), attempts = [];
  let totalBytes = 0, totalReads = 0, firstFailure;
  const explain = error => {
    error.replica_attempts = Object.freeze(attempts.slice());
    error.replica_bytes_read = String(totalBytes);
    error.selected_head_generation = statement.head_generation;
    return error;
  };
  for (const [index, candidate] of highest.entries()) {
    live.check(); candidate.verified.checkCurrent();
    // maximumBytes bounds both a single archive and all streamed replica bytes.
    // Do not begin a copy that cannot finish inside the remaining shared budget.
    // Control-file reads and the scanner's bounded one-byte EOF probes are not
    // part of this payload counter. No retry resets the absolute time budget.
    if (expectedBytes > live.maximumBytes - totalBytes) {
      const error = backupError('backup_replica_read_budget');
      error.cause = firstFailure;
      throw explain(error);
    }
    let bytesRead = 0, readCalls = 0, observerFailed = false;
    const attempt = code => Object.freeze({ input: candidate.observation.input,
      approval: candidate.observation.approval, outcome: code === null ? 'authenticated' : 'unavailable',
      code, bytes_read: String(bytesRead), read_calls: readCalls });
    try {
      const artifact = await hashRepositoryBackup(candidate.observation.input, {
        ...live,
        // Refuse an oversized replacement before reading it, even when the
        // invocation has spare budget for other copies of the signed archive.
        maximumBytes: expectedBytes,
        async onProgress(event) {
          totalBytes += event.bytes_read - bytesRead;
          bytesRead = event.bytes_read; readCalls++; totalReads++;
          try { await live.onProgress(event); }
          catch (error) { observerFailed = true; throw error; }
        },
      });
      live.check();
      const authentication = candidate.verified.checkCurrent();
      if (artifact.sha256 !== statement.artifact.sha256 || artifact.bytes !== statement.artifact.bytes) fail('backup_artifact_mismatch');
      attempts.push(attempt(null));
      return { winner: candidate, authentication, artifact,
        attempts: Object.freeze(attempts), totalBytes, totalReads };
    } catch (error) {
      // An observer may throw an error whose code resembles a filesystem error.
      // Its origin, not just its spelling, decides whether failover is allowed.
      if (observerFailed) throw error;
      live.check(); candidate.verified.checkCurrent();
      if (!REPLICA_UNAVAILABLE.has(error?.code)) throw error;
      attempts.push(attempt(error.code)); firstFailure ??= error;
      await live.onProgress(Object.freeze({ phase: 'replica_unavailable',
        head_generation: statement.head_generation, replica_index: index + 1,
        replicas: highest.length, code: error.code }));
      live.check(); candidate.verified.checkCurrent();
    }
  }
  // Preserve the first actionable path/commitment failure and all attempts.
  // The caller never receives a lower-generation candidate as an alternative.
  throw explain(firstFailure);
}

/** Read-only selection. Every supplied approval must authenticate in the exact
 * external namespace. Compare full u64 generations BEFORE testing winner expiry,
 * floor, size or availability. Never substitute a lower generation after failure.
 * Missing/corrupt copies may fail over only within that exact signed statement,
 * in canonical path order and within one shared maximumBytes/time budget.
 * Returned paths are not pinned handles; downstream consumers must reauthenticate
 * and enforce `checkpoint`, and still perform native archive/authority checks.
 */
export async function selectRepositoryBackup(candidates, trustKey, expected, options = {}) {
  const live = backupLifetime(options), rows = repositoryBackupCandidates(candidates);
  const policy = backupPolicy(expected), keyPath = resolve(backupPath(trustKey));
  const fixed = options.now; // Capture a testing clock, never learn time from input.
  const key = await readBackupControl(keyPath, BACKUP_LIMITS.keyBytes, live);
  live.check();
  let winner = null, maximum = 0n;
  const inspected = [], observations = [];
  for (const row of rows) {
    live.check();
    const encoded = await readBackupControl(row.approval, BACKUP_LIMITS.envelopeBytes, live);
    const verified = await inspectRepositoryBackupApproval(encoded, key, policy, {
      // All signed generations remain visible even when their artifacts exceed
      // this invocation's narrower I/O budget. That budget gates the winner.
      maximumBytes: BACKUP_LIMITS.maximumArchiveBytes, timeoutMs: live.remaining(),
      signal: live.signal, ...(fixed === undefined ? {} : { now: fixed }),
    });
    live.check();
    const statement = verified.checkpoint.statement, generation = BigInt(statement.head_generation);
    const signedBytes = JSON.stringify(statement);
    const observation = Object.freeze({ ...row, head_generation: statement.head_generation,
      approval_sha256: hash(encoded), statement_sha256: hash(signedBytes) });
    observations.push(observation); inspected.push({ verified, signedBytes, observation });
    if (generation > maximum) { maximum = generation; winner = inspected.at(-1); }
    await live.onProgress(Object.freeze({ phase: 'approval_inspected', inspected: observations.length, total: rows.length }));
    live.check();
  }
  // Duplicated replicas of the SAME signed statement are deterministic aliases.
  // Different statements at the maximum generation require an explicit operator
  // choice, even if their artifact bytes or approval lifetimes happen to agree.
  const highest = inspected.filter(row => BigInt(row.observation.head_generation) === maximum);
  if (highest.some(row => row.signedBytes !== winner.signedBytes)) fail('backup_checkpoint_ambiguous');
  const statement = winner.verified.checkCurrent().statement; live.check();
  if (BigInt(statement.artifact.bytes) > BigInt(live.maximumBytes)) fail('backup_selected_archive_limit');
  await live.onProgress(Object.freeze({ phase: 'checkpoint_selected', head_generation: statement.head_generation }));
  live.check(); winner.verified.checkCurrent();
  // First choose the signed checkpoint, then its available byte replica. Lower
  // artifacts are NEVER opened. Successful hashing is not native verification;
  // the consumer must reauthenticate the selected replica's own approval pin.
  const replica = await readCheckpointReplicas(highest, statement, live);
  winner = replica.winner;
  const { authentication, artifact } = replica, selected = winner.observation;
  const checkpoint = Object.freeze({ approval_sha256: selected.approval_sha256, trusted_key_id: authentication.trusted_key_id });
  const report = Object.freeze({ type: 'repository_backup_selection', schema_version: 1,
    selected, checkpoint, authentication, candidates: Object.freeze(observations),
    candidate_set_sha256: hash(JSON.stringify({ policy, trusted_key_id: authentication.trusted_key_id, candidates: observations })),
    highest_supplied_generation_selected: true, selected_artifact_authenticated: true,
    identical_statement_candidates: highest.length, read_only: true,
    replica_attempts: replica.attempts,
    native_content_verified: false, newest_checkpoint_verified: false, candidate_set_completeness_verified: false,
    streaming: Object.freeze({ read_calls: artifact.read_calls, maximum_read_bytes: artifact.maximum_read_bytes,
      total_payload_bytes_read: String(replica.totalBytes), total_payload_read_calls: replica.totalReads,
      replica_payload_byte_budget: String(live.maximumBytes) }) });
  return Object.freeze({ report, checkCurrent() { live.check(); winner.verified.checkCurrent(); } });
}
