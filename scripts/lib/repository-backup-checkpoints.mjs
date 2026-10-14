// Select signed recovery intent BEFORE asking whether any payload is available.
// Shared by local replica selection/scrubbing and offsite-to-native recovery.
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupPath, backupLifetime, readBackupControl } from './repository-backup-io.mjs';
import { backupPolicy, inspectRepositoryBackupApproval } from './repository-backup-approval.mjs';

export const MAX_BACKUP_APPROVALS = 64;
const hash = value => createHash('sha256').update(value).digest('hex');
const fail = code => { throw backupError(code); };

/** Authenticate ALL explicit approval files and select the highest unique signed
 * statement. No archive, URL file, endpoint or native process is opened here.
 * Caller order is retained only to break ties between IDENTICAL signed statements;
 * names and ordering never outrank a higher generation. Duplicate paths are allowed
 * for local replicas sharing one approval, and each bounded read authenticates.
 * The returned inspection records are immutable and contain real verification
 * closures; consumers must keep the same witness owned and call checkCurrent().
 */
export async function selectRepositoryBackupApprovals(approvals, trustKey, expected, options = {}, witness = null) {
  const live = backupLifetime(options);
  if (!Array.isArray(approvals) || !approvals.length || approvals.length > MAX_BACKUP_APPROVALS) fail('backup_candidate_limit');
  let pathBytes = 0;
  const paths = Object.freeze(approvals.map(path => {
    const resolved = resolve(backupPath(path)); backupPath(resolved);
    pathBytes += Buffer.byteLength(resolved);
    if (pathBytes > 256 * 1024) fail('backup_candidate_path_limit');
    return resolved;
  }));
  const policy = backupPolicy(expected), keyPath = resolve(backupPath(trustKey)); backupPath(keyPath);
  const fixed = options.now;
  const key = await readBackupControl(keyPath, BACKUP_LIMITS.keyBytes, live);
  const inspected = [], observations = [];
  let maximum = 0n, selectedIndex = 0;
  for (const [index, approval] of paths.entries()) {
    live.check();
    const encoded = await readBackupControl(approval, BACKUP_LIMITS.envelopeBytes, live);
    const verified = await inspectRepositoryBackupApproval(encoded, key, policy, {
      // Rank every signed generation, even when its archive exceeds this run's
      // narrower payload ceiling. Freshness and size gate the winner, not intake.
      maximumBytes: BACKUP_LIMITS.maximumArchiveBytes, timeoutMs: live.remaining(), signal: live.signal,
      ...(fixed === undefined ? {} : { now: fixed }),
    });
    live.check();
    // Persist before progress/freshness/size/availability checks. A failed later
    // candidate must not erase newer knowledge already authenticated in this run.
    if (witness) await witness.observe(encoded);
    const statement = verified.checkpoint.statement, signedBytes = JSON.stringify(statement);
    const observation = Object.freeze({ approval, head_generation: statement.head_generation,
      approval_sha256: hash(encoded), statement_sha256: hash(signedBytes) });
    observations.push(observation);
    inspected.push(Object.freeze({ verified, signedBytes, observation }));
    const generation = BigInt(statement.head_generation);
    if (generation > maximum) { maximum = generation; selectedIndex = index; }
    await live.onProgress(Object.freeze({ phase: 'approval_inspected', inspected: observations.length, total: paths.length }));
    live.check();
  }
  const winner = inspected[selectedIndex];
  const highestIndices = Object.freeze(inspected.flatMap((row, index) =>
    BigInt(row.observation.head_generation) === maximum ? [index] : []));
  if (highestIndices.some(index => inspected[index].signedBytes !== winner.signedBytes)) fail('backup_checkpoint_ambiguous');
  const checkCurrent = () => {
    live.check();
    if (witness) witness.require(winner.verified.checkpoint.statement);
    return winner.verified.checkCurrent();
  };
  const authentication = checkCurrent();
  if (BigInt(authentication.statement.artifact.bytes) > BigInt(live.maximumBytes)) fail('backup_selected_archive_limit');
  const checkpoint = Object.freeze({ approval_sha256: winner.observation.approval_sha256,
    trusted_key_id: authentication.trusted_key_id });
  const report = Object.freeze({ type: 'repository_backup_checkpoint_selection', schema_version: 1,
    selected: winner.observation, selected_index: selectedIndex, highest_indices: highestIndices,
    candidates: Object.freeze(observations), checkpoint, authentication,
    candidate_set_sha256: hash(JSON.stringify({ policy, trusted_key_id: authentication.trusted_key_id, candidates: observations })),
    all_supplied_approvals_authenticated: true, highest_supplied_generation_selected: true,
    payloads_read: false, read_only: witness === null,
    ...(witness ? { recovery_witness: witness.snapshot(), highest_retained_generation_enforced: true } : {}),
    native_content_verified: false, newest_checkpoint_verified: false, candidate_set_completeness_verified: false });
  return Object.freeze({ report, inspected: Object.freeze(inspected), checkCurrent });
}
