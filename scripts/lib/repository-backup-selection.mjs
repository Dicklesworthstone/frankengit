// Highest uniquely signed checkpoint from an EXPLICIT bounded candidate set.
// No bucket/directory listing, filename/mtime ranking, root publication or retry.
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

/** Read-only selection. Every supplied approval must authenticate in the exact
 * external namespace. Compare full u64 generations BEFORE testing winner expiry,
 * floor, size or availability. Never substitute a lower generation after failure.
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
  const authentication = winner.verified.checkCurrent(); live.check();
  const statement = authentication.statement;
  if (BigInt(statement.artifact.bytes) > BigInt(live.maximumBytes)) fail('backup_selected_archive_limit');
  const selected = winner.observation;
  await live.onProgress(Object.freeze({ phase: 'checkpoint_selected', head_generation: selected.head_generation }));
  live.check(); winner.verified.checkCurrent();
  // Lower artifacts are NEVER opened, including corrupt/missing old archives.
  // A missing, replaced or corrupt winner is an error, not a search for a backup
  // that happens to work. The native consumer must verify these bytes again.
  const artifact = await hashRepositoryBackup(selected.input, live);
  live.check(); winner.verified.checkCurrent();
  if (artifact.sha256 !== statement.artifact.sha256 || artifact.bytes !== statement.artifact.bytes) fail('backup_artifact_mismatch');
  const checkpoint = Object.freeze({ approval_sha256: selected.approval_sha256, trusted_key_id: authentication.trusted_key_id });
  const report = Object.freeze({ type: 'repository_backup_selection', schema_version: 1,
    selected, checkpoint, authentication, candidates: Object.freeze(observations),
    candidate_set_sha256: hash(JSON.stringify({ policy, trusted_key_id: authentication.trusted_key_id, candidates: observations })),
    highest_supplied_generation_selected: true, selected_artifact_authenticated: true,
    identical_statement_candidates: highest.length, read_only: true,
    native_content_verified: false, newest_checkpoint_verified: false, candidate_set_completeness_verified: false,
    streaming: Object.freeze({ read_calls: artifact.read_calls, maximum_read_bytes: artifact.maximum_read_bytes }) });
  return Object.freeze({ report, checkCurrent() { live.check(); winner.verified.checkCurrent(); } });
}
