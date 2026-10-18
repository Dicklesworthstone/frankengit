// Immutable, trusted-local replenishment intent. Not repository authority.
// No mutable success index: every restart reauthenticates actual surviving bytes.
import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { resolve, join, dirname, basename, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupPath, backupLifetime, exact,
  readBackupControl, publishBackupControl } from './repository-backup-io.mjs';
import { backupPolicy, inspectRepositoryBackupApproval, verifyRepositoryBackupApproval } from './repository-backup-approval.mjs';
import { MAX_BACKUP_CANDIDATES, selectRepositoryBackup } from './repository-backup-selection.mjs';
import { repositoryBackupReplicationCheckpoint } from './repository-backup-replication.mjs';
import { MAX_REPLENISHMENT_DESTINATIONS, MAX_REPLENISHMENT_READ_BYTES,
  repositoryBackupReplenishmentOptions, replenishRepositoryBackups } from './repository-backup-replenishment.mjs';

export const BACKUP_JOB_TYPE = 'repository_backup_replenishment_intent_v1';
export const MAX_BACKUP_JOB_BYTES = BACKUP_LIMITS.envelopeBytes;
const IDENTITY = ['tenant_id', 'repository_id', 'incarnation_id', 'object_format'];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const fail = code => { throw backupError(code); };
const overlaps = (a, b) => a === b || a.startsWith(b + sep) || b.startsWith(a + sep);
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const fileFields = ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs'];
const sameFile = (a, b) => fileFields.every(k => a[k] === b[k]);
const identity = stat => Object.freeze({ device: String(stat.dev), inode: String(stat.ino) });
const approvalName = checkpoint => `checkpoint-sha256-${checkpoint.approval_sha256}.approval.json`;
const archiveName = statement => `archive-sha256-${statement.artifact.sha256}.fgbackup`;
function absolute(path) {
  const normalized = resolve(backupPath(path)); backupPath(normalized); return normalized;
}
function privateOwner(stat) {
  if (typeof process.getuid !== 'function' || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_job_private_owner_required');
}
async function ownDirectory(requested, live) {
  live.check();
  const initial = await lstat(requested, { bigint: true }); privateOwner(initial);
  if (!initial.isDirectory() || dirname(requested) === requested) fail('backup_job_directory_required');
  const path = await realpath(requested);
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat({ bigint: true });
    const check = async () => {
      live.check();
      const named = await lstat(path, { bigint: true }), current = await handle.stat({ bigint: true });
      privateOwner(named); privateOwner(current);
      if (!named.isDirectory() || !same(initial, stat) || !same(named, stat) || !same(current, stat)
        || await realpath(requested) !== path) fail('backup_job_directory_changed');
    };
    await check(); return { path, handle, saved: Object.freeze({ path, ...identity(stat) }), check };
  } catch (error) { await handle.close(); throw error; }
}
async function closeOwned(owned, problem, completed) {
  let failure;
  for (const owner of owned) {
    try { await owner.handle.close(); } catch (error) { failure ??= error; }
  }
  if (failure) {
    if (problem) problem.job_cleanup_error = failure.code ?? 'backup_job_close_failed';
    else { failure.completed_result = completed; throw failure; }
  }
}
// The existing publisher supplies create-only staging/readback/sync. An exact
// retry must also synchronize the reused original file and directory, not just
// infer a completed durability epoch from a filename or matching digest.
async function publishExact(owner, path, bytes, live) {
  await owner.check();
  try { await publishBackupControl(path, bytes, live); }
  catch (error) { if (error.code !== 'EEXIST' || error.cleanup_error) throw error; }
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    const readback = await readBackupControl(path, MAX_BACKUP_JOB_BYTES, live, true);
    if (!bytes.equals(readback)) fail('backup_job_control_conflict');
    const after = await file.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    if (!sameFile(before, after) || !sameFile(after, named)) fail('backup_job_control_changed');
    await file.sync(); await owner.handle.sync(); await owner.check();
  } finally { await file.close(); }
}
function requireSeparate(path, others) {
  if (others.some(other => overlaps(path, other))) fail('backup_job_separate_path_required');
}
async function requireKeyApart(trustKey, directories, live) {
  live.check(); const key = await realpath(trustKey);
  for (const path of directories) requireSeparate(path, [key]);
  live.check();
}
async function requireExistingSourcesApart(sources, directories, trustKey, witnessDirectory, live) {
  live.check();
  const protectedPaths = [...directories, await realpath(trustKey), ...(witnessDirectory ? [witnessDirectory] : [])];
  for (const source of sources) {
    live.check(); let physical;
    try { physical = await realpath(source); }
    catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR') continue;
      throw error;
    }
    for (const path of protectedPaths) requireSeparate(physical, [path]);
  }
  live.check();
}
async function requireExistingCandidatesApart(candidates, directories, trustKey, witnessDirectory, live) {
  live.check();
  const protectedPaths = [...directories, await realpath(trustKey), ...(witnessDirectory ? [witnessDirectory] : [])];
  for (const row of candidates) {
    for (const candidate of [row.input, row.approval]) {
      live.check(); let physical;
      try { physical = await realpath(candidate); }
      catch (error) {
        if (error.code === 'ENOENT' || error.code === 'ENOTDIR') continue;
        throw error;
      }
      for (const path of protectedPaths) requireSeparate(physical, [path]);
    }
  }
  live.check();
}
function controlPaths(owner, checkpoint) { return join(owner.path, approvalName(checkpoint)); }
function checkedWitness(manifest, witness) {
  const directory = witness?.snapshot().directory ?? null;
  if (manifest.witness_directory !== null && manifest.witness_directory !== directory) fail('backup_job_witness_required');
  return directory;
}
function report(intent, manifest) {
  return Object.freeze({ type: 'repository_backup_job', intent, job_id: hash(encode(manifest)),
    checkpoint: manifest.checkpoint, policy: manifest.policy, destinations: manifest.destinations,
    witness_directory: manifest.witness_directory, immutable_intent: true,
    native_content_verified: false, newest_checkpoint_verified: false, complete_capsule_verified: false });
}

/** Seal ONE already authenticated checkpoint and fixed destinations before any
 * copying. Approval bytes publish before the immutable, content-addressed intent.
 * The caller owns any witness lease. Missing state is never recreated by run().
 */
export async function sealRepositoryBackupJob(raw, witness = null) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('backup_invalid_job_options');
  const { jobDirectory, ...rest } = raw;
  if (Object.hasOwn(rest, 'sourceHandoff')) fail('backup_invalid_job_options');
  const options = repositoryBackupReplenishmentOptions(rest), directory = absolute(jobDirectory);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs,
    signal: options.signal, now: options.now });
  const owned = []; let completed, problem, job = null, state = 'not_started', selected;
  try {
    const owner = await ownDirectory(directory, live); owned.push(owner);
    const witnessDirectory = witness?.snapshot().directory ?? null;
    requireSeparate(owner.path, [...options.destinations, options.trustKey,
      ...options.candidates.flatMap(row => [row.input, row.approval]), ...(witnessDirectory ? [witnessDirectory] : [])]);
    for (const path of options.destinations) {
      const target = await ownDirectory(path, live); owned.push(target);
      requireSeparate(target.path, owned.slice(0, -1).map(o => o.path));
      if (witnessDirectory) requireSeparate(target.path, [witnessDirectory]);
    }
    await requireKeyApart(options.trustKey, [...owned.map(o => o.path), ...(witnessDirectory ? [witnessDirectory] : [])], live);
    // Candidate controls are independent trust inputs, not material owned by
    // writable recovery custody. Resolve every existing input/approval before
    // authentication or payload reads so parent aliases cannot hide overlap.
    await requireExistingCandidatesApart(options.candidates, owned.map(o => o.path), options.trustKey, witnessDirectory, live);
    const gate = async () => { live.check(); selected?.checkCurrent(); for (const o of owned) await o.check(); };
    selected = await selectRepositoryBackup(options.candidates, options.trustKey, options.policy, {
      maximumBytes: live.maximumBytes,
      maximumReplicaBytes: Math.min(options.maximumTotalBytes, BACKUP_LIMITS.maximumArchiveBytes * MAX_BACKUP_CANDIDATES),
      timeoutMs: live.remaining(), signal: live.signal, now: options.now,
      async onProgress(event) { await options.onProgress(event); await gate(); },
    }, witness);
    const checkpoint = selected.report.checkpoint;
    if (options.checkpoint && JSON.stringify(options.checkpoint) !== JSON.stringify(checkpoint)) fail('backup_replication_checkpoint_mismatch');
    const selectedPaths = [selected.report.selected.input, selected.report.selected.approval];
    const protectedSelected = [...owned.map(o => o.path), await realpath(options.trustKey),
      ...(witnessDirectory ? [witnessDirectory] : [])];
    // Re-resolve the chosen pair after selection observers. A candidate parent
    // can be redirected while authentication is running; the approval is opened
    // again below and must still be physically independent at that handoff.
    for (const path of selectedPaths) {
      const physical = await realpath(path);
      for (const protectedPath of protectedSelected) requireSeparate(physical, [protectedPath]);
    }
    const envelope = await readBackupControl(selected.report.selected.approval, BACKUP_LIMITS.envelopeBytes, live);
    if (hash(envelope) !== checkpoint.approval_sha256) fail('backup_replica_approval_changed');
    const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, live);
    const verified = await verifyRepositoryBackupApproval(envelope, key, options.policy, {
      maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal, now: options.now,
    });
    if (verified.authentication.trusted_key_id !== checkpoint.trusted_key_id) fail('backup_replica_key_changed');
    const artifact = verified.authentication.statement.artifact;
    const statement = verified.authentication.statement;
    const sources = [...new Set(selected.report.candidates.filter(row => row.statement_sha256 === selected.report.selected.statement_sha256)
      .map(row => row.input))].sort();
    // Lexical separation is insufficient when a parent component is a symlink.
    // Existing source bytes must remain outside every writable recovery custody
    // domain. Missing optional sources stay admissible for later restart.
    await requireExistingSourcesApart(sources, owned.map(o => o.path), options.trustKey, witnessDirectory, live);
    const destinations = owned.slice(1).map(o => o.saved).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    const candidates = new Set([...sources, ...destinations.map(row => join(row.path, archiveName(statement)))]);
    if (candidates.size > MAX_BACKUP_CANDIDATES) fail('backup_job_source_limit');
    const manifest = { type: BACKUP_JOB_TYPE, policy: options.policy, checkpoint,
      statement_sha256: hash(JSON.stringify(statement)), sources: Object.freeze(sources), destinations: Object.freeze(destinations), witness_directory: witnessDirectory };
    const bytes = encode(manifest);
    if (bytes.length > MAX_BACKUP_JOB_BYTES) fail('backup_job_intent_limit');
    const intent = join(owner.path, `job-sha256-${hash(bytes)}.json`); job = report(intent, manifest);
    const current = () => { live.check(); selected.checkCurrent(); verified.checkCurrent(); if (witness) witness.require(statement); };
    await gate(); current(); state = 'approval_publication_unknown';
    await publishExact(owner, controlPaths(owner, checkpoint), envelope, { ...live, check: current });
    await gate(); current(); state = 'intent_publication_unknown';
    await publishExact(owner, intent, bytes, { ...live, check: current });
    state = 'sealed'; completed = Object.freeze({ ...job, state, approval_preserved: true,
      streaming: selected.report.streaming, repository_changed: false });
    // Preserve the confirmed intent even if its receipt observer fails.
    await options.onProgress(Object.freeze({ phase: 'job_sealed', job: completed }));
    return completed;
  } catch (caught) {
    problem = caught instanceof Error ? caught : backupError('backup_job_observer_failed');
    problem.job = job; problem.job_state = state;
    if (completed) problem.completed_result = completed;
    throw problem;
  } finally { await closeOwned(owned, problem, completed); }
}

function decodeIntent(bytes, intent) {
  const match = /^job-sha256-([0-9a-f]{64})\.json$/.exec(basename(intent));
  if (!match || hash(bytes) !== match[1]) fail('backup_job_identity_mismatch');
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('backup_job_invalid_intent'); }
  if (!exact(value, ['type', 'policy', 'checkpoint', 'statement_sha256', 'sources', 'destinations', 'witness_directory'])
    || value.type !== BACKUP_JOB_TYPE || typeof value.statement_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.statement_sha256)
    || !Array.isArray(value.sources) || !value.sources.length || value.sources.length > MAX_BACKUP_CANDIDATES
    || !Array.isArray(value.destinations) || !value.destinations.length || value.destinations.length > MAX_REPLENISHMENT_DESTINATIONS) fail('backup_job_invalid_intent');
  const policy = backupPolicy(value.policy), checkpoint = repositoryBackupReplicationCheckpoint(value.checkpoint);
  if (!checkpoint) fail('backup_job_invalid_intent');
  const sources = value.sources.map(absolute);
  if (sources.some((path, i) => path !== value.sources[i] || (i && path <= sources[i - 1]))) fail('backup_job_invalid_intent');
  const destinations = value.destinations.map(row => {
    if (!exact(row, ['path', 'device', 'inode']) || absolute(row.path) !== row.path
      || [row.device, row.inode].some(v => typeof v !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(v)
        || BigInt(v) > 18446744073709551615n)) fail('backup_job_invalid_intent');
    return Object.freeze({ path: row.path, device: row.device, inode: row.inode });
  });
  if (destinations.some((row, i) => i && row.path <= destinations[i - 1].path)) fail('backup_job_invalid_intent');
  const witnessDirectory = value.witness_directory === null ? null : absolute(value.witness_directory);
  if (witnessDirectory !== value.witness_directory) fail('backup_job_invalid_intent');
  const manifest = { type: BACKUP_JOB_TYPE, policy, checkpoint, statement_sha256: value.statement_sha256,
    sources: Object.freeze(sources), destinations: Object.freeze(destinations), witness_directory: witnessDirectory };
  if (!encode(manifest).equals(bytes)) fail('backup_job_noncanonical_intent');
  return Object.freeze(manifest);
}

/** Reauthenticate an existing immutable job, then verify every byte used/output.
 * Candidate paths come ONLY from its fixed source/target set and share the saved
 * original approval. Thus lost original controls, lost stdout and process death
 * do not require a different checkpoint or an invented success record. The
 * supplied independent policy may strengthen but never weaken the sealed floor.
 */
export async function runRepositoryBackupJob(raw, witness = null) {
  const keys = ['intent', 'trustKey', 'policy', 'maximumBytes', 'maximumTotalBytes', 'timeoutMs', 'signal', 'onProgress', 'now'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !keys.includes(k))) fail('backup_invalid_job_options');
  const intent = absolute(raw.intent), trustKey = absolute(raw.trustKey), policy = backupPolicy(raw.policy);
  const { maximumTotalBytes, now } = raw; // Snapshot operational bounds before the first await.
  const live = backupLifetime({ maximumBytes: raw.maximumBytes, timeoutMs: raw.timeoutMs,
    signal: raw.signal, onProgress: raw.onProgress, now: now });
  if (maximumTotalBytes !== undefined && (!Number.isSafeInteger(maximumTotalBytes) || maximumTotalBytes < 1
    || maximumTotalBytes > MAX_REPLENISHMENT_READ_BYTES)) fail('backup_replenishment_read_limit');
  const owned = []; let completed, problem, job = null;
  try {
    const owner = await ownDirectory(dirname(intent), live); owned.push(owner);
    const canonicalIntent = join(owner.path, basename(intent));
    const encoded = await readBackupControl(canonicalIntent, MAX_BACKUP_JOB_BYTES, live, true);
    const manifest = decodeIntent(encoded, canonicalIntent); job = report(canonicalIntent, manifest);
    if (IDENTITY.some(k => policy[k] !== manifest.policy[k])) fail('backup_job_policy_mismatch');
    if (BigInt(policy.minimum_head_generation) < BigInt(manifest.policy.minimum_head_generation)) fail('backup_job_floor_regression');
    const witnessDirectory = checkedWitness(manifest, witness);
    requireSeparate(owner.path, [trustKey, ...manifest.sources, ...manifest.destinations.map(row => row.path),
      ...(witnessDirectory ? [witnessDirectory] : [])]);
    const approval = controlPaths(owner, manifest.checkpoint);
    const envelope = await readBackupControl(approval, BACKUP_LIMITS.envelopeBytes, live, true);
    if (hash(envelope) !== manifest.checkpoint.approval_sha256) fail('backup_job_approval_changed');
    const key = await readBackupControl(trustKey, BACKUP_LIMITS.keyBytes, live);
    // Signed higher evidence is retained even when this invocation cannot use
    // the archive because of expiry, a stricter floor, or its narrower size cap.
    const verified = await inspectRepositoryBackupApproval(envelope, key, policy, {
      maximumBytes: BACKUP_LIMITS.maximumArchiveBytes, timeoutMs: live.remaining(), signal: live.signal, now: now,
    });
    const statement = verified.checkpoint.statement;
    if (verified.checkpoint.trusted_key_id !== manifest.checkpoint.trusted_key_id
      || hash(JSON.stringify(statement)) !== manifest.statement_sha256) fail('backup_job_checkpoint_mismatch');
    if (witness) { await witness.observe(envelope); witness.require(statement); }
    verified.checkCurrent();
    if (BigInt(statement.artifact.bytes) > BigInt(live.maximumBytes)) fail('backup_selected_archive_limit');
    for (const saved of manifest.destinations) {
      const target = await ownDirectory(saved.path, live); owned.push(target);
      if (target.path !== saved.path || target.saved.device !== saved.device || target.saved.inode !== saved.inode) fail('backup_job_destination_changed');
      requireSeparate(target.path, owned.slice(0, -1).map(o => o.path));
      if (witnessDirectory) requireSeparate(target.path, [witnessDirectory]);
    }
    await requireKeyApart(trustKey, owned.map(o => o.path), live);
    if (witnessDirectory) await requireKeyApart(trustKey, [witnessDirectory], live);
    // Re-resolve surviving original sources on every restart. A safe source
    // parent at seal time may have been redirected before this invocation.
    await requireExistingSourcesApart(manifest.sources, owned.map(o => o.path), trustKey, witnessDirectory, live);
    const gate = async () => {
      live.check(); verified.checkCurrent(); if (witness) witness.require(statement);
      for (const o of owned) await o.check();
    };
    const paths = [...new Set([...manifest.sources, ...manifest.destinations.map(row => join(row.path, archiveName(statement)))])].sort();
    if (paths.length > MAX_BACKUP_CANDIDATES) fail('backup_job_source_limit');
    // Existing selector failover checks each candidate against the SAME saved
    // signed bytes. Absent output payloads are not treated as completed copies.
    const result = await replenishRepositoryBackups({ candidates: paths.map(input => ({ input, approval })),
      destinations: manifest.destinations.map(row => row.path), trustKey, policy,
      checkpoint: manifest.checkpoint, sourceHandoff: true, maximumBytes: live.maximumBytes,
      maximumTotalBytes: maximumTotalBytes, timeoutMs: live.remaining(), signal: live.signal, now: now,
      async onProgress(event) { await live.onProgress(Object.freeze({ ...event, job })); await gate(); },
    }, witness);
    completed = Object.freeze({ type: 'repository_backup_job_run', state: result.state, job, result });
    // A successful group receipt is not revoked by late cancellation/expiry.
    return completed;
  } catch (caught) {
    problem = caught instanceof Error ? caught : backupError('backup_job_observer_failed');
    problem.job = job; throw problem;
  } finally { await closeOwned(owned, problem, completed); }
}
