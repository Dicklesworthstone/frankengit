// Durable private source custody for explicit offsite publication jobs. These
// intents select operator effects; neither a file hash nor an archive signature
// authorizes an untrusted job or establishes canonical repository authority.
import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { resolve, dirname, basename, join, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, exact,
  readBackupControl, publishBackupControl } from './repository-backup-io.mjs';
import { backupPolicy, verifyRepositoryBackupApproval } from './repository-backup-approval.mjs';
import { replicateRepositoryBackup, repositoryBackupReplicationCheckpoint } from './repository-backup-replication.mjs';
import { repositoryBackupUploadTarget, uploadRepositoryBackup } from './repository-backup-upload.mjs';

export const BACKUP_UPLOAD_JOB_TYPE = 'repository_backup_upload_intent_v1';
export const MAX_BACKUP_UPLOAD_TARGETS = 16;
export const MAX_BACKUP_UPLOAD_TOTAL_BYTES = 3 * MAX_BACKUP_UPLOAD_TARGETS * BACKUP_LIMITS.maximumArchiveBytes;
const MAX_TARGET_TEXT = 256 * 1024;
const IDENTITY = ['tenant_id', 'repository_id', 'incarnation_id', 'object_format'];
const FIELDS = ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs'];
const hash = value => createHash('sha256').update(value).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const fail = code => { throw backupError(code); };
const absolute = value => backupPath(resolve(backupPath(value)));
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const sameFile = (a, b) => FIELDS.every(field => a[field] === b[field]);
const overlaps = (a, b) => a === b || a.startsWith(b + sep) || b.startsWith(a + sep);
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const decimal = value => typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value) && value.length <= 32;
const archiveName = statement => `archive-sha256-${statement.artifact.sha256}.fgbackup`;
const approvalName = checkpoint => `checkpoint-sha256-${checkpoint.approval_sha256}.approval.json`;

function logicalTarget(target) {
  const result = {};
  for (const kind of ['archive', 'approval']) {
    const url = new URL(target[kind].get);
    // Method-specific query capabilities are deliberately absent from identity.
    // This still relies on the service identifying its objects by origin/path.
    result[`${kind}_sha256`] = hash(url.origin + url.pathname);
  }
  return Object.freeze(result);
}
const targetId = target => hash(encode(target));
function targets(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_BACKUP_UPLOAD_TARGETS) fail('backup_upload_job_targets');
  let bytes = 0; const objects = new Set();
  const rows = value.map(row => {
    if (!row || typeof row !== 'object' || Array.isArray(row)
      || Object.keys(row).some(key => !['target', 'caFile'].includes(key)) || !Object.hasOwn(row, 'target')) fail('backup_upload_job_targets');
    const target = repositoryBackupUploadTarget(row.target), logical = logicalTarget(target);
    for (const pair of Object.values(target)) for (const url of Object.values(pair)) bytes += Buffer.byteLength(url);
    if (bytes > MAX_TARGET_TEXT) fail('backup_upload_job_target_bytes');
    for (const object of Object.values(logical)) {
      if (objects.has(object)) fail('backup_upload_job_target_alias');
      objects.add(object);
    }
    return Object.freeze({ target, logical, target_id: targetId(logical),
      ...(row.caFile === undefined ? {} : { caFile: absolute(row.caFile) }) });
  });
  return Object.freeze(rows.sort((a, b) => a.target_id < b.target_id ? -1 : a.target_id > b.target_id ? 1 : 0));
}

/** Parameter-only capture. No source, control, directory or socket is opened. */
export function repositoryBackupUploadJobOptions(raw, mode) {
  const extra = mode === 'seal' ? ['jobDirectory', 'input', 'approval'] : mode === 'run' ? ['intent'] : null;
  const common = ['trustedLocal', 'trustKey', 'policy', 'targets', 'maximumBytes', 'maximumTotalBytes',
    'timeoutMs', 'signal', 'now', 'onProgress'];
  if (extra === null || !raw || typeof raw !== 'object' || Array.isArray(raw)
    || Object.keys(raw).some(key => ![...common, ...extra].includes(key)) || raw.trustedLocal !== true) fail('backup_upload_job_options');
  const paths = Object.fromEntries([...extra, 'trustKey'].map(key => [key, absolute(raw[key])]));
  const captured = targets(raw.targets), policy = backupPolicy(raw.policy);
  const live = backupLifetime({ maximumBytes: raw.maximumBytes, timeoutMs: raw.timeoutMs,
    signal: raw.signal, now: raw.now, onProgress: raw.onProgress });
  const maximumTotalBytes = raw.maximumTotalBytes ?? 3 * live.maximumBytes * (mode === 'seal' ? 1 : captured.length);
  if (!Number.isSafeInteger(maximumTotalBytes) || maximumTotalBytes < 1 || maximumTotalBytes > MAX_BACKUP_UPLOAD_TOTAL_BYTES) fail('backup_upload_job_budget');
  const directory = mode === 'seal' ? paths.jobDirectory : dirname(paths.intent);
  const separate = [paths.trustKey, ...captured.flatMap(row => row.caFile === undefined ? [] : [row.caFile]),
    ...(mode === 'seal' ? [paths.input, paths.approval] : [])];
  if (separate.some(path => overlaps(directory, path))) fail('backup_upload_job_separate_paths');
  return Object.freeze({ ...paths, trustedLocal: true, targets: captured, policy,
    maximumBytes: live.maximumBytes, maximumTotalBytes, timeoutMs: raw.timeoutMs,
    signal: live.signal, now: raw.now, onProgress: live.onProgress });
}
function supported() {
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined
    || constants.O_NONBLOCK === undefined || constants.O_DIRECTORY === undefined) fail('backup_unsupported_filesystem');
}
function privateOwner(stat) {
  if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_upload_job_private_owner');
}
async function ownDirectory(requested, live) {
  supported(); live.check();
  const initial = await lstat(requested, { bigint: true }); privateOwner(initial);
  if (!initial.isDirectory() || dirname(requested) === requested) fail('backup_upload_job_directory');
  const path = await realpath(requested), handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat({ bigint: true });
    const check = async () => {
      const named = await lstat(path, { bigint: true }), current = await handle.stat({ bigint: true });
      privateOwner(named); privateOwner(current);
      if (!named.isDirectory() || !same(initial, stat) || !same(stat, named) || !same(stat, current)
        || await realpath(requested) !== path) fail('backup_upload_job_directory_changed');
    };
    await check(); live.check();
    return { path, handle, check, identity: Object.freeze({ path, device: String(stat.dev), inode: String(stat.ino) }) };
  } catch (error) { await handle.close(); throw error; }
}
async function separate(owner, paths, live) {
  for (const path of paths) {
    live.check();
    if (overlaps(owner.path, await realpath(path))) fail('backup_upload_job_separate_paths');
  }
  await owner.check(); live.check();
}
async function ownFile(path, live, { expectedSize, maximum, privateFile = true } = {}) {
  live.check(); const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    const check = async () => {
      const current = await handle.stat({ bigint: true }), named = await lstat(path, { bigint: true });
      if (!named.isFile() || !sameFile(before, current) || !sameFile(current, named)) fail('backup_upload_job_file_changed');
    };
    if (!before.isFile() || before.size < 1n || (maximum !== undefined && before.size > BigInt(maximum))
      || (expectedSize !== undefined && before.size !== BigInt(expectedSize))) fail('backup_upload_job_file_size');
    if (privateFile) { privateOwner(before); if (before.nlink !== 1n) fail('backup_upload_job_file_links'); }
    await check(); live.check(); return { path, handle, check };
  } catch (error) { await handle.close(); throw error; }
}
async function closeOwned(owned, problem, completed) {
  let failed;
  for (const item of [...owned].reverse()) {
    try { await item.handle.close(); } catch { failed ??= backupError('backup_upload_job_close_failed'); }
  }
  if (failed) {
    if (problem) problem.job_cleanup_error = failed.code;
    else { failed.completed_result = completed; failed.publication_state = completed ? 'complete' : 'unknown'; throw failed; }
  }
}
async function publishExact(owner, path, bytes, live) {
  await owner.check();
  let published = false;
  try { await publishBackupControl(path, bytes, live); published = true; }
  catch (error) { if (error.code !== 'EEXIST' || error.cleanup_error) throw error; }
  // A confirmed new control publication owns its remaining readback/close even
  // if cancellation arrives now. Existing-file reuse still needs a live check.
  const finalLive = published ? { ...live, check() {} } : live;
  let file, failure;
  try {
    file = await ownFile(path, finalLive, { expectedSize: bytes.length });
    if (!bytes.equals(await readBackupControl(path, BACKUP_LIMITS.envelopeBytes, finalLive, true))) fail('backup_upload_job_intent_conflict');
    await file.check(); await file.handle.sync(); await owner.handle.sync(); await owner.check();
  } catch (error) {
    failure = error; error.publication_state ??= published ? 'published' : 'existing_unknown'; throw error;
  } finally {
    try { await file?.handle.close(); }
    catch (error) {
      if (failure) failure.job_cleanup_error = 'backup_upload_job_close_failed';
      else { error.publication_state = published ? 'published' : 'existing_unknown'; throw error; }
    }
  }
}
function jobReport(intent, manifest) {
  return Object.freeze({ intent, sha256: hash(encode(manifest)), checkpoint: manifest.checkpoint,
    artifact: Object.freeze({ ...manifest.statement.artifact }), target_ids: Object.freeze(manifest.targets.map(targetId)) });
}
const clockOptions = (options, live) => ({ maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal,
  ...(options.now === undefined ? {} : { now: options.now }) });
function checkpointOf(envelope, approved) {
  return Object.freeze({ approval_sha256: hash(envelope), trusted_key_id: approved.authentication.trusted_key_id });
}
function matchCheckpoint(a, b) {
  if (a.approval_sha256 !== b.approval_sha256 || a.trusted_key_id !== b.trusted_key_id) fail('backup_upload_job_checkpoint_mismatch');
}
function observer(options) {
  const failures = new WeakSet();
  return { failures, async emit(event) {
    try { await options.onProgress(Object.freeze(event)); }
    catch (caught) {
      const error = caught instanceof Error ? caught : backupError('backup_upload_job_observer_failed');
      failures.add(error); throw error;
    }
  } };
}

/** Retain an authenticated private archive/approval, then publish intent last.
 * Seal has no network effects. Failed sealing never deletes retained material. */
export async function sealRepositoryBackupUploadJob(raw) {
  const options = repositoryBackupUploadJobOptions(raw, 'seal');
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs,
    signal: options.signal, now: options.now });
  const notifications = observer(options);
  const owned = []; let problem, completed, job, snapshot;
  try {
    const owner = await ownDirectory(options.jobDirectory, live); owned.push(owner);
    await separate(owner, [options.approval, options.trustKey, ...options.targets.flatMap(row => row.caFile ? [row.caFile] : [])], live);
    const envelope = await readBackupControl(options.approval, BACKUP_LIMITS.envelopeBytes, live);
    const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, live);
    const approved = await verifyRepositoryBackupApproval(envelope, key, options.policy, clockOptions(options, live));
    const checkpoint = checkpointOf(envelope, approved), statement = approved.authentication.statement;
    if (3 * Number(statement.artifact.bytes) > options.maximumTotalBytes) fail('backup_upload_job_budget');
    await separate(owner, [options.input], live);
    const gate = async () => { live.check(); approved.checkCurrent(); await owner.check(); live.check(); };
    snapshot = await replicateRepositoryBackup({ candidates: [{ input: options.input, approval: options.approval }],
      trustKey: options.trustKey, policy: options.policy, destination: owner.path, checkpoint,
      maximumBytes: live.maximumBytes, maximumTotalBytes: Math.min(options.maximumTotalBytes, 3 * Number(statement.artifact.bytes)),
      timeoutMs: live.remaining(), signal: live.signal, ...(options.now === undefined ? {} : { now: options.now }),
      onProgress: gate });
    const archive = await ownFile(snapshot.candidate.input, live, { expectedSize: statement.artifact.bytes }); owned.push(archive);
    const approval = await ownFile(snapshot.candidate.approval, live, { expectedSize: envelope.length }); owned.push(approval);
    if (!envelope.equals(await readBackupControl(approval.path, BACKUP_LIMITS.envelopeBytes, live, true))) fail('backup_upload_job_checkpoint_mismatch');
    const manifest = { type: BACKUP_UPLOAD_JOB_TYPE, schema_version: 1, directory: owner.identity,
      checkpoint, policy: options.policy, statement, targets: options.targets.map(row => row.logical) };
    const bytes = encode(manifest);
    if (bytes.length > BACKUP_LIMITS.envelopeBytes) fail('backup_upload_job_intent_size');
    const intent = join(owner.path, `upload-job-sha256-${hash(bytes)}.json`); job = jobReport(intent, manifest);
    await notifications.emit({ phase: 'snapshot_retained', job });
    await gate(); await archive.check(); await approval.check();
    await publishExact(owner, intent, bytes, { ...live, check() { live.check(); approved.checkCurrent(); } });
    completed = Object.freeze({ type: 'repository_backup_upload_job_sealed', state: 'complete', job, snapshot,
      source_custody_retained: true, network_accessed: false });
    await notifications.emit({ phase: 'job_sealed', job });
    return completed;
  } catch (caught) {
    problem = caught instanceof Error ? caught : backupError('backup_upload_job_observer_failed');
    problem.job = job ?? null; problem.snapshot = snapshot ?? null;
    if (notifications.failures.has(problem)) {
      delete problem.completed_result; problem.publication_state = completed ? 'complete' : 'not_created';
    }
    if (completed) { problem.completed_result = completed; problem.publication_state = 'complete'; }
    throw problem;
  } finally { await closeOwned(owned, problem, completed); }
}

function decodeIntent(bytes, path, owner) {
  const match = /^upload-job-sha256-([0-9a-f]{64})\.json$/.exec(basename(path));
  if (!match || hash(bytes) !== match[1]) fail('backup_upload_job_intent_hash');
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('backup_upload_job_intent'); }
  if (!exact(value, ['type', 'schema_version', 'directory', 'checkpoint', 'policy', 'statement', 'targets'])
    || value.type !== BACKUP_UPLOAD_JOB_TYPE || value.schema_version !== 1
    || !exact(value.directory, ['path', 'device', 'inode']) || value.directory.path !== owner.path
    || !decimal(value.directory.device) || !decimal(value.directory.inode)
    || value.directory.device !== owner.identity.device || value.directory.inode !== owner.identity.inode
    || !Array.isArray(value.targets) || value.targets.length < 1 || value.targets.length > MAX_BACKUP_UPLOAD_TARGETS) fail('backup_upload_job_intent');
  const objects = new Set(); let previous = '';
  const logical = value.targets.map(row => {
    if (!exact(row, ['archive_sha256', 'approval_sha256']) || !hex(row.archive_sha256) || !hex(row.approval_sha256)) fail('backup_upload_job_intent');
    const result = Object.freeze({ archive_sha256: row.archive_sha256, approval_sha256: row.approval_sha256 });
    const id = targetId(result); if (id <= previous) fail('backup_upload_job_intent'); previous = id;
    for (const digest of Object.values(result)) { if (objects.has(digest)) fail('backup_upload_job_intent'); objects.add(digest); }
    return result;
  });
  const result = { type: value.type, schema_version: 1, directory: owner.identity,
    checkpoint: repositoryBackupReplicationCheckpoint(value.checkpoint), policy: backupPolicy(value.policy),
    statement: value.statement, targets: logical };
  if (!encode(result).equals(bytes)) fail('backup_upload_job_noncanonical_intent');
  return result;
}
function sanitizedReceipt(result, id) {
  const { target: _capabilityHashes, ...receipt } = result;
  return Object.freeze({ ...receipt, target_id: id });
}

/** Every run uses the retained pair, independent trust and refreshed capabilities.
 * Actual remote GET/readback owns progress; no saved completion bit is trusted. */
export async function runRepositoryBackupUploadJob(raw) {
  const options = repositoryBackupUploadJobOptions(raw, 'run');
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs,
    signal: options.signal, now: options.now });
  const notifications = observer(options);
  const childFailures = new WeakSet();
  const owned = [], completedTargets = []; let problem, completed, job, active = null, total = 0;
  const accounting = () => Object.freeze({ total_payload_bytes: String(total), total_payload_budget: String(options.maximumTotalBytes) });
  const state = () => Object.freeze({ state: completed ? 'complete' : 'incomplete', job: job ?? null,
    completed_targets: Object.freeze([...completedTargets]), active_target: active, streaming: accounting() });
  try {
    const owner = await ownDirectory(dirname(options.intent), live); owned.push(owner);
    const intent = join(owner.path, basename(options.intent));
    const intentFile = await ownFile(intent, live, { maximum: BACKUP_LIMITS.envelopeBytes }); owned.push(intentFile);
    const encoded = await readBackupControl(intent, BACKUP_LIMITS.envelopeBytes, live, true);
    await intentFile.check(); const manifest = decodeIntent(encoded, intent, owner);
    if (IDENTITY.some(field => options.policy[field] !== manifest.policy[field])
      || BigInt(options.policy.minimum_head_generation) < BigInt(manifest.policy.minimum_head_generation)) fail('backup_upload_job_policy_mismatch');
    if (JSON.stringify(options.targets.map(row => row.logical)) !== JSON.stringify(manifest.targets)) fail('backup_upload_job_target_mismatch');
    await separate(owner, [options.trustKey, ...options.targets.flatMap(row => row.caFile ? [row.caFile] : [])], live);
    const approvalPath = join(owner.path, approvalName(manifest.checkpoint));
    const approval = await ownFile(approvalPath, live, { maximum: BACKUP_LIMITS.envelopeBytes }); owned.push(approval);
    const envelope = await readBackupControl(approvalPath, BACKUP_LIMITS.envelopeBytes, live, true);
    const trust = await ownFile(options.trustKey, live, { maximum: BACKUP_LIMITS.keyBytes, privateFile: false }); owned.push(trust);
    const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, live);
    await approval.check(); await trust.check();
    const approved = await verifyRepositoryBackupApproval(envelope, key, options.policy, clockOptions(options, live));
    matchCheckpoint(manifest.checkpoint, checkpointOf(envelope, approved));
    if (JSON.stringify(manifest.statement) !== JSON.stringify(approved.authentication.statement)) fail('backup_upload_job_statement_mismatch');
    job = jobReport(intent, manifest);
    const size = Number(approved.authentication.statement.artifact.bytes), reserve = 3 * size;
    if (reserve * options.targets.length > options.maximumTotalBytes) fail('backup_upload_job_budget');
    const input = join(owner.path, archiveName(approved.authentication.statement));
    const archive = await ownFile(input, live, { expectedSize: size }); owned.push(archive);
    // TLS trust is captured for this attempt just like the independent signing
    // key. A later destination must not reopen silently substituted CA bytes.
    const certificates = [];
    for (const path of new Set(options.targets.flatMap(row => row.caFile ? [row.caFile] : []))) {
      const certificate = await ownFile(path, live, { maximum: BACKUP_LIMITS.envelopeBytes, privateFile: false });
      owned.push(certificate); certificates.push(certificate);
    }
    const gate = async () => {
      live.check(); approved.checkCurrent(); await owner.check();
      for (const file of [intentFile, approval, trust, archive, ...certificates]) await file.check();
      await separate(owner, [options.trustKey, ...options.targets.flatMap(row => row.caFile ? [row.caFile] : [])], live);
      live.check();
    };
    const finish = () => Object.freeze({ type: 'repository_backup_upload_job_run', state: 'complete', job,
      completed_targets: Object.freeze([...completedTargets]), streaming: accounting(),
      cancellation_requested: Boolean(options.signal?.aborted), remote_readback_verified: true,
      native_content_verified: false, remote_physical_durability_verified: false,
      failure_domain_independence_verified: false, newest_checkpoint_verified: false });
    await notifications.emit({ phase: 'job_verified', job }); await gate();
    for (const row of options.targets) {
      active = row.target_id; await gate();
      await notifications.emit({ phase: 'target_started', job, target_id: active }); await gate();
      let receipt;
      try {
        receipt = await uploadRepositoryBackup({ input, approval: approvalPath, trustKey: options.trustKey,
          policy: options.policy, target: row.target, ...(row.caFile ? { caFile: row.caFile } : {}), checkpoint: manifest.checkpoint,
          maximumBytes: live.maximumBytes, maximumTotalBytes: Math.min(reserve, options.maximumTotalBytes - total),
          timeoutMs: live.remaining(), signal: live.signal, ...(options.now === undefined ? {} : { now: options.now }),
          async onProgress(event) {
            await notifications.emit({ phase: 'target_progress', target_phase: event.phase,
              job, target_id: active, publication_state: event.state }); await gate();
          } });
      } catch (caught) {
        const error = caught instanceof Error ? caught : backupError('backup_upload_job_observer_failed');
        childFailures.add(error);
        const count = Number(error.streaming?.total_payload_bytes ?? error.completed_result?.streaming?.total_payload_bytes ?? 0);
        if (Number.isSafeInteger(count) && count >= 0) total += count;
        error.target = { target_id: active };
        // Only the child owner's close-after-completion path can supply this
        // receipt. Callback-owned error fields are not evidence of an effect.
        if (!notifications.failures.has(error) && error.completed_result?.type === 'repository_backup_upload') {
          const result = sanitizedReceipt(error.completed_result, active);
          completedTargets.push(Object.freeze({ target_id: active, result }));
          error.completed_result = result;
          if (completedTargets.length === options.targets.length) completed = finish();
        }
        throw error;
      }
      total += Number(receipt.streaming.total_payload_bytes);
      const result = sanitizedReceipt(receipt, active);
      completedTargets.push(Object.freeze({ target_id: active, result })); active = null;
      if (completedTargets.length === options.targets.length) completed = finish();
      // Record completion before observers; a failing channel cannot erase it.
      await notifications.emit({ phase: 'target_complete', job, target_id: row.target_id,
        completed_targets: completedTargets.length, streaming: accounting() });
      if (!completed) await gate();
    }
    // There is no post-effect expiry/cancellation gate. All network owners have
    // drained, and the last target's exact remote readback established success.
    completed = finish(); return completed;
  } catch (caught) {
    problem = caught instanceof Error ? caught : backupError('backup_upload_job_observer_failed');
    problem.job = job ?? null; problem.upload_job = state();
    if (notifications.failures.has(problem)) {
      delete problem.completed_result;
      if (!childFailures.has(problem)) problem.publication_state = active === null && completedTargets.length ? 'complete' : 'not_started';
    }
    if (completed) { problem.completed_result = completed; problem.publication_state = 'complete'; }
    throw problem;
  } finally { await closeOwned(owned, problem, completed); }
}
