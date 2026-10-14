// Trusted-local recovery memory, NOT repository authority or a freshness oracle.
// An independently retained directory remembers signed observations across runs.
import { constants } from 'node:fs';
import { open, lstat, mkdir, rename, unlink, realpath } from 'node:fs/promises';
import { resolve, dirname, basename, join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, exact, readBackupControl } from './repository-backup-io.mjs';
import { backupPolicy, inspectRepositoryBackupApproval, repositoryBackupTrustedKeyId } from './repository-backup-approval.mjs';

const TYPE = 'repository_backup_witness_v1', MAX_STATE = 64 * 1024;
const IDENTITIES = ['tenant_id', 'repository_id', 'incarnation_id', 'object_format'];
const STATE = 'witness.json', LOCK = '.witness-lock';
const fail = code => { throw backupError(code); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const fileFields = ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs'];
const sameFile = (a, b) => fileFields.every(k => a[k] === b[k]);
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
function privateOwner(stat) {
  if (typeof process.getuid !== 'function' || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_witness_private_owner_required');
}
function supported() {
  if ([constants.O_NOFOLLOW, constants.O_NONBLOCK, constants.O_DIRECTORY].some(v => v === undefined)
    || typeof process.getuid !== 'function') fail('backup_witness_unsupported_filesystem');
}
function argumentsFor(directory, trustKey, expected, options) {
  supported();
  const path = resolve(backupPath(directory)), keyPath = resolve(backupPath(trustKey));
  backupPath(path); backupPath(keyPath);
  if (dirname(path) === path || keyPath === path || keyPath.startsWith(path + '/')) fail('backup_witness_separate_path_required');
  return { path, keyPath, policy: backupPolicy(expected), live: backupLifetime(options) };
}
async function ownedDirectory(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const identity = await handle.stat({ bigint: true });
    privateOwner(identity);
    const check = async () => {
      const named = await lstat(path, { bigint: true }), current = await handle.stat({ bigint: true });
      if (!named.isDirectory() || !same(named, identity) || !same(current, identity)) fail('backup_witness_directory_changed');
      privateOwner(named);
    };
    await check(); return { handle, identity, check };
  } catch (error) { await handle.close(); throw error; }
}
async function readState(path, live) {
  live.check();
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true }); privateOwner(before);
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(MAX_STATE)) fail('backup_witness_invalid_file');
    // Fixed bound, including one trailing-byte probe. Never trust a growing file.
    const bytes = Buffer.alloc(Number(before.size) + 1); let offset = 0;
    while (offset < bytes.length) {
      live.check(); const { bytesRead } = await file.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) break; offset += bytesRead;
    }
    const after = await file.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    if (offset !== Number(before.size) || !named.isFile() || !sameFile(before, after) || !sameFile(after, named)) fail('backup_witness_changed');
    live.check(); return bytes.subarray(0, offset);
  } finally { await file.close(); }
}
async function signedObservation(encoded, key, policy, live) {
  const inspected = await inspectRepositoryBackupApproval(encoded, key, policy, {
    maximumBytes: BACKUP_LIMITS.maximumArchiveBytes, timeoutMs: live.remaining(), signal: live.signal, now: live.now(),
  });
  live.check();
  // Do not call checkCurrent: expired, future-dated and currently unavailable
  // signed checkpoints still constrain subsequent recovery selection.
  return { encoded: Buffer.from(encoded).toString('base64'), statement: inspected.checkpoint.statement };
}
async function decodeState(bytes, key, policy, live) {
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('backup_witness_invalid_state'); }
  if (!exact(value, ['type', 'policy', 'trusted_key_id', 'observations']) || value.type !== TYPE
    || !Array.isArray(value.observations) || value.observations.length > 2) fail('backup_witness_invalid_state');
  const retained = backupPolicy(value.policy), trusted = repositoryBackupTrustedKeyId(key);
  if (IDENTITIES.some(k => retained[k] !== policy[k]) || value.trusted_key_id !== trusted) fail('backup_witness_trust_mismatch');
  if (BigInt(policy.minimum_head_generation) < BigInt(retained.minimum_head_generation)) fail('backup_witness_floor_regression');
  const observations = [];
  for (const text of value.observations) {
    if (typeof text !== 'string' || text.length < 4 || text.length > 4 * Math.ceil(BACKUP_LIMITS.envelopeBytes / 3)) fail('backup_witness_invalid_state');
    const envelope = Buffer.from(text, 'base64');
    if (envelope.toString('base64') !== text) fail('backup_witness_invalid_state');
    observations.push(await signedObservation(envelope, key, retained, live));
  }
  if (observations.length === 2 && (observations[0].statement.head_generation !== observations[1].statement.head_generation
    || JSON.stringify(observations[0].statement) === JSON.stringify(observations[1].statement))) fail('backup_witness_invalid_state');
  if (!encode({ type: TYPE, policy: retained, trusted_key_id: trusted, observations: observations.map(o => o.encoded) }).equals(bytes)) fail('backup_witness_noncanonical_state');
  return { observations, retained, trusted };
}

/** Explicit create-only bootstrap. Normal selection NEVER recreates a missing
 * witness, treats missing/corrupt state as empty, or learns its key from disk.
 * Caller must retain this private directory independently of repository loss.
 */
export async function initializeRepositoryBackupWitness(directory, trustKey, expected, options = {}) {
  const { path: requested, keyPath, policy, live } = argumentsFor(directory, trustKey, expected, options);
  const key = await readBackupControl(keyPath, BACKUP_LIMITS.keyBytes, live), trusted = repositoryBackupTrustedKeyId(key);
  const parent = await realpath(dirname(requested)), path = join(parent, basename(requested));
  const owner = await ownedDirectory(parent); let root, file;
  try {
    live.check(); await owner.check(); await mkdir(path, { mode: 0o700 });
    root = await ownedDirectory(path);
    file = await open(join(path, STATE), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await file.writeFile(encode({ type: TYPE, policy, trusted_key_id: trusted, observations: [] }));
    await file.sync(); await root.handle.sync(); await owner.handle.sync(); await root.check(); await owner.check(); live.check();
    return { type: 'repository_backup_witness_initialized', directory: path, initialized: true, policy,
      trusted_key_id: trusted, newest_checkpoint_verified: false, repository_changed: false };
  } catch (error) {
    // Never remove/reinitialize a partially published trust directory on failure.
    error.witness_directory = path; throw error;
  } finally { try { await file?.close(); } finally { try { await root?.handle.close(); } finally { await owner.handle.close(); } } }
}

/** Exclusive ownership lasts through selection AND the native verification /
 * restore callback. Lock conflicts refuse immediately. A crash/failed child
 * containment leaves the lock: no PID/age guessing and no automatic lock break.
 * The directory/parents must be stable, owner-controlled local filesystem paths.
 */
export async function withRepositoryBackupWitness(directory, trustKey, expected, options, action) {
  const { path: requested, keyPath, policy, live } = argumentsFor(directory, trustKey, expected, options);
  if (typeof action !== 'function') fail('backup_witness_invalid_action');
  const path = join(await realpath(dirname(requested)), basename(requested));
  const key = await readBackupControl(keyPath, BACKUP_LIMITS.keyBytes, live);
  const root = await ownedDirectory(path), lockPath = join(path, LOCK), statePath = join(path, STATE);
  let lock, lockIdentity, original, observations = [], retained, trusted, problem, result, closing = false, closed = false, poisoned = false;
  const view = () => Object.freeze({ directory: path, minimum_head_generation: retained?.minimum_head_generation ?? null,
    highest_observed_generation: observations[0]?.statement.head_generation ?? null, conflicting_statements: observations.length === 2,
    state_sha256: original ? hash(original) : null, newest_checkpoint_verified: false });
  const current = () => { if (closed || poisoned) fail('backup_witness_not_live'); live.check(); };
  async function persist(next, nextPolicy = retained) {
    let temp, file, identity, published = false, failure;
    let publication = 'not_published';
    try {
      // The next authenticated observation/floor is already a recovery
      // obligation. ANY failure to retain it must keep the durable lease:
      // reopening old disk state must not forget known newer or conflicting data.
      current(); await root.check();
      if (!(await readState(statePath, live)).equals(original)) fail('backup_witness_changed');
      const bytes = encode({ type: TYPE, policy: nextPolicy, trusted_key_id: trusted, observations: next.map(o => o.encoded) });
      if (bytes.length > MAX_STATE) fail('backup_witness_state_limit');
      temp = join(path, `.witness-${randomBytes(16).toString('hex')}.tmp`);
      file = await open(temp, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      identity = await file.stat({ bigint: true });
      await file.writeFile(bytes); await file.sync();
      if (!(await readState(temp, live)).equals(bytes)) fail('backup_witness_readback');
      current(); await root.check();
      if (!(await readState(statePath, live)).equals(original)) fail('backup_witness_changed');
      publication = 'publication_unknown';
      await rename(temp, statePath); published = true;
      publication = 'visible_completion_incomplete';
      // Once visible, never roll back even when sync, readback or cancellation fails.
      original = bytes; observations = next; retained = nextPolicy;
      await root.handle.sync(); await root.check();
      if (!(await readState(statePath, live)).equals(bytes)) fail('backup_witness_readback');
    } catch (caught) {
      failure = caught instanceof Error ? caught : backupError('backup_witness_persistence_failed');
      poisoned = true; failure.witness_publication_state = publication;
    } finally {
      let cleanup;
      try {
        // An ambiguous rename may have consumed the temporary name. Preserve
        // both names for inspection rather than guessing ownership or rollback.
        if (identity && !published && publication === 'not_published') {
          await root.check(); const named = await lstat(temp, { bigint: true });
          if (!named.isFile() || !same(named, identity)) fail('backup_witness_temporary_changed');
          await unlink(temp); await root.handle.sync();
        }
      } catch (error) { cleanup = error; }
      try { await file?.close(); } catch (error) { cleanup ??= error; }
      if (cleanup) {
        poisoned = true;
        if (failure) failure.witness_cleanup_error = cleanup.code ?? 'backup_witness_cleanup_failed';
        else { failure = cleanup; failure.witness_publication_state = publication; }
      }
    }
    if (failure) throw failure;
  }
  let observing = false, pending = null;
  const witness = Object.freeze({
    snapshot: view,
    async observe(input) {
      if (closing) fail('backup_witness_not_live');
      current();
      if (observing) fail('backup_witness_concurrent_observation');
      if (!(input instanceof Uint8Array) || input.buffer instanceof SharedArrayBuffer || input.length < 1 || input.length > BACKUP_LIMITS.envelopeBytes) fail('backup_approval_byte_limit');
      const encoded = Buffer.from(input); observing = true;
      pending = (async () => {
      try {
        const next = await signedObservation(encoded, key, retained, live); current();
        const generation = BigInt(next.statement.head_generation), highest = BigInt(observations[0]?.statement.head_generation ?? '0');
        if (generation > highest) await persist([next]);
        else if (generation === highest && observations.length < 2
          && JSON.stringify(next.statement) !== JSON.stringify(observations[0].statement)) await persist([...observations, next]);
        return view();
      } finally { observing = false; }
      })();
      // Retain child responsibility even when a caller forgets to await it.
      pending.catch(() => {});
      return pending;
    },
    require(statement) {
      if (closing) fail('backup_witness_not_live');
      current();
      if (observing) fail('backup_witness_concurrent_observation');
      if (!observations.length || BigInt(statement.head_generation) < BigInt(observations[0].statement.head_generation)
        || BigInt(statement.head_generation) < BigInt(retained.minimum_head_generation)) fail('backup_below_witness');
      if (observations.length === 2) fail('backup_witness_checkpoint_ambiguous');
      if (JSON.stringify(statement) !== JSON.stringify(observations[0].statement)) fail('backup_witness_statement_mismatch');
    },
  });
  try {
    live.check(); await root.check();
    try { lock = await open(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
    catch (error) { if (error.code === 'EEXIST') fail('backup_witness_locked'); throw error; }
    lockIdentity = await lock.stat({ bigint: true });
    await lock.writeFile(encode({ type: 'repository_backup_witness_lock_v1', pid: process.pid, token: randomBytes(16).toString('hex') }));
    await lock.sync(); await root.handle.sync();
    original = await readState(statePath, live);
    ({ observations, retained, trusted } = await decodeState(original, key, policy, live));
    if (policy.minimum_head_generation !== retained.minimum_head_generation) await persist(observations, policy);
    result = await action(witness);
    // No deadline/expiry check after a callback may have confirmed native publication.
  } catch (caught) {
    problem = caught instanceof Error ? caught : backupError('backup_witness_callback_failed');
    problem.witness = view();
  } finally {
    // Stop accepting new work, but let an already owned observation finish its
    // authenticated persistence before closing the lifetime or releasing its lease.
    closing = true;
    try { await pending; } catch (error) {
      if (!problem) {
        problem = error;
        if (result !== undefined) { problem.completed_result = result; problem.state = result?.state ?? 'selection_complete'; }
      }
      problem.witness = view();
    }
    closed = true;
    try {
      if (lockIdentity) {
        if (poisoned || problem?.code === 'native_import_containment_failed' || problem?.code === 'native_process_containment_failed') {
          problem ??= backupError('backup_witness_persistence_failed');
          problem.witness = view();
          problem.witness_lock_retained = true;
        } else {
          await root.check(); const named = await lstat(lockPath, { bigint: true });
          if (!named.isFile() || !same(named, lockIdentity)) fail('backup_witness_lock_changed');
          await unlink(lockPath); await root.handle.sync();
        }
      }
    } catch (cleanup) {
      if (problem) { problem.witness_cleanup_error = cleanup.code ?? 'backup_witness_cleanup_failed'; problem.witness_lock_retained = true; }
      else { problem = cleanup; problem.completed_result = result; problem.state = result?.state ?? 'selection_complete'; problem.witness = view(); }
    } finally {
      for (const handle of [lock, root.handle]) {
        try { await handle?.close(); } catch (error) {
          if (problem) problem.witness_cleanup_error = error.code ?? 'backup_witness_close_failed';
          else { problem = error; problem.completed_result = result; problem.state = result?.state ?? 'selection_complete'; problem.witness = view(); }
        }
      }
    }
  }
  if (problem) throw problem;
  return result;
}
