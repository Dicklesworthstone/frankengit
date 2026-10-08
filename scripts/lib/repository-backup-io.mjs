// Trusted-local, bounded operator I/O. Never a parser or repository authority.
import { constants } from 'node:fs';
import { open, lstat, link, unlink, realpath } from 'node:fs/promises';
import { dirname, basename, join, resolve } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';

export const BACKUP_LIMITS = Object.freeze({ maximumBytes: 1024 ** 3, timeoutMs: 300000,
  envelopeBytes: 16384, keyBytes: 8192, maximumArchiveBytes: 1024 ** 4 });
export function backupError(code) { const e = new Error(code); e.code = code; return e; }
export function exact(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
}
export function backupPath(path) {
  if (typeof path !== 'string' || !path || path.length > 4096 || /[\0\r\n\uD800-\uDFFF]/u.test(path)) throw backupError('backup_invalid_path');
  return path;
}
export function backupLifetime(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)
    || Object.keys(options).some(k => !['maximumBytes', 'timeoutMs', 'signal', 'now', 'onProgress'].includes(k))) throw backupError('backup_invalid_options');
  const maximumBytes = options.maximumBytes ?? BACKUP_LIMITS.maximumBytes;
  const timeoutMs = options.timeoutMs ?? BACKUP_LIMITS.timeoutMs, signal = options.signal;
  const onProgress = options.onProgress ?? (() => {}), fixed = options.now;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > BACKUP_LIMITS.maximumArchiveBytes
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3600000
    || (signal !== undefined && !(signal instanceof AbortSignal)) || typeof onProgress !== 'function'
    || (fixed !== undefined && (!Number.isSafeInteger(fixed) || fixed < 0 || fixed > 253402300799999))) throw backupError('backup_invalid_options');
  const until = performance.now() + timeoutMs, now = () => fixed ?? Date.now();
  const check = () => {
    if (signal?.aborted) throw backupError('backup_cancelled');
    if (performance.now() >= until) throw backupError('backup_deadline');
  };
  check(); return { maximumBytes, signal, now, check, onProgress,
    remaining: () => Math.max(1, Math.ceil(until - performance.now())) };
}
const fields = ['dev', 'ino', 'size', 'mode', 'uid', 'nlink', 'mtimeNs', 'ctimeNs'];
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const sameFile = (a, b) => fields.every(k => a[k] === b[k]);
function supported() {
  if (constants.O_NOFOLLOW === undefined || constants.O_NONBLOCK === undefined
    || constants.O_DIRECTORY === undefined || typeof process.getuid !== 'function') throw backupError('backup_unsupported_filesystem');
}
function privateOwner(stat) {
  if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n) !== 0n) throw backupError('backup_private_owner_required');
}
async function scan(path, maximum, live, consume, privateKey = false) {
  supported(); backupPath(path); live.check();
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const buffer = Buffer.alloc(65536);
  try {
    const before = await file.stat({ bigint: true }); live.check();
    if (!before.isFile() || before.size < 1n || before.size > BigInt(maximum)) throw backupError('backup_file_size_or_type');
    if (privateKey) { privateOwner(before); if (before.nlink !== 1n) throw backupError('backup_private_key_links'); }
    let offset = 0, reads = 0, maximumRead = 0;
    while (offset < Number(before.size)) {
      live.check();
      const { bytesRead } = await file.read(buffer, 0, Math.min(buffer.length, Number(before.size) - offset), offset);
      live.check(); if (!bytesRead) throw backupError('backup_file_changed');
      consume(buffer.subarray(0, bytesRead)); offset += bytesRead; reads++; maximumRead = Math.max(maximumRead, bytesRead);
      if (!privateKey) await live.onProgress(Object.freeze({ bytes_read: offset, total_bytes: Number(before.size) }));
      live.check();
    }
    if ((await file.read(buffer, 0, 1, offset)).bytesRead) throw backupError('backup_file_changed');
    const after = await file.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    if (!named.isFile() || !sameFile(before, after) || !sameFile(after, named)) throw backupError('backup_file_changed');
    live.check(); return { bytes: String(offset), read_calls: reads, maximum_read_bytes: maximumRead };
  } finally { buffer.fill(0); await file.close(); }
}
export async function hashRepositoryBackup(path, live) {
  const digest = createHash('sha256');
  const result = await scan(path, live.maximumBytes, live, bytes => digest.update(bytes));
  return { ...result, sha256: digest.digest('hex') };
}
export async function readBackupControl(path, maximum, live, privateKey = false) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > BACKUP_LIMITS.envelopeBytes) throw backupError('backup_control_limit');
  const chunks = [];
  try {
    await scan(path, maximum, { ...live, onProgress: () => {} }, bytes => chunks.push(Buffer.from(bytes)), privateKey);
    return Buffer.concat(chunks);
  } finally { for (const chunk of chunks) chunk.fill(0); }
}
// New control files publish by no-replace hard link after sync and readback.
// A failed post-publication observer/cancellation cannot undo a visible file.
export async function publishBackupControl(path, bytes, live) {
  supported(); backupPath(path); live.check();
  if (!(bytes instanceof Uint8Array) || bytes.buffer instanceof SharedArrayBuffer
    || !bytes.length || bytes.length > BACKUP_LIMITS.envelopeBytes) throw backupError('backup_control_limit');
  const owned = Buffer.from(bytes), requested = resolve(path);
  const parent = await realpath(dirname(requested)), destination = join(parent, basename(requested));
  const temporary = join(parent, `.fg-backup-approval-${randomBytes(16).toString('hex')}.tmp`);
  let directory, file, identity, parentIdentity, state = 'not_created', failure;
  async function checkParent() {
    const named = await lstat(parent, { bigint: true }), opened = await directory.stat({ bigint: true });
    if (!named.isDirectory() || !same(named, opened) || !same(opened, parentIdentity)) throw backupError('backup_parent_changed');
    privateOwner(named);
  }
  async function removeOwned() {
    if (!identity) return;
    await checkParent(); const current = await lstat(temporary, { bigint: true });
    if (!current.isFile() || !same(current, identity)) throw backupError('backup_temporary_changed');
    await unlink(temporary); identity = null;
  }
  try {
    directory = await open(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    parentIdentity = await directory.stat({ bigint: true }); await checkParent(); live.check();
    file = await open(temporary, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    identity = await file.stat({ bigint: true }); state = 'staging';
    await file.writeFile(owned); await file.sync(); live.check();
    const readback = await readBackupControl(temporary, BACKUP_LIMITS.envelopeBytes, live);
    if (!owned.equals(readback)) throw backupError('backup_control_readback');
    await checkParent(); live.check(); state = 'publication_unknown';
    try { await link(temporary, destination); }
    catch (error) { if (error.code === 'EEXIST') state = 'not_created'; throw error; }
    state = 'published';
    await directory.sync(); await removeOwned(); await directory.sync(); await checkParent();
    const final = await lstat(destination, { bigint: true }), opened = await file.stat({ bigint: true });
    if (!final.isFile() || !sameFile(final, opened) || final.nlink !== 1n) throw backupError('backup_published_file_changed');
    return { path: destination, state: 'complete', sha256: createHash('sha256').update(owned).digest('hex') };
  } catch (error) {
    failure = error; error.publication_state = state;
    try { await removeOwned(); } catch { error.cleanup_error = 'backup_control_cleanup_failed'; }
    throw error;
  } finally {
    let closeFailure;
    for (const handle of [file, directory]) {
      try { await handle?.close(); } catch (error) {
        if (failure) failure.cleanup_error = 'backup_control_close_failed';
        else closeFailure ??= error;
      }
    }
    // A close-only failure is not allowed to turn a visible output into success.
    if (closeFailure) { closeFailure.publication_state = state; throw closeFailure; }
  }
}
