// Trusted-local source recovery into a NEW disposable bare Git materialization.
// This is not native authority/capsule restore. Repository names never become
// filesystem paths, and no Git executable, hook, config include or network runs.
import { mkdir, open, lstat, realpath, link, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, dirname, basename, join } from 'node:path';
import { webcrypto, randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { prepareGitBundleRecovery } from '../../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';

export class SourceRecoveryError extends Error {
  constructor(code, state, destination, cause = null) {
    super(`Source recovery ${state}: ${code}`, { cause }); this.name = 'SourceRecoveryError';
    this.code = code; this.state = state; this.destination = destination;
  }
}
const LOCK = '.frankengit-source-recovery.lock';
const MARKER = '.frankengit-source-recovery.json', HEAD_STAGE = '.frankengit-source-recovery-head';
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const failure = code => { const error = new Error(code); error.code = code; throw error; };
const flags = constants.O_NOFOLLOW | constants.O_NONBLOCK;

async function checkedDirectory(path, identity) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || (identity && !same(stat, identity))) failure('recovery_directory_changed');
  return stat;
}
async function syncDirectory(path, identity) {
  await checkedDirectory(path, identity);
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | flags);
  try {
    if (!same(await handle.stat(), identity)) failure('recovery_directory_changed');
    await handle.sync();
  } finally { await handle.close(); }
}
async function verifyFile(path, expected, check, identity = null) {
  check();
  const handle = await open(path, constants.O_RDONLY | flags);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size !== expected.length || (identity && !same(before, identity))) failure('recovery_file_changed');
    const buffer = new Uint8Array(Math.min(65536, expected.length)); let offset = 0;
    while (offset < expected.length) {
      check(); const count = Math.min(buffer.length, expected.length - offset);
      const { bytesRead } = await handle.read(buffer, 0, count, offset);
      if (!bytesRead || !buffer.subarray(0, bytesRead).every((byte, index) => byte === expected[offset + index])) failure('recovery_file_mismatch');
      offset += bytesRead;
    }
    const after = await handle.stat(), pathStat = await lstat(path);
    if (!same(before, after) || !same(after, pathStat) || !pathStat.isFile() ||
        after.size !== expected.length || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) failure('recovery_file_changed');
    check(); return after;
  } finally { await handle.close(); }
}
async function writeNew(path, bytes, check, created = () => {}) {
  check(); const handle = await open(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | flags, 0o600);
  let identity;
  try {
    identity = await handle.stat(); created(identity); let offset = 0;
    while (offset < bytes.length) {
      check(); const { bytesWritten } = await handle.write(bytes, offset, Math.min(65536, bytes.length - offset), offset);
      if (!bytesWritten) failure('recovery_write_stalled'); offset += bytesWritten;
    }
    check(); await handle.sync();
  } finally { await handle.close(); }
  await verifyFile(path, bytes, check, identity); return identity;
}

// Every invocation re-verifies the supplied bundle; a saved JSON report cannot
// substitute for verified objects. The parent directory is operator-controlled
// and must remain quiescent: Node's path APIs are not an openat-based sandbox.
export async function recoverGitBundle(input, destination, request, options = {}) {
  let state = 'not_created', target = null, releaseLock = null;
  try {
    if (!options || typeof options !== 'object' || Array.isArray(options) ||
        Object.keys(options).some(key => !['signal', 'timeoutMs', 'verificationLimits', 'onProgress'].includes(key))) failure('invalid_recovery_options');
    const { signal, onProgress = () => {}, timeoutMs = 60000, verificationLimits = {} } = options;
    if ((signal !== undefined && !(signal instanceof AbortSignal)) || typeof onProgress !== 'function' ||
        !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) failure('invalid_recovery_options');
    if (typeof destination !== 'string' || !destination || destination.length > 4096 ||
        destination.includes('\0') || /[\uD800-\uDFFF]/u.test(destination)) failure('invalid_recovery_destination');
    if (constants.O_NOFOLLOW === undefined || constants.O_DIRECTORY === undefined) failure('recovery_filesystem_profile_unsupported');
    const deadline = performance.now() + timeoutMs;
    const check = () => {
      if (signal?.aborted) failure('recovery_cancelled');
      if (performance.now() >= deadline) failure('recovery_deadline');
    };
    check();
    const plan = await prepareGitBundleRecovery(input, request, { cryptoImpl: webcrypto, signal,
      checkpoint: check, limits: verificationLimits });
    check();
    const requested = resolve(destination), parent = await realpath(dirname(requested));
    if (dirname(requested) === requested) failure('invalid_recovery_destination');
    target = join(parent, basename(requested));
    const parentIdentity = await checkedDirectory(parent);
    const progress = async phase => { await onProgress(Object.freeze({ phase, destination: target })); check(); };
    await progress('verified');
    // mkdir is the exclusive reservation. Existing files, directories and even
    // dangling symlinks refuse; no existence-check/rename overwrite window.
    await mkdir(target, { mode: 0o700 }); state = 'staging';
    const directories = new Map([[target, await checkedDirectory(target)]]);
    const rootIdentity = directories.get(target);
    const checkRoot = () => checkedDirectory(target, rootIdentity);
    let lockIdentity = null;
    releaseLock = async () => {
      if (!lockIdentity) return;
      await checkRoot(); const path = join(target, LOCK), current = await lstat(path);
      if (!current.isFile() || !same(current, lockIdentity)) failure('recovery_lock_changed');
      await unlink(path); lockIdentity = null; await syncDirectory(target, rootIdentity);
    };
    const lockBytes = new TextEncoder().encode(JSON.stringify({ schema: 'frankengit-source-recovery-lock-v1',
      hostname: hostname(), pid: process.pid, nonce: randomUUID(), plan_sha256: plan.plan_sha256 }) + '\n');
    await writeNew(join(target, LOCK), lockBytes, check, identity => { lockIdentity = identity; });
    const receiptBytes = new TextEncoder().encode(JSON.stringify({ ...plan.receipt, plan_sha256: plan.plan_sha256 }) + '\n');
    await writeNew(join(target, MARKER), receiptBytes, check);
    await progress('reserved');
    for (const relative of plan.directories) {
      check(); await checkRoot(); const path = join(target, relative);
      await mkdir(path, { mode: 0o700 }); directories.set(path, await checkedDirectory(path));
    }
    const installed = [];
    for (const file of plan.files) {
      const relative = file.path === 'HEAD' ? HEAD_STAGE : file.path;
      await progress(`before:${file.path}`); await checkRoot();
      await checkedDirectory(dirname(join(target, relative)), directories.get(dirname(join(target, relative))));
      const identity = await writeNew(join(target, relative), file.bytes, check);
      installed.push({ path: relative, bytes: file.bytes, identity });
      await progress(`staged:${file.path}`);
    }
    for (const [path, identity] of [...directories].reverse()) { check(); await syncDirectory(path, identity); }
    await progress('before_publication');
    await checkRoot();
    for (const file of installed) await verifyFile(join(target, file.path), file.bytes, check, file.identity);
    await verifyFile(join(target, MARKER), receiptBytes, check);
    for (const [path, identity] of directories) { check(); await checkedDirectory(path, identity); }
    check(); state = 'publication_unknown';
    // A hard-link install is atomic and fails if HEAD already exists. Do not
    // use rename(), which can replace another writer's destination on POSIX.
    await link(join(target, HEAD_STAGE), join(target, 'HEAD')); state = 'published';
    // Publication acquired responsibility. Drain/finalize despite cancellation;
    // failures now report published, never pretend to roll the repository back.
    await onProgress(Object.freeze({ phase: 'published', destination: target }));
    await syncDirectory(target, rootIdentity); await syncDirectory(parent, parentIdentity);
    const head = installed.find(file => file.path === HEAD_STAGE);
    await verifyFile(join(target, 'HEAD'), head.bytes, () => {}, head.identity);
    await verifyFile(join(target, HEAD_STAGE), head.bytes, () => {}, head.identity);
    await unlink(join(target, HEAD_STAGE)); await syncDirectory(target, rootIdentity);
    await releaseLock(); state = 'complete';
    return { type: 'frankengit-source-recovery-v1', state, destination: target, bare: true,
      head_ref_hex: plan.receipt.head_ref_hex, plan_sha256: plan.plan_sha256,
      files_synced: true, directories_synced: true, cancellation_requested: Boolean(signal?.aborted),
      verification: plan.verification, forge_state_restored: false, native_authority_restored: false };
  } catch (error) {
    if (error instanceof SourceRecoveryError) throw error;
    // Keep a partial directory for inspection. Never recursively remove unknown
    // files, retry publication, replace an existing repository, or undo HEAD.
    const result = new SourceRecoveryError(error?.code ?? 'recovery_failed', state, target, error);
    try { await releaseLock?.(); } catch (cleanup) { result.lock_cleanup_error = cleanup.code ?? 'lock_cleanup_failed'; }
    throw result;
  }
}
