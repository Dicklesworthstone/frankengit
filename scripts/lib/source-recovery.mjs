// Trusted-local source recovery into a NEW disposable bare Git materialization.
// This is not native authority/capsule restore. Repository names never become
// filesystem paths, and no Git executable, hook, config include or network runs.
import { mkdir, open, lstat, realpath, link, unlink, opendir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, dirname, basename, join } from 'node:path';
import { webcrypto, randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { prepareNativeGitBundleRecovery } from './native-source-layout.mjs';

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
async function writeNew(path, bytes, check, created = () => {}, advanced = async () => {}) {
  check(); const handle = await open(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | flags, 0o600);
  let identity;
  try {
    identity = await handle.stat(); created(identity); let offset = 0;
    while (offset < bytes.length) {
      check(); const { bytesWritten } = await handle.write(bytes, offset, Math.min(65536, bytes.length - offset), offset);
      if (!bytesWritten) failure('recovery_write_stalled'); offset += bytesWritten;
      await advanced(offset);
    }
    check(); await handle.sync();
  } finally { await handle.close(); }
  await verifyFile(path, bytes, check, identity); return identity;
}

// Append-only ownership slots avoid a stale-lock unlink race. A complete lease
// is atomically linked into its sequence slot; a same-inode .done link releases
// it. Dead owners are superseded, never removed by competing contenders. This
// trusted-local profile requires the same host and PID namespace across runs.
const OWNERS = '.frankengit-source-recovery-owners';
const MAX_OWNERS = 128, MAX_OWNER_ENTRIES = MAX_OWNERS * 3;
const encode = value => new TextEncoder().encode(value);
const privateStat = stat => {
  if ((stat.mode & 0o077) || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) failure('recovery_permissions_or_owner');
};
async function maybeStat(path) {
  try { return await lstat(path); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
async function entriesBounded(path, maximum, check) {
  const entries = [], directory = await opendir(path, { encoding: 'buffer' });
  try {
    while (true) {
      check(); const entry = await directory.read(); if (!entry) break;
      if (entries.length === maximum) failure('recovery_directory_entry_limit');
      // All local layout names are fixed ASCII; native ref bytes never appear here.
      const bytes = Buffer.from(entry.name);
      if (bytes.some(byte => byte > 127)) failure('unexpected_recovery_entry');
      entries.push(bytes.toString('ascii'));
    }
  } finally { await directory.close(); }
  return entries.sort();
}
async function smallFile(path, maximum, check) {
  check(); const handle = await open(path, constants.O_RDONLY | flags);
  try {
    const before = await handle.stat(); privateStat(before);
    if (!before.isFile() || before.size < 1 || before.size > maximum) failure('invalid_recovery_owner_record');
    const bytes = new Uint8Array(before.size); let offset = 0;
    while (offset < bytes.length) {
      check(); const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) failure('recovery_file_changed'); offset += bytesRead;
    }
    const after = await handle.stat(), current = await lstat(path);
    if (!same(before, after) || !same(before, current) || !current.isFile() || before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) failure('recovery_file_changed');
    return { bytes, identity: after };
  } finally { await handle.close(); }
}
function ownerRecord(bytes, plan, sequence = null) {
  let row;
  try { row = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { failure('invalid_recovery_owner_record'); }
  const fields = ['schema', 'hostname', 'pid', 'nonce', 'plan_sha256', ...(sequence === null ? [] : ['sequence'])];
  if (!row || typeof row !== 'object' || Array.isArray(row) || Object.keys(row).length !== fields.length ||
      Object.keys(row).some(key => !fields.includes(key)) || row.schema !== (sequence === null ? 'frankengit-source-recovery-lock-v1' : 'frankengit-source-recovery-owner-v1') ||
      row.plan_sha256 !== plan.plan_sha256 || typeof row.hostname !== 'string' || !row.hostname || row.hostname.length > 256 ||
      !Number.isSafeInteger(row.pid) || row.pid < 1 || row.pid > 0x7fffffff ||
      typeof row.nonce !== 'string' || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(row.nonce) ||
      (sequence !== null && row.sequence !== sequence)) failure('invalid_recovery_owner_record');
  return row;
}
function requireDead(row) {
  if (row.hostname !== hostname()) failure('recovery_owner_host_mismatch');
  try { process.kill(row.pid, 0); } catch (error) { if (error.code === 'ESRCH') return; failure('recovery_owner_liveness_unknown'); }
  failure('recovery_owner_active');
}
async function ownerState(path, plan, check) {
  const identity = await maybeStat(path); if (!identity) return { identity: null, sequence: 0, entryCount: 0 };
  if (!identity.isDirectory()) failure('recovery_directory_changed'); privateStat(identity);
  const names = await entriesBounded(path, MAX_OWNER_ENTRIES, check), leases = [], done = new Set();
  for (const name of names) {
    check(); const stat = await lstat(join(path, name)); privateStat(stat);
    if (!stat.isFile() || stat.nlink < 1 || stat.nlink > 3) failure('invalid_recovery_owner_record');
    const installed = /^([0-9]{6})\.(lease|done)$/.exec(name);
    if (installed) {
      const sequence = Number(installed[1]);
      if (sequence < 1 || sequence > MAX_OWNERS) failure('recovery_owner_limit');
      if (installed[2] === 'lease') leases.push({ name, sequence }); else done.add(sequence);
    } else if (!/^candidate-[1-9][0-9]{0,9}-[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(name) || stat.size > 1024) {
      failure('unexpected_recovery_entry');
    }
    // A partial candidate is inert: only a complete, atomically linked numbered
    // lease grants writer ownership. Interrupted candidates are retained/bounded.
  }
  let latest = null;
  for (let i = 0; i < leases.length; i++) {
    const lease = leases[i]; if (lease.sequence !== i + 1) failure('recovery_owner_sequence_gap');
    const original = await smallFile(join(path, lease.name), 1024, check);
    const row = ownerRecord(original.bytes, plan, lease.sequence);
    if (done.has(lease.sequence)) {
      const released = await lstat(join(path, `${String(lease.sequence).padStart(6, '0')}.done`));
      if (!released.isFile() || !same(released, original.identity)) failure('recovery_owner_release_mismatch');
      done.delete(lease.sequence);
    } else if (i === leases.length - 1) requireDead(row);
    latest = { ...original, row };
  }
  if (done.size) failure('recovery_owner_release_mismatch');
  return { identity, sequence: leases.length, latest, entryCount: names.length };
}
async function inventory(target, plan, receiptBytes, check) {
  const allowedDirectories = new Set(plan.directories), files = new Map(plan.files.map(file => [file.path, file.bytes]));
  files.set(MARKER, receiptBytes); files.set(HEAD_STAGE, files.get('HEAD'));
  const directories = new Map(), found = new Map(), root = await checkedDirectory(target); privateStat(root);
  const visit = async relative => {
    const path = relative ? join(target, relative) : target, stat = await checkedDirectory(path); privateStat(stat); directories.set(path, stat);
    for (const name of await entriesBounded(path, relative ? 8 : 12, check)) {
      const child = relative ? `${relative}/${name}` : name, childPath = join(target, child), stat = await lstat(childPath); privateStat(stat);
      if (allowedDirectories.has(child)) { if (!stat.isDirectory()) failure('recovery_directory_changed'); await visit(child); }
      else if (files.has(child)) {
        if (!stat.isFile() || stat.size > files.get(child).length || stat.nlink < 1 ||
            stat.nlink > (['HEAD', HEAD_STAGE].includes(child) ? 2 : 1)) failure('recovery_file_changed');
        found.set(child, { identity: stat, bytes: files.get(child) });
      } else if (!relative && name === LOCK) {
        if (!stat.isFile() || stat.size > 1024 || stat.nlink !== 1) failure('invalid_recovery_owner_record');
      } else if (!relative && name === OWNERS) {
        if (!stat.isDirectory()) failure('recovery_directory_changed');
      } else failure('unexpected_recovery_entry');
    }
  };
  await visit('');
  return { directories, found };
}
async function validateExisting(path, expected, identity, check, complete) {
  if (complete && identity.size !== expected.length) failure('published_recovery_incomplete');
  await verifyFile(path, expected.subarray(0, identity.size), check, identity);
}
async function appendVerified(path, expected, prior, check, advanced) {
  if (!prior) return { identity: await writeNew(path, expected, check, () => {}, advanced), reused: 0, appended: expected.length };
  await validateExisting(path, expected, prior.identity, check, false);
  const reused = prior.identity.size;
  if (reused === expected.length) {
    // A crash can leave a complete-length file before its fsync. Reuse bytes,
    // not the old process's assertion that those bytes reached durable storage.
    const handle = await open(path, constants.O_RDONLY | flags);
    try { if (!same(await handle.stat(), prior.identity)) failure('recovery_file_changed'); check(); await handle.sync(); }
    finally { await handle.close(); }
    return { identity: await verifyFile(path, expected, check, prior.identity), reused, appended: 0 };
  }
  if (prior.identity.nlink !== 1) failure('recovery_file_changed');
  check(); const handle = await open(path, constants.O_RDWR | flags);
  try {
    const stat = await handle.stat();
    if (!same(stat, prior.identity) || stat.size !== reused || stat.mtimeMs !== prior.identity.mtimeMs || stat.ctimeMs !== prior.identity.ctimeMs) failure('recovery_file_changed');
    let offset = reused;
    while (offset < expected.length) {
      check(); const { bytesWritten } = await handle.write(expected, offset, Math.min(65536, expected.length - offset), offset);
      if (!bytesWritten) failure('recovery_write_stalled'); offset += bytesWritten;
      await advanced(offset);
    }
    check(); await handle.sync();
  } finally { await handle.close(); }
  return { identity: await verifyFile(path, expected, check, prior.identity), reused, appended: expected.length - reused };
}
async function resumePlan(plan, target, parent, parentIdentity, check, progress, signal, ownRelease, setState, onProgress) {
  const receiptBytes = encode(JSON.stringify({ ...plan.receipt, plan_sha256: plan.plan_sha256 }) + '\n');
  let observed = await inventory(target, plan, receiptBytes, check);
  const rootIdentity = observed.directories.get(target), checkRoot = () => checkedDirectory(target, rootIdentity);
  const legacy = await maybeStat(join(target, LOCK));
  let legacyRecord = null;
  if (legacy) { legacyRecord = await smallFile(join(target, LOCK), 1024, check); ownerRecord(legacyRecord.bytes, plan); }
  const ownersPath = join(target, OWNERS), owners = await ownerState(ownersPath, plan, check);
  // A complete regenerated marker, or the exact dead original owner record,
  // establishes that this is this operation's staging area, not a random repo.
  const marker = observed.found.get(MARKER);
  if (!marker || marker.identity.size !== receiptBytes.length) {
    if (!legacyRecord) failure('recovery_receipt_missing_or_partial');
  }
  if (!owners.sequence && legacyRecord) requireDead(ownerRecord(legacyRecord.bytes, plan));
  const alreadyPublished = observed.found.has('HEAD');
  for (const [relative, file] of observed.found) await validateExisting(join(target, relative), file.bytes, file.identity, check, alreadyPublished);
  if (alreadyPublished) {
    if (!marker || plan.files.some(file => !observed.found.has(file.path)) ||
        plan.directories.some(dir => !observed.directories.has(join(target, dir)))) failure('published_recovery_incomplete');
    setState('published');
  } else setState('staging');
  if (owners.sequence >= MAX_OWNERS || owners.entryCount + 3 > MAX_OWNER_ENTRIES) failure('recovery_owner_limit');
  check(); await checkRoot();
  if (!owners.identity) {
    try { await mkdir(ownersPath, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  }
  const ownerDirectory = await checkedDirectory(ownersPath, owners.identity); privateStat(ownerDirectory);
  const sequence = owners.sequence + 1, slot = String(sequence).padStart(6, '0'), nonce = randomUUID();
  const candidate = join(ownersPath, `candidate-${process.pid}-${nonce}`), lease = join(ownersPath, `${slot}.lease`), done = join(ownersPath, `${slot}.done`);
  const ownerBytes = encode(JSON.stringify({ schema: 'frankengit-source-recovery-owner-v1', hostname: hostname(),
    pid: process.pid, nonce, plan_sha256: plan.plan_sha256, sequence }) + '\n');
  const candidateIdentity = await writeNew(candidate, ownerBytes, check);
  let acquired = false, released = false;
  try {
    await checkRoot(); await checkedDirectory(ownersPath, ownerDirectory); check();
    await link(candidate, lease); acquired = true;
    ownRelease(async () => {
      if (released) return;
      await checkRoot(); await checkedDirectory(ownersPath, ownerDirectory);
      await verifyFile(lease, ownerBytes, () => {}, candidateIdentity);
      await link(lease, done); released = true;
      await syncDirectory(ownersPath, ownerDirectory); await syncDirectory(target, rootIdentity);
    });
    await syncDirectory(ownersPath, ownerDirectory); await syncDirectory(target, rootIdentity);
  } finally {
    // Never delete installed sequence slots, another contender's lease, or an
    // interrupted candidate we did not create. This unlink targets our inode.
    const stat = await lstat(candidate);
    if (!stat.isFile() || !same(stat, candidateIdentity)) failure('recovery_owner_candidate_changed');
    await unlink(candidate);
  }
  if (!acquired) failure('recovery_owner_not_acquired');
  const checkLease = async () => {
    await checkRoot(); await checkedDirectory(ownersPath, ownerDirectory);
    await verifyFile(lease, ownerBytes, check, candidateIdentity);
    if (await maybeStat(done)) failure('recovery_owner_released_early');
  };
  await checkLease();
  // Re-read under the exclusive lease. A previous validation is not write authority.
  observed = await inventory(target, plan, receiptBytes, check);
  if (observed.found.has('HEAD') !== alreadyPublished) { setState('existing_unknown'); failure('recovery_publication_changed'); }
  for (const [relative, file] of observed.found) await validateExisting(join(target, relative), file.bytes, file.identity, check, alreadyPublished);
  if (legacyRecord) {
    await verifyFile(join(target, LOCK), legacyRecord.bytes, check, legacyRecord.identity);
    await unlink(join(target, LOCK)); await syncDirectory(target, rootIdentity);
  }
  await progress('resuming');
  let reusedBytes = 0, appendedBytes = 0;
  const keep = async (relative, bytes) => {
    await checkLease(); await checkRoot(); const parentPath = dirname(join(target, relative));
    await checkedDirectory(parentPath, observed.directories.get(parentPath));
    const result = await appendVerified(join(target, relative), bytes, observed.found.get(relative), check, written => progress(`writing:${relative}`, { written, total: bytes.length }));
    reusedBytes += result.reused; appendedBytes += result.appended;
    observed.found.set(relative, { identity: result.identity, bytes }); return result.identity;
  };
  await keep(MARKER, receiptBytes);
  for (const relative of plan.directories) {
    check(); await checkRoot(); const path = join(target, relative);
    if (!observed.directories.has(path)) {
      await checkLease(); await checkedDirectory(dirname(path), observed.directories.get(dirname(path)));
      await mkdir(path, { mode: 0o700 }); observed.directories.set(path, await checkedDirectory(path));
    }
  }
  for (const file of plan.files) {
    if (file.path === 'HEAD' && alreadyPublished) { await keep('HEAD', file.bytes); continue; }
    await progress(`before:${file.path}`);
    await keep(file.path === 'HEAD' ? HEAD_STAGE : file.path, file.bytes);
    await progress(`staged:${file.path}`);
  }
  for (const [path, identity] of [...observed.directories].reverse()) { check(); await syncDirectory(path, identity); }
  if (!alreadyPublished) {
    await progress('before_publication');
    const final = await inventory(target, plan, receiptBytes, check);
    for (const [relative, file] of final.found) await validateExisting(join(target, relative), file.bytes, file.identity, check, true);
    if (final.found.has('HEAD') || plan.files.some(file => !final.found.has(file.path === 'HEAD' ? HEAD_STAGE : file.path))) { setState('existing_unknown'); failure('recovery_publication_changed'); }
    for (const [path, identity] of observed.directories) await checkedDirectory(path, identity);
    await checkLease();
    await progress('publication_ready');
    check(); setState('publication_unknown');
    await link(join(target, HEAD_STAGE), join(target, 'HEAD')); setState('published');
  }
  let observerError = null;
  try { await onProgress(Object.freeze({ phase: alreadyPublished ? 'already_published' : 'published', destination: target })); }
  catch (error) { observerError = { error }; }
  // Finish an already-visible operation without cancellation-induced rollback.
  await syncDirectory(target, rootIdentity); await syncDirectory(parent, parentIdentity);
  const headBytes = plan.files.find(file => file.path === 'HEAD').bytes;
  const headIdentity = await verifyFile(join(target, 'HEAD'), headBytes, () => {});
  const staged = await maybeStat(join(target, HEAD_STAGE));
  if (staged) {
    if (!same(staged, headIdentity)) failure('recovery_head_identity_changed');
    await verifyFile(join(target, HEAD_STAGE), headBytes, () => {}, headIdentity); await unlink(join(target, HEAD_STAGE));
  }
  await syncDirectory(target, rootIdentity);
  if (observerError !== null) throw observerError.error;
  return { type: 'frankengit-source-recovery-v1', state: 'complete', destination: target, bare: true,
    resumed: true, already_published: alreadyPublished, owner_sequence: sequence, reused_bytes: reusedBytes, appended_bytes: appendedBytes,
    head_ref_hex: plan.receipt.head_ref_hex, plan_sha256: plan.plan_sha256,
    files_synced: true, directories_synced: true, cancellation_requested: Boolean(signal?.aborted),
    verification: plan.verification, forge_state_restored: false, native_authority_restored: false };
}

// Copy only bounded, plain request data. This is not Git ref/expectation
// semantics; the legacy preparer still validates its complete original grammar.
function captureLegacyRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some(key => !['head_ref_hex', 'expectations'].includes(key))
    || typeof value.head_ref_hex !== 'string' || value.head_ref_hex.length > 8192) failure('invalid_recovery_request');
  const captured = { ...value };
  if (Object.hasOwn(value, 'expectations')) {
    const expected = value.expectations;
    if (!expected || typeof expected !== 'object' || Array.isArray(expected)
      || Object.keys(expected).some(key => !['sha256', 'object_format', 'refs', 'exact_refs'].includes(key))) failure('invalid_recovery_request');
    for (const key of ['sha256', 'object_format', 'exact_refs']) {
      if (Object.hasOwn(expected, key) && !['string', 'boolean'].includes(typeof expected[key])) failure('invalid_recovery_request');
      if (typeof expected[key] === 'string' && expected[key].length > 128) failure('invalid_recovery_request');
    }
    captured.expectations = { ...expected };
    if (Object.hasOwn(expected, 'refs')) {
      if (!Array.isArray(expected.refs) || expected.refs.length > 4096) failure('invalid_recovery_request');
      let bytes = 0;
      captured.expectations.refs = expected.refs.map(row => {
        if (!row || typeof row !== 'object' || Array.isArray(row)
          || Object.keys(row).some(key => !['ref_hex', 'object_id'].includes(key))
          || typeof row.ref_hex !== 'string' || typeof row.object_id !== 'string'
          || row.ref_hex.length > 8192 || row.object_id.length > 128
          || (bytes += row.ref_hex.length + row.object_id.length) > 2 * 1024 * 1024) failure('invalid_recovery_request');
        return { ...row };
      });
    }
  }
  return captured;
}

// Every invocation re-verifies the supplied bundle; a saved JSON report cannot
// substitute for verified objects. The parent directory is operator-controlled
// and must remain quiescent: Node's path APIs are not an openat-based sandbox.
export async function recoverGitBundle(input, destination, request, options = {}) {
  let state = 'not_created', target = null, releaseLock = null;
  try {
    if (!options || typeof options !== 'object' || Array.isArray(options) ||
        Object.keys(options).some(key => !['signal', 'timeoutMs', 'verificationLimits', 'onProgress', 'resume', 'nativeFg', 'nativeApprovalBinding'].includes(key))) failure('invalid_recovery_options');
    const { signal, onProgress = () => {}, timeoutMs = 60000, verificationLimits = {}, resume = false } = options;
    if (typeof resume !== 'boolean' || (signal !== undefined && !(signal instanceof AbortSignal)) || typeof onProgress !== 'function' ||
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
    let plan;
    if (Object.hasOwn(options, 'nativeFg')) {
      // An explicitly selected native backend never imports the legacy decoder,
      // falls back, or accepts legacy-only verification limits silently.
      if (Object.hasOwn(options, 'verificationLimits')) failure('native_recovery_limits_not_supported');
      if (resume) state = 'existing_unknown';
      plan = await prepareNativeGitBundleRecovery(input, request,
        { fg: options.nativeFg, signal, timeoutMs,
          ...(Object.hasOwn(options, 'nativeApprovalBinding') ? { approvalBinding: options.nativeApprovalBinding } : {}) });
    } else {
      if (Object.hasOwn(options, 'nativeApprovalBinding')) failure('native_recovery_backend_required');
      // Preserve owned input across the lazy import. Bound/copy plain request
      // data before yielding; semantic validation remains with the old engine.
      if (!(input instanceof Uint8Array) || !input.length || input.length > 16 * 1024 * 1024
        || input.buffer instanceof SharedArrayBuffer) failure('recovery_input_limit');
      const captured = Buffer.from(input), query = captureLegacyRequest(request);
      const { prepareGitBundleRecovery } = await import('../../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs');
      check();
      plan = await prepareGitBundleRecovery(captured, query, { cryptoImpl: webcrypto, signal,
        checkpoint: check, limits: verificationLimits });
    }
    check();
    const requested = resolve(destination), parent = await realpath(dirname(requested));
    if (dirname(requested) === requested) failure('invalid_recovery_destination');
    target = join(parent, basename(requested));
    const parentIdentity = await checkedDirectory(parent);
    const progress = async (phase, details = {}) => { await onProgress(Object.freeze({ phase, destination: target, ...details })); check(); };
    await progress('verified');
    if (resume) {
      state = 'existing_unknown';
      const result = await resumePlan(plan, target, parent, parentIdentity, check, progress, signal,
        release => { releaseLock = release; }, value => { state = value; }, onProgress);
      await releaseLock(); state = 'complete'; return result;
    }
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
      const identity = await writeNew(join(target, relative), file.bytes, check, () => {}, written => progress(`writing:${file.path}`, { written, total: file.bytes.length }));
      installed.push({ path: relative, bytes: file.bytes, identity });
      await progress(`staged:${file.path}`);
    }
    for (const [path, identity] of [...directories].reverse()) { check(); await syncDirectory(path, identity); }
    await progress('before_publication');
    await checkRoot();
    for (const file of installed) await verifyFile(join(target, file.path), file.bytes, check, file.identity);
    await verifyFile(join(target, MARKER), receiptBytes, check);
    for (const [path, identity] of directories) { check(); await checkedDirectory(path, identity); }
    await progress('publication_ready');
    check(); state = 'publication_unknown';
    // A hard-link install is atomic and fails if HEAD already exists. Do not
    // use rename(), which can replace another writer's destination on POSIX.
    await link(join(target, HEAD_STAGE), join(target, 'HEAD')); state = 'published';
    // Publication acquired responsibility. Drain/finalize despite cancellation;
    // failures now report published, never pretend to roll the repository back.
    let observerError = null;
    try { await onProgress(Object.freeze({ phase: 'published', destination: target })); }
    catch (error) { observerError = { error }; }
    await syncDirectory(target, rootIdentity); await syncDirectory(parent, parentIdentity);
    const head = installed.find(file => file.path === HEAD_STAGE);
    await verifyFile(join(target, 'HEAD'), head.bytes, () => {}, head.identity);
    await verifyFile(join(target, HEAD_STAGE), head.bytes, () => {}, head.identity);
    await unlink(join(target, HEAD_STAGE)); await syncDirectory(target, rootIdentity);
    await releaseLock(); state = 'complete';
    if (observerError !== null) throw observerError.error;
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
