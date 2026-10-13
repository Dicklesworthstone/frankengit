// Private, root-last custody for the native candidate capture/inspect CLI.
// These files retain read observations, never approval or repository authority.
import { constants } from 'node:fs';
import { open, lstat, realpath, mkdir, opendir, link, unlink } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { randomBytes } from 'node:crypto';
import { validateCandidateCapture, candidateCanonical, candidateHash } from './pull_candidate_capture.mjs';
import { candidateKeys, candidateJson, candidateToken, candidateFail, CANDIDATE_IO_LIMITS } from './pull_candidate_io.mjs';
import { BUNDLE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';

export const CANDIDATE_PACKAGE_SCHEMA = 'frankengit-pull-candidate-package-v1';
export const CANDIDATE_MANIFEST_LIMIT = 4096;
export function candidateClock(options = {}) {
  candidateKeys(options, ['timeoutMs', 'signal'], []);
  const timeout = options.timeoutMs ?? 30000, signal = options.signal;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300000 ||
      (signal !== undefined && !(signal instanceof AbortSignal))) candidateFail('invalid_candidate_file_options');
  const end = performance.now() + timeout;
  return () => {
    if (signal?.aborted) candidateFail('candidate_cancelled');
    const remaining = Math.ceil(end - performance.now());
    if (remaining <= 0) candidateFail('candidate_timeout');
    return remaining;
  };
}
function privateStat(stat, directory = false) {
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined || constants.O_NONBLOCK === undefined ||
      constants.O_DIRECTORY === undefined) candidateFail('candidate_posix_files_required');
  if (!(directory ? stat.isDirectory() : stat.isFile()) || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o077n) !== 0n || (!directory && stat.nlink !== 1n)) candidateFail('private_owned_candidate_file_required');
}
async function directory(path, check) {
  check(); const absolute = resolve(path);
  if (await realpath(absolute) !== absolute) candidateFail('candidate_directory_alias');
  privateStat(await lstat(absolute, { bigint: true }), true);
  // Operator-owned filesystem profile, not protection against hostile same-UID
  // parent swaps. Candidate bodies and tokens must not enter a Git worktree.
  for (let cursor = absolute;; cursor = dirname(cursor)) {
    check();
    if (cursor.split('/').includes('.git')) candidateFail('candidate_worktree_path');
    try { await lstat(join(cursor, '.git')); candidateFail('candidate_worktree_path'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(cursor) === cursor) break;
  }
  check(); return absolute;
}
const same = (a, b) => a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
async function read(path, maximum, check) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > Math.max(BUNDLE_LIMIT, CANDIDATE_IO_LIMITS.capture)) candidateFail('candidate_file_limit');
  const absolute = resolve(path); await directory(dirname(absolute), check);
  const before = await lstat(absolute, { bigint: true }); privateStat(before);
  if (before.size > BigInt(maximum)) candidateFail('candidate_file_limit');
  check(); const file = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const selected = await file.stat({ bigint: true }); privateStat(selected);
    if (!same(before, selected)) candidateFail('candidate_file_changed');
    const bytes = Buffer.alloc(Number(before.size) + 1); let used = 0;
    while (used < bytes.length) { check(); const part = await file.read(bytes, used, bytes.length - used, used);
      if (!part.bytesRead) break; used += part.bytesRead; }
    const after = await file.stat({ bigint: true }), named = await lstat(absolute, { bigint: true });
    privateStat(after); privateStat(named);
    if (used > maximum || BigInt(used) !== before.size || !same(before, after) || !same(after, named)) candidateFail('candidate_file_changed');
    check(); return bytes.subarray(0, used);
  } finally { await file.close(); }
}
export async function readCandidatePrivate(path, maximum, options = {}) { return read(path, maximum, candidateClock(options)); }
export async function readCandidateToken(path, options = {}) {
  const bytes = await readCandidatePrivate(path, 65, options);
  if (bytes.length !== 64 && !(bytes.length === 65 && bytes[64] === 10)) candidateFail('invalid_candidate_token_file');
  return candidateToken(bytes.subarray(0, 64).toString('utf8'));
}
async function absent(path, check) {
  const absolute = resolve(path); await directory(dirname(absolute), check);
  try { await lstat(absolute); candidateFail('candidate_destination_exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  check(); return absolute;
}
export async function candidateDestination(path, options = {}) { return absent(path, candidateClock(options)); }
async function syncDirectory(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try { await file.sync(); } finally { await file.close(); }
}
async function writeNew(path, bytes) {
  const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
}
function descriptor(bytes) { return { bytes: bytes.length, sha256: candidateHash(bytes) }; }
function digest(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) candidateFail('candidate_package_pin_required');
  return value;
}
function checkDescriptor(value, maximum) {
  candidateKeys(value, ['bytes', 'sha256']); digest(value.sha256);
  if (!Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > maximum) candidateFail('candidate_file_limit');
}
async function inventory(path, bundle, check) {
  const expected = new Set(['manifest.json', 'capture.json', ...(bundle ? ['candidate.bundle'] : [])]);
  const entries = await opendir(path);
  for await (const entry of entries) {
    check(); if (!expected.delete(entry.name) || !entry.isFile()) candidateFail('candidate_package_inventory');
  }
  if (expected.size) candidateFail('candidate_package_inventory');
}
export async function saveCandidatePackage(path, input, suppliedBundle = null, options = {}) {
  const check = candidateClock(options); check();
  if (suppliedBundle !== null && typeof SharedArrayBuffer !== 'undefined' && suppliedBundle.buffer instanceof SharedArrayBuffer) candidateFail('candidate_shared_bundle_refused');
  // The existing validator detaches reports and bytes before its first digest.
  const checked = await validateCandidateCapture(input, suppliedBundle); check();
  const capture = Buffer.from(candidateCanonical(checked.capture)), bundle = checked.bundle;
  const manifest = { schema: CANDIDATE_PACKAGE_SCHEMA, capture: descriptor(capture), bundle: bundle === null ? null : descriptor(bundle) };
  const root = Buffer.from(candidateCanonical(manifest)), absolute = await absent(path, check), parent = dirname(absolute);
  await mkdir(absolute, { mode: 0o700 }); await directory(absolute, check);
  // Retain interrupted slots. Never overwrite, delete, or repair another attempt.
  await syncDirectory(parent); check();
  await writeNew(join(absolute, 'capture.json'), capture); check();
  if (bundle !== null) { await writeNew(join(absolute, 'candidate.bundle'), bundle); check(); }
  await syncDirectory(absolute); check();
  await writeNew(join(absolute, 'manifest.json'), root); await syncDirectory(absolute);
  // Once all selected files/root are synced, completion wins a racing signal.
  return { path: absolute, sha256: candidateHash(root), state: checked.capture.preparation.state,
    bundle_path: bundle === null ? null : join(absolute, 'candidate.bundle') };
}
export async function loadCandidatePackage(path, expectedHash, options = {}) {
  digest(expectedHash); const check = candidateClock(options), absolute = await directory(path, check);
  const root = await read(join(absolute, 'manifest.json'), CANDIDATE_MANIFEST_LIMIT, check);
  if (candidateHash(root) !== expectedHash) candidateFail('candidate_package_hash_mismatch');
  const manifest = candidateJson(root, CANDIDATE_MANIFEST_LIMIT);
  candidateKeys(manifest, ['schema', 'capture', 'bundle']);
  if (manifest.schema !== CANDIDATE_PACKAGE_SCHEMA || !root.equals(Buffer.from(candidateCanonical(manifest)))) candidateFail('invalid_candidate_package');
  checkDescriptor(manifest.capture, CANDIDATE_IO_LIMITS.capture);
  if (manifest.bundle !== null) checkDescriptor(manifest.bundle, BUNDLE_LIMIT);
  await inventory(absolute, manifest.bundle !== null, check);
  const capture = await read(join(absolute, 'capture.json'), manifest.capture.bytes, check);
  if (capture.length !== manifest.capture.bytes || candidateHash(capture) !== manifest.capture.sha256) candidateFail('candidate_capture_hash_mismatch');
  const bundle = manifest.bundle === null ? null : await read(join(absolute, 'candidate.bundle'), manifest.bundle.bytes, check);
  if (bundle !== null && (bundle.length !== manifest.bundle.bytes || candidateHash(bundle) !== manifest.bundle.sha256)) candidateFail('candidate_bundle_hash_mismatch');
  const checked = await validateCandidateCapture(candidateJson(capture, CANDIDATE_IO_LIMITS.capture), bundle); check();
  if (!capture.equals(Buffer.from(candidateCanonical(checked.capture)))) candidateFail('noncanonical_candidate_capture');
  if (!root.equals(await read(join(absolute, 'manifest.json'), CANDIDATE_MANIFEST_LIMIT, check))) candidateFail('candidate_package_changed');
  await inventory(absolute, bundle !== null, check); check();
  return { ...checked, path: absolute, sha256: expectedHash, bundle_path: bundle === null ? null : join(absolute, 'candidate.bundle') };
}

// Create-only publication of the small sender input. The staging file survives
// interrupted final-name publication; no existing destination is replaced.
export async function saveCandidateJson(path, value, options = {}) {
  const check = candidateClock(options), bytes = Buffer.from(candidateCanonical(value));
  if (bytes.length > 512 * 1024) candidateFail('candidate_draft_file_limit');
  const absolute = await absent(path, check), parent = dirname(absolute);
  const temporary = join(parent, `.candidate-draft-${randomBytes(16).toString('hex')}.pending`);
  await writeNew(temporary, bytes); check();
  await link(temporary, absolute); await syncDirectory(parent);
  await unlink(temporary); await syncDirectory(parent);
  return { path: absolute, sha256: candidateHash(bytes), bytes: bytes.length };
}
