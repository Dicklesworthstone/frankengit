// Private read captures/draft inputs, never a repository authority or a credential store.
import { constants } from 'node:fs';
import { open, lstat, realpath, link, unlink } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { REVIEW_LIMITS, failReview, reviewCanonical, reviewHash, parseReviewJson, validateReviewCapture } from './pull_review_snapshot.mjs';
function privateStat(stat, directory = false) {
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined || constants.O_NONBLOCK === undefined ||
      constants.O_DIRECTORY === undefined) failReview('review_posix_files_required');
  if (!(directory ? stat.isDirectory() : stat.isFile()) || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o077n) !== 0n || (!directory && stat.nlink !== 1n)) failReview('private_owned_review_file_required');
}
async function parent(path) {
  const result = dirname(resolve(path));
  if (await realpath(result) !== result) failReview('review_directory_alias');
  privateStat(await lstat(result, { bigint: true }), true);
  for (let cursor = result;; cursor = dirname(cursor)) {
    if (cursor.split('/').includes('.git')) failReview('review_worktree_path');
    try { await lstat(join(cursor, '.git')); failReview('review_worktree_path'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(cursor) === cursor) break;
  }
  return result;
}
function same(a, b) { return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs; }
export async function readReviewPrivate(path, maximum = REVIEW_LIMITS.capture) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > REVIEW_LIMITS.capture) failReview('review_file_limit');
  const absolute = resolve(path); await parent(absolute);
  const before = await lstat(absolute, { bigint: true }); privateStat(before);
  if (before.size > BigInt(maximum)) failReview('review_file_limit');
  const file = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const selected = await file.stat({ bigint: true }); privateStat(selected); if (!same(before, selected)) failReview('review_file_changed');
    const bytes = Buffer.alloc(maximum + 1); let used = 0;
    while (used < bytes.length) { const r = await file.read(bytes, used, bytes.length - used, used); if (!r.bytesRead) break; used += r.bytesRead; }
    const after = await file.stat({ bigint: true }), named = await lstat(absolute, { bigint: true }); privateStat(after); privateStat(named);
    if (used > maximum || BigInt(used) !== before.size || !same(before, after) || !same(after, named)) failReview('review_file_changed');
    return bytes.subarray(0, used);
  } finally { await file.close(); }
}
export async function reviewDestination(path) {
  const absolute = resolve(path); await parent(absolute);
  try { await lstat(absolute); failReview('review_output_exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  return absolute;
}
async function syncDirectory(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await file.sync(); } finally { await file.close(); }
}
export async function saveReviewJson(path, value) {
  const bytes = Buffer.from(reviewCanonical(value)); if (bytes.length > REVIEW_LIMITS.capture) failReview('review_file_limit');
  const absolute = await reviewDestination(path), directory = dirname(absolute);
  const temporary = join(directory, `.review-${randomBytes(16).toString('hex')}.pending`);
  // A failed publication retains only this invocation's residue. Never overwrite
  // a named file, erase another writer, or claim a partially written capture.
  const file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
  await link(temporary, absolute); await syncDirectory(directory);
  await unlink(temporary); await syncDirectory(directory);
  return { path: absolute, sha256: reviewHash(bytes), bytes: bytes.length };
}
export async function loadReviewCapture(path, expectedHash) {
  if (typeof expectedHash !== 'string' || !/^[0-9a-f]{64}$/.test(expectedHash)) failReview('review_capture_pin_required');
  const bytes = await readReviewPrivate(path);
  if (reviewHash(bytes) !== expectedHash) failReview('review_capture_hash_mismatch');
  const capture = validateReviewCapture(parseReviewJson(bytes));
  if (!bytes.equals(Buffer.from(reviewCanonical(capture)))) failReview('noncanonical_review_capture');
  return capture;
}
