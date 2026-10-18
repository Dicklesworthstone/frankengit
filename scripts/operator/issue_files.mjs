// Operator-owned POSIX request slots. These are recovery inputs, not authority.
import { constants } from 'node:fs';
import { open, lstat, mkdir, realpath, link, unlink } from 'node:fs/promises';
import { dirname, basename, resolve, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ISSUE_LIMITS, IssueError, issueCanonical, parseIssueJson, validateIssueIntent, issueTokenFingerprint } from './remote_issue.mjs';
const fail = code => { throw new IssueError(code, { phase: 'files' }); };
function privateStat(stat, directory = false) {
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined || constants.O_NONBLOCK === undefined ||
      constants.O_DIRECTORY === undefined) fail('issue_posix_profile_required');
  if ((directory ? !stat.isDirectory() : !stat.isFile()) || (stat.mode & 0o077n) !== 0n ||
      stat.uid !== BigInt(process.getuid()) || (!directory && stat.nlink !== 1n)) fail('issue_private_owned_file_required');
}
function sameFile(a, b) { return a.dev === b.dev && a.ino === b.ino; }
function unchanged(a, b) { return sameFile(a, b) && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs; }
async function absent(path) {
  try { await lstat(path); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  fail('issue_output_already_exists');
}
async function outsideWorktree(path) {
  for (let current = path;; current = dirname(current)) {
    if (basename(current) === '.git') fail('issue_request_inside_worktree');
    try { await lstat(join(current, '.git')); fail('issue_request_inside_worktree'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(current) === current) return;
  }
}
export async function issuePrivateDirectory(path) {
  const absolute = resolve(path);
  if (await realpath(absolute) !== absolute) fail('issue_directory_alias');
  privateStat(await lstat(absolute, { bigint: true }), true); return absolute;
}
export async function issueSyncDirectory(path) {
  const named = await lstat(path, { bigint: true }); privateStat(named, true);
  const file = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const selected = await file.stat({ bigint: true }); privateStat(selected, true);
    if (!sameFile(named, selected)) fail('issue_directory_changed');
    await file.sync();
    if (!sameFile(selected, await lstat(path, { bigint: true }))) fail('issue_directory_changed');
  } finally { await file.close(); }
}
export async function readIssuePrivate(path, maximum = ISSUE_LIMITS.intent, resync = false) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > ISSUE_LIMITS.intent) fail('issue_invalid_file_bound');
  const absolute = resolve(path), parent = dirname(absolute);
  await issuePrivateDirectory(parent);
  const before = await lstat(absolute, { bigint: true }); privateStat(before);
  if (before.size > BigInt(maximum)) fail('issue_file_limit');
  const file = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const selected = await file.stat({ bigint: true }); privateStat(selected);
    if (!unchanged(before, selected)) fail('issue_file_changed');
    const bytes = Buffer.alloc(maximum + 1); let count = 0;
    while (count < bytes.length) {
      const { bytesRead } = await file.read(bytes, count, bytes.length - count, count);
      if (!bytesRead) break; count += bytesRead;
    }
    const after = await file.stat({ bigint: true }), named = await lstat(absolute, { bigint: true });
    privateStat(after); privateStat(named);
    if (count > maximum || BigInt(count) !== before.size || !unchanged(before, after) || !unchanged(after, named)) fail('issue_file_changed');
    if (resync) await file.sync();
    return bytes.subarray(0, count);
  } finally { await file.close(); }
}
export async function readIssueToken(path) {
  const bytes = await readIssuePrivate(path, 65);
  try {
    if (bytes.length !== 64 && !(bytes.length === 65 && bytes[64] === 10)) fail('issue_invalid_token_file');
    const token = bytes.subarray(0, 64).toString('utf8'); issueTokenFingerprint(token); return token;
  } finally { bytes.fill(0); }
}
async function writeNew(path, bytes) {
  const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
}
export async function saveIssueIntent(path, value) {
  const intent = validateIssueIntent(value), bytes = Buffer.from(issueCanonical(intent)), absolute = resolve(path);
  const parent = await issuePrivateDirectory(dirname(absolute)); await outsideWorktree(parent);
  await mkdir(absolute, { mode: 0o700 }); // Existing or interrupted slots are never recycled.
  await issuePrivateDirectory(absolute); await issueSyncDirectory(parent);
  await writeNew(join(absolute, 'intent.json'), bytes); await issueSyncDirectory(absolute);
  return intent;
}
export async function loadIssueIntent(path, resync = false) {
  const directory = await issuePrivateDirectory(path); await outsideWorktree(directory);
  const bytes = await readIssuePrivate(join(directory, 'intent.json'), ISSUE_LIMITS.intent, resync);
  const intent = validateIssueIntent(parseIssueJson(bytes));
  if (!bytes.equals(Buffer.from(issueCanonical(intent)))) fail('issue_noncanonical_intent_file');
  if (resync) { await issueSyncDirectory(directory); await issueSyncDirectory(dirname(directory)); }
  return intent;
}
export async function checkIssueRecordDestination(path) {
  const absolute = resolve(path), parent = await issuePrivateDirectory(dirname(absolute));
  await outsideWorktree(parent); await absent(absolute); return absolute;
}
export async function saveIssueRecord(path, value) {
  const absolute = await checkIssueRecordDestination(path), parent = dirname(absolute);
  const bytes = Buffer.from(issueCanonical(value)); if (bytes.length > ISSUE_LIMITS.intent) fail('issue_record_limit');
  const staging = join(parent, `.issue-record-${randomBytes(16).toString('hex')}.staged`);
  // Body first, create-only final name last. No rename can overwrite a record.
  // Any failure leaves its files for inspection; a visible result is not erased.
  await writeNew(staging, bytes); await link(staging, absolute); await unlink(staging); await issueSyncDirectory(parent);
}
