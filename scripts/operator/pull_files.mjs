// Private external-operator files. No file grants repository authority, changes
// a saved request, or establishes non-commit after an interrupted invocation.
import { constants } from 'node:fs';
import { open, lstat, mkdir, realpath, link, unlink } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { PULL_LIMITS, PullError, failPull, pullFields, pullHash, pullCanonical, parsePullJson,
  pullTokenFingerprint, validatePullIntent, validatePullPublication, pullOutcomeScope, validatePullBundle } from './pull_command.mjs';
import { validateOutcomeReply } from './transaction_outcome.mjs';

export const PULL_RECORD_LIMIT = 128 * 1024;
function privateStat(stat, directory = false) {
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined ||
      constants.O_DIRECTORY === undefined || constants.O_NONBLOCK === undefined) failPull('posix_pull_files_required');
  if (!(directory ? stat.isDirectory() : stat.isFile()) || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o077n) !== 0n || (!directory && stat.nlink !== 1n)) failPull('private_owned_pull_file_required');
}
export async function privatePullDirectory(path) {
  const absolute = resolve(path);
  if (await realpath(absolute) !== absolute) failPull('pull_directory_alias');
  privateStat(await lstat(absolute, { bigint: true }), true);
  // These credential-bearing workflows must not leave private draft records
  // in a worktree. This is not a general sandbox or hostile-parent defense.
  for (let cursor = absolute;; cursor = dirname(cursor)) {
    if (cursor.split('/').includes('.git')) failPull('pull_worktree_path');
    try { await lstat(join(cursor, '.git')); failPull('pull_worktree_path'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(cursor) === cursor) break;
  }
  return absolute;
}
function same(a, b) { return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs; }
export async function readPullPrivate(path, maximum, { sync = false } = {}) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > PULL_LIMITS.bundle || typeof sync !== 'boolean') failPull('pull_file_limit');
  const absolute = resolve(path); await privatePullDirectory(dirname(absolute));
  const before = await lstat(absolute, { bigint: true }); privateStat(before);
  if (before.size > BigInt(maximum)) failPull('pull_file_limit');
  const file = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const selected = await file.stat({ bigint: true }); privateStat(selected);
    if (!same(before, selected)) failPull('pull_file_changed');
    const bytes = Buffer.alloc(Number(before.size) + 1); let used = 0;
    while (used < bytes.length) {
      const next = await file.read(bytes, used, bytes.length - used, used);
      if (!next.bytesRead) break; used += next.bytesRead;
    }
    const after = await file.stat({ bigint: true }), named = await lstat(absolute, { bigint: true }); privateStat(after); privateStat(named);
    if (BigInt(used) !== before.size || used > maximum || !same(before, after) || !same(after, named)) failPull('pull_file_changed');
    if (sync) await file.sync();
    return bytes.subarray(0, used);
  } finally { await file.close(); }
}
export async function readPullToken(path) {
  const bytes = await readPullPrivate(path, 65);
  if (bytes.length !== 64 && !(bytes.length === 65 && bytes[64] === 10)) failPull('invalid_pull_token_file');
  const token = bytes.subarray(0, 64).toString('utf8'); pullTokenFingerprint(token); return token;
}
async function syncDirectory(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await file.sync(); } finally { await file.close(); }
}
async function writeNew(path, bytes) {
  const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
}
export async function savePullIntent(path, value, bundle = null) {
  const intent = validatePullIntent(value), absolute = resolve(path), parent = dirname(absolute);
  // The fixed-name payload is copied and verified before any asynchronous I/O.
  // Publish its bytes first, then the small intent that selects their checksum.
  const payload = intent.bundle ? validatePullBundle(intent, bundle) : null;
  if (payload === null && bundle !== null) failPull('unexpected_pull_bundle');
  await privatePullDirectory(parent); await mkdir(absolute, { mode: 0o700 });
  await privatePullDirectory(absolute);
  // An interrupted slot is never erased, repaired, or reused automatically.
  if (payload !== null) { await writeNew(join(absolute, 'candidate.bundle'), payload); await syncDirectory(absolute); }
  await writeNew(join(absolute, 'intent.json'), Buffer.from(pullCanonical(intent)));
  await syncDirectory(absolute); await syncDirectory(parent);
  return intent;
}
export async function loadPullIntent(path, { sync = false } = {}) {
  const directory = await privatePullDirectory(path);
  const bytes = await readPullPrivate(join(directory, 'intent.json'), PULL_LIMITS.intent, { sync });
  const intent = validatePullIntent(parsePullJson(bytes));
  if (!bytes.equals(Buffer.from(pullCanonical(intent)))) failPull('noncanonical_pull_intent_file');
  if (sync) { await syncDirectory(directory); await syncDirectory(dirname(directory)); }
  return intent;
}
// Outcome recovery intentionally loads only intent.json. Losing bundle bytes
// cannot prevent an original-key lookup or justify inventing a replacement key.
export async function loadPullBundle(path, value, { sync = false } = {}) {
  const intent = validatePullIntent(value);
  if (!intent.bundle) failPull('unexpected_pull_bundle');
  const directory = await privatePullDirectory(path);
  const bytes = await readPullPrivate(join(directory, 'candidate.bundle'), PULL_LIMITS.bundle, { sync });
  return validatePullBundle(intent, bytes);
}
export function pullRecord(intent, result, error = null) {
  const value = { schema: 'frankengit-remote-pull-record-v1', intent_sha256: pullHash(pullCanonical(validatePullIntent(intent))),
    key: intent.key, outcome: result?.outcome ?? null, publication: result?.publication ?? error?.publication ?? null,
    dispatched: result?.dispatched ?? error?.dispatched ?? false,
    error: error === null ? null : { code: error instanceof PullError ? error.code : 'pull_operation_unavailable',
      phase: error instanceof PullError ? error.phase : 'validation', status: error instanceof PullError ? error.status : null } };
  return validatePullRecord(value, intent);
}
export function validatePullRecord(value, input) {
  const intent = validatePullIntent(input);
  pullFields(value, ['schema', 'intent_sha256', 'key', 'outcome', 'publication', 'dispatched', 'error']);
  if (value.schema !== 'frankengit-remote-pull-record-v1' || value.intent_sha256 !== pullHash(pullCanonical(intent)) ||
      value.key !== intent.key || typeof value.dispatched !== 'boolean') failPull('pull_record_binding');
  const scope = pullOutcomeScope(intent.scope), outcome = value.outcome === null ? null : validateOutcomeReply(value.outcome, scope);
  const publication = value.publication === null ? null : validatePullPublication(value.publication, intent,
    value.publication.outcome === 'committed' ? 200 : 409);
  if (outcome !== null && publication !== null) {
    const d = outcome.decision;
    if (!outcome.terminal || outcome.transaction.tx_id !== publication.tx_id || d.kind !== publication.outcome ||
        d.decision_sequence !== publication.decision_sequence || (d.repository_commit_id ?? null) !== publication.repository_commit_id ||
        (d.refusal_record_id ?? null) !== publication.refusal_record_id || (d.code ?? null) !== publication.refusal_code ||
        (d.code_point ?? null) !== publication.refusal_code_point) failPull('conflicting_pull_record');
  }
  if (value.error === null) { if (outcome === null) failPull('empty_pull_record'); }
  else {
    pullFields(value.error, ['code', 'phase', 'status']);
    if (typeof value.error.code !== 'string' || !/^[a-z_]{1,128}$/.test(value.error.code) ||
        !['validation', 'preflight', 'publication', 'confirmation'].includes(value.error.phase) ||
        (value.error.status !== null && (!Number.isSafeInteger(value.error.status) || value.error.status < 100 || value.error.status > 599))) failPull('invalid_pull_record_error');
  }
  return { ...value, outcome, publication, error: value.error === null ? null : { ...value.error } };
}
export async function readPullRecord(path, intent) {
  return validatePullRecord(parsePullJson(await readPullPrivate(path, PULL_RECORD_LIMIT), { maximum: PULL_RECORD_LIMIT }), intent);
}
export async function checkPullRecordDestination(path) {
  const absolute = resolve(path); await privatePullDirectory(dirname(absolute));
  try { await lstat(absolute); failPull('pull_record_exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  return absolute;
}
export async function savePullRecord(path, value, intent) {
  const bytes = Buffer.from(pullCanonical(validatePullRecord(value, intent)));
  if (bytes.length > PULL_RECORD_LIMIT) failPull('pull_record_limit');
  const absolute = await checkPullRecordDestination(path), parent = dirname(absolute);
  const temporary = join(parent, `.pull-record-${randomBytes(16).toString('hex')}.pending`);
  // The final name can expose only complete, synced bytes. link is create-only:
  // a concurrent publisher cannot overwrite another receipt, even identical.
  try {
    await writeNew(temporary, bytes);
    await link(temporary, absolute); await syncDirectory(parent);
    await unlink(temporary); await syncDirectory(parent);
  } catch {
    const error = new PullError('pull_record_publication_incomplete');
    error.stagingPath = await lstat(temporary).then(() => temporary, () => null); throw error;
  }
  return absolute;
}
