// Immutable private operator custody. These files record reviewed inputs and
// historical observations; they never establish repository authority.
import { mkdir, lstat } from 'node:fs/promises';
import { dirname, basename, join } from 'node:path';
import { absolute, directory, syncDirectory, writeNew } from './workflow_watch_io.mjs';
import { readPrivateOperatorFile, readSynchronizedOperatorRecord } from '../lib/forge-operator-io.mjs';
import { BRANCH_LIMITS, fields, fail, pin, hash, encode, parse, credential, validateBranchIntent, validateBranchRecord } from './branch_transaction.mjs';
import { MAX_CREDENTIAL_TOKEN_BYTES } from './credential_token.mjs';

export async function privateDirectory(path) {
  await directory(absolute(path));
  for (let cursor = path;; cursor = dirname(cursor)) {
    if (basename(cursor) === '.git') fail('branch_transaction_worktree_path');
    try { await lstat(join(cursor, '.git')); fail('branch_transaction_worktree_path'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(cursor) === cursor) break;
  }
  return path;
}
export async function readFile(path, maximum, check = () => {}, sync = false) {
  absolute(path); check(); await privateDirectory(dirname(path)); check();
  return (sync ? readSynchronizedOperatorRecord : readPrivateOperatorFile)(path, maximum, check);
}
export async function tokenFile(path, check = () => {}) {
  const bytes = await readFile(path, MAX_CREDENTIAL_TOKEN_BYTES + 1, check);
  try { return credential(bytes.toString('utf8').replace(/\n$/, '')); }
  finally { bytes.fill(0); }
}
export async function recordDestination(path) {
  absolute(path); await privateDirectory(dirname(path));
  try { await lstat(path); fail('branch_transaction_record_exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  return path;
}
export async function saveIntent(path, input, check = () => {}) {
  const intent = validateBranchIntent(input), bytes = encode(intent);
  absolute(path); check(); await privateDirectory(dirname(path)); check();
  const receipt = { type: 'branch_transaction_prepared', schema_version: 1, request_dir: path,
    intent_sha256: hash(bytes), key: intent.key, command_count: intent.changes.length, publication_attempted: false };
  let created = false;
  try {
    await mkdir(path, { mode: 0o700 }); created = true;
    // Once claimed, finish the small local publication or retain the slot.
    await syncDirectory(dirname(path)); await writeNew(join(path, 'intent.json'), bytes);
    await syncDirectory(path); await syncDirectory(dirname(path));
    return receipt;
  } catch (error) {
    if (created) error.branch_progress = receipt;
    throw error;
  }
}
export async function loadIntent(path, confirm, check = () => {}, sync = false) {
  pin(confirm); await privateDirectory(absolute(path));
  const bytes = await readFile(join(path, 'intent.json'), BRANCH_LIMITS.intent, check, sync);
  if (hash(bytes) !== confirm) fail('branch_transaction_intent_pin_changed');
  const intent = validateBranchIntent(parse(bytes));
  if (!bytes.equals(encode(intent))) fail('branch_transaction_intent_encoding');
  check(); return intent;
}
export async function loadRecord(path, intent, check = () => {}) {
  const bytes = await readFile(path, BRANCH_LIMITS.record, check);
  const record = validateBranchRecord(parse(bytes, false, BRANCH_LIMITS.record), intent);
  if (!bytes.equals(encode(record))) fail('branch_transaction_record_encoding');
  return record;
}
export async function saveRecord(path, value, intent) {
  const record = validateBranchRecord(value, intent), bytes = encode(record);
  if (bytes.length > BRANCH_LIMITS.record) fail('branch_transaction_record_limit');
  await recordDestination(path); await writeNew(path, bytes); return path;
}
export function lifetime(options = {}) {
  fields(options, ['timeoutMs', 'signal'], []);
  const timeoutMs = options.timeoutMs ?? 30000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000 ||
      options.signal !== undefined && !(options.signal instanceof AbortSignal)) fail('branch_transaction_options');
  const deadline = performance.now() + timeoutMs;
  const remaining = () => {
    if (options.signal?.aborted) fail('branch_transaction_cancelled');
    const left = Math.ceil(deadline - performance.now());
    if (left < 1) fail('branch_transaction_timeout');
    return left;
  };
  return { remaining, check: () => { remaining(); } };
}
