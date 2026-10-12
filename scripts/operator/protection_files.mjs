// Private, bounded local operator intents. Files never publish repository state.
import { constants } from 'node:fs';
import { open, lstat, mkdir, realpath } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { LIMITS, ProtectionError, canonical, parseJson, validateIntent, tokenFingerprint } from './review_protection.mjs';
const fail = code => { throw new ProtectionError(code); };
function privateStat(stat, directory = false) {
  if ((directory ? !stat.isDirectory() : !stat.isFile()) || (stat.mode & 0o077) !== 0 ||
      (typeof process.getuid === 'function' && stat.uid !== process.getuid()) || (!directory && stat.nlink !== 1)) fail('private_owned_regular_file_required');
}
export async function privateDirectory(path) {
  const absolute = resolve(path);
  if (await realpath(absolute) !== absolute) fail('directory_alias_refused');
  privateStat(await lstat(absolute), true);
  return absolute;
}
export async function readPrivate(path, maximum) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > LIMITS.intent) fail('invalid_file_limit');
  const absolute = resolve(path);
  if (await realpath(dirname(absolute)) !== dirname(absolute)) fail('directory_alias_refused');
  const before = await lstat(absolute); privateStat(before);
  if (before.size > maximum) fail('file_byte_limit');
  const file = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const selected = await file.stat(); privateStat(selected);
    if (selected.dev !== before.dev || selected.ino !== before.ino || selected.size !== before.size) fail('file_changed');
    const bytes = Buffer.alloc(maximum + 1); let used = 0;
    while (used < bytes.length) {
      const next = await file.read(bytes, used, bytes.length - used, used);
      if (!next.bytesRead) break;
      used += next.bytesRead;
    }
    const after = await file.stat(), named = await lstat(absolute); privateStat(after); privateStat(named);
    if (used > maximum) fail('file_byte_limit');
    if (used !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs ||
        after.ctimeMs !== before.ctimeMs || named.dev !== after.dev || named.ino !== after.ino) fail('file_changed');
    return bytes.subarray(0, used);
  } finally { await file.close(); }
}
export async function privateJson(path, maximum = LIMITS.intent) { return parseJson(await readPrivate(path, maximum)); }
export async function readToken(path) {
  const bytes = await readPrivate(path, 65);
  if (bytes.length !== 64 && !(bytes.length === 65 && bytes[64] === 10)) fail('invalid_token_file');
  const token = bytes.subarray(0, 64).toString('utf8');
  tokenFingerprint(token);
  return token;
}
export async function syncDirectory(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await file.sync(); } finally { await file.close(); }
}
export async function createPrivate(path, bytes) {
  const content = Buffer.isBuffer(bytes) ? Buffer.from(bytes) : Buffer.from(bytes, 'utf8');
  if (content.length > LIMITS.intent) fail('file_byte_limit');
  const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(content); await file.sync(); } finally { await file.close(); }
  await syncDirectory(dirname(path));
}
export async function saveIntent(path, value) {
  const intent = validateIntent(value), absolute = resolve(path), parent = dirname(absolute);
  if (await realpath(parent) !== parent) fail('directory_alias_refused');
  await mkdir(absolute, { mode: 0o700 }); // Never overwrite or clean up an existing request.
  await privateDirectory(absolute);
  // A failed/partial prepare remains diagnosable. It never dispatches a request.
  await createPrivate(join(absolute, 'intent.json'), canonical(intent));
  await syncDirectory(parent);
  return intent;
}
export async function loadIntent(path) {
  const directory = await privateDirectory(path);
  const bytes = await readPrivate(join(directory, 'intent.json'), LIMITS.intent);
  const intent = validateIntent(parseJson(bytes));
  if (!bytes.equals(Buffer.from(canonical(intent)))) fail('noncanonical_intent_file');
  return intent;
}
