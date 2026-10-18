// Private, bounded operator files. This is not a hostile same-UID sandbox or
// repository authority. Incomplete files are retained, never overwritten.
import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { resolve, dirname, basename, join } from 'node:path';
import { createHash } from 'node:crypto';

export function operatorError(code) { const e = new Error(code); e.code = code; return e; }
export function operatorPath(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096 || /[\0\r\n\uD800-\uDFFF]/u.test(value)) {
    throw operatorError('operator_invalid_path');
  }
  return resolve(value);
}
function supported() {
  if (typeof process.getuid !== 'function' || constants.O_NOFOLLOW === undefined ||
      constants.O_NONBLOCK === undefined || constants.O_DIRECTORY === undefined) throw operatorError('operator_filesystem_unsupported');
}
function privateOwner(stat) {
  if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n) !== 0n) throw operatorError('operator_private_owner_required');
}
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const unchanged = (a, b) => ['dev', 'ino', 'mode', 'uid', 'size', 'nlink', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
export async function privateRecordPath(value) {
  supported(); const path = operatorPath(value), parent = await realpath(dirname(path));
  const stat = await lstat(parent, { bigint: true });
  if (!stat.isDirectory()) throw operatorError('operator_directory_required');
  privateOwner(stat); return join(parent, basename(path));
}
export async function absentRecord(path) {
  try { await lstat(path); throw operatorError('operator_record_exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
export function readPrivateOperatorFile(value, maximum, check = () => {}, minimum = 1) {
  return readOperatorFile(value, maximum, check, minimum, false);
}
// A submitting retry cannot rely on the original creator having finished its
// sync: a complete record can be readable before that creator's barrier ends.
// Synchronize the exact descriptor read here and its private parent ourselves.
export function readSynchronizedOperatorRecord(value, maximum, check = () => {}) {
  return readOperatorFile(value, maximum, check, 1, true);
}
async function readOperatorFile(value, maximum, check, minimum, synchronize) {
  supported(); const path = operatorPath(value); check();
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1024 * 1024 || ![0, 1].includes(minimum)) throw operatorError('operator_file_limit');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let bytes;
  try {
    const before = await file.stat({ bigint: true }); privateOwner(before); check();
    if (!before.isFile() || before.nlink !== 1n || before.size < BigInt(minimum) || before.size > BigInt(maximum)) throw operatorError('operator_file_type_or_size');
    bytes = Buffer.alloc(Number(before.size)); let at = 0;
    while (at < bytes.length) {
      check(); const result = await file.read(bytes, at, Math.min(65536, bytes.length - at), at);
      if (!result.bytesRead) throw operatorError('operator_file_changed');
      at += result.bytesRead;
    }
    const tail = Buffer.alloc(1);
    if ((await file.read(tail, 0, 1, at)).bytesRead) throw operatorError('operator_file_changed');
    const after = await file.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    if (!named.isFile() || !unchanged(before, after) || !unchanged(after, named)) throw operatorError('operator_file_changed');
    if (synchronize) await synchronizeRecord(file, path, before, check);
    check(); return bytes;
  } catch (error) { bytes?.fill(0); throw error; }
  finally { await file.close(); }
}
async function synchronizeRecord(file, path, before, check) {
  const parent = dirname(path);
  const directory = await open(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const parentId = await directory.stat({ bigint: true }); privateOwner(parentId);
    if (!parentId.isDirectory()) throw operatorError('operator_directory_required');
    check(); await file.sync(); check(); await directory.sync();
    const after = await file.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    if (!named.isFile() || !unchanged(before, after) || !unchanged(after, named)) throw operatorError('operator_record_changed');
    const namedParent = await lstat(parent, { bigint: true }); privateOwner(namedParent);
    if (!namedParent.isDirectory() || !same(parentId, namedParent)) throw operatorError('operator_parent_changed');
    check();
  } finally { await directory.close(); }
}
export const recordDigest = bytes => createHash('sha256').update(bytes).digest('hex');
export async function saveOperatorRecord(path, bytes, check = () => {}) {
  // New-file creation arbitrates simultaneous preparations for this name. The
  // caller cannot send until file sync, readback, parent sync AND close succeed.
  // A crash/short write leaves a suspect record; absence is never a retry key.
  const destination = await privateRecordPath(path); check();
  if (!(bytes instanceof Uint8Array) || bytes.buffer instanceof SharedArrayBuffer || !bytes.length || bytes.length > 1024 * 1024) throw operatorError('operator_record_limit');
  const owned = Buffer.from(bytes), parent = dirname(destination);
  const directory = await open(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let file;
  try {
    const parentId = await directory.stat({ bigint: true }); privateOwner(parentId);
    file = await open(destination, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const identity = await file.stat({ bigint: true }); privateOwner(identity);
    await file.writeFile(owned); await file.sync(); check();
    const actual = await readPrivateOperatorFile(destination, 1024 * 1024, check);
    if (!owned.equals(actual) || !same(identity, await lstat(destination, { bigint: true }))) throw operatorError('operator_record_changed');
    const namedParent = await lstat(parent, { bigint: true }); privateOwner(namedParent);
    if (!namedParent.isDirectory() || !same(parentId, namedParent)) throw operatorError('operator_parent_changed');
    await directory.sync(); check();
  } finally {
    try { await file?.close(); } finally { await directory.close(); }
  }
  return { path: destination, sha256: recordDigest(owned) };
}
export function operatorJson(value) {
  // JSON framing alone does not escape C1/bidi terminal controls.
  return JSON.stringify(value).replace(/[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu,
    c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')) + '\n';
}
