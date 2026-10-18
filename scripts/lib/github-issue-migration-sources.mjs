// FG-049 operator input selection, not native custody or a new migration authority.
import { constants as F } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';

const MAX_BYTES = 1024 * 1024;
const fail = reason => { throw new Error(`github_migration_sources_${reason}`); };
function path(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096 ||
      /[\x00-\x1f\x7f\uD800-\uDFFF]/u.test(value) || resolve(value) !== value) fail('absolute_path');
  return value;
}
function pin(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('pin');
  return value;
}
function fields(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !allowed.includes(key)) || required.some(key => !Object.hasOwn(value, key))) fail('fields');
}
function integer(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('bound');
  return value;
}
export function parseGithubIssueMigrationSources(bytes) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > MAX_BYTES) fail('size');
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  // Two documented serializations avoid ambiguous duplicate keys and rounded
  // numeric spellings without introducing a second general-purpose JSON parser.
  if (![undefined, 2].some(indent => bytes.equals(Buffer.from(JSON.stringify(value, null, indent) + '\n')))) fail('json_encoding');
  const required = ['schema', 'inventory', 'captures'];
  fields(value, [...required, 'offset', 'maxCaptureBytes', 'maxRequestBytes', 'maxSteps'], required);
  if (value.schema !== 'frankengit-github-issue-migration-sources-v1') fail('schema');
  fields(value.inventory, ['path', 'sha256']);
  if (!Array.isArray(value.captures)) fail('captures');
  integer(value.captures.length, 1, 128);
  const selected = new Set();
  const captures = value.captures.map(row => {
    fields(row, ['batch', 'path', 'sha256']);
    const name = path(row.path);
    if (selected.has(name)) fail('duplicate_capture_path');
    selected.add(name);
    return { batch: integer(row.batch, 1, 128), path: name, sha256: pin(row.sha256) };
  }).sort((a, b) => a.batch - b.batch);
  if (captures.some((row, index) => row.batch !== index + 1)) fail('batch_coverage');
  const result = { inventoryFile: path(value.inventory.path), inventorySha256: pin(value.inventory.sha256), captures };
  if (selected.has(result.inventoryFile)) fail('overlapping_inventory');
  for (const [name, min, max] of [['offset', 0, Number.MAX_SAFE_INTEGER], ['maxCaptureBytes', 1, 64 * 1024 * 1024],
    ['maxRequestBytes', 1, 128 * 1024 * 1024], ['maxSteps', 1, 10000]]) {
    if (Object.hasOwn(value, name)) result[name] = integer(value[name], min, max);
  }
  for (const row of captures) Object.freeze(row);
  Object.freeze(captures); return Object.freeze(result);
}
export async function loadGithubIssueMigrationSources(raw) {
  fields(raw, ['path', 'sha256', 'signal'], ['path', 'sha256']);
  const name = path(raw.path), expected = pin(raw.sha256), signal = raw.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('signal');
  const check = () => signal?.throwIfAborted();
  check();
  if (typeof process.getuid !== 'function' || await realpath(name) !== name) fail('path_alias');
  const file = await open(name, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  try {
    check(); const before = await file.stat();
    if (!before.isFile() || before.uid !== process.getuid() || (before.mode & 0o077) !== 0 ||
        before.nlink !== 1 || before.size < 1 || before.size > MAX_BYTES) fail('private_file');
    const bytes = Buffer.alloc(before.size + 1); let size = 0;
    while (size < bytes.length) {
      check(); const read = await file.read(bytes, size, bytes.length - size, size);
      if (!read.bytesRead) break;
      size += read.bytesRead;
    }
    const after = await file.stat(), current = await lstat(name);
    if (size !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs ||
        after.ctimeMs !== before.ctimeMs || current.dev !== before.dev || current.ino !== before.ino) fail('changed');
    const selected = bytes.subarray(0, size);
    if (createHash('sha256').update(selected).digest('hex') !== expected) fail('pin_mismatch');
    check(); return parseGithubIssueMigrationSources(selected);
  } finally { await file.close(); }
}
