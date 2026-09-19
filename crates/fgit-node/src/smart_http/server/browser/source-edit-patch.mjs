// Exact full-file patches for native source admission. No host worktree or Git
// subprocess is involved; byte paths and file modes remain explicit inputs.
import { fail, keys, hex, unhex, utf8 } from './pulls-core.mjs';
export const FILE_LIMIT = 256 * 1024;
export const PATCH_LIMIT = 1024 * 1024;
export const EDIT_LIMIT = 64;
const LINE_LIMIT = 65536;
export function sourcePath(value) {
  const bytes = unhex(value, 4096);
  if (!bytes.length || bytes.includes(0)) fail('An exact repository path is required.');
  let start = 0, components = 0;
  for (let i = 0; i <= bytes.length; i += 1) if (i === bytes.length || bytes[i] === 47) {
    const part = bytes.subarray(start, i), ascii = String.fromCharCode(...part).toLowerCase();
    if (++components > 64 || !part.length || ['.', '..', '.git'].includes(ascii)) fail('Unsafe repository path component.');
    start = i + 1;
  }
  return bytes;
}
// Binary content is an explicit caller profile, not a change to text editors
// or initial-history consumers of these shared helpers.
export function fileBytes(value, allowBinary = false) {
  if (typeof allowBinary !== 'boolean') fail('Choose an explicit file-byte profile.');
  if (!(value instanceof Uint8Array) || value.length > FILE_LIMIT) fail('File exceeds the 256 KiB editor limit.');
  if (!allowBinary && value.includes(0)) fail('This text profile refuses NUL bytes; choose binary-safe authoring.');
  return value;
}
export function fileMode(value) {
  if (![0o100644, 0o100755].includes(value)) fail('Only ordinary and executable regular files are editable.');
  return value;
}
export function quotePath(prefix, bytes) {
  let out = '"' + prefix;
  for (const byte of bytes) {
    if (byte === 34 || byte === 92) out += '\\' + String.fromCharCode(byte);
    else if (byte < 32 || byte > 126) out += '\\' + byte.toString(8).padStart(3, '0');
    else out += String.fromCharCode(byte);
  }
  return out + '"';
}
function same(a, b) { return a.length === b.length && a.every((byte, i) => byte === b[i]); }
export function normalizeEdits(edits, options = {}) {
  keys(options, ['allowBinary']);
  const allowBinary = options.allowBinary === undefined ? false : options.allowBinary;
  if (typeof allowBinary !== 'boolean') fail('Choose an explicit file-byte profile.');
  if (!Array.isArray(edits) || !edits.length || edits.length > EDIT_LIMIT) fail('Choose 1 through 64 complete edits.');
  const paths = new Set(); let bytes = 0, lines = 0;
  const normalized = edits.map(edit => {
    keys(edit, ['path_hex', 'before', 'after']); sourcePath(edit.path_hex);
    if (paths.has(edit.path_hex)) fail('Duplicate edited path.'); paths.add(edit.path_hex);
    const result = { path_hex: edit.path_hex };
    for (const side of ['before', 'after']) {
      const value = edit[side];
      if (value === null) result[side] = null;
      else {
        keys(value, ['bytes', 'mode']); fileBytes(value.bytes, allowBinary); fileMode(value.mode);
        bytes += value.bytes.length;
        lines += value.bytes.reduce((n, byte) => n + Number(byte === 10), 0) + Number(value.bytes.length > 0 && value.bytes.at(-1) !== 10);
        if (bytes > PATCH_LIMIT || lines > LINE_LIMIT) fail('Combined edits exceed the patch byte or line budget.');
        result[side] = { bytes: value.bytes.slice(), mode: value.mode };
      }
    }
    if (!result.before && !result.after) fail('Both sides of an edit are absent.');
    if (result.before && result.after && result.before.mode === result.after.mode && same(result.before.bytes, result.after.bytes)) fail('Unchanged files are not edits.');
    return result;
  }).sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
  for (const edit of normalized) {
    const path = sourcePath(edit.path_hex);
    for (let i = 0; i < path.length; i += 1) if (path[i] === 47 && paths.has(hex(path.subarray(0, i)))) fail('Overlapping edited paths.');
  }
  return normalized;
}
function lineCount(bytes) { return bytes.reduce((n, byte) => n + Number(byte === 10), 0) + Number(bytes.length > 0 && bytes.at(-1) !== 10); }
export function fullFilePatch(edits, options = {}) {
  const normalized = normalizeEdits(edits, options), parts = []; let size = 0;
  const put = value => {
    const bytes = typeof value === 'string' ? utf8.encode(value) : value;
    if ((size += bytes.length) > PATCH_LIMIT) fail('Encoded patch exceeds 1 MiB.');
    parts.push(bytes);
  };
  for (const { path_hex, before, after } of normalized) {
    const path = sourcePath(path_hex), a = quotePath('a/', path), b = quotePath('b/', path);
    put(`diff --git ${a} ${b}\n`);
    if (before === null) put(`new file mode ${after.mode.toString(8)}\n`);
    else if (after === null) put(`deleted file mode ${before.mode.toString(8)}\n`);
    else if (before.mode !== after.mode) put(`old mode ${before.mode.toString(8)}\nnew mode ${after.mode.toString(8)}\n`);
    const old = before?.bytes ?? new Uint8Array(), next = after?.bytes ?? new Uint8Array();
    if (same(old, next)) continue; // Header-only empty creation/deletion or mode-only change.
    const oldCount = lineCount(old), newCount = lineCount(next);
    put(`--- ${before === null ? '/dev/null' : a}\n+++ ${after === null ? '/dev/null' : b}\n`);
    put(`@@ -${oldCount ? 1 : 0},${oldCount} +${newCount ? 1 : 0},${newCount} @@\n`);
    for (const [prefix, bytes] of [['-', old], ['+', next]]) {
      let start = 0;
      for (let i = 0; i <= bytes.length; i += 1) if (bytes[i] === 10 || (i === bytes.length && start < i)) {
        const end = i < bytes.length ? i + 1 : i;
        put(prefix); put(bytes.subarray(start, end));
        if (end === bytes.length && bytes.at(-1) !== 10) put('\n\\ No newline at end of file\n');
        start = end;
      }
    }
  }
  // Avoid a variadic spread: a permitted many-line file can exceed JavaScript's
  // argument limit even while remaining inside all patch and line budgets.
  const bytes = new Uint8Array(size); let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  return { bytes, edits: normalized };
}
