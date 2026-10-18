// Complete file replacements for native source admission, encoded as bounded
// exact byte hunks. No host worktree or Git subprocess is involved; native
// preparation still verifies the complete intended effects.
import { fail, keys, hex, unhex, utf8 } from './pulls-core.mjs';
export const FILE_LIMIT = 256 * 1024;
export const PATCH_LIMIT = 1024 * 1024;
// Retained verification bytes and transported patch bytes are separate budgets.
export const INPUT_LIMIT = 4 * 1024 * 1024;
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
        if (bytes > INPUT_LIMIT || lines > LINE_LIMIT) fail('Combined edits exceed the retained byte or line budget.');
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
// Offsets, not decoded strings: CRLF, invalid UTF-8 and a missing final LF are
// all part of a line's identity. Allocation is bounded by the checked input.
function indexedLines(bytes) {
  const offsets = new Uint32Array(lineCount(bytes) + 1); let line = 1;
  for (let i = 0; i < bytes.length; i += 1) if (bytes[i] === 10) offsets[line++] = i + 1;
  if (offsets.at(-1) !== bytes.length) offsets[line] = bytes.length;
  return { bytes, offsets, count: offsets.length - 1 };
}
function equalLine(a, ai, b, bi) {
  const start = a.offsets[ai], other = b.offsets[bi], length = a.offsets[ai + 1] - start;
  if (length !== b.offsets[bi + 1] - other) return false;
  for (let i = 0; i < length; i += 1) if (a.bytes[start + i] !== b.bytes[other + i]) return false;
  return true;
}
function putLines(put, prefix, lines, start, end) {
  for (let line = start; line < end; line += 1) {
    const bytes = lines.bytes.subarray(lines.offsets[line], lines.offsets[line + 1]);
    put(prefix); put(bytes);
    if (bytes.at(-1) !== 10) put('\n\\ No newline at end of file\n');
  }
}
// A bounded Myers search separates nearby insertions/deletions and distant
// small edits without an input-sized quadratic table. The shared work ledger
// bounds all files together; trace allocation is at most 65 small frontiers.
// Exhaustion retains the whole exact middle, never a partial set of changes.
const MAX_EDIT_DISTANCE = 64;
function changedRanges(old, next, prefix, suffix, work) {
  const n = old.count - prefix - suffix, m = next.count - prefix - suffix;
  const fallback = () => [{ oldStart: prefix, oldEnd: prefix + n, newStart: prefix, newEnd: prefix + m }];
  if (!n || !m || Math.abs(n - m) > MAX_EDIT_DISTANCE || work.cells <= 0 || work.bytes <= 0) return fallback();
  const limit = Math.min(n + m, MAX_EDIT_DISTANCE), offset = limit + 1;
  const frontier = new Int32Array(2 * limit + 3).fill(-1), trace = [];
  frontier[offset + 1] = 0;
  for (let distance = 0; distance <= limit; distance += 1) {
    trace.push(frontier.slice());
    for (let diagonal = -distance; diagonal <= distance; diagonal += 2) {
      if (--work.cells < 0) return fallback();
      const k = offset + diagonal;
      let x = diagonal === -distance || (diagonal !== distance && frontier[k - 1] < frontier[k + 1])
        ? frontier[k + 1] : frontier[k - 1] + 1;
      let y = x - diagonal;
      while (x < n && y < m) {
        if (--work.cells < 0) return fallback();
        const ai = prefix + x, bi = prefix + y;
        const length = old.offsets[ai + 1] - old.offsets[ai];
        if (length !== next.offsets[bi + 1] - next.offsets[bi]) break;
        if ((work.bytes -= length) < 0) return fallback();
        if (!equalLine(old, ai, next, bi)) break;
        x += 1; y += 1;
      }
      frontier[k] = x;
      if (x >= n && y >= m) {
        const reversed = []; x = n; y = m;
        for (let d = distance; d > 0; d -= 1) {
          const prior = trace[d], diagonal = x - y, k = offset + diagonal;
          const previous = diagonal === -d || (diagonal !== d && prior[k - 1] < prior[k + 1]) ? diagonal + 1 : diagonal - 1;
          const px = prior[offset + previous], py = px - previous;
          while (x > px && y > py) { x -= 1; y -= 1; }
          if (x === px) reversed.push({ oldStart: prefix + x, oldEnd: prefix + x, newStart: prefix + y - 1, newEnd: prefix + y });
          else reversed.push({ oldStart: prefix + x - 1, oldEnd: prefix + x, newStart: prefix + y, newEnd: prefix + y });
          x = px; y = py;
        }
        const changes = [];
        for (const range of reversed.reverse()) {
          const previous = changes.at(-1);
          if (previous && previous.oldEnd === range.oldStart && previous.newEnd === range.newStart) {
            previous.oldEnd = range.oldEnd; previous.newEnd = range.newEnd;
          } else changes.push(range);
        }
        return changes;
      }
    }
  }
  return fallback();
}
function putHunks(put, old, next, work) {
  let prefix = 0, suffix = 0;
  while (prefix < old.count && prefix < next.count && equalLine(old, prefix, next, prefix)) prefix += 1;
  while (suffix < old.count - prefix && suffix < next.count - prefix &&
      equalLine(old, old.count - suffix - 1, next, next.count - suffix - 1)) suffix += 1;
  const changes = changedRanges(old, next, prefix, suffix, work);
  // Preserve the original short/full-replacement form when there is no useful
  // unchanged region to elide. Frozen candidate/retry bytes are never rebuilt.
  if (changes.length === 1 && prefix <= 3 && suffix <= 3) {
    put(`@@ -${old.count ? 1 : 0},${old.count} +${next.count ? 1 : 0},${next.count} @@\n`);
    putLines(put, '-', old, 0, old.count); putLines(put, '+', next, 0, next.count);
    return;
  }
  for (let first = 0; first < changes.length;) {
    let last = first;
    // Coalesce touching context rather than overlapping or duplicating lines.
    while (last + 1 < changes.length && changes[last + 1].oldStart - changes[last].oldEnd <= 6) last += 1;
    const initial = changes[first], final = changes[last];
    const oldStart = Math.max(0, initial.oldStart - 3), newStart = Math.max(0, initial.newStart - 3);
    const oldEnd = Math.min(old.count, final.oldEnd + 3), newEnd = Math.min(next.count, final.newEnd + 3);
    const oldCount = oldEnd - oldStart, newCount = newEnd - newStart;
    put(`@@ -${oldCount ? oldStart + 1 : oldStart},${oldCount} +${newCount ? newStart + 1 : newStart},${newCount} @@\n`);
    let position = oldStart;
    for (let i = first; i <= last; i += 1) {
      const range = changes[i];
      putLines(put, ' ', old, position, range.oldStart);
      putLines(put, '-', old, range.oldStart, range.oldEnd);
      putLines(put, '+', next, range.newStart, range.newEnd);
      position = range.oldEnd;
    }
    putLines(put, ' ', old, position, oldEnd);
    first = last + 1;
  }
}

export function fullFilePatch(edits, options = {}) {
  const normalized = normalizeEdits(edits, options), parts = []; let size = 0;
  const work = { cells: 262144, bytes: 8 * INPUT_LIMIT };
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
    put(`--- ${before === null ? '/dev/null' : a}\n+++ ${after === null ? '/dev/null' : b}\n`);
    putHunks(put, indexedLines(old), indexedLines(next), work);
  }
  // Avoid a variadic spread: a permitted many-line file can exceed JavaScript's
  // argument limit even while remaining inside all patch and line budgets.
  const bytes = new Uint8Array(size); let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  return { bytes, edits: normalized };
}

// Git records trees, not a separate move object. Lower the explicit relocation
// into two disjoint, byte-exact effects for the existing native patch service.
// The caller must keep this pair together; native preparation checks that the
// destination is absent and the source belongs to the selected immutable base.
export function renameEdits(source, destination, before, after = before, options = {}) {
  if (before == null || after == null) fail('A rename requires complete original and resulting file bytes.');
  return normalizeEdits([
    { path_hex: source, before, after: null },
    { path_hex: destination, before: null, after },
  ], options);
}
