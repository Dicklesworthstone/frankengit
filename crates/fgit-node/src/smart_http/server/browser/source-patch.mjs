// Exact regular-file patches for native source preparation. No filesystem,
// subprocess, fuzzy application, rename inference, or publication lives here.
export const EDIT_LIMITS = Object.freeze({ files: 64, fileBytes: 1024 * 1024,
  totalBytes: 4 * 1024 * 1024, patchBytes: 8 * 1024 * 1024, lines: 160_000, pathBytes: 4096 });
const utf8 = new TextEncoder();
const fail = message => { throw new Error(message); };
export const bytesHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export function pathBytes(value) {
  if (typeof value !== 'string' || !value.length || value.length > EDIT_LIMITS.pathBytes * 2 || value.length % 2 || !/^[0-9a-f]+$/.test(value)) fail('Invalid byte path.');
  const bytes = Uint8Array.from(value.match(/../g), pair => Number.parseInt(pair, 16));
  if (bytes.includes(0)) fail('NUL is not a repository path byte.');
  let start = 0, components = 0;
  for (let i = 0; i <= bytes.length; i += 1) if (i === bytes.length || bytes[i] === 47) {
    const part = bytes.subarray(start, i);
    if (!part.length || (part.length <= 2 && part.every(b => b === 46)) ||
        (part.length === 4 && part[0] === 46 && (part[1] | 32) === 103 && (part[2] | 32) === 105 && (part[3] | 32) === 116)) fail('Unsafe repository path component.');
    start = i + 1; if (++components > 64) fail('Repository path exceeds 64 components.');
  }
  return bytes;
}
export function textBytes(text) {
  if (typeof text !== 'string' || text.length > EDIT_LIMITS.fileBytes || /[\uD800-\uDFFF]/u.test(text) || text.includes('\0')) fail('Invalid, binary, or oversized text.');
  const bytes = utf8.encode(text);
  if (bytes.length > EDIT_LIMITS.fileBytes) fail('File exceeds 1 MiB.');
  return bytes;
}
export function exactText(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > EDIT_LIMITS.fileBytes || bytes.includes(0)) fail('Only bounded, NUL-free UTF-8 files can be edited as text.');
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { return fail('This file is not UTF-8. Use an exact-byte patch workflow instead.'); }
}
function mode(value) { if (![0o100644, 0o100755].includes(value)) fail('Only regular and executable files can be edited.'); return value; }
function equal(left, right) { return left.length === right.length && left.every((b, i) => b === right[i]); }
function checkSide(side) {
  if (side === null) return;
  if (!side || Object.keys(side).some(k => !['mode', 'bytes'].includes(k))) fail('Invalid file side.');
  mode(side.mode);
  if (!(side.bytes instanceof Uint8Array) || side.bytes.length > EDIT_LIMITS.fileBytes || side.bytes.includes(0)) fail('File is binary or exceeds 1 MiB.');
}
function capture(edits) {
  if (!Array.isArray(edits) || !edits.length || edits.length > EDIT_LIMITS.files) fail('Select 1 through 64 explicit file changes.');
  let total = 0; const paths = new Set();
  for (const edit of edits) {
    if (!edit || Object.keys(edit).some(k => !['path_hex', 'before', 'after'].includes(k))) fail('Unknown edit field.');
    pathBytes(edit.path_hex); checkSide(edit.before); checkSide(edit.after);
    if (edit.before === null && edit.after === null) fail('An edit must have a present side.');
    if (paths.has(edit.path_hex)) fail('Duplicate edit path.'); paths.add(edit.path_hex);
    total += (edit.before?.bytes.length ?? 0) + (edit.after?.bytes.length ?? 0);
    if (total > EDIT_LIMITS.totalBytes) fail('Edit set exceeds 4 MiB of retained file bytes.');
  }
  for (const value of paths) {
    const path = pathBytes(value);
    for (let i = 0; i < path.length; i += 1) if (path[i] === 47 && paths.has(bytesHex(path.subarray(0, i)))) fail('Overlapping file and directory edits.');
  }
  // Own all caller bytes before the first digest await. Subsequent UI edits
  // cannot change the patch, blob expectations or frozen candidate inputs.
  const clone = side => side === null ? null : { mode: side.mode, bytes: side.bytes.slice() };
  return edits.map(e => ({ path_hex: e.path_hex, before: clone(e.before), after: clone(e.after) }))
    .filter(e => !e.before || !e.after || e.before.mode !== e.after.mode || !equal(e.before.bytes, e.after.bytes))
    .sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
}
export function quotedPath(path, prefix) {
  pathBytes(bytesHex(path));
  if (!['a/', 'b/'].includes(prefix)) fail('Invalid Git path prefix.');
  let out = `"${prefix}`;
  for (const b of path) out += b === 34 ? '\\"' : b === 92 ? '\\\\' : b >= 32 && b <= 126 ? String.fromCharCode(b) : `\\${b.toString(8).padStart(3, '0')}`;
  return out + '"';
}
export async function gitObjectId(kind, bytes, algorithm, crypto = globalThis.crypto) {
  if (!['sha1', 'sha256'].includes(algorithm) || !['blob', 'commit'].includes(kind) || !(bytes instanceof Uint8Array) || bytes.length > 2 * 1024 * 1024) fail('Invalid native object hashing request.');
  const header = utf8.encode(`${kind} ${bytes.length}\0`), framed = new Uint8Array(header.length + bytes.length);
  framed.set(header); framed.set(bytes, header.length);
  return bytesHex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
}
function lines(bytes) {
  const out = []; let start = 0;
  for (let i = 0; i < bytes.length; i += 1) if (bytes[i] === 10) { out.push(bytes.subarray(start, i + 1)); start = i + 1; }
  if (start < bytes.length) out.push(bytes.subarray(start));
  return out;
}
export async function buildPatch(edits, algorithm, { crypto = globalThis.crypto, signal } = {}) {
  if (!['sha1', 'sha256'].includes(algorithm)) fail('Choose an explicit Git hash domain.');
  signal?.throwIfAborted(); const owned = capture(edits);
  if (!owned.length) fail('No file changes to prepare.');
  let size = 0, lineCount = 0; const chunks = [], manifest = [];
  const put = bytes => {
    size += bytes.length;
    if (size > EDIT_LIMITS.patchBytes) fail('Patch exceeds 8 MiB.');
    lineCount += bytes.reduce((n, b) => n + Number(b === 10), 0);
    if (lineCount > EDIT_LIMITS.lines) fail('Patch exceeds the line budget.');
    chunks.push(bytes);
  };
  const string = value => put(utf8.encode(value));
  for (const edit of owned) {
    signal?.throwIfAborted(); const { before, after, path_hex } = edit;
    const oldId = before === null ? null : await gitObjectId('blob', before.bytes, algorithm, crypto);
    signal?.throwIfAborted();
    const newId = after === null ? null : await gitObjectId('blob', after.bytes, algorithm, crypto);
    signal?.throwIfAborted();
    const oldPath = quotedPath(pathBytes(path_hex), 'a/'), newPath = quotedPath(pathBytes(path_hex), 'b/');
    string(`diff --git ${oldPath} ${newPath}\n`);
    if (before === null) string(`new file mode ${after.mode.toString(8)}\n`);
    else if (after === null) string(`deleted file mode ${before.mode.toString(8)}\n`);
    else if (before.mode !== after.mode) string(`old mode ${before.mode.toString(8)}\nnew mode ${after.mode.toString(8)}\n`);
    const zeros = '0'.repeat(algorithm === 'sha1' ? 40 : 64);
    string(`index ${oldId ?? zeros}..${newId ?? zeros}${before && after && before.mode === after.mode ? ` ${before.mode.toString(8)}` : ''}\n`);
    const oldLines = lines(before?.bytes ?? new Uint8Array()), newLines = lines(after?.bytes ?? new Uint8Array());
    const changed = oldId !== newId && (oldLines.length || newLines.length);
    if (changed) {
      string(`--- ${before ? oldPath : '/dev/null'}\n+++ ${after ? newPath : '/dev/null'}\n`);
      string(`@@ -${oldLines.length ? 1 : 0},${oldLines.length} +${newLines.length ? 1 : 0},${newLines.length} @@\n`);
      for (const [prefix, rows] of [[45, oldLines], [43, newLines]]) for (const line of rows) {
        signal?.throwIfAborted(); put(Uint8Array.of(prefix)); put(line);
        if (line.at(-1) !== 10) string('\n\\ No newline at end of file\n');
      }
    }
    manifest.push({ path_hex, old_blob: oldId, new_blob: newId, old_mode: before?.mode ?? null, new_mode: after?.mode ?? null, hunks: changed ? 1 : 0 });
  }
  signal?.throwIfAborted(); const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return { bytes, paths: manifest };
}
