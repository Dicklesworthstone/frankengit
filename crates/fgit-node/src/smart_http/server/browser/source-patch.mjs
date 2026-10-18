// Exact regular-file patches for native source preparation. No filesystem,
// subprocess, fuzzy application, rename inference, or publication lives here.
export const EDIT_LIMITS = Object.freeze({ files: 64, fileBytes: 1024 * 1024,
  totalBytes: 4 * 1024 * 1024, patchBytes: 8 * 1024 * 1024, lines: 160_000, pathBytes: 4096 });
export const COMPACT_PATCH_PROFILE = 'trim-common-lines-v1';
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
function checkSide(side, allowBinary) {
  if (side === null) return;
  if (!side || Object.keys(side).some(k => !['mode', 'bytes'].includes(k))) fail('Invalid file side.');
  mode(side.mode);
  if (!(side.bytes instanceof Uint8Array) || side.bytes.length > EDIT_LIMITS.fileBytes || (!allowBinary && side.bytes.includes(0))) fail('File exceeds 1 MiB or contains NUL outside the binary-safe profile.');
}
function capture(edits, allowBinary) {
  if (!Array.isArray(edits) || !edits.length || edits.length > EDIT_LIMITS.files) fail('Select 1 through 64 explicit file changes.');
  let total = 0; const paths = new Set();
  for (const edit of edits) {
    if (!edit || Object.keys(edit).some(k => !['path_hex', 'before', 'after'].includes(k))) fail('Unknown edit field.');
    pathBytes(edit.path_hex); checkSide(edit.before, allowBinary); checkSide(edit.after, allowBinary);
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
  const clone = side => side === null ? null : { mode: side.mode, bytes: new Uint8Array(side.bytes) };
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
// Trim only byte-identical COMPLETE lines, with three unchanged context lines
// at each edge. This is not fuzzy matching, rename detection or semantic merge.
// Two monotone scans keep work linear and avoid one array allocation per line
// for the potentially much larger unchanged portions of a file.
function compactHunk(before, after, put, string, check) {
  const priorStart = (bytes, end) => {
    const from = end - 1 - Number(bytes[end - 1] === 10);
    return from < 0 ? 0 : bytes.lastIndexOf(10, from) + 1;
  };
  const nextEnd = (bytes, start) => { const lf = bytes.indexOf(10, start); return lf < 0 ? bytes.length : lf + 1; };
  let common = 0, leading = 0;
  for (let i = 0; i < Math.min(before.length, after.length) && before[i] === after[i]; i++) {
    if (i % 4096 === 0) check();
    if (before[i] === 10) { common = i + 1; leading++; }
  }
  let oldEnd = before.length, newEnd = after.length, trailing = 0;
  while (oldEnd > common && newEnd > common) {
    check(); const oldStart = priorStart(before, oldEnd), newStart = priorStart(after, newEnd);
    if (oldStart < common || newStart < common || oldEnd - oldStart !== newEnd - newStart) break;
    let same = true;
    for (let i = 0; i < oldEnd - oldStart; i++) {
      if (i % 4096 === 0) check();
      if (before[oldStart + i] !== after[newStart + i]) { same = false; break; }
    }
    if (!same) break;
    oldEnd = oldStart; newEnd = newStart; trailing++;
  }
  const prefixCount = Math.min(3, leading), suffixCount = Math.min(3, trailing);
  let start = common, oldStop = oldEnd, newStop = newEnd;
  for (let n = 0; n < prefixCount; n++) start = priorStart(before, start);
  for (let n = 0; n < suffixCount; n++) { oldStop = nextEnd(before, oldStop); newStop = nextEnd(after, newStop); }
  const count = (bytes, from, to) => {
    let result = Number(to > from && bytes[to - 1] !== 10);
    for (let i = from; i < to; i++) { if (i % 4096 === 0) check(); if (bytes[i] === 10) result++; }
    return result;
  };
  const oldCount = count(before, start, oldStop), newCount = count(after, start, newStop), first = leading - prefixCount;
  string(`@@ -${first + Number(oldCount !== 0)},${oldCount} +${first + Number(newCount !== 0)},${newCount} @@\n`);
  const span = (prefix, bytes, from, to) => {
    let at = from;
    for (let i = from; i <= to; i++) {
      if (i % 4096 === 0) check();
      if (i < to ? bytes[i] !== 10 : at === i) continue;
      const end = i < to ? i + 1 : i;
      put(Uint8Array.of(prefix)); put(bytes.subarray(at, end));
      if (bytes[end - 1] !== 10) string('\n\\ No newline at end of file\n');
      at = end;
    }
  };
  span(32, before, start, common);
  span(45, before, common, oldEnd);
  span(43, after, common, newEnd);
  span(32, before, oldEnd, oldStop);
  check();
}
// A bounded shortest-edit-path search over EXACT LF-terminated byte lines.
// This changes patch representation only, not the selected before/after images.
// No hash, fuzzy match, word classifier, or native Git subprocess decides equality.
export const MULTI_HUNK_PATCH_PROFILE = 'bounded-line-hunks-v1';
export const LINE_DIFF_LIMITS = Object.freeze({ maxWork: 16_777_216, maxLines: 1_048_576,
  maxDistance: 256, maxTraceCells: 66_049, maxHunks: 4096 });
export class PatchDiffError extends Error {
  constructor(code) { super(code); this.name = 'PatchDiffError'; this.code = code; }
}
const diffRefuse = code => { throw new PatchDiffError(`source_patch_diff_${code}`); };
function lineDiffBudget(check) {
  return { work: 0, lines: 0, hunks: 0, nextYield: 65536, check,
    spend(n = 1) {
      this.work += n;
      if (this.work > LINE_DIFF_LIMITS.maxWork) diffRefuse('work_limit');
    },
    async yield() {
      check(); await new Promise(resolve => setTimeout(resolve, 0)); check();
      this.nextYield = this.work + 65536;
    } };
}
async function lineOffsets(bytes, budget) {
  // Count before allocating. The shared line/work ceilings cover ALL file pairs,
  // including unchanged context. Offsets cost four bytes per admitted line.
  budget.spend(2 * bytes.length);
  let count = Number(bytes.length > 0 && bytes.at(-1) !== 10);
  for (let at = 0; at < bytes.length; at++) {
    if (bytes[at] === 10) count++;
    if (count > LINE_DIFF_LIMITS.maxLines - budget.lines) diffRefuse('line_limit');
    if (at && at % 65536 === 0) await budget.yield();
  }
  budget.lines += count;
  const offsets = new Uint32Array(count + 1); let line = 0;
  for (let at = 0; at < bytes.length; at++) {
    if (bytes[at] === 10) offsets[++line] = at + 1;
    if (at && at % 65536 === 0) await budget.yield();
  }
  offsets[count] = bytes.length; budget.check(); return offsets;
}
function equalLine(before, old, x, after, next, y, budget) {
  budget.spend();
  const size = old[x + 1] - old[x];
  if (size !== next[y + 1] - next[y]) return false;
  for (let at = 0; at < size; at++) {
    budget.spend(); if (at % 4096 === 0) budget.check();
    if (before[old[x] + at] !== after[next[y] + at]) return false;
  }
  return true;
}
function frontier(row, diagonal) {
  const at = diagonal + (row.length - 1) / 2;
  return at < 0 || at >= row.length ? -1 : row[at];
}
function predecessor(row, diagonal, n, m) {
  const left = frontier(row, diagonal - 1), down = frontier(row, diagonal + 1);
  const deletion = left >= 0 && left < n ? left + 1 : -1;
  const insertion = down >= 0 && down - diagonal < m + 1 ? down : -1;
  // Equal resulting frontiers choose insertion; reconstruction uses this same
  // rule. Unreachable and out-of-rectangle transitions never seed a new path.
  if (insertion >= 0 && insertion >= deletion) return { x: insertion, y: insertion - diagonal, px: down, py: down - diagonal - 1 };
  if (deletion >= 0) return { x: deletion, y: deletion - diagonal, px: left, py: left - diagonal + 1 };
  return null;
}
async function changedLineSpans(before, old, after, next, budget) {
  const n = old.length - 1, m = next.length - 1, trace = []; let cells = 0;
  if (Math.abs(n - m) > LINE_DIFF_LIMITS.maxDistance) diffRefuse('distance_limit');
  for (let distance = 0; distance <= LINE_DIFF_LIMITS.maxDistance; distance++) {
    budget.check();
    const width = 2 * distance + 1;
    if ((cells += width) > LINE_DIFF_LIMITS.maxTraceCells) diffRefuse('trace_limit');
    const row = new Int32Array(width).fill(-1); trace.push(row);
    for (let diagonal = -distance; diagonal <= distance; diagonal += 2) {
      budget.spend();
      const start = distance === 0 ? { x: 0, y: 0 } : predecessor(trace[distance - 1], diagonal, n, m);
      if (start === null || start.x > n || start.y < 0 || start.y > m) continue;
      let { x, y } = start;
      while (x < n && y < m && equalLine(before, old, x, after, next, y, budget)) {
        x++; y++;
        if (budget.work >= budget.nextYield) await budget.yield();
      }
      row[diagonal + distance] = x;
      if (x === n && y === m) {
        // Retain only changed spans (at most maxDistance), not an object for
        // each matching line. The frontier trace is at most 66,049 i32 cells.
        const reversed = [];
        for (let d = distance; d > 0; d--) {
          budget.check(); budget.spend();
          const p = predecessor(trace[d - 1], x - y, n, m);
          if (!p || p.x > x || p.y > y || x - p.x !== y - p.y) diffRefuse('invalid_trace');
          reversed.push({ oldStart: p.px, oldEnd: p.x, newStart: p.py, newEnd: p.y });
          x = p.px; y = p.py;
        }
        const spans = [];
        for (const span of reversed.reverse()) {
          const previous = spans.at(-1);
          if (previous && previous.oldEnd === span.oldStart && previous.newEnd === span.newStart) {
            previous.oldEnd = span.oldEnd; previous.newEnd = span.newEnd;
          } else spans.push(span);
        }
        budget.check(); return spans;
      }
      if (budget.work >= budget.nextYield) await budget.yield();
    }
  }
  // A high-distance rewrite can be explicitly authored with another profile.
  // Never silently change encoding, return a partial patch, or widen the budget.
  diffRefuse('distance_limit');
}
async function lineHunks(before, after, put, string, budget) {
  const old = await lineOffsets(before, budget), next = await lineOffsets(after, budget);
  const n = old.length - 1, m = next.length - 1;
  // Fix identical edges before searching. Otherwise repeated lines can admit
  // an equally short but misleading insertion near the edit plus deletion at
  // EOF. Edge matching is exact and charged to the same global work budget.
  let lead = 0, oldEnd = n, newEnd = m;
  while (lead < n && lead < m && equalLine(before, old, lead, after, next, lead, budget)) {
    lead++; if (budget.work >= budget.nextYield) await budget.yield();
  }
  while (oldEnd > lead && newEnd > lead && equalLine(before, old, oldEnd - 1, after, next, newEnd - 1, budget)) {
    oldEnd--; newEnd--; if (budget.work >= budget.nextYield) await budget.yield();
  }
  // Creation/deletion and a whole-file empty transition need no diff search.
  const spans = !n || !m ? [{ oldStart: 0, oldEnd: n, newStart: 0, newEnd: m }]
    : (await changedLineSpans(before, old.subarray(lead, oldEnd + 1), after, next.subarray(lead, newEnd + 1), budget))
      .map(span => ({ oldStart: span.oldStart + lead, oldEnd: span.oldEnd + lead,
        newStart: span.newStart + lead, newEnd: span.newEnd + lead }));
  const groups = [];
  for (const span of spans) {
    const previous = groups.at(-1)?.at(-1);
    if (previous && span.oldStart - previous.oldEnd !== span.newStart - previous.newEnd) diffRefuse('invalid_trace');
    if (previous && span.oldStart - previous.oldEnd <= 6) groups.at(-1).push(span);
    else groups.push([span]);
  }
  if ((budget.hunks += groups.length) > LINE_DIFF_LIMITS.maxHunks) diffRefuse('hunk_limit');
  const emit = (prefix, bytes, offsets, from, to) => {
    for (let at = from; at < to; at++) {
      budget.check(); const line = bytes.subarray(offsets[at], offsets[at + 1]);
      put(Uint8Array.of(prefix)); put(line);
      if (line.at(-1) !== 10) string('\n\\ No newline at end of file\n');
    }
  };
  for (const group of groups) {
    budget.check(); const first = group[0], last = group.at(-1);
    const lead = Math.min(3, first.oldStart, first.newStart), tail = Math.min(3, n - last.oldEnd, m - last.newEnd);
    const oldStart = first.oldStart - lead, newStart = first.newStart - lead;
    const oldCount = last.oldEnd + tail - oldStart, newCount = last.newEnd + tail - newStart;
    string(`@@ -${oldStart + Number(oldCount > 0)},${oldCount} +${newStart + Number(newCount > 0)},${newCount} @@\n`);
    let x = oldStart, y = newStart;
    for (const span of group) {
      if (span.oldStart - x !== span.newStart - y) diffRefuse('invalid_trace');
      emit(32, before, old, x, span.oldStart);
      emit(45, before, old, span.oldStart, span.oldEnd);
      emit(43, after, next, span.newStart, span.newEnd);
      x = span.oldEnd; y = span.newEnd;
    }
    emit(32, before, old, x, x + tail);
  }
  budget.check(); return groups.length;
}

// Binary-safe callers still use byte-exact counted hunks, NOT a new compressed
// Git-binary-patch codec. Text consumers retain their original NUL refusal.
export async function buildPatch(edits, algorithm, { crypto = globalThis.crypto, signal, allowBinary = false, patchProfile = null } = {}) {
  if (!['sha1', 'sha256'].includes(algorithm)) fail('Choose an explicit Git hash domain.');
  if (typeof allowBinary !== 'boolean') fail('Choose an explicit binary-safe boolean.');
  if (patchProfile !== null && ![COMPACT_PATCH_PROFILE, MULTI_HUNK_PATCH_PROFILE].includes(patchProfile)) fail('Unsupported patch profile.');
  signal?.throwIfAborted(); const owned = capture(edits, allowBinary);
  if (!owned.length) fail('No file changes to prepare.');
  let size = 0, lineCount = 0; const chunks = [], manifest = [];
  const diffBudget = lineDiffBudget(() => signal?.throwIfAborted());
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
    const oldBytes = before?.bytes ?? new Uint8Array(), newBytes = after?.bytes ?? new Uint8Array();
    const changed = oldId !== newId && (oldBytes.length || newBytes.length);
    let hunks = changed ? 1 : 0;
    if (changed) {
      string(`--- ${before ? oldPath : '/dev/null'}\n+++ ${after ? newPath : '/dev/null'}\n`);
      if (patchProfile === MULTI_HUNK_PATCH_PROFILE) hunks = await lineHunks(oldBytes, newBytes, put, string, diffBudget);
      else if (patchProfile === COMPACT_PATCH_PROFILE) compactHunk(oldBytes, newBytes, put, string, () => signal?.throwIfAborted());
      else {
        const oldLines = lines(oldBytes), newLines = lines(newBytes);
        string(`@@ -${oldLines.length ? 1 : 0},${oldLines.length} +${newLines.length ? 1 : 0},${newLines.length} @@\n`);
        for (const [prefix, rows] of [[45, oldLines], [43, newLines]]) for (const line of rows) {
          signal?.throwIfAborted(); put(Uint8Array.of(prefix)); put(line);
          if (line.at(-1) !== 10) string('\n\\ No newline at end of file\n');
        }
      }
    }
    manifest.push({ path_hex, old_blob: oldId, new_blob: newId, old_mode: before?.mode ?? null, new_mode: after?.mode ?? null, hunks });
  }
  signal?.throwIfAborted(); const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return { bytes, paths: manifest };
}
