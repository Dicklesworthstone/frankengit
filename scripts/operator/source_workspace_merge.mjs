// Bounded textual reconciliation for a trusted-local workspace, NOT Git merge.
// Inputs are already selected by the workspace's native source verifier. This
// module owns no filesystem, network, source authority or publication decision.
import { isUtf8 } from 'node:buffer';

export const WORKSPACE_TEXT_MERGE_PROFILE = 'bounded-line-merge-v1';
export const TEXT_MERGE_LIMITS = Object.freeze({ fileBytes: 1048576, lines: 131072,
  work: 4194304, distance: 256 });
class MergeLimit extends Error {}
const fail = code => { throw new Error(code); };
function fields(value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !allowed.includes(key))) fail('source_workspace_text_merge_options');
}

// A single instance is shared by all sorted files in ONE refresh. No file gets
// a fresh work/line allowance. Only lower limits are accepted by this helper.
export function createWorkspaceTextMerger(options = {}) {
  fields(options, ['check', 'limits']);
  const check = Object.hasOwn(options, 'check') ? options.check : (() => {});
  if (typeof check !== 'function') fail('source_workspace_text_merge_options');
  const inputLimits = Object.hasOwn(options, 'limits') ? options.limits : {}; fields(inputLimits, Object.keys(TEXT_MERGE_LIMITS));
  const limits = Object.fromEntries(Object.entries(TEXT_MERGE_LIMITS).map(([name, maximum]) => {
    const value = Object.hasOwn(inputLimits, name) ? inputLimits[name] : maximum;
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) fail('source_workspace_text_merge_limits');
    return [name, value];
  }));
  let work = 0, lines = 0, attempts = 0, exhausted = null;
  const spend = (amount = 1) => {
    check();
    if (exhausted || amount > limits.work - work) {
      exhausted ??= 'work_limit'; throw new MergeLimit(exhausted);
    }
    work += amount;
  };
  const witness = () => ({ profile: WORKSPACE_TEXT_MERGE_PROFILE, limits: { ...limits },
    attempts, work_used: work, lines_used: lines, exhausted });
  function tokenize(bytes, dictionary) {
    const tokens = [], offsets = [0]; let start = 0;
    for (let at = 0; at <= bytes.length; at++) {
      if ((at & 4095) === 0) spend(1 + Math.ceil(Math.min(4096, bytes.length - at) / 64));
      if (at < bytes.length ? bytes[at] !== 10 : at === start) continue;
      if (lines === limits.lines) { exhausted = 'line_limit'; throw new MergeLimit(exhausted); }
      lines++; spend();
      const end = at < bytes.length ? at + 1 : at;
      // Latin-1 is an injective byte key, not a lossy UTF-8 decode or a digest.
      // CRLF, BOM, blank lines and unterminated EOF all retain their exact bytes.
      const key = bytes.toString('latin1', start, end);
      let id = dictionary.get(key);
      if (id === undefined) { id = dictionary.size; dictionary.set(key, id); }
      tokens.push(id); offsets.push(end); start = end;
    }
    return { bytes, tokens, offsets };
  }
  function changes(base, other) {
    const a = base.tokens, b = other.tokens; let prefix = 0, endA = a.length, endB = b.length;
    while (prefix < endA && prefix < endB) { spend(); if (a[prefix] !== b[prefix]) break; prefix++; }
    while (endA > prefix && endB > prefix) { spend(); if (a[endA - 1] !== b[endB - 1]) break; endA--; endB--; }
    const n = endA - prefix, m = endB - prefix;
    const edit = (start, end, first, last) => ({ start, end,
      tokens: b.slice(first, last), bytes: other.bytes.subarray(other.offsets[first], other.offsets[last]) });
    if (n === 0 && m === 0) return [];
    if (n + m > limits.distance && (n === 0 || m === 0)) throw new MergeLimit('distance_limit');
    if (n === 0 || m === 0) return [edit(prefix, endA, prefix, endB)];
    if (Math.abs(n - m) > limits.distance) throw new MergeLimit('distance_limit');
    // Deterministic Myers frontier; ties prefer deletion. Both time and retained
    // trace are bounded independently of file size. No heuristic fallback can
    // convert an unresolved edit into an unchanged or accepted result.
    const offset = limits.distance + 1, frontier = new Int32Array(2 * limits.distance + 3);
    frontier.fill(-1); frontier[offset + 1] = 0;
    const trace = []; let distance = null;
    search: for (let d = 0; d <= limits.distance; d++) {
      spend(); trace.push(frontier.slice());
      for (let k = -d; k <= d; k += 2) {
        spend();
        let x = k === -d || k !== d && frontier[offset + k - 1] < frontier[offset + k + 1]
          ? frontier[offset + k + 1] : frontier[offset + k - 1] + 1;
        let y = x - k;
        while (x < n && y < m) { spend(); if (a[prefix + x] !== b[prefix + y]) break; x++; y++; }
        frontier[offset + k] = x;
        if (x >= n && y >= m) { distance = d; break search; }
      }
    }
    if (distance === null) throw new MergeLimit('distance_limit');
    const equal = []; let x = n, y = m;
    for (let d = distance; d > 0; d--) {
      spend(); const previous = trace[d], k = x - y;
      const priorK = k === -d || k !== d && previous[offset + k - 1] < previous[offset + k + 1] ? k + 1 : k - 1;
      const priorX = previous[offset + priorK], priorY = priorX - priorK;
      while (x > priorX && y > priorY) { spend(); equal.push([prefix + --x, prefix + --y]); }
      x = priorX; y = priorY;
    }
    while (x > 0 && y > 0) { spend(); equal.push([prefix + --x, prefix + --y]); }
    equal.reverse();
    const result = []; let oldAt = prefix, newAt = prefix;
    for (const [oldLine, newLine] of equal) {
      spend();
      if (oldLine > oldAt || newLine > newAt) result.push(edit(oldAt, oldLine, newAt, newLine));
      oldAt = oldLine + 1; newAt = newLine + 1;
    }
    if (oldAt !== endA || newAt !== endB) result.push(edit(oldAt, endA, newAt, endB));
    return result;
  }
  function overlap(a, b) {
    // Two insertions at one boundary, or an insertion touching either edge of
    // a replacement/deletion, require agreement. Do not invent their ordering.
    if (a.start === a.end) return b.start <= a.start && a.start <= b.end;
    if (b.start === b.end) return a.start <= b.start && b.start <= a.end;
    return a.start < b.end && b.start < a.end;
  }
  function combine(base, ours, theirs) {
    const duplicates = new Set();
    for (const a of ours) for (const [i, b] of theirs.entries()) {
      spend(); if (!overlap(a, b)) continue;
      if (a.start !== b.start || a.end !== b.end || a.tokens.length !== b.tokens.length) return null;
      for (let j = 0; j < a.tokens.length; j++) { spend(); if (a.tokens[j] !== b.tokens[j]) return null; }
      duplicates.add(i);
    }
    const edits = [...ours, ...theirs.filter((_b, i) => !duplicates.has(i))].sort((a, b) => a.start - b.start || a.end - b.end);
    const parts = []; let cursor = 0, size = 0;
    const append = bytes => {
      spend(1 + Math.ceil(bytes.length / 64));
      if (bytes.length > limits.fileBytes - size) throw new MergeLimit('output_limit');
      size += bytes.length; parts.push(bytes);
    };
    for (const edit of edits) {
      spend();
      if (edit.start < cursor) fail('source_workspace_text_merge_invariant');
      append(base.bytes.subarray(base.offsets[cursor], base.offsets[edit.start]));
      append(edit.bytes); cursor = edit.end;
    }
    append(base.bytes.subarray(base.offsets[cursor]));
    check(); return { bytes: Buffer.concat(parts, size), identical_edits: duplicates.size };
  }
  return Object.freeze({ witness, merge(before, local, selected) {
    // Own all input images before invoking caller checkpoints. Shared memory,
    // oversized inputs and alternate coercions never enter the line algorithm.
    const values = [before, local, selected];
    if (values.some(b => !(b instanceof Uint8Array) || !(b.buffer instanceof ArrayBuffer) || b.length > limits.fileBytes)) fail('source_workspace_text_merge_input');
    const images = values.map(b => Buffer.from(b));
    attempts++; const startWork = work, startLines = lines;
    const finish = (status, reason, data = {}) => ({ status, reason, ...data,
      work_used: work - startWork, lines_used: lines - startLines });
    try {
      spend();
      if (images.some(b => b.includes(0) || !isUtf8(b))) return finish('conflict', 'not_text');
      const dictionary = new Map(), [base, ours, theirs] = images.map(b => tokenize(b, dictionary));
      const a = changes(base, ours), b = changes(base, theirs), merged = combine(base, a, b);
      if (merged === null) return finish('conflict', 'overlapping_changes', { local_edits: a.length, selected_edits: b.length });
      check(); return finish('merged', null, { ...merged, local_edits: a.length, selected_edits: b.length });
    } catch (error) {
      if (!(error instanceof MergeLimit)) throw error; // Never turn cancellation into a conflict or success.
      return finish('conflict', error.message);
    }
  } });
}
