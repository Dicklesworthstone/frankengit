// Exact original-coordinate byte edits over independently pinned whole blobs.
// No substring search, offset adjustment, Unicode conversion or publication.
import { createHash } from 'node:crypto';
import { editInput } from './source_edit_candidate.mjs';
import { compileSourceReplacements, captureSourceReplacements, REPLACEMENT_LIMITS } from './source_edit_replacements.mjs';
import { fail, fields, integer, clock } from './source_edit_wire.mjs';

export const SPLICE_PROFILE = 'frankengit-source-splices-v1';
export const SPLICE_LIMITS = Object.freeze({ maxSplices: 4096,
  maxExpectedBytes: 8388608, maxInsertedBytes: 8388608 });
const FILE_BYTES = 1048576, MODES = [0o100644, 0o100755];
const blob = (bytes, format) => createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');

function path(value) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(value)) fail('source_splice_path');
  const bytes = Buffer.from(value, 'hex'), parts = bytes.toString('latin1').split('/');
  if (bytes.includes(0) || parts.length > 64 || parts.some(p => !p || p === '.' || p === '..' || p.toLowerCase() === '.git')) fail('source_splice_path');
  return value;
}
function limitsFor(options) {
  fields(options, [...Object.keys(SPLICE_LIMITS), 'maxSourceBytes', 'maxResultBytes'], []);
  return Object.fromEntries(Object.entries({ ...SPLICE_LIMITS,
    maxSourceBytes: REPLACEMENT_LIMITS.maxSourceBytes, maxResultBytes: REPLACEMENT_LIMITS.maxResultBytes })
    .map(([key, maximum]) => [key, integer(Object.hasOwn(options, key) ? options[key] : maximum, 1, maximum)]));
}

// All ranges address ORIGINAL bytes, even after a length-changing earlier edit.
// Adjacent ranges are allowed. Overlaps and duplicate starts (including two
// insertions at one offset) are ambiguous and refuse; combine them explicitly.
// Removing all bytes leaves an empty file, NEVER a file-deletion instruction.
export function spliceSourceFiles(format, files, options = {}, check = () => {}) {
  if (!['sha1', 'sha256'].includes(format) || typeof check !== 'function') fail('source_splice_input');
  check(); const limits = limitsFor(options);
  if (!Array.isArray(files) || !files.length || files.length > 32) fail('source_splice_files');
  let sourceBytes = 0, resultBytes = 0, pathBytes = 0, count = 0, expectedBytes = 0, insertedBytes = 0;
  // Validate the complete inventory and final lengths before allocating any
  // result body. Retained source and instruction buffers have separate bounds.
  const owned = files.map(row => {
    check(); fields(row, ['path_hex', 'before', 'after_mode', 'edits']);
    const name = path(row.path_hex);
    if ((pathBytes += name.length / 2) > 32768) fail('source_splice_paths');
    fields(row.before, ['blob', 'mode', 'bytes']);
    if (!MODES.includes(row.before.mode) || !MODES.includes(row.after_mode) ||
        !(row.before.bytes instanceof Uint8Array) || row.before.bytes.length > FILE_BYTES ||
        (sourceBytes += row.before.bytes.length) > limits.maxSourceBytes) fail('source_splice_source');
    const bytes = Buffer.from(row.before.bytes);
    if (row.before.blob !== blob(bytes, format)) fail('source_splice_preimage');
    if (!Array.isArray(row.edits) || row.edits.length > limits.maxSplices - count) fail('source_splice_count');
    count += row.edits.length;
    let removed = 0, inserted = 0;
    const edits = row.edits.map(edit => {
      check(); fields(edit, ['byte_start', 'before', 'after']);
      const start = integer(edit.byte_start, 0, bytes.length);
      if (!(edit.before instanceof Uint8Array) || !(edit.after instanceof Uint8Array) ||
          edit.before.length > bytes.length - start || edit.after.length > FILE_BYTES) fail('source_splice_range');
      if ((expectedBytes += edit.before.length) > limits.maxExpectedBytes ||
          (insertedBytes += edit.after.length) > limits.maxInsertedBytes) fail('source_splice_bytes');
      const before = Buffer.from(edit.before), after = Buffer.from(edit.after);
      if (!bytes.subarray(start, start + before.length).equals(before)) fail('source_splice_context_mismatch');
      if (before.equals(after)) fail('source_splice_no_effect');
      removed += before.length; inserted += after.length;
      return { start, end: start + before.length, after };
    }).sort((a, b) => a.start - b.start);
    for (let i = 1; i < edits.length; i++) {
      if (edits[i].start === edits[i - 1].start || edits[i].start < edits[i - 1].end) fail('source_splice_overlap');
    }
    const size = bytes.length - removed + inserted;
    if (size < 0 || size > FILE_BYTES || (resultBytes += size) > limits.maxResultBytes) fail('source_splice_result_limit');
    if (!edits.length && row.before.mode === row.after_mode) fail('source_splice_no_effect');
    return { path_hex: name, before: { bytes, mode: row.before.mode, blob: row.before.blob }, mode: row.after_mode, edits, size };
  }).sort((a, b) => a.path_hex < b.path_hex ? -1 : a.path_hex > b.path_hex ? 1 : 0);
  for (let i = 0; i < owned.length; i++) for (let j = 0; j < i; j++) {
    if (owned[i].path_hex === owned[j].path_hex || owned[i].path_hex.startsWith(`${owned[j].path_hex}2f`)) fail('source_splice_paths');
  }
  const changes = owned.map(row => {
    check(); const parts = []; let end = 0;
    for (const edit of row.edits) {
      check(); parts.push(row.before.bytes.subarray(end, edit.start), edit.after); end = edit.end;
    }
    parts.push(row.before.bytes.subarray(end));
    const after = { mode: row.mode, bytes: Buffer.concat(parts, row.size) };
    // Individually nonempty edits may cancel one another; never manufacture a
    // no-op candidate or silently omit a selected file from the effect set.
    if (after.mode === row.before.mode && after.bytes.equals(row.before.bytes)) fail('source_splice_no_effect');
    return { path_hex: row.path_hex, before: row.before, after };
  });
  check();
  return { profile: SPLICE_PROFILE, changes, splice_count: count,
    source_bytes: sourceBytes, result_bytes: resultBytes, expected_bytes: expectedBytes, inserted_bytes: insertedBytes,
    preimages_verified: true, source_membership_verified: false, publication_authorized: false };
}

export function compileSourceSplices(format, files, options = {}, check = () => {}) {
  fields(options, [...Object.keys(REPLACEMENT_LIMITS), ...Object.keys(SPLICE_LIMITS), 'binary'], []);
  const splice = {}, patch = {};
  for (const [key, value] of Object.entries(options)) {
    if (Object.hasOwn(SPLICE_LIMITS, key) || key === 'maxSourceBytes' || key === 'maxResultBytes') splice[key] = value;
    if (!Object.hasOwn(SPLICE_LIMITS, key)) patch[key] = value;
  }
  const result = spliceSourceFiles(format, files, splice, check);
  const compiled = compileSourceReplacements(format, result.changes, patch, check);
  return { ...compiled, splice_profile: SPLICE_PROFILE, splice_count: result.splice_count,
    expected_bytes: result.expected_bytes, inserted_bytes: result.inserted_bytes, preimages_verified: true };
}

// Reuse the existing one-deadline, result-root-pinned preparation/inspection
// owner. Caller changes are fully detached before its first network await.
export async function captureSourceSplices(selection, files, credential, options = {}) {
  fields(options, ['signal', 'timeoutMs', 'ca', 'maxWireBytes', 'binary', ...Object.keys(SPLICE_LIMITS)], []);
  const { binary, maxSplices, maxExpectedBytes, maxInsertedBytes, ...network } = options;
  const request = editInput(selection), time = clock(network); time.check();
  if (!Object.hasOwn(request, 'expected_result_tree')) fail('source_replacement_result_required');
  const narrowed = {};
  for (const key of Object.keys(SPLICE_LIMITS)) if (Object.hasOwn(options, key)) narrowed[key] = options[key];
  const result = spliceSourceFiles(request.scope.object_format, files, narrowed, time.check);
  const captured = await captureSourceReplacements(request, result.changes, credential, {
    timeoutMs: time.remaining(), signal: time.signal, maxWireBytes: time.maxWireBytes,
    ...(time.ca ? { ca: time.ca } : {}), ...(Object.hasOwn(options, 'binary') ? { binary } : {}) });
  time.check();
  return { ...captured, splice_profile: SPLICE_PROFILE, splice_count: result.splice_count,
    expected_bytes: result.expected_bytes, inserted_bytes: result.inserted_bytes, preimages_verified: true };
}
