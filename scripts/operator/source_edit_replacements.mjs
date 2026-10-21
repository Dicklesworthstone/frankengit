// Exact whole-file Git patch encoding, not a diff heuristic or a Git subprocess.
// Native Rust remains the patch/admission authority. Supplied preimage hashes
// bind bytes, not repository membership; use independently verified evidence.
import { createHash } from 'node:crypto';
import { editInput, captureSourceEdit } from './source_edit_candidate.mjs';
import { fail, fields, integer, clock } from './source_edit_wire.mjs';
import { binaryLiteralCost, emitBinaryLiteral, emitBinaryMember } from './source_edit_binary_literal.mjs';
import { planBinaryMember, planBinaryRunMember } from './source_edit_binary_delta.mjs';

export const REPLACEMENT_PROFILE = 'frankengit-source-replacements-v1';
export const BINARY_REPLACEMENT_PROFILE = 'frankengit-source-replacements-binary-v1';
export const DELTA_REPLACEMENT_PROFILE = 'frankengit-source-replacements-delta-v1';
export const RUN_DELTA_REPLACEMENT_PROFILE = 'frankengit-source-replacements-delta-runs-v1';
function binaryMode(options) {
  if (!Object.hasOwn(options, 'binary')) return false;
  if (!['literal', 'delta', 'delta-runs'].includes(options.binary)) fail('source_replacement_binary_profile');
  return options.binary;
}
export const REPLACEMENT_LIMITS = Object.freeze({ maxPatchBytes: 1048576,
  maxSourceBytes: 8388608, maxResultBytes: 8388608, maxRecords: 131072 });
const FILE_BYTES = 1048576, MODES = [0o100644, 0o100755];
const blob = (bytes, format) => createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
function path(value) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(value)) fail('source_replacement_path');
  const bytes = Buffer.from(value, 'hex'), parts = bytes.toString('latin1').split('/');
  if (bytes.includes(0) || parts.length > 64 || parts.some(p => !p || p === '.' || p === '..' || p.toLowerCase() === '.git')) {
    fail('source_replacement_path');
  }
  return value;
}
function quoted(prefix, value) {
  let text = `"${prefix}/`;
  for (const byte of Buffer.from(value, 'hex')) {
    text += byte >= 33 && byte <= 126 && byte !== 34 && byte !== 92 ? String.fromCharCode(byte)
      : `\\${byte.toString(8).padStart(3, '0')}`;
  }
  return text + '"';
}
function body(value, format, original, binary) {
  if (value === null) return null;
  fields(value, original ? ['mode', 'blob', 'bytes'] : ['mode', 'bytes']);
  if (!MODES.includes(value.mode) || !(value.bytes instanceof Uint8Array) || value.bytes.length > FILE_BYTES) {
    fail('source_replacement_file');
  }
  const bytes = Buffer.from(value.bytes);
  // Unified text records can preserve arbitrary non-NUL bytes. Binary patches
  // are a separate grammar; never truncate or transcode one into text.
  if (!binary && bytes.includes(0)) fail('source_replacement_binary');
  const id = blob(bytes, format);
  if (original && value.blob !== id) fail('source_replacement_preimage');
  return { mode: value.mode, blob: id, bytes };
}
function lines(bytes, check, maximum) {
  const result = []; let start = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (i % 4096 === 0) check();
    if (bytes[i] === 10) {
      if (result.length >= maximum) fail('source_replacement_patch_limit');
      result.push(bytes.subarray(start, i + 1)); start = i + 1;
    }
  }
  if (start < bytes.length) {
    if (result.length >= maximum) fail('source_replacement_patch_limit');
    result.push(bytes.subarray(start));
  }
  return result;
}

export function compileSourceReplacements(format, changes, options = {}, check = () => {}) {
  if (!['sha1', 'sha256'].includes(format) || typeof check !== 'function') fail('source_replacement_input');
  check(); fields(options, [...Object.keys(REPLACEMENT_LIMITS), 'binary'], []);
  const binary = binaryMode(options);
  const limits = Object.fromEntries(Object.entries(REPLACEMENT_LIMITS).map(([key, maximum]) =>
    [key, integer(options[key] ?? maximum, 1, maximum)]));
  if (!Array.isArray(changes) || !changes.length || changes.length > 32) fail('source_replacement_changes');
  let sourceBytes = 0, resultBytes = 0, pathBytes = 0;
  const owned = changes.map(row => {
    check(); fields(row, ['path_hex', 'before', 'after']); const name = path(row.path_hex);
    pathBytes += name.length / 2;
    if (pathBytes > 32768) fail('source_replacement_paths');
    const before = body(row.before, format, true, binary), after = body(row.after, format, false, binary);
    if (!before && !after || before && after && before.mode === after.mode && before.blob === after.blob) {
      fail('source_replacement_no_effect');
    }
    sourceBytes += before?.bytes.length ?? 0; resultBytes += after?.bytes.length ?? 0;
    if (sourceBytes > limits.maxSourceBytes || resultBytes > limits.maxResultBytes) fail('source_replacement_bytes');
    return { path_hex: name, before, after };
  }).sort((a, b) => a.path_hex < b.path_hex ? -1 : a.path_hex > b.path_hex ? 1 : 0);
  for (let i = 0; i < owned.length; i++) for (let j = 0; j < i; j++) {
    if (owned[i].path_hex === owned[j].path_hex || owned[i].path_hex.startsWith(`${owned[j].path_hex}2f`)) {
      fail('source_replacement_collision');
    }
  }
  const chunks = []; let size = 0, records = 0, binaryFiles = 0, deltaMembers = 0, alignedCopyRegions = 0;
  const put = (data, record = true) => {
    check(); const bytes = typeof data === 'string' ? Buffer.from(data) : data;
    if (size + bytes.length > limits.maxPatchBytes || record && ++records > limits.maxRecords) fail('source_replacement_patch_limit');
    size += bytes.length; chunks.push(bytes);
  };
  const emitLine = (prefix, data) => {
    put(prefix); put(data, false);
    if (data.at(-1) !== 10) { put('\n', false); put('\\ No newline at end of file\n'); }
  };
  const zero = '0'.repeat(format === 'sha1' ? 40 : 64);
  for (const row of owned) {
    const { before, after } = row, a = quoted('a', row.path_hex), b = quoted('b', row.path_hex);
    put(`diff --git ${a} ${b}\n`);
    if (!before) put(`new file mode ${after.mode.toString(8)}\n`);
    else if (!after) put(`deleted file mode ${before.mode.toString(8)}\n`);
    else if (before.mode !== after.mode) { put(`old mode ${before.mode.toString(8)}\n`); put(`new mode ${after.mode.toString(8)}\n`); }
    put(`index ${before?.blob ?? zero}..${after?.blob ?? zero}${before && after && before.mode === after.mode ? ` ${before.mode.toString(8)}` : ''}\n`);
    // Empty additions/deletions and pure executable-bit changes need no hunk.
    if ((before?.blob ?? null) === (after?.blob ?? null) || !(before?.bytes.length || after?.bytes.length)) continue;
    if (binary && (before?.bytes.includes(0) || after?.bytes.includes(0))) {
      const old = before?.bytes ?? Buffer.alloc(0), next = after?.bytes ?? Buffer.alloc(0);
      const planner = binary === 'delta-runs' ? planBinaryRunMember : planBinaryMember;
      const plans = binary !== 'literal' ? [planner(old, next, check), planner(next, old, check)] : null;
      const forward = plans?.[0].cost ?? binaryLiteralCost(next.length), reverse = plans?.[1].cost ?? binaryLiteralCost(old.length);
      const marker = 'GIT binary patch\n';
      if (size + marker.length + forward.bytes + reverse.bytes > limits.maxPatchBytes ||
          records + 1 + forward.records + reverse.records > limits.maxRecords) fail('source_replacement_patch_limit');
      put(marker);
      if (plans) {
        for (const plan of plans) {
          emitBinaryMember(plan.kind, plan.body, put, check); deltaMembers += Number(plan.kind === 'delta');
          alignedCopyRegions += plan.aligned_copy_regions ?? 0;
        }
      } else { emitBinaryLiteral(next, put, check); emitBinaryLiteral(old, put, check); }
      binaryFiles++; continue;
    }
    const oldLines = lines(before?.bytes ?? Buffer.alloc(0), check, limits.maxRecords - records);
    const newLines = lines(after?.bytes ?? Buffer.alloc(0), check, limits.maxRecords - records - oldLines.length);
    put(`--- ${before ? a : '/dev/null'}\n`); put(`+++ ${after ? b : '/dev/null'}\n`);
    put(`@@ -${oldLines.length ? 1 : 0},${oldLines.length} +${newLines.length ? 1 : 0},${newLines.length} @@\n`);
    for (const line of oldLines) emitLine('-', line);
    for (const line of newLines) emitLine('+', line);
  }
  check(); const patch = Buffer.concat(chunks, size);
  return { profile: binary === 'delta-runs' ? RUN_DELTA_REPLACEMENT_PROFILE
      : binary === 'delta' ? DELTA_REPLACEMENT_PROFILE : binary ? BINARY_REPLACEMENT_PROFILE : REPLACEMENT_PROFILE,
    ...(['delta', 'delta-runs'].includes(binary) ? { delta_members: deltaMembers, literal_members: 2 * binaryFiles - deltaMembers } : {}),
    ...(binary === 'delta-runs' ? { aligned_copy_regions: alignedCopyRegions } : {}),
    ...(binary ? { binary_files: binaryFiles } : {}), patch, source_bytes: sourceBytes, result_bytes: resultBytes, records,
    changes: owned.map(row => ({ path_hex: row.path_hex, before_blob: row.before?.blob ?? null,
      after_blob: row.after?.blob ?? null, before_mode: row.before?.mode ?? null, after_mode: row.after?.mode ?? null })),
    source_membership_verified: false, publication_authorized: false };
}

// The existing prepare/inspect reader owns networking and candidate validation.
// A root chosen independently of that reader is mandatory for this convenience
// path. The compiler never derives it from a server reply or silently retries.
export async function captureSourceReplacements(selection, changes, credential, options = {}) {
  fields(options, ['signal', 'timeoutMs', 'ca', 'maxWireBytes', 'binary'], []);
  const binary = binaryMode(options), { binary: _binary, ...network } = options;
  const time = clock(network), request = editInput(selection); time.check();
  if (!Object.hasOwn(request, 'expected_result_tree')) fail('source_replacement_result_required');
  const compiled = compileSourceReplacements(request.scope.object_format, changes, binary ? { binary } : {}, time.check);
  if (compiled.changes.length !== request.paths_hex.length || compiled.changes.some((row, i) => row.path_hex !== request.paths_hex[i])) {
    fail('source_replacement_paths');
  }
  const captured = await captureSourceEdit(request, compiled.patch, credential, { timeoutMs: time.remaining(),
    signal: time.signal, maxWireBytes: time.maxWireBytes, ...(time.ca ? { ca: time.ca } : {}) });
  const actual = new Map(captured.capture.inspection.comparison.entries.map(row => [row.path_hex, row]));
  for (const wanted of compiled.changes) {
    time.check(); const row = actual.get(wanted.path_hex), format = request.scope.object_format;
    const id = entry => entry?.oid.startsWith(`${format}:`) ? entry.oid.slice(format.length + 1) : entry?.oid ?? null;
    if (!row || id(row.before) !== wanted.before_blob || id(row.after) !== wanted.after_blob ||
        (row.before?.mode ?? null) !== wanted.before_mode || (row.after?.mode ?? null) !== wanted.after_mode) {
      fail('source_replacement_effect_mismatch');
    }
  }
  return { ...captured, replacement_profile: compiled.profile,
    ...(binary === 'delta-runs' ? { aligned_copy_regions: compiled.aligned_copy_regions } : {}) };
}
