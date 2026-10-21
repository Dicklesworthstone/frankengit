// Checked byte edits with the existing bounded exact-line encoder. This owns
// no diff algorithm, wire transport, repository authority, or publication.
import { createHash, webcrypto } from 'node:crypto';
import { buildPatch, COMPACT_PATCH_PROFILE, MULTI_HUNK_PATCH_PROFILE, EDIT_LIMITS }
  from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
import { spliceSourceFiles, SPLICE_LIMITS, SPLICE_PROFILE } from './source_edit_splices.mjs';
import { REPLACEMENT_LIMITS } from './source_edit_replacements.mjs';
import { editInput, captureSourceEdit, oid } from './source_edit_candidate.mjs';
import { fail, fields, integer, clock } from './source_edit_wire.mjs';

export const COMPACT_SPLICE_PROFILE = 'frankengit-source-splices-compact-v1';
export const SPLICE_PATCH_PROFILES = Object.freeze([COMPACT_PATCH_PROFILE, MULTI_HUNK_PATCH_PROFILE]);
const native = (bytes, format) => createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
const LIMIT_KEYS = [...Object.keys(REPLACEMENT_LIMITS), ...Object.keys(SPLICE_LIMITS)];

// This is deliberately async: the shared hunk owner yields during bounded line
// search. Default compileSourceSplices remains synchronous and byte-compatible.
export async function compileCompactSourceSplices(format, files, options, check = () => {}) {
  if (typeof check !== 'function') fail('source_splice_input');
  check(); fields(options, ['patchProfile', ...LIMIT_KEYS], ['patchProfile']);
  const profile = options.patchProfile;
  if (!SPLICE_PATCH_PROFILES.includes(profile)) fail('source_splice_patch_profile');
  const maximum = integer(Object.hasOwn(options, 'maxPatchBytes') ? options.maxPatchBytes : REPLACEMENT_LIMITS.maxPatchBytes,
    1, REPLACEMENT_LIMITS.maxPatchBytes);
  const maxRecords = integer(Object.hasOwn(options, 'maxRecords') ? options.maxRecords : REPLACEMENT_LIMITS.maxRecords,
    1, REPLACEMENT_LIMITS.maxRecords);
  const narrowed = {};
  for (const key of [...Object.keys(SPLICE_LIMITS), 'maxSourceBytes', 'maxResultBytes']) {
    if (Object.hasOwn(options, key)) narrowed[key] = options[key];
  }
  // Complete native preimage and exact ranges are checked before hashing yields.
  // All remaining buffers and options are owned; later caller edits cannot win.
  const result = spliceSourceFiles(format, files, narrowed, check);
  if (result.source_bytes + result.result_bytes > EDIT_LIMITS.totalBytes) fail('source_splice_compact_input_limit');
  const changes = result.changes;
  if (changes.some(row => row.before.bytes.includes(0) || row.after.bytes.includes(0))) fail('source_splice_compact_binary');
  const wanted = changes.map(row => ({ path_hex: row.path_hex, before_blob: row.before.blob,
    after_blob: native(row.after.bytes, format), before_mode: row.before.mode, after_mode: row.after.mode }));
  const built = await buildPatch(changes.map(row => ({ path_hex: row.path_hex,
    before: { mode: row.before.mode, bytes: row.before.bytes }, after: row.after })), format,
  { crypto: webcrypto, patchProfile: profile, signal: { throwIfAborted: check } });
  check();
  // The shared encoder bounds temporary output at 8 MiB. Apply the narrower
  // operator ceiling before allocating its returned copy or performing any I/O.
  if (!built.bytes.length || built.bytes.length > maximum) fail('source_replacement_patch_limit');
  let records = 0;
  for (let at = 0; at < built.bytes.length; at++) {
    if (at % 4096 === 0) check();
    if (built.bytes[at] === 10 && ++records > maxRecords) fail('source_replacement_patch_limit');
  }
  if (built.paths.length !== wanted.length || built.paths.some((row, i) => {
    const w = wanted[i];
    return row.path_hex !== w.path_hex || row.old_blob !== w.before_blob || row.new_blob !== w.after_blob ||
      row.old_mode !== w.before_mode || row.new_mode !== w.after_mode;
  })) fail('source_splice_compact_identity');
  check();
  return { profile: COMPACT_SPLICE_PROFILE, patch_profile: profile, patch: Buffer.from(built.bytes),
    hunks: built.paths.reduce((n, row) => n + row.hunks, 0), records, changes: wanted,
    source_bytes: result.source_bytes, result_bytes: result.result_bytes, splice_profile: SPLICE_PROFILE,
    splice_count: result.splice_count, expected_bytes: result.expected_bytes, inserted_bytes: result.inserted_bytes,
    preimages_verified: true, source_membership_verified: false, publication_authorized: false };
}

export async function captureCompactSourceSplices(selection, files, credential, options) {
  fields(options, ['patchProfile', ...LIMIT_KEYS, 'signal', 'timeoutMs', 'ca', 'maxWireBytes'], ['patchProfile']);
  const request = editInput(selection), network = {}, compile = {};
  for (const key of ['signal', 'timeoutMs', 'ca', 'maxWireBytes']) if (Object.hasOwn(options, key)) network[key] = options[key];
  for (const key of ['patchProfile', ...LIMIT_KEYS]) if (Object.hasOwn(options, key)) compile[key] = options[key];
  const time = clock(network); time.check();
  if (!Object.hasOwn(request, 'expected_result_tree')) fail('source_replacement_result_required');
  // Check the input path set before starting a hash/diff await. The compiler
  // additionally verifies all identities, overlap and exact original bytes.
  if (!Array.isArray(files) || files.length !== request.paths_hex.length ||
      files.some(row => !request.paths_hex.includes(row?.path_hex))) fail('source_replacement_paths');
  const compiled = await compileCompactSourceSplices(request.scope.object_format, files, compile, time.check);
  time.check();
  const captured = await captureSourceEdit(request, compiled.patch, credential, {
    timeoutMs: time.remaining(), signal: time.signal, maxWireBytes: time.maxWireBytes, ...(time.ca ? { ca: time.ca } : {}) });
  const rows = captured.capture.inspection.comparison.entries, format = request.scope.object_format;
  if (rows.length !== compiled.changes.length || rows.some((row, i) => {
    const wanted = compiled.changes[i];
    return row.path_hex !== wanted.path_hex || !row.before || !row.after ||
      oid(row.before.oid, format) !== wanted.before_blob || oid(row.after.oid, format) !== wanted.after_blob ||
      row.before.mode !== wanted.before_mode || row.after.mode !== wanted.after_mode;
  })) fail('source_replacement_effect_mismatch');
  time.check();
  return { ...captured, replacement_profile: compiled.profile, patch_profile: compiled.patch_profile,
    splice_profile: SPLICE_PROFILE, splice_count: compiled.splice_count, expected_bytes: compiled.expected_bytes,
    inserted_bytes: compiled.inserted_bytes, preimages_verified: true };
}
