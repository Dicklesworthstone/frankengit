// Turn an independently selected source package and exact byte instructions into
// a reviewed candidate. Package text never selects a host, scope or permission.
import { webcrypto } from 'node:crypto';
import { readSourcePackage, SOURCE_PACKAGE_BYTES }
  from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { sourceEditResultSelection, bindVerifiedEditSource, captureVerifiedSourceEdit }
  from './source_edit_from_package.mjs';
import { spliceSourceFiles, compileSourceSplices, SPLICE_LIMITS } from './source_edit_splices.mjs';
import { compileCompactSourceSplices, SPLICE_PATCH_PROFILES } from './source_edit_compact_splices.mjs';
import { REPLACEMENT_LIMITS } from './source_edit_replacements.mjs';
import { editInput, oid } from './source_edit_candidate.mjs';
import { fields, integer, fail, clock, hash } from './source_edit_wire.mjs';

export const VERIFIED_SPLICE_PLAN = 'frankengit-source-package-splices-v1';
const FILE_BYTES = 1048576;
const LIMIT_KEYS = [...Object.keys(REPLACEMENT_LIMITS), ...Object.keys(SPLICE_LIMITS)];
const COMPILE_KEYS = [...LIMIT_KEYS, 'binary', 'patchProfile'];
function expectedSource(value) {
  // This entry point accepts a POSITIVE independent source selection. Never
  // discard an existing result/creation schema by taking only its source field.
  fields(value, ['format', 'commit', 'files']);
  const commit = oid(value.commit, value.format);
  if (!Array.isArray(value.files) || !value.files.length || value.files.length > 32) fail('verified_splice_source');
  let total = 0;
  const files = value.files.map(row => {
    fields(row, ['pathHex', 'blob']);
    if (typeof row.pathHex !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(row.pathHex) ||
        (total += row.pathHex.length / 2) > 32768) fail('verified_splice_source');
    return { pathHex: row.pathHex, blob: oid(row.blob, value.format) };
  });
  return { format: value.format, commit, files };
}
function instructions(value, request, options) {
  fields(value, ['schema', 'files']);
  if (value.schema !== VERIFIED_SPLICE_PLAN || !Array.isArray(value.files) ||
      value.files.length !== request.paths_hex.length || !value.files.length || value.files.length > 32) fail('verified_splice_paths');
  let count = 0, expected = 0, inserted = 0;
  const maximum = key => options[key] ?? SPLICE_LIMITS[key];
  const rows = value.files.map(row => {
    fields(row, ['path_hex', 'after_mode', 'edits']);
    if (!request.paths_hex.includes(row.path_hex) || ![0o100644, 0o100755].includes(row.after_mode) ||
        !Array.isArray(row.edits) || row.edits.length > maximum('maxSplices') - count) fail('verified_splice_instruction');
    count += row.edits.length;
    const edits = row.edits.map(edit => {
      fields(edit, ['byte_start', 'before_hex', 'after_hex']);
      const start = integer(edit.byte_start, 0, FILE_BYTES);
      const decode = (value, before) => {
        if (typeof value !== 'string' || value.length > 2 * FILE_BYTES || !/^(?:[0-9a-f]{2})*$/.test(value)) fail('verified_splice_bytes');
        if (before) expected += value.length / 2; else inserted += value.length / 2;
        if (expected > maximum('maxExpectedBytes') || inserted > maximum('maxInsertedBytes')) fail('verified_splice_bytes');
        return Buffer.from(value, 'hex');
      };
      return { byte_start: start, before: decode(edit.before_hex, true), after: decode(edit.after_hex, false) };
    });
    return { path_hex: row.path_hex, after_mode: row.after_mode, edits };
  }).sort((a, b) => a.path_hex < b.path_hex ? -1 : a.path_hex > b.path_hex ? 1 : 0);
  if (rows.some((row, i) => row.path_hex !== request.paths_hex[i])) fail('verified_splice_paths');
  return rows;
}
function compileOptions(options) {
  fields(options, COMPILE_KEYS, []);
  const out = {};
  for (const key of LIMIT_KEYS) if (Object.hasOwn(options, key)) {
    out[key] = integer(options[key], 1, REPLACEMENT_LIMITS[key] ?? SPLICE_LIMITS[key]);
  }
  if (Object.hasOwn(options, 'binary')) {
    if (!['literal', 'delta', 'delta-runs'].includes(options.binary)) fail('source_replacement_binary_profile');
    out.binary = options.binary;
  }
  if (Object.hasOwn(options, 'patchProfile')) {
    if (!SPLICE_PATCH_PROFILES.includes(options.patchProfile) || Object.hasOwn(options, 'binary')) fail('source_splice_patch_profile');
    out.patchProfile = options.patchProfile;
  }
  return out;
}

// Offline planning owns all inputs before the first verification await. The
// complete original comes ONLY from the verified package, not a mutable file.
export async function planVerifiedSourceSplices(selection, plan, evidence, options = {}, check = () => {}) {
  if (typeof check !== 'function') fail('verified_splice_input');
  check(); fields(evidence, ['package_bytes', 'expected']);
  const request = editInput(selection), compile = compileOptions(options);
  const expected = expectedSource(evidence.expected), rows = instructions(plan, request, compile);
  if (!(evidence.package_bytes instanceof Uint8Array) || !evidence.package_bytes.length ||
      evidence.package_bytes.length > SOURCE_PACKAGE_BYTES) fail('source_edit_package_input');
  const bytes = Buffer.from(evidence.package_bytes);
  const loaded = await readSourcePackage(bytes, expected, webcrypto, check); check();
  if (request.expected_commit !== loaded.verified.commit || request.scope.object_format !== expected.format) fail('source_edit_package_commit');
  const selected = new Map(loaded.verified.files.map(row => [row.pathHex, row]));
  const bodies = new Map(loaded.package.blobs.map(row => [row.oid, row.bytesHex]));
  let sourceBytes = 0;
  // Budget and validate the entire instruction inventory before copying any
  // original bodies. A package may prove more files than this operation edits.
  for (const row of rows) {
    check(); const file = selected.get(row.path_hex);
    if (!file || file.sourceBytes > FILE_BYTES ||
        (sourceBytes += file.sourceBytes) > (compile.maxSourceBytes ?? REPLACEMENT_LIMITS.maxSourceBytes)) fail('verified_splice_selected_source');
  }
  const files = rows.map(row => {
    check(); const file = selected.get(row.path_hex);
    return { ...row, before: { blob: file.blob, mode: file.kind === 'executable' ? 0o100755 : 0o100644,
      bytes: Buffer.from(bodies.get(file.blob), 'hex') } };
  });
  const spliceLimits = {};
  for (const key of [...Object.keys(SPLICE_LIMITS), 'maxSourceBytes', 'maxResultBytes']) {
    if (Object.hasOwn(compile, key)) spliceLimits[key] = compile[key];
  }
  const result = spliceSourceFiles(expected.format, files, spliceLimits, check);
  const intended = sourceEditResultSelection(expected, result.changes.map(row => ({ pathHex: row.path_hex,
    bytes: row.after.bytes, kind: row.after.mode === 0o100755 ? 'executable' : 'file' })), check);
  // The existing tree-transition verifier owns untouched siblings and computes
  // this root from authenticated originals plus locally checked result bytes.
  const bound = await bindVerifiedEditSource(bytes, intended, request, check); check();
  if (Object.hasOwn(request, 'expected_result_tree') && request.expected_result_tree !== bound.intended_tree) fail('source_edit_result_tree_mismatch');
  request.expected_result_tree = bound.intended_tree;
  const compiled = Object.hasOwn(compile, 'patchProfile')
    ? await compileCompactSourceSplices(expected.format, files, compile, check)
    : compileSourceSplices(expected.format, files, compile, check);
  check();
  return { request, patch: compiled.patch, source_evidence: { package_bytes: bytes, expected: intended },
    receipt: { profile: VERIFIED_SPLICE_PLAN, package_sha256: hash(bytes), source_commit: expected.commit,
      expected_result_tree: bound.intended_tree, patch_sha256: hash(compiled.patch), patch_bytes: compiled.patch.length,
      changed_paths: compiled.changes.length, splice_count: result.splice_count,
      expected_bytes: result.expected_bytes, inserted_bytes: result.inserted_bytes,
      encoding_profile: compiled.profile, ...(compiled.patch_profile ? { patch_profile: compiled.patch_profile } : {}),
      ...(compiled.aligned_copy_regions !== undefined ? { aligned_copy_regions: compiled.aligned_copy_regions } : {}),
      source_membership_verified: true, candidate_result_verified: false, publication_authorized: false } };
}

// One deadline spans proof verification, exact edits, root derivation, encoding,
// transport and result replay. Return the existing v4-compatible evidence owner;
// no separate stage/apply/recovery implementation or trust cache is introduced.
export async function captureVerifiedSourceSplices(selection, plan, credential, evidence, options = {}) {
  const networkKeys = ['signal', 'timeoutMs', 'ca', 'maxWireBytes'];
  fields(options, [...COMPILE_KEYS, ...networkKeys], []);
  const network = {}, compile = {};
  for (const [key, value] of Object.entries(options)) (networkKeys.includes(key) ? network : compile)[key] = value;
  const time = clock(network); time.check();
  const prepared = await planVerifiedSourceSplices(selection, plan, evidence, compile, time.check); time.check();
  const captured = await captureVerifiedSourceEdit(prepared.request, prepared.patch, credential, prepared.source_evidence,
    { timeoutMs: time.remaining(), signal: time.signal, maxWireBytes: time.maxWireBytes, ...(time.ca ? { ca: time.ca } : {}) });
  time.check(); return { ...captured, splice_plan: prepared.receipt };
}
