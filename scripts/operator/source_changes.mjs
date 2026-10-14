// Turn explicit byte edits into the existing native exact-patch input. The
// shared package verifier owns membership and the shared encoder owns patches;
// this adapter neither implements a second Git engine nor publishes anything.
import { createHash, webcrypto } from 'node:crypto';
import { readSourcePackage, SOURCE_PACKAGE_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { buildPatch, EDIT_LIMITS, pathBytes } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
import { verifyPathAbsence, deriveEditedTree } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-membership.mjs';
import { oid } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

export { SOURCE_PACKAGE_BYTES };
export const CHANGES_SCHEMA = 'frankengit-source-changes-v1';
export const CHANGES_INPUT_BYTES = 10 * 1024 * 1024;
export const CHANGE_LIMITS = Object.freeze({ files: 32, fileBytes: EDIT_LIMITS.fileBytes,
  totalBytes: EDIT_LIMITS.totalBytes, patchBytes: 1024 * 1024, splices: 4096 });
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const canonical = value => Buffer.from(`${JSON.stringify(value)}\n`);
export class SourceChangesError extends Error {
  constructor(code) { super(code); this.name = 'SourceChangesError'; this.code = code; }
}
export const fail = code => { throw new SourceChangesError(code); };
function fields(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !allowed.includes(key)) || required.some(key => !Object.hasOwn(value, key))) fail('source_changes_fields');
}
function integer(value, low, high, code) {
  if (!Number.isSafeInteger(value) || value < low || value > high) fail(code);
  return value;
}
function byteLength(value, maximum) {
  if (typeof value !== 'string' || value.length > maximum * 2 || value.length % 2 || /[^0-9a-f]/u.test(value)) fail('source_changes_bytes');
  return value.length / 2;
}
function limits(input = {}) {
  fields(input, Object.keys(CHANGE_LIMITS), []);
  return Object.fromEntries(Object.entries(CHANGE_LIMITS).map(([key, max]) =>
    [key, integer(input[key] ?? max, 1, max, 'source_changes_limit')]));
}
function expectation(value) {
  fields(value, ['format', 'commit', 'files']);
  const commit = oid(value.commit, value.format);
  if (!Array.isArray(value.files) || !value.files.length || value.files.length > 32) fail('source_changes_expectation');
  let pathTotal = 0;
  const files = value.files.map(file => {
    fields(file, ['pathHex', 'blob']);
    pathTotal += byteLength(file.pathHex, 4096);
    if (pathTotal > 32768) fail('source_changes_expectation');
    return { pathHex: file.pathHex, blob: oid(file.blob, value.format) };
  });
  // Complete path syntax/order and membership stay the shared verifier's job.
  return { format: value.format, commit, files };
}
function encoded(row, stem, charge) {
  const hex = `${stem}_hex`, text = `${stem}_utf8`;
  if (Object.hasOwn(row, hex) === Object.hasOwn(row, text)) fail('source_changes_encoding');
  if (Object.hasOwn(row, hex)) return charge(row[hex]);
  const value = row[text];
  if (typeof value !== 'string' || value.length > EDIT_LIMITS.fileBytes || /[\uD800-\uDFFF]/u.test(value)) fail('source_changes_text');
  return charge(Buffer.from(value, 'utf8').toString('hex'));
}
function changes(value, bound) {
  fields(value, ['schema', 'changes']);
  if (value.schema !== CHANGES_SCHEMA || !Array.isArray(value.changes) || !value.changes.length ||
      value.changes.length > bound.files) fail('source_changes_inventory');
  let paths = 0, bytes = 0, spliceCount = 0;
  const seen = new Set(), charge = hex => {
    bytes += byteLength(hex, bound.fileBytes);
    if (bytes > bound.totalBytes) fail('source_changes_input_budget');
    return hex;
  };
  const owned = value.changes.map(row => {
    fields(row, ['path_hex', 'operation', 'content_hex', 'content_utf8', 'before_hex', 'before_utf8', 'after_hex', 'after_utf8', 'splices', 'executable'], ['path_hex', 'operation']);
    pathBytes(row.path_hex); paths += row.path_hex.length / 2;
    if (paths > 32768 || seen.has(row.path_hex)) fail('source_changes_paths');
    seen.add(row.path_hex);
    const result = { path_hex: row.path_hex, operation: row.operation };
    if (Object.hasOwn(row, 'executable')) {
      if (typeof row.executable !== 'boolean') fail('source_changes_mode');
      result.executable = row.executable;
    }
    switch (row.operation) {
      case 'create':
        fields(row, ['path_hex', 'operation', 'content_hex', 'content_utf8', 'executable'], ['path_hex', 'operation', 'executable']);
        result.content_hex = encoded(row, 'content', charge); break;
      case 'replace':
        fields(row, ['path_hex', 'operation', 'content_hex', 'content_utf8', 'executable'], ['path_hex', 'operation']);
        result.content_hex = encoded(row, 'content', charge); break;
      case 'replace-once':
        fields(row, ['path_hex', 'operation', 'before_hex', 'before_utf8', 'after_hex', 'after_utf8', 'executable'], ['path_hex', 'operation']);
        result.before_hex = encoded(row, 'before', charge); result.after_hex = encoded(row, 'after', charge);
        if (!result.before_hex.length) fail('source_changes_empty_match');
        break;
      case 'splice': {
        fields(row, ['path_hex', 'operation', 'splices', 'executable'], ['path_hex', 'operation', 'splices']);
        if (!Array.isArray(row.splices) || !row.splices.length || row.splices.length > bound.splices - spliceCount) fail('source_changes_splice_limit');
        spliceCount += row.splices.length;
        let previous = -1, end = 0;
        result.splices = row.splices.map(part => {
          fields(part, ['byte_offset', 'before_hex', 'before_utf8', 'after_hex', 'after_utf8'], ['byte_offset']);
          const offset = integer(part.byte_offset, 0, bound.fileBytes, 'source_changes_offset');
          const before = encoded(part, 'before', charge), after = encoded(part, 'after', charge);
          if (offset <= previous || offset < end) fail('source_changes_overlap');
          previous = offset; end = offset + before.length / 2;
          return { byte_offset: offset, before_hex: before, after_hex: after };
        });
        break;
      }
      case 'delete': fields(row, ['path_hex', 'operation']); break;
      case 'mode': fields(row, ['path_hex', 'operation', 'executable']); break;
      default: fail('source_changes_operation');
    }
    return result;
  }).sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
  // Never create a file at an ancestor of another edit, or infer that deleting
  // an old file authorizes a directory replacement in the same edit set.
  for (const row of owned) if (owned.some(other => other.path_hex !== row.path_hex &&
      row.path_hex.startsWith(`${other.path_hex}2f`))) fail('source_changes_paths');
  return { schema: CHANGES_SCHEMA, changes: owned };
}
// Every splice addresses the ORIGINAL file, never an earlier splice's output.
// Preflight all extents and projected sizes before allocating any after-image.
function projected(row, before, bound, check) {
  if (row.operation === 'delete') return 0;
  if (row.operation === 'replace' || row.operation === 'create') return row.content_hex.length / 2;
  let size = before.length;
  for (const part of row.splices ?? []) {
    check(); const removed = part.before_hex.length / 2;
    if (part.byte_offset > before.length || removed > before.length - part.byte_offset) fail('source_changes_extent');
    if (!before.subarray(part.byte_offset, part.byte_offset + removed).equals(Buffer.from(part.before_hex, 'hex'))) fail('source_changes_preimage');
    size += (part.after_hex.length - part.before_hex.length) / 2;
  }
  if (size > bound.fileBytes) fail('source_changes_file_budget');
  return size;
}
function afterImage(row, before, size, check) {
  if (row.operation === 'delete') return null;
  if (row.operation === 'replace' || row.operation === 'create') return Buffer.from(row.content_hex, 'hex');
  if (row.operation === 'mode') return Buffer.from(before);
  const result = Buffer.alloc(size); let old = 0, next = 0;
  for (const part of row.splices) {
    check(); const span = before.subarray(old, part.byte_offset), replacement = Buffer.from(part.after_hex, 'hex');
    span.copy(result, next); next += span.length;
    replacement.copy(result, next); next += replacement.length;
    old = part.byte_offset + part.before_hex.length / 2;
  }
  before.copy(result, next, old); return result;
}
export async function buildSourceChanges(packageBytes, expected, input, options = {}) {
  fields(options, ['signal', 'check', 'limits'], []);
  if (options.signal !== undefined && !(options.signal instanceof AbortSignal) ||
      options.check !== undefined && typeof options.check !== 'function') fail('source_changes_host');
  const signal = options.signal, checkpoint = options.check;
  const check = () => { signal?.throwIfAborted(); checkpoint?.(); };
  check(); const bound = limits(options.limits);
  if (!(packageBytes instanceof Uint8Array) || !packageBytes.length || packageBytes.length > SOURCE_PACKAGE_BYTES ||
      !(packageBytes.buffer instanceof ArrayBuffer)) fail('source_changes_package');
  // Own every request field, expected pin and byte before the first await.
  const source = Buffer.from(packageBytes), selected = expectation(expected), owned = changes(input, bound);
  const packageHash = sha256(source), expectedHash = sha256(canonical(selected)), changesHash = sha256(canonical(owned));
  const loaded = await readSourcePackage(source, selected, webcrypto, check); check();
  const created = owned.changes.filter(row => row.operation === 'create').map(row => row.path_hex);
  const creationPreconditions = created.length === 0 ? null : await verifyPathAbsence(
    loaded.package.membership, selected, created, webcrypto, check);
  check();
  const files = new Map(loaded.verified.files.map(file => [file.pathHex, file]));
  const bodies = new Map(loaded.package.blobs.map(blob => [blob.oid, blob.bytesHex]));
  let retained = 0;
  const plans = owned.changes.map(row => {
    check(); const file = files.get(row.path_hex);
    if (row.operation === 'create') {
      // All creation targets were proved absent together under the independent
      // commit. Lack of a selected body alone never reaches this path.
      const size = row.content_hex.length / 2;
      retained += size;
      if (retained > bound.totalBytes) fail('source_changes_retained_budget');
      return { row, file: null, before: null, size };
    }
    if (!file) fail('source_changes_unselected_path');
    if (file.sourceBytes > bound.fileBytes) fail('source_changes_file_budget');
    const before = Buffer.from(bodies.get(file.blob), 'hex');
    if (before.includes(0)) fail('source_changes_binary_unsupported');
    let execution = row;
    if (row.operation === 'replace-once') {
      const needle = Buffer.from(row.before_hex, 'hex'), offset = before.indexOf(needle);
      if (offset < 0) fail('source_changes_match_missing');
      if (before.indexOf(needle, offset + 1) >= 0) fail('source_changes_match_ambiguous');
      execution = { ...row, operation: 'splice', splices: [{ byte_offset: offset, before_hex: row.before_hex, after_hex: row.after_hex }] };
    }
    const size = projected(execution, before, bound, check);
    retained += before.length + size;
    if (retained > bound.totalBytes) fail('source_changes_retained_budget');
    return { row: execution, file, before, size };
  });
  const edits = plans.map(({ row, file, before, size }) => {
    check(); const bytes = afterImage(row, before, size, check), oldMode = file?.kind === 'executable' ? 0o100755 : 0o100644;
    if (bytes?.includes(0)) fail('source_changes_binary_unsupported');
    return { path_hex: row.path_hex, before: before === null ? null : { mode: oldMode, bytes: new Uint8Array(before) },
      after: bytes === null ? null : { mode: row.executable === undefined ? oldMode : row.executable ? 0o100755 : 0o100644,
        bytes: new Uint8Array(bytes) } };
  });
  const noops = edits.filter(e => e.before !== null && e.after !== null && e.before.mode === e.after.mode &&
    Buffer.from(e.before.bytes).equals(Buffer.from(e.after.bytes))).map(e => e.path_hex);
  if (noops.length === edits.length) fail('source_changes_no_effect');
  // A checkpointing signal adapter keeps the encoder's existing synchronous
  // loops and every digest await under the caller's one remaining-time budget.
  const patch = await buildPatch(edits, selected.format, { crypto: webcrypto, signal: { throwIfAborted: check } }); check();
  if (patch.bytes.length > bound.patchBytes) fail('source_changes_patch_budget');
  for (const effect of patch.paths) if (effect.old_blob !== (files.get(effect.path_hex)?.blob ?? null)) fail('source_changes_old_identity');
  const bytes = Buffer.from(patch.bytes);
  const manifest = { schema: 'frankengit-source-change-draft-v1', object_format: selected.format,
    source_commit: loaded.verified.commit, root_tree: loaded.verified.rootTree,
    package_sha256: packageHash, expected_sha256: expectedHash, changes_sha256: changesHash,
    patch_sha256: sha256(bytes), patch_bytes: bytes.length, retained_file_bytes: retained,
    effects: patch.paths, no_op_paths_hex: noops, source_membership_verified: true,
    before_bytes_verified: true, after_images_locally_constructed: true,
    native_patch_applied: false, authority_verified: false, freshness_verified: false,
    publication_authorized: false, source_material_untrusted: true };
  // Preserve byte-identical v1 drafts for existing-file operations. A creation
  // draft additionally commits to its concrete, reproducible absence witnesses.
  if (creationPreconditions !== null) manifest.creation_preconditions = creationPreconditions;
  // The source package's complete parent trees also determine the WHOLE new
  // root. Keep this derived evidence outside the reviewed v1 manifest so old
  // draft bytes remain stable; preparation and offline replay recompute it.
  const fileSide = (blob, mode) => blob === null ? null : { blob, kind: mode === 0o100755 ? 'executable' : 'file' };
  const tree = await deriveEditedTree(loaded.package.membership, selected, patch.paths.map(effect => ({
    pathHex: effect.path_hex, before: fileSide(effect.old_blob, effect.old_mode), after: fileSide(effect.new_blob, effect.new_mode),
  })), webcrypto, check);
  check(); return { bytes, manifest, tree };
}
