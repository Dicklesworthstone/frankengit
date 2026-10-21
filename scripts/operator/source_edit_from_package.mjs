// Independent source evidence for a native source candidate. A verified input
// package alone is not evidence that the inspected candidate used those bytes.
import { createHash, webcrypto } from 'node:crypto';
import { readSourcePackage, SOURCE_PACKAGE_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { deriveEditedTree, verifyPathAbsence } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-membership.mjs';
import { editInput, oid, validateSourceEdit, captureSourceEdit } from './source_edit_candidate.mjs';
import { fail, hash, fields, clock } from './source_edit_wire.mjs';

export { SOURCE_PACKAGE_BYTES };
export const SOURCE_EXPECTED_BYTES = 128 * 1024;
export const SOURCE_EVIDENCE_PROFILE = 'frankengit-source-edit-evidence-v1';
export const SOURCE_CREATION_SELECTION = 'frankengit-source-edit-create-selection-v1';
export const SOURCE_CREATION_EVIDENCE_PROFILE = 'frankengit-source-edit-evidence-v2';
export const SOURCE_RESULT_SELECTION = 'frankengit-source-edit-result-selection-v1';
export const SOURCE_RESULT_EVIDENCE_PROFILE = 'frankengit-source-edit-evidence-v3';
const RESULT_FILE_BYTES = 1024 * 1024, RESULT_TOTAL_BYTES = 8 * 1024 * 1024;

function resultPath(value) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(value)) fail('source_edit_result_path');
  const bytes = Buffer.from(value, 'hex'), parts = bytes.toString('latin1').split('/');
  if (bytes.includes(0) || parts.length > 64 || parts.some(p => !p || p === '.' || p === '..' || p.toLowerCase() === '.git')) {
    fail('source_edit_result_path');
  }
  return value;
}
function ownAfter(rows, format) {
  if (!Array.isArray(rows) || !rows.length || rows.length > 32) fail('source_edit_result_selection');
  let previous = '', pathBytes = 0;
  return rows.map(row => {
    fields(row, ['pathHex', 'blob', 'kind']); const path = resultPath(row.pathHex);
    if (path <= previous || (pathBytes += path.length / 2) > 32768) fail('source_edit_result_selection');
    previous = path;
    if (row.blob === null) {
      if (row.kind !== null) fail('source_edit_result_selection');
      return { pathHex: path, blob: null, kind: null };
    }
    if (!['file', 'executable'].includes(row.kind)) fail('source_edit_result_selection');
    return { pathHex: path, blob: oid(row.blob, format), kind: row.kind };
  });
}
// Build independent RESULT commitments from caller-owned desired bytes, not a
// server diff. This is neither patch application nor authorization. A path not
// in the positive selection becomes an explicit creation intent; basis() must
// still prove its absence before any native request. Empty bytes are a file;
// null bytes are a deletion. No shell, checkout, encoding or newline rewrite.
export function sourceEditResultSelection(source, changes, check = () => {}) {
  if (typeof check !== 'function') fail('source_edit_result_selection');
  check(); const original = ownSourceExpected(source);
  if (!Array.isArray(changes) || !changes.length || changes.length > 32) fail('source_edit_result_selection');
  let total = 0;
  const rows = changes.map(row => {
    check(); fields(row, ['pathHex', 'bytes', 'kind']); const pathHex = resultPath(row.pathHex);
    if (row.bytes === null) {
      if (row.kind !== null) fail('source_edit_result_selection');
      return { pathHex, blob: null, kind: null };
    }
    if (!(row.bytes instanceof Uint8Array) || !['file', 'executable'].includes(row.kind) ||
        row.bytes.length > RESULT_FILE_BYTES || (total += row.bytes.length) > RESULT_TOTAL_BYTES) fail('source_edit_result_bytes');
    const bytes = Buffer.from(row.bytes);
    const blob = createHash(original.format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    check(); return { pathHex, blob, kind: row.kind };
  }).sort((a, b) => a.pathHex < b.pathHex ? -1 : a.pathHex > b.pathHex ? 1 : 0);
  const selected = new Set(original.files.map(row => row.pathHex));
  const create = rows.filter(row => !selected.has(row.pathHex));
  if (create.some(row => row.blob === null)) fail('source_edit_result_unselected_deletion');
  const expected = ownExpected({ schema: SOURCE_RESULT_SELECTION, source: original,
    create_paths_hex: create.map(row => row.pathHex), after: rows });
  check(); return expected;
}

// Bound primitives before owning an expected selection. Its commit comes from
// the operator, never from the package or a native preparation response.
function ownSourceExpected(value) {
  fields(value, ['format', 'commit', 'files']);
  const commit = oid(value.commit, value.format);
  if (!Array.isArray(value.files) || !value.files.length || value.files.length > 32) fail('source_edit_package_selection');
  let total = 0;
  const files = value.files.map(row => {
    fields(row, ['pathHex', 'blob']);
    if (typeof row.pathHex !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(row.pathHex) ||
        (total += row.pathHex.length / 2) > 32768) fail('source_edit_package_selection');
    return { pathHex: row.pathHex, blob: oid(row.blob, value.format) };
  });
  return { format: value.format, commit, files };
}
// Creation intent is independently supplied and distinct from positive file
// membership. Omission from a source package is NEVER an absence witness.
function ownExpected(value) {
  if (!value || !Object.hasOwn(value, 'schema')) return ownSourceExpected(value);
  const result = value.schema === SOURCE_RESULT_SELECTION;
  fields(value, ['schema', 'source', 'create_paths_hex', ...(result ? ['after'] : [])]);
  if ((!result && value.schema !== SOURCE_CREATION_SELECTION) || !Array.isArray(value.create_paths_hex) ||
      (!result && !value.create_paths_hex.length) || value.create_paths_hex.length > 32) fail('source_edit_creation_selection');
  const source = ownSourceExpected(value.source); let total = 0, previous = '';
  const paths = value.create_paths_hex.map(path => {
    if (typeof path !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(path) ||
        path <= previous || (total += path.length / 2) > 32768) fail('source_edit_creation_selection');
    previous = path;
    const bytes = Buffer.from(path, 'hex'), parts = bytes.toString('latin1').split('/');
    if (bytes.includes(0) || parts.length > 64 || parts.some(p => !p || p === '.' || p === '..')) fail('source_edit_creation_selection');
    return path;
  });
  const all = [...source.files.map(row => row.pathHex), ...paths];
  if (new Set(all).size !== all.length || all.some(p => all.some(q => p !== q && p.startsWith(`${q}2f`)))) {
    fail('source_edit_creation_collision');
  }
  const expected = { schema: value.schema, source, create_paths_hex: paths,
    ...(result ? { after: ownAfter(value.after, source.format) } : {}) };
  if (result) {
    const targets = expected.after.map(row => row.pathHex);
    if (targets.some(p => targets.some(q => p !== q && p.startsWith(`${q}2f`))) ||
        paths.some(p => !targets.includes(p)) ||
        expected.after.some(row => !source.files.some(file => file.pathHex === row.pathHex) && !paths.includes(row.pathHex)) ||
        expected.after.some(row => paths.includes(row.pathHex) && row.blob === null) ||
        Buffer.byteLength(`${JSON.stringify(expected)}\n`) > SOURCE_EXPECTED_BYTES) fail('source_edit_result_selection');
  }
  return expected;
}
async function basis(packageBytes, expected, selection, check) {
  if (!(packageBytes instanceof Uint8Array) || !packageBytes.length || packageBytes.length > SOURCE_PACKAGE_BYTES ||
      typeof check !== 'function') fail('source_edit_package_input');
  check();
  const request = editInput(selection), expectedOwned = ownExpected(expected), bytes = Buffer.from(packageBytes);
  const source = expectedOwned.source ?? expectedOwned, created = new Set(expectedOwned.create_paths_hex ?? []);
  // Mirror the existing tree-effect ceiling before any network request, not
  // only after the server has already prepared a candidate.
  if (request.paths_hex.length > 32 || request.paths_hex.reduce((n, p) => n + p.length / 2, 0) > 32768 ||
      [...created].some(path => !request.paths_hex.includes(path))) fail('source_edit_creation_selection');
  if (expectedOwned.after && (expectedOwned.after.length !== request.paths_hex.length ||
      expectedOwned.after.some((row, i) => row.pathHex !== request.paths_hex[i]))) fail('source_edit_result_paths');
  const loaded = await readSourcePackage(bytes, source, webcrypto, check);
  check();
  if (request.scope.object_format !== loaded.package.membership.objectFormat || request.expected_commit !== loaded.verified.commit) {
    fail('source_edit_package_commit');
  }
  const selected = new Map(loaded.verified.files.map(file => [file.pathHex, file]));
  for (const path of request.paths_hex) if (!selected.has(path) && !created.has(path)) fail('source_edit_package_path');
  const absence = created.size ? await verifyPathAbsence(loaded.package.membership, source, [...created], webcrypto, check) : null;
  check();
  // Derive the intended candidate root BEFORE native preparation, from the
  // authenticated base plus independent after commitments. No server value
  // participates in this derivation. The existing kernel rejects no-op effects.
  const intended = expectedOwned.after ? await deriveEditedTree(loaded.package.membership, source,
    expectedOwned.after.map(row => ({ pathHex: row.pathHex,
      before: created.has(row.pathHex) ? null : { blob: selected.get(row.pathHex).blob, kind: selected.get(row.pathHex).kind },
      after: row.blob === null ? null : { blob: row.blob, kind: row.kind } })), webcrypto, check) : null;
  check();
  return { request, expected: expectedOwned, source, bytes, loaded, selected, created, absence, intended };
}
function receipt(b) {
  return Object.freeze({
    request: b.request, package_sha256: hash(b.bytes), verified_commit: b.loaded.verified.commit,
    verified_paths: b.request.paths_hex.filter(path => !b.created.has(path)).map(path => Object.freeze({ path_hex: path, blob: b.selected.get(path).blob,
      kind: b.selected.get(path).kind, source_bytes: b.selected.get(path).sourceBytes })),
    ...(b.absence ? { verified_absence: b.absence } : {}),
    ...(b.intended ? { intended_tree: b.intended.afterTree, candidate_result_verified: false } : {}),
    source_package_verified: true, authority_verified: false, freshness_verified: false, publication_authorized: false,
  });
}
// Retained for callers needing input preflight only. This receipt cannot replace
// validateSourceEditEvidence, which also checks the returned candidate effects.
export async function bindVerifiedEditSource(packageBytes, expected, selection, check = () => {}) {
  return receipt(await basis(packageBytes, expected, selection, check));
}
function lineBreaks(bytes, check) {
  let count = 0;
  for (let at = 0; at < bytes.length; at++) {
    if (at % 4096 === 0) check();
    if (bytes[at] === 10) count++;
  }
  return count;
}
function boundary(bytes, at) { return at === 0 || at === bytes.length || bytes[at - 1] === 10; }
// Replay native REVIEW spans, not the submitted patch grammar or a diff engine.
// Unchanged gaps come from verified source. New text must hash to the reported
// after blob; the submitted patch's intended semantics still belong to native.
function textEffect(row, original, format, check) {
  const c = row.content;
  if (original.includes(0) || c.before_bytes !== original.length) fail('source_edit_preimage_size');
  const parts = []; let oldEnd = 0, newSize = 0, oldLines = 0, newLines = 0;
  const append = bytes => {
    check(); newSize += bytes.length;
    if (newSize > c.after_bytes) fail('source_edit_after_size');
    newLines += lineBreaks(bytes, check); parts.push(bytes);
  };
  for (const h of c.hunks) {
    check();
    if (!boundary(original, h.old.byte_start) || !boundary(original, h.old.byte_end)) fail('source_edit_preimage_boundary');
    const gap = original.subarray(oldEnd, h.old.byte_start), before = original.subarray(h.old.byte_start, h.old.byte_end);
    oldLines += lineBreaks(gap, check); append(gap);
    if (h.old.line_start !== oldLines || h.new.line_start !== newLines || h.new.byte_start !== newSize ||
        !before.equals(Buffer.from(h.before_hex, 'hex'))) fail('source_edit_preimage_span');
    const after = Buffer.from(h.after_hex, 'hex');
    if (after.includes(0) || after.length && after.at(-1) !== 10 && h.new.byte_end !== c.after_bytes) fail('source_edit_after_boundary');
    oldLines += lineBreaks(before, check); append(after); oldEnd = h.old.byte_end;
  }
  append(original.subarray(oldEnd));
  if (newSize !== c.after_bytes || row.after === null && newSize !== 0) fail('source_edit_after_size');
  const next = Buffer.concat(parts, newSize); check();
  if (row.after !== null && createHash(format).update(`blob ${next.length}\0`).update(next).digest('hex') !== oid(row.after.oid, format)) {
    fail('source_edit_after_blob');
  }
  check();
}
async function effects(checked, b, check) {
  const c = checked.capture.inspection.comparison, format = b.request.scope.object_format;
  if (oid(c.before_tree, format) !== b.loaded.verified.rootTree) fail('source_edit_preimage_tree');
  if (b.intended) {
    if (oid(c.after_tree, format) !== b.intended.afterTree) fail('source_edit_requested_result');
    for (let i = 0; i < c.entries.length; i++) {
      check(); const actual = c.entries[i], wanted = b.expected.after[i];
      if (actual.path_hex !== wanted.pathHex || (actual.after === null ? wanted.blob !== null :
          oid(actual.after.oid, format) !== wanted.blob ||
          (actual.after.mode === 0o100755 ? 'executable' : 'file') !== wanted.kind)) fail('source_edit_requested_result');
    }
  }
  const bodies = new Map(b.loaded.package.blobs.map(row => [row.oid, row.bytesHex]));
  const unverifiedAfter = [], transitions = []; let replayed = 0;
  for (const row of c.entries) {
    check(); const file = b.selected.get(row.path_hex), before = row.before, created = b.created.has(row.path_hex);
    if (created) {
      if (before !== null || row.after === null || row.kind !== 'added') fail('source_edit_creation_effect');
    } else if (!file || !before || oid(before.oid, format) !== file.blob ||
        before.mode !== (file.kind === 'executable' ? 0o100755 : 0o100644)) fail('source_edit_preimage_identity');
    const original = created ? Buffer.alloc(0) : Buffer.from(bodies.get(file.blob), 'hex');
    if (row.content.type === 'text') { textEffect(row, original, format, check); replayed++; }
    else if (row.content.type === 'binary') {
      if (row.content.before_bytes !== original.length || row.after === null && row.content.after_bytes !== 0) fail('source_edit_preimage_size');
      // A native binary review intentionally omits the new body. Do not turn
      // that omission into a full candidate-blob or patch-application proof.
      if (row.after !== null) unverifiedAfter.push(row.path_hex);
    } else if (created || row.content.type !== 'identical') fail('source_edit_preimage_content');
    transitions.push({ pathHex: row.path_hex, before: created ? null : { blob: file.blob, kind: file.kind },
      after: row.after === null ? null : { blob: oid(row.after.oid, format), kind: row.after.mode === 0o100755 ? 'executable' : 'file' } });
  }
  const tree = await deriveEditedTree(b.loaded.package.membership, b.source, transitions, webcrypto, check);
  if (tree.afterTree !== oid(c.after_tree, format)) fail('source_edit_unreported_tree_effect');
  check();
  return { ...checked, source_evidence: { package_bytes: b.bytes, expected: b.expected },
    source_verification: { profile: b.intended ? SOURCE_RESULT_EVIDENCE_PROFILE : b.absence ? SOURCE_CREATION_EVIDENCE_PROFILE : SOURCE_EVIDENCE_PROFILE, package_sha256: hash(b.bytes),
      expected_sha256: hash(Buffer.from(`${JSON.stringify(b.expected)}\n`)),
      commit: tree.commit, before_tree: tree.beforeTree, after_tree: tree.afterTree,
      verified_paths: transitions.length, replayed_text_files: replayed, unverified_after_paths_hex: unverifiedAfter,
      ...(b.absence ? { path_absence_verified: true, created_paths_hex: [...b.created], absence: b.absence } : {}),
      ...(b.intended ? { requested_result_verified: true, intended_tree: b.intended.afterTree,
        result_commitments_from: 'independent-expected-selection' } : {}),
      preimages_verified: true, exact_tree_effects_verified: true, unrelated_entries_preserved: true,
      patch_application_verified: false, bundle_objects_independently_verified: false,
      authority_verified: false, freshness_verified: false, publication_authorized: false } };
}
// Offline replay always rehashes evidence. Boolean receipts and caller-created
// objects cannot install a trusted preimage inventory or a different candidate.
export async function validateSourceEditEvidence(capture, bundle, evidence, check = () => {}) {
  if (typeof check !== 'function') fail('source_edit_package_input');
  check(); fields(evidence, ['package_bytes', 'expected']);
  const checked = validateSourceEdit(capture, bundle);
  const b = await basis(evidence.package_bytes, evidence.expected, checked.capture.request, check);
  return effects(checked, b, check);
}
// The same finite operation includes input proof, native prepare/inspect, and
// independent effect replay. No stage/apply or new source lookup is performed.
export async function captureVerifiedSourceEdit(selection, patch, credential, evidence, options = {}) {
  const time = clock(options); time.check(); fields(evidence, ['package_bytes', 'expected']);
  if (!Buffer.isBuffer(patch) || !patch.length || patch.length > 1048576) fail('source_edit_patch_limit');
  const ownedPatch = Buffer.from(patch);
  const b = await basis(evidence.package_bytes, evidence.expected, selection, time.check);
  const checked = await captureSourceEdit(b.request, ownedPatch, credential, {
    timeoutMs: time.remaining(), signal: time.signal, ...(time.ca ? { ca: time.ca } : {}), maxWireBytes: time.maxWireBytes });
  time.check(); return effects(checked, b, time.check);
}
