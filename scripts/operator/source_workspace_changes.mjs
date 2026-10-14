// Explicit-path reconciliation into the existing exact source-authoring engine.
// No scan, ignore-file interpretation, rename inference or repository mutation.
import { mkdir, lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { webcrypto } from 'node:crypto';
import { loadSourceWorkspace, readWorkspaceFiles, selectedPaths, workspaceManifest,
  lifetime, fields, pin, fail, WORKSPACE_LIMITS, SOURCE_PACKAGE_BYTES } from './source_workspace.mjs';
import { buildSourceChanges, canonical, sha256, CHANGES_SCHEMA, CHANGES_INPUT_BYTES, sourceByteProfile, sourcePatchProfile } from './source_changes.mjs';
import { readSourcePackage } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { verifyPathAbsence } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-membership.mjs';
import { absolute, contains, directory, readPrivate, writeNew, syncDirectory } from './workflow_watch_io.mjs';
import { parse } from './source_edit_wire.mjs';

const SCHEMA = 'frankengit-workspace-change-capture-v1';
const LIMITS = Object.freeze({ 'source.json': SOURCE_PACKAGE_BYTES, 'expected.json': WORKSPACE_LIMITS.expectedBytes,
  'paths.json': WORKSPACE_LIMITS.expectedBytes, 'changes.json': CHANGES_INPUT_BYTES,
  'patch.diff': 1048576, 'draft.json': 262144 });
export function workspaceChangeSelection(value) {
  fields(value, ['paths_hex', 'byte_profile', 'patch_profile'], ['paths_hex']);
  return { paths_hex: selectedPaths(value.paths_hex), ...(Object.hasOwn(value, 'byte_profile')
    ? { byte_profile: sourceByteProfile(value.byte_profile) } : {}), ...(Object.hasOwn(value, 'patch_profile')
    ? { patch_profile: sourcePatchProfile(value.patch_profile) } : {}) };
}
// Omit defaults entirely: existing capture payloads and retained hashes stay stable.
function profiles(value) {
  return Object.fromEntries(['byte_profile', 'patch_profile'].filter(k => Object.hasOwn(value, k)).map(k => [k, value[k]]));
}
function rootManifest(workspaceHash, payloads, draft, selection, changes) {
  return { schema: SCHEMA, workspace_sha256: workspaceHash,
    payloads: Object.keys(LIMITS).map(name => ({ name, sha256: sha256(payloads[name]), bytes: payloads[name].length })),
    source_commit: draft.manifest.source_commit, expected_tree: draft.tree.afterTree,
    draft_sha256: sha256(payloads['draft.json']), selected_path_count: selection.paths_hex.length,
    changed_path_count: changes.changes.length, unchanged_path_count: selection.paths_hex.length - changes.changes.length,
    selected_files_only: true, unselected_paths_examined: false, atomic_filesystem_snapshot: false,
    source_material_untrusted: true, repository_changed: false, publication_authorized: false,
    ...profiles(selection) };
}
function payloadSet(baseline, selection, changes, draft) {
  const payloads = { 'source.json': baseline.packageBytes, 'expected.json': canonical(baseline.expected),
    'paths.json': canonical(selection), 'changes.json': canonical(changes), 'patch.diff': draft.bytes, 'draft.json': canonical(draft.manifest) };
  for (const [name, bytes] of Object.entries(payloads)) if (bytes.length > LIMITS[name]) fail('source_workspace_capture_budget');
  return payloads;
}
// Only the mutable filesystem is observed here. Everything passed to the
// authoring kernel is an owned byte image with an independently verified base.
export async function collectWorkspaceChanges(root, workspaceHash, inputSelection, options = {}) {
  const time = lifetime(options), selection = workspaceChangeSelection(inputSelection); pin(workspaceHash);
  const baseline = await loadSourceWorkspace(root, workspaceHash, { check: time.check, timeoutMs: time.remaining() });
  const original = new Map(baseline.manifest.files.map(f => [f.path_hex, f]));
  const pkg = JSON.parse(baseline.packageBytes.toString('utf8'));
  const bodies = new Map(pkg.blobs.map(b => [b.oid, b.bytesHex]));
  const newPaths = selection.paths_hex.filter(p => !original.has(p));
  // Before reading a newly selected local path, prove it is genuinely absent
  // in the repository. Omitted package bodies or unexamined parents are not absence.
  if (newPaths.length) await verifyPathAbsence(pkg.membership, baseline.expected, newPaths, webcrypto, time.check);
  time.check();
  const observed = await readWorkspaceFiles(root, selection.paths_hex, { check: time.check, timeoutMs: time.remaining() });
  const changes = { schema: CHANGES_SCHEMA, ...profiles(selection), changes: [] };
  for (const path of selection.paths_hex) {
    time.check(); const before = original.get(path), after = observed.files.get(path);
    if (!before && !after) fail('source_workspace_new_file_missing');
    if (before && after && before.executable === after.executable && bodies.get(before.blob) === after.bytes.toString('hex')) continue;
    if (!after) changes.changes.push({ path_hex: path, operation: 'delete' });
    else changes.changes.push({ path_hex: path, operation: before ? 'replace' : 'create',
      content_hex: after.bytes.toString('hex'), executable: after.executable });
  }
  if (!changes.changes.length) fail('source_workspace_no_changes');
  const draft = await buildSourceChanges(baseline.packageBytes, baseline.expected, changes, { check: time.check, signal: time.signal });
  // All selected observations, including missing paths, must still match after
  // asynchronous object hashing. A changed editor buffer never slips into a
  // completed capture under an earlier observation.
  await observed.recheck(); time.check();
  const payloads = payloadSet(baseline, selection, changes, draft);
  const manifest = rootManifest(workspaceHash, payloads, draft, selection, changes);
  return { baseline, selection, changes, draft, manifest, payloads };
}
function summary(path, hash, m) {
  return { type: 'source_workspace_change_capture', directory: path, capture_sha256: hash,
    workspace_sha256: m.workspace_sha256, source_commit: m.source_commit, expected_tree: m.expected_tree,
    draft_sha256: m.draft_sha256, selected_path_count: m.selected_path_count, changed_path_count: m.changed_path_count,
    unchanged_path_count: m.unchanged_path_count, selected_files_only: true,
    unselected_paths_examined: false, repository_changed: false, source_material_untrusted: true,
    ...profiles(m) };
}
export async function captureWorkspaceChanges(root, workspaceHash, inputSelection, output, options = {}) {
  const time = lifetime(options), selection = workspaceChangeSelection(inputSelection); pin(workspaceHash);
  absolute(root); absolute(output);
  if (contains(root, output) || contains(output, root)) fail('source_workspace_overlapping_output');
  await directory(dirname(output));
  try { await lstat(output); fail('source_workspace_output_exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  time.check();
  const collected = await collectWorkspaceChanges(root, workspaceHash, selection, { check: time.check, signal: time.signal, timeoutMs: time.remaining() });
  const rootBytes = canonical(collected.manifest);
  if (rootBytes.length > WORKSPACE_LIMITS.manifestBytes) fail('source_workspace_manifest_budget');
  const result = summary(output, sha256(rootBytes), collected.manifest);
  time.check(); await mkdir(output, { mode: 0o700 });
  try {
    await syncDirectory(dirname(output));
    for (const [name, bytes] of Object.entries(collected.payloads)) {
      time.check(); await writeNew(join(output, name), bytes);
      if (!bytes.equals(await readPrivate(join(output, name), LIMITS[name]))) fail('source_workspace_capture_readback');
    }
    time.check();
    // Owned captured bytes, not live files/, are published. Stop checking live
    // editors here: later edits belong to a different explicit capture.
    await writeNew(join(output, 'manifest.json'), rootBytes);
    if (!rootBytes.equals(await readPrivate(join(output, 'manifest.json'), WORKSPACE_LIMITS.manifestBytes))) fail('source_workspace_capture_readback');
    await syncDirectory(output); await syncDirectory(dirname(output));
    return { ...result, stop_requested: time.signal?.aborted ?? false };
  } catch (error) { error.publication_unconfirmed = result; throw error; }
}
export async function inspectWorkspaceChangeCapture(path, expectedHash, options = {}) {
  const time = lifetime(options); absolute(path); pin(expectedHash); await directory(path);
  const rootBytes = await readPrivate(join(path, 'manifest.json'), WORKSPACE_LIMITS.manifestBytes); time.check();
  if (sha256(rootBytes) !== expectedHash) fail('source_workspace_capture_changed');
  const manifest = parse(rootBytes, WORKSPACE_LIMITS.manifestBytes);
  if (manifest.schema !== SCHEMA || !Array.isArray(manifest.payloads) || manifest.payloads.length !== Object.keys(LIMITS).length) fail('source_workspace_capture_schema');
  pin(manifest.workspace_sha256); const payloads = {};
  for (const [i, name] of Object.keys(LIMITS).entries()) {
    time.check(); const entry = manifest.payloads[i]; fields(entry, ['name', 'sha256', 'bytes']);
    if (entry.name !== name) fail('source_workspace_capture_inventory');
    const bytes = await readPrivate(join(path, name), LIMITS[name]); time.check();
    if (sha256(bytes) !== entry.sha256 || bytes.length !== entry.bytes) fail('source_workspace_capture_changed');
    payloads[name] = bytes;
  }
  const expected = parse(payloads['expected.json'], WORKSPACE_LIMITS.expectedBytes);
  const selection = workspaceChangeSelection(parse(payloads['paths.json'], WORKSPACE_LIMITS.expectedBytes));
  const changes = parse(payloads['changes.json'], CHANGES_INPUT_BYTES);
  fields(changes, ['schema', 'byte_profile', 'patch_profile', 'changes'], ['schema', 'changes']);
  // The saved changes cannot broaden the profile chosen with the path list.
  if (changes.byte_profile !== selection.byte_profile || changes.patch_profile !== selection.patch_profile) fail('source_workspace_capture_profile');
  if (changes.schema !== CHANGES_SCHEMA || !Array.isArray(changes.changes) || !changes.changes.length || changes.changes.length > selection.paths_hex.length) fail('source_workspace_capture_changes');
  const selected = new Set(selection.paths_hex); let previous = '';
  for (const change of changes.changes) {
    fields(change, change.operation === 'delete' ? ['path_hex', 'operation'] : ['path_hex', 'operation', 'content_hex', 'executable']);
    if (!['delete', 'replace', 'create'].includes(change.operation) || !selected.has(change.path_hex) || change.path_hex <= previous) fail('source_workspace_capture_changes');
    previous = change.path_hex;
  }
  // Re-derive the original workspace root and the entire expected change tree.
  // Capture hashes are not substitutes for the original native commitments.
  const loaded = await readSourcePackage(payloads['source.json'], expected, webcrypto, time.check);
  const basis = workspaceManifest(payloads['source.json'], expected, loaded.verified);
  if (sha256(canonical(basis)) !== manifest.workspace_sha256) fail('source_workspace_baseline_changed');
  const original = new Set(basis.files.map(f => f.path_hex));
  if (selection.paths_hex.some(p => !original.has(p) && !changes.changes.some(c => c.path_hex === p && c.operation === 'create')) ||
      changes.changes.some(c => original.has(c.path_hex) === (c.operation === 'create'))) fail('source_workspace_capture_changes');
  const draft = await buildSourceChanges(payloads['source.json'], expected, changes, { check: time.check, signal: time.signal });
  if (!canonical(expected).equals(payloads['expected.json']) || !canonical(selection).equals(payloads['paths.json']) ||
      !canonical(changes).equals(payloads['changes.json']) || !canonical(draft.manifest).equals(payloads['draft.json']) ||
      !draft.bytes.equals(payloads['patch.diff']) || draft.manifest.no_op_paths_hex.length) fail('source_workspace_capture_changed');
  const recomputed = rootManifest(manifest.workspace_sha256, payloads, draft, selection, changes);
  if (!canonical(recomputed).equals(rootBytes)) fail('source_workspace_capture_changed');
  time.check(); return { ...summary(path, expectedHash, recomputed), offline_recomputed: true,
    authority_verified: false, atomic_filesystem_snapshot: false };
}
