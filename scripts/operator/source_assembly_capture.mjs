// Private create-only custody. Original reviews are inputs, never a mutable
// approval database; reopening regenerates every contribution and combined draft.
import { mkdir, lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { assembleSourceChanges, ASSEMBLY_LIMITS, SOURCE_ASSEMBLY_PROFILE, assemblyPin, contributionId, fail } from './source_assembly.mjs';
import { canonical, sha256, SOURCE_PACKAGE_BYTES, CHANGES_INPUT_BYTES } from './source_changes.mjs';
import { fields, clock, parse } from './source_edit_wire.mjs';
import { absolute, directory, readPrivate, writeNew, syncDirectory } from './workflow_watch_io.mjs';

export const ASSEMBLY_CAPTURE_SCHEMA = 'frankengit-source-assembly-capture-v1';
export const ASSEMBLY_MANIFEST_BYTES = 32768;
export const ASSEMBLY_CAPTURE_BYTES = 128 * 1024 * 1024;
function inventory(count) {
  return { ...Object.fromEntries(Array.from({ length: count }, (_, i) => [
    [`contribution-${i}-source.json`, SOURCE_PACKAGE_BYTES], [`contribution-${i}-expected.json`, 131072],
    [`contribution-${i}-changes.json`, CHANGES_INPUT_BYTES], [`contribution-${i}-draft.json`, 262144],
  ]).flat()), 'source.json': SOURCE_PACKAGE_BYTES, 'expected.json': 131072,
  'changes.json': CHANGES_INPUT_BYTES, 'patch.diff': 1048576, 'draft.json': 262144, 'assembly.json': 1048576 };
}
export async function absentAssemblyOutput(output) {
  await directory(dirname(absolute(output)));
  try { await lstat(output); fail('source_assembly_output_exists'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
function payloads(assembled) {
  const bodies = {};
  for (const [i, row] of assembled.contributions.entries()) {
    bodies[`contribution-${i}-source.json`] = row.packageBytes;
    bodies[`contribution-${i}-expected.json`] = canonical(row.expected);
    bodies[`contribution-${i}-changes.json`] = canonical(row.changes);
    bodies[`contribution-${i}-draft.json`] = canonical(assembled.drafts[i].manifest);
  }
  Object.assign(bodies, { 'source.json': assembled.combined.packageBytes, 'expected.json': canonical(assembled.combined.expected),
    'changes.json': canonical(assembled.combined.changes), 'patch.diff': assembled.draft.bytes,
    'draft.json': canonical(assembled.draft.manifest), 'assembly.json': canonical(assembled.receipt) });
  let total = 0;
  for (const [name, maximum] of Object.entries(inventory(assembled.contributions.length))) {
    if (bodies[name].length > maximum || (total += bodies[name].length) > ASSEMBLY_CAPTURE_BYTES) fail('source_assembly_capture_limit');
  }
  return bodies;
}
function manifestFor(assembled, bodies) {
  return { schema: ASSEMBLY_CAPTURE_SCHEMA, profile: SOURCE_ASSEMBLY_PROFILE,
    contributions: assembled.contributions.map(row => ({ id: row.id, confirm_draft_sha256: row.confirmDraftSha256 })),
    draft_sha256: assembled.receipt.draft_sha256,
    payloads: Object.entries(bodies).map(([name, bytes]) => ({ name, bytes: bytes.length, sha256: sha256(bytes) })) };
}
function saved(output, hash, assembled) {
  return { type: 'source_assembly_capture', directory: output, capture_sha256: hash,
    draft_sha256: assembled.receipt.draft_sha256, assembly_sha256: sha256(canonical(assembled.receipt)),
    source_commit: assembled.receipt.source_commit, expected_tree: assembled.receipt.expected_tree,
    contribution_count: assembled.contributions.length, effect_count: assembled.receipt.effect_count,
    new_review_required: true, repository_changed: false, publication_authorized: false };
}
export async function captureSourceAssembly(output, input, options = {}) {
  fields(options, ['signal', 'timeoutMs'], []);
  const time = clock(options); absolute(output); time.check();
  const assembled = await assembleSourceChanges(input, { signal: time.signal, timeoutMs: time.remaining() });
  time.check(); await absentAssemblyOutput(output); time.check();
  const bodies = payloads(assembled), root = canonical(manifestFor(assembled, bodies));
  if (root.length > ASSEMBLY_MANIFEST_BYTES) fail('source_assembly_capture_limit');
  const result = saved(output, sha256(root), assembled);
  await mkdir(output, { mode: 0o700 });
  try {
    await syncDirectory(dirname(output));
    for (const [name, bytes] of Object.entries(bodies)) {
      time.check(); await writeNew(join(output, name), bytes);
      if (!bytes.equals(await readPrivate(join(output, name), bytes.length))) fail('source_assembly_output_changed');
    }
    time.check();
    // Root last: finish this begun write/sync/readback even on a late stop.
    await writeNew(join(output, 'manifest.json'), root);
    if (!root.equals(await readPrivate(join(output, 'manifest.json'), ASSEMBLY_MANIFEST_BYTES))) fail('source_assembly_output_changed');
    await syncDirectory(output); await syncDirectory(dirname(output));
    return { ...result, stop_requested: time.signal?.aborted ?? false };
  } catch (error) { error.publication_unconfirmed = result; throw error; }
}
export async function loadSourceAssembly(path, expectedHash, options = {}) {
  fields(options, ['signal', 'timeoutMs'], []);
  const time = clock(options); absolute(path); assemblyPin(expectedHash); time.check(); await directory(path);
  const root = await readPrivate(join(path, 'manifest.json'), ASSEMBLY_MANIFEST_BYTES); time.check();
  if (sha256(root) !== expectedHash) fail('source_assembly_capture_changed');
  const manifest = parse(root, ASSEMBLY_MANIFEST_BYTES);
  fields(manifest, ['schema', 'profile', 'contributions', 'draft_sha256', 'payloads']);
  if (manifest.schema !== ASSEMBLY_CAPTURE_SCHEMA || manifest.profile !== SOURCE_ASSEMBLY_PROFILE ||
      !Array.isArray(manifest.contributions) || manifest.contributions.length < 2 || manifest.contributions.length > ASSEMBLY_LIMITS.contributions) fail('source_assembly_capture_schema');
  let previous = '';
  for (const row of manifest.contributions) {
    fields(row, ['id', 'confirm_draft_sha256']); contributionId(row.id); assemblyPin(row.confirm_draft_sha256);
    if (row.id <= previous) fail('source_assembly_capture_inventory'); previous = row.id;
  }
  const names = Object.entries(inventory(manifest.contributions.length));
  if (!Array.isArray(manifest.payloads) || manifest.payloads.length !== names.length) fail('source_assembly_capture_inventory');
  let total = 0;
  // Validate the entire bounded inventory before opening any payload. Imported
  // filenames never choose host paths, even under a caller-supplied new root.
  for (const [i, [name, maximum]] of names.entries()) {
    const row = manifest.payloads[i]; fields(row, ['name', 'bytes', 'sha256']); assemblyPin(row.sha256);
    if (row.name !== name || !Number.isSafeInteger(row.bytes) || row.bytes < 1 || row.bytes > maximum ||
        (total += row.bytes) > ASSEMBLY_CAPTURE_BYTES) fail('source_assembly_capture_inventory');
  }
  const bodies = {};
  for (const row of manifest.payloads) {
    time.check(); const bytes = await readPrivate(join(path, row.name), row.bytes); time.check();
    if (bytes.length !== row.bytes || sha256(bytes) !== row.sha256) fail('source_assembly_capture_changed'); bodies[row.name] = bytes;
  }
  const json = name => parse(bodies[name], inventory(manifest.contributions.length)[name]);
  const input = manifest.contributions.map((row, i) => ({ id: row.id, confirmDraftSha256: row.confirm_draft_sha256,
    packageBytes: bodies[`contribution-${i}-source.json`], expected: json(`contribution-${i}-expected.json`), changes: json(`contribution-${i}-changes.json`) }));
  const assembled = await assembleSourceChanges(input, { signal: time.signal, timeoutMs: time.remaining() });
  const regenerated = payloads(assembled);
  // A checksum proves custody only. Recreate the union, all original drafts,
  // complete combined effects and patch, and the returned attribution evidence.
  for (const [name, bytes] of Object.entries(regenerated)) if (!bytes.equals(bodies[name])) fail('source_assembly_regeneration_mismatch');
  if (!canonical(manifestFor(assembled, regenerated)).equals(root)) fail('source_assembly_regeneration_mismatch');
  time.check(); return { ...assembled, saved: saved(path, expectedHash, assembled) };
}
