// Combine separately reviewed same-base contributions, not native merge or a
// permission broker. The existing authoring and package verifiers own semantics.
import { ownSourceChangeInputs, buildSourceChanges, canonical, sha256, CHANGES_SCHEMA } from './source_changes.mjs';
import { mergeSelectedSourcePackages } from './source_package_union.mjs';
import { fields, clock } from './source_edit_wire.mjs';

export const SOURCE_ASSEMBLY_PROFILE = 'frankengit-reviewed-source-assembly-v1';
export const ASSEMBLY_LIMITS = Object.freeze({ contributions: 8, inputBytes: 64 * 1024 * 1024 });
export class SourceAssemblyError extends Error {
  constructor(code) { super(code); this.name = 'SourceAssemblyError'; this.code = code; }
}
export const fail = code => { throw new SourceAssemblyError(code); };
export function assemblyPin(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('source_assembly_confirmation');
  return value;
}
export function contributionId(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value)) fail('source_assembly_id');
  return value;
}
const same = (a, b) => canonical(a).equals(canonical(b));
const byPath = (a, b) => a.path_hex < b.path_hex ? -1 : a.path_hex > b.path_hex ? 1 : 0;
const overlap = (a, b) => a === b || a.startsWith(`${b}2f`) || b.startsWith(`${a}2f`);
export function assemblyLimits(input = {}) {
  fields(input, Object.keys(ASSEMBLY_LIMITS), []);
  return Object.fromEntries(Object.entries(ASSEMBLY_LIMITS).map(([name, maximum]) => {
    const n = input[name] ?? maximum;
    if (!Number.isSafeInteger(n) || n < (name === 'contributions' ? 2 : 1) || n > maximum) fail('source_assembly_limit');
    return [name, n];
  }));
}
// Before any await: copy ALL independently chosen sources, edits, labels and
// review pins. Labels are local attribution only, never authenticated agents.
function ownContributions(input, bound) {
  if (!Array.isArray(input) || input.length < 2 || input.length > bound.contributions) fail('source_assembly_count');
  let total = 0; const seen = new Set();
  return input.map(row => {
    fields(row, ['id', 'packageBytes', 'expected', 'changes', 'confirmDraftSha256']);
    const id = contributionId(row.id), confirmDraftSha256 = assemblyPin(row.confirmDraftSha256);
    if (seen.has(id)) fail('source_assembly_duplicate_id'); seen.add(id);
    // Charge the encoded source before copying it. Repeated packages count each
    // time: reference sharing does not create more input capacity.
    if (!(row.packageBytes instanceof Uint8Array) || (total += row.packageBytes.length) > bound.inputBytes) fail('source_assembly_input_limit');
    const owned = ownSourceChangeInputs(row.packageBytes, row.expected, row.changes);
    total += canonical(owned.expected).length + canonical(owned.changes).length;
    if (total > bound.inputBytes) fail('source_assembly_input_limit');
    return { id, confirmDraftSha256, ...owned };
  }).sort((a, b) => a.id < b.id ? -1 : 1);
}
function conflictChecks(contributions, drafts, check) {
  // Include attempted no-op writes: an unchanged instruction is still part of
  // the original reviewed intent and cannot acquire an implicit replay order.
  const targets = contributions.map(row => row.changes.changes.flatMap(edit =>
    edit.operation === 'rename' ? [edit.path_hex, edit.from_path_hex] : [edit.path_hex]));
  for (let i = 0; i < contributions.length; i++) for (let j = i + 1; j < contributions.length; j++) {
    check();
    if (targets[i].some(a => targets[j].some(b => overlap(a, b)))) fail('source_assembly_write_conflict');
    const reads = n => contributions[n].expected.files.map(file => file.pathHex);
    // Only actual effects invalidate another contribution's complete selected
    // read set. Context, read-only copy sources and unchanged files all count.
    if (drafts[i].manifest.effects.some(a => reads(j).some(b => overlap(a.path_hex, b))) ||
        drafts[j].manifest.effects.some(a => reads(i).some(b => overlap(a.path_hex, b)))) fail('source_assembly_read_write_conflict');
  }
}
export async function assembleSourceChanges(input, options = {}) {
  fields(options, ['signal', 'timeoutMs', 'limits'], []);
  const time = clock({ signal: options.signal, timeoutMs: options.timeoutMs }); time.check();
  const contributions = ownContributions(input, assemblyLimits(options.limits)), first = contributions[0];
  for (const row of contributions) {
    if (row.expected.format !== first.expected.format || row.expected.commit !== first.expected.commit) fail('source_assembly_basis');
    if (row.changes.byte_profile !== first.changes.byte_profile || row.changes.patch_profile !== first.changes.patch_profile) fail('source_assembly_profiles');
  }
  const drafts = [];
  for (const row of contributions) {
    time.check();
    const draft = await buildSourceChanges(row.packageBytes, row.expected, row.changes, { signal: time.signal, check: time.check });
    if (sha256(canonical(draft.manifest)) !== row.confirmDraftSha256) fail('source_assembly_confirmation');
    drafts.push(draft);
  }
  conflictChecks(contributions, drafts, time.check);
  // Each draft already stood alone, including creation absence. Unioning proofs
  // cannot repair an originally missing dependency or silently widen its review.
  let source = { packageBytes: first.packageBytes, expected: first.expected };
  for (const row of contributions.slice(1)) {
    source = await mergeSelectedSourcePackages(source.packageBytes, source.expected, row.packageBytes, row.expected,
      { signal: time.signal, timeoutMs: time.remaining(), check: time.check });
  }
  const combined = { schema: CHANGES_SCHEMA,
    ...(first.changes.byte_profile === undefined ? {} : { byte_profile: first.changes.byte_profile }),
    ...(first.changes.patch_profile === undefined ? {} : { patch_profile: first.changes.patch_profile }),
    changes: contributions.flatMap(row => row.changes.changes) };
  const owned = ownSourceChangeInputs(source.packageBytes, source.expected, combined);
  const draft = await buildSourceChanges(owned.packageBytes, owned.expected, owned.changes, { signal: time.signal, check: time.check });
  time.check();
  const effects = drafts.flatMap(row => row.manifest.effects).sort(byPath);
  const noops = drafts.flatMap(row => row.manifest.no_op_paths_hex).sort();
  const relocations = drafts.flatMap(row => row.manifest.relocations ?? []).sort(byPath);
  if (!same(effects, draft.manifest.effects) || !same(noops, draft.manifest.no_op_paths_hex) ||
      !same(relocations, draft.manifest.relocations ?? [])) fail('source_assembly_effects_changed');
  const receipt = { profile: SOURCE_ASSEMBLY_PROFILE, source_commit: owned.expected.commit, object_format: owned.expected.format,
    contributions: contributions.map((row, i) => ({ id: row.id, draft_sha256: row.confirmDraftSha256,
      package_sha256: drafts[i].manifest.package_sha256, expected_sha256: drafts[i].manifest.expected_sha256,
      changes_sha256: drafts[i].manifest.changes_sha256, patch_sha256: drafts[i].manifest.patch_sha256,
      selected_paths_hex: row.expected.files.map(file => file.pathHex), effect_paths_hex: drafts[i].manifest.effects.map(e => e.path_hex),
      no_op_paths_hex: drafts[i].manifest.no_op_paths_hex })),
    package_sha256: draft.manifest.package_sha256, expected_sha256: draft.manifest.expected_sha256,
    changes_sha256: draft.manifest.changes_sha256, patch_sha256: draft.manifest.patch_sha256,
    draft_sha256: sha256(canonical(draft.manifest)), expected_tree: draft.tree.afterTree,
    selected_file_count: owned.expected.files.length, effect_count: effects.length,
    contribution_reviews_matched: true, exact_effects_preserved: true, selected_read_write_conflicts_excluded: true,
    new_review_required: true, contributor_identity_authenticated: false, semantic_compatibility_verified: false,
    authority_verified: false, freshness_verified: false, publication_authorized: false, repository_changed: false };
  time.check(); return { contributions, drafts, combined: owned, draft, receipt };
}
