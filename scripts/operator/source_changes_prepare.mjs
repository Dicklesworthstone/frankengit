// Bind an independently regenerated edit to native preparation and inspection.
// Native Rust still owns patch application, complete candidate-object validation,
// authorization and publication. Matching a report is not an independent proof
// of pack closure. Independently deriving the expected tree root additionally
// excludes unreported changes under the native Git commitment.
import { buildSourceChanges, canonical, sha256, fail } from './source_changes.mjs';
import { editInput, captureSourceEdit, validateSourceEdit, oid } from './source_edit_candidate.mjs';
import { clock, fields } from './source_edit_wire.mjs';

function lifetime(options) {
  fields(options, ['confirmDraftSha256', 'signal', 'timeoutMs', 'ca', 'maxWireBytes'], ['confirmDraftSha256']);
  const pin = options.confirmDraftSha256;
  if (typeof pin !== 'string' || !/^[0-9a-f]{64}$/.test(pin)) fail('source_changes_confirmation');
  const { confirmDraftSha256, ...rest } = options;
  return { pin, time: clock(rest) };
}
function confirm(draft, pin) {
  if (sha256(canonical(draft.manifest)) !== pin) fail('source_changes_confirmation');
}
function requestMatches(request, draft) {
  const m = draft.manifest;
  if (request.scope.object_format !== m.object_format || request.expected_commit !== m.source_commit ||
      request.paths_hex.length !== m.effects.length || request.paths_hex.some((p, i) => p !== m.effects[i].path_hex)) {
    fail('source_changes_selection_mismatch');
  }
}
function matches(draft, candidate, pin) {
  const m = draft.manifest, c = candidate.capture, format = m.object_format;
  requestMatches(c.request, draft);
  if (c.patch_sha256 !== m.patch_sha256 || c.patch_bytes !== m.patch_bytes ||
      oid(c.inspection.comparison.before_tree, format) !== m.root_tree) fail('source_changes_candidate_basis');
  const prepared = new Map(c.preparation.paths.map(row => [row.path_hex, row]));
  const actual = new Map(c.inspection.comparison.entries.map(row => [row.path_hex, row]));
  if (prepared.size !== m.effects.length || actual.size !== m.effects.length) fail('source_changes_candidate_effects');
  for (const effect of m.effects) {
    const p = prepared.get(effect.path_hex), a = actual.get(effect.path_hex);
    if (!p || !a || (p.old_blob === null ? null : oid(p.old_blob, format)) !== effect.old_blob ||
        (p.new_blob === null ? null : oid(p.new_blob, format)) !== effect.new_blob || p.new_mode !== effect.new_mode ||
        (a.before === null ? null : oid(a.before.oid, format)) !== effect.old_blob || (a.before?.mode ?? null) !== effect.old_mode ||
        (a.after === null ? null : oid(a.after.oid, format)) !== effect.new_blob || (a.after?.mode ?? null) !== effect.new_mode) {
      fail('source_changes_candidate_effects');
    }
  }
  if (!draft.tree || draft.tree.beforeTree !== m.root_tree ||
      oid(c.preparation.root_tree, format) !== draft.tree.afterTree ||
      oid(c.inspection.comparison.after_tree, format) !== draft.tree.afterTree) fail('source_changes_candidate_tree');
  return { type: 'source_change_candidate_binding', draft_sha256: pin,
    package_sha256: m.package_sha256, patch_sha256: m.patch_sha256,
    source_commit: m.source_commit, candidate_commit: candidate.candidate_commit,
    effect_count: m.effects.length, no_op_count: m.no_op_paths_hex.length,
    ...(m.creation_preconditions ? { created_path_count: m.creation_preconditions.paths.length,
      creation_absence_independently_verified: true } : {}),
    intended_effect_reports_matched: true, before_membership_independently_verified: true,
    expected_tree: draft.tree.afterTree, tree_transition_profile: draft.tree.profile,
    candidate_root_matches_exact_effects: true, unrelated_subtree_commitments_preserved: true,
    native_bundle_validation_observed: true, candidate_tree_independently_verified: false,
    bundle_objects_independently_verified: false, publication_authorized: false };
}
export async function prepareSourceChanges(packageBytes, expected, changes, selection, credential, options) {
  const { pin, time } = lifetime(options), request = editInput(selection);
  if (typeof credential !== 'string' || !/^[0-9a-f]{64}$/.test(credential)) fail('source_changes_credential');
  const draft = await buildSourceChanges(packageBytes, expected, changes, { signal: time.signal, check: time.check });
  time.check(); confirm(draft, pin); requestMatches(request, draft);
  const candidate = await captureSourceEdit(request, draft.bytes, credential, {
    signal: time.signal, ca: time.ca, timeoutMs: time.remaining(), maxWireBytes: time.maxWireBytes,
  });
  time.check(); const binding = matches(draft, candidate, pin); time.check();
  return { ...candidate, draft, binding };
}
// Re-check an existing standard source candidate without credentials or I/O.
// A saved success flag cannot replace regeneration or the complete validator.
export async function verifySourceChangeCandidate(packageBytes, expected, changes, capture, bundle, options) {
  const { pin, time } = lifetime(options);
  const candidate = validateSourceEdit(capture, bundle); time.check();
  const draft = await buildSourceChanges(packageBytes, expected, changes, { signal: time.signal, check: time.check });
  time.check(); confirm(draft, pin);
  const binding = matches(draft, candidate, pin); time.check();
  return { ...candidate, draft, binding };
}
