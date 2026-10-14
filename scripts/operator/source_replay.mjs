// Explicit exact-preimage replay of a reviewed source draft onto another pinned
// commit. This is not automatic Git rebase, a semantic merge, or outcome recovery.
import { ownSourceChangeInputs, buildSourceChanges, canonical, sha256 } from './source_changes.mjs';
import { fields, clock } from './source_edit_wire.mjs';

export const SOURCE_REPLAY_PROFILE = 'frankengit-exact-source-replay-v1';
export class SourceReplayError extends Error {
  constructor(code) { super(code); this.name = 'SourceReplayError'; this.code = code; }
}
export const fail = code => { throw new SourceReplayError(code); };
export function reviewedHash(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('source_replay_confirmation');
  return value;
}
const same = (a, b) => canonical(a).equals(canonical(b));
// Called only after complete source/commit/tree/blob validation by the shared
// authoring kernel, on the SAME privately owned bytes. No second Git decoder.
function readSet(bytes) {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  return value.membership.files.map(row => [row.pathHex, row.blob, row.kind]);
}
export async function replaySourceChanges(packageBytes, expected, changes, nextPackageBytes, nextExpected, options) {
  fields(options, ['confirmDraftSha256', 'signal', 'timeoutMs', 'limits'], ['confirmDraftSha256']);
  const confirmed = reviewedHash(options.confirmDraftSha256);
  const time = clock({ signal: options.signal, timeoutMs: options.timeoutMs }); time.check();
  // Capture BOTH independently selected sources and every original operation
  // before the first await. A later caller edit cannot replace the second base.
  const original = ownSourceChangeInputs(packageBytes, expected, changes, options.limits);
  const next = ownSourceChangeInputs(nextPackageBytes, nextExpected, original.changes, options.limits);
  const build = input => buildSourceChanges(input.packageBytes, input.expected, input.changes,
    { signal: time.signal, check: time.check, limits: input.limits });
  const previousDraft = await build(original); time.check();
  if (sha256(canonical(previousDraft.manifest)) !== confirmed) fail('source_replay_confirmation');
  if (original.expected.format !== next.expected.format) fail('source_replay_format_changed');
  if (original.expected.commit === next.expected.commit) fail('source_replay_same_commit');
  // Preserve the entire selected read set, not just the paths that emitted a
  // patch. No-op intents, copy sources and unmodified selected context count.
  // A different read set requires a newly authored change, not this replay.
  if (!same(original.expected.files, next.expected.files)) fail('source_replay_read_set_changed');
  const draft = await build(next); time.check();
  if (!same(readSet(original.packageBytes), readSet(next.packageBytes))) fail('source_replay_read_set_changed');
  // Proving the preimages is primary. The independently regenerated patch and
  // effect/no-op equality also prevent a transform or mode default from changing
  // the reviewed intent. New creation proofs and the whole root may differ.
  if (!previousDraft.bytes.equals(draft.bytes) ||
      !same(previousDraft.manifest.effects, draft.manifest.effects) ||
      !same(previousDraft.manifest.no_op_paths_hex, draft.manifest.no_op_paths_hex) ||
      !same(previousDraft.manifest.relocations ?? [], draft.manifest.relocations ?? [])) fail('source_replay_effects_changed');
  const receipt = {
    profile: SOURCE_REPLAY_PROFILE, object_format: next.expected.format,
    original_commit: previousDraft.manifest.source_commit, selected_commit: draft.manifest.source_commit,
    original_draft_sha256: confirmed, draft_sha256: sha256(canonical(draft.manifest)),
    original_package_sha256: previousDraft.manifest.package_sha256, package_sha256: draft.manifest.package_sha256,
    original_expected_sha256: previousDraft.manifest.expected_sha256, expected_sha256: draft.manifest.expected_sha256,
    changes_sha256: draft.manifest.changes_sha256, patch_sha256: draft.manifest.patch_sha256,
    original_root_tree: previousDraft.manifest.root_tree, selected_root_tree: draft.manifest.root_tree,
    original_expected_tree: previousDraft.tree.afterTree, expected_tree: draft.tree.afterTree,
    selected_file_count: next.expected.files.length, effect_count: draft.manifest.effects.length,
    no_op_count: draft.manifest.no_op_paths_hex.length,
    selected_preimages_verified: true, exact_patch_preserved: true, selected_read_set_preserved: true,
    new_review_required: true, ancestry_verified: false, semantic_compatibility_verified: false,
    authority_verified: false, freshness_verified: false, publication_authorized: false,
    repository_changed: false, source_material_untrusted: true,
  };
  time.check(); return { original, next, previousDraft, draft, receipt };
}
