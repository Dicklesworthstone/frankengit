// Verify the native source service's incremental candidate, not a full backup.
// Reuse the existing pack decoder; the original bundle is never rewritten for
// publication. Its absent base history remains an explicit external dependency.
import { webcrypto } from 'node:crypto';
import { verifySourceChangeCandidate } from './source_changes_prepare.mjs';
import { canonical, sha256, fail } from './source_changes.mjs';
import { clock, fields } from './source_edit_wire.mjs';
import { BUNDLE_VERIFY_LIMITS, verifyGitBundleObjects } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';

export const SOURCE_CANDIDATE_PACK_PROFILE = 'frankengit-source-candidate-pack-v1';
function settings(options) {
  fields(options, ['confirmDraftSha256', 'timeoutMs', 'signal', 'limits'], ['confirmDraftSha256']);
  if (typeof options.confirmDraftSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(options.confirmDraftSha256)) fail('source_pack_confirmation');
  const input = options.limits ?? {};
  fields(input, Object.keys(BUNDLE_VERIFY_LIMITS), []);
  const limits = { ...BUNDLE_VERIFY_LIMITS, ...input };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1 || value > BUNDLE_VERIFY_LIMITS[name]) fail('source_pack_limit');
  }
  return { confirmDraftSha256: options.confirmDraftSha256, limits,
    time: clock({ signal: options.signal, timeoutMs: options.timeoutMs ?? 30000 }) };
}
function inventory(candidate) {
  const objects = new Map(), add = (id, kind) => {
    if (id === null) return;
    if (objects.has(id) && objects.get(id) !== kind) fail('source_pack_identity_conflict');
    objects.set(id, kind);
  };
  add(candidate.candidate_commit, 'commit');
  // Native ExportPlanner emits every rebuilt nonempty tree, even when another
  // path or the original base already has that identity. Identity deduplication
  // happens in its object map, not by omitting a same-ID reconstructed tree.
  for (const tree of candidate.draft.tree.rewrittenTrees) add(tree.afterTree, 'tree');
  for (const effect of candidate.draft.manifest.effects) add(effect.new_blob, 'blob');
  return [...objects].sort(([a], [b]) => a < b ? -1 : 1).map(([oid, kind]) => ({ oid, kind }));
}
export async function verifySourceCandidatePack(packageBytes, expected, changes, capture, suppliedBundle, options) {
  const { time, limits, confirmDraftSha256 } = settings(options); time.check();
  // The existing verifier owns all source/request/pack inputs before its first
  // await and independently derives both the exact effects and whole new root.
  const candidate = await verifySourceChangeCandidate(packageBytes, expected, changes, capture, suppliedBundle,
    { confirmDraftSha256, signal: time.signal, timeoutMs: time.remaining() });
  time.check();
  const { request } = candidate.capture, format = request.scope.object_format;
  const signature = format === 'sha1' ? '# v2 git bundle\n' : '# v3 git bundle\n@object-format=sha256\n';
  const originalHeader = Buffer.from(`${signature}-${request.expected_commit} patch base\n${candidate.candidate_commit} ${request.ref}\n\n`);
  if (!candidate.bundle.subarray(0, originalHeader.length).equals(originalHeader)) fail('source_pack_envelope');
  const objects = inventory(candidate);
  if (objects.length > limits.maxRefs || objects.length > limits.maxObjects) fail('source_pack_inventory_limit');
  if (candidate.capture.preparation.object_count !== objects.length) fail('source_pack_reported_count');
  // The full-bundle decoder intentionally refuses prerequisites. Give only its
  // object-verification entrypoint a private assertion envelope over EXACTLY the
  // same pack bytes: each locally derived ID is an advertised assertion. Every
  // assertion must exist, and the exact count below excludes all other objects.
  // This view is never exported, submitted, or claimed to be self-contained.
  const assertions = objects.map((object, i) => `${object.oid} ${object.kind === 'commit' ? 'refs/heads/candidate' : `refs/objects/${i}`}\n`).join('');
  const header = Buffer.from(`${signature}${assertions}\n`), pack = candidate.bundle.subarray(originalHeader.length);
  if (header.length > limits.maxHeaderBytes || header.length + pack.length > limits.maxInputBytes) fail('source_pack_view_limit');
  const view = Buffer.concat([header, pack]); time.check();
  const result = await verifyGitBundleObjects(view, { cryptoImpl: webcrypto, signal: time.signal, checkpoint: time.check,
    limits: { ...limits, maxObjects: objects.length, timeoutMs: Math.min(limits.timeoutMs, time.remaining()) } });
  time.check();
  if (result.pack_objects !== objects.length) fail('source_pack_inventory_mismatch');
  // This profile matches COMPRESSED_NO_DELTA_V1 from native source preparation;
  // other transport encodings need their own explicitly selected contract.
  if (result.delta_objects !== 0) fail('source_pack_delta_profile');
  return { ...candidate, verification: {
    profile: SOURCE_CANDIDATE_PACK_PROFILE, object_format: format,
    bundle_sha256: sha256(candidate.bundle), bundle_bytes: candidate.bundle.length,
    source_commit: request.expected_commit, candidate_commit: candidate.candidate_commit,
    expected_tree: candidate.draft.tree.afterTree, draft_sha256: confirmDraftSha256,
    expected_object_count: objects.length, expected_inventory_sha256: sha256(canonical(objects)),
    original_envelope_verified: true, pack_checksum_verified: true,
    packed_objects_independently_verified: true, exact_object_inventory_verified: true,
    packed_candidate_matches_reviewed_effects: true, pack_bytes_rewritten: false,
    expanded_bytes: result.expanded_bytes, decoder_work: result.work,
    base_closure_verified: false, complete_repository: false, gitlink_targets_verified: false,
    authority_verified: false, freshness_verified: false, signatures_verified: false,
    publication_authorized: false, source_material_untrusted: true,
  } };
}
