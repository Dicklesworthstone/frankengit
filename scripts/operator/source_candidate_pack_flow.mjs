// Strict packed-candidate consumers over the existing source/publication owners.
// No new journal, admission route, decoder, automatic retry or inferred consent.
import { ownSourceChangeInputs, canonical, fail } from './source_changes.mjs';
import { editInput, identity, oid } from './source_edit_candidate.mjs';
import { prepareSourceChanges, stageVerifiedSourceChanges } from './source_changes_prepare.mjs';
import { verifySourceCandidatePack } from './source_candidate_pack.mjs';
import { loadSourceEdit } from './source_edit_publish.mjs';
import { absolute, contains } from './workflow_watch_io.mjs';
import { clock, fields } from './source_edit_wire.mjs';
import { BUNDLE_VERIFY_LIMITS } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';

function settings(options, stage = false) {
  const required = ['confirmDraftSha256', ...(stage ? ['confirmCandidate', 'principal'] : [])];
  fields(options, [...required, 'signal', 'timeoutMs', 'packLimits', ...(stage ? [] : ['ca', 'maxWireBytes'])], required);
  const pin = options.confirmDraftSha256;
  if (typeof pin !== 'string' || !/^[0-9a-f]{64}$/.test(pin)) fail('source_pack_confirmation');
  const input = options.packLimits ?? {};
  fields(input, Object.keys(BUNDLE_VERIFY_LIMITS), []);
  const limits = { ...BUNDLE_VERIFY_LIMITS, ...input };
  for (const [key, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1 || value > BUNDLE_VERIFY_LIMITS[key]) fail('source_pack_limit');
  }
  const time = clock({ signal: options.signal, timeoutMs: options.timeoutMs,
    ...(stage ? {} : { ca: options.ca, maxWireBytes: options.maxWireBytes }) });
  time.check(); return { pin, limits, time };
}
function packOptions({ pin, limits, time }) {
  return { confirmDraftSha256: pin, limits, signal: time.signal, timeoutMs: time.remaining() };
}
function packed(candidate) {
  // Older report-only binding fields remain meaningful; upgrade only the claim
  // the actual decoder established. Untouched base closure is still unverified.
  return { ...candidate, bundle_objects_independently_verified: true,
    binding: { ...candidate.binding, bundle_objects_independently_verified: true },
    pack_verification: candidate.verification };
}
export async function preparePackedSourceChanges(packageBytes, expected, changes, selection, credential, options) {
  const context = settings(options), { time, pin } = context, request = editInput(selection);
  // Freeze the full source/read set, profile choices, independent target and
  // budgets before any asynchronous source hashing or network request.
  const owned = ownSourceChangeInputs(packageBytes, expected, changes);
  const candidate = await prepareSourceChanges(owned.packageBytes, owned.expected, owned.changes, request, credential,
    { confirmDraftSha256: pin, signal: time.signal, timeoutMs: time.remaining(), ca: time.ca, maxWireBytes: time.maxWireBytes });
  const verified = await verifySourceCandidatePack(owned.packageBytes, owned.expected, owned.changes,
    candidate.capture, candidate.bundle, packOptions(context));
  time.check();
  return { ...packed(verified), metrics: candidate.metrics };
}
export async function inspectPackedSourceChanges(candidatePath, candidateHash, packageBytes, expected, changes, options) {
  const context = settings(options, false), { time } = context;
  // Inspection has no transport options, even though preparation shares settings.
  fields(options, ['confirmDraftSha256', 'signal', 'timeoutMs', 'packLimits'], ['confirmDraftSha256']);
  const owned = ownSourceChangeInputs(packageBytes, expected, changes);
  const candidate = await loadSourceEdit(candidatePath, candidateHash, time.check);
  const verified = await verifySourceCandidatePack(owned.packageBytes, owned.expected, owned.changes,
    candidate.capture, candidate.bundle, packOptions(context));
  time.check(); return { ...packed(verified), manifest_sha256: candidateHash };
}
export async function stagePackedSourceChanges(journal, candidatePath, candidateHash,
  packageBytes, expected, changes, selection, options) {
  const context = settings(options, true), { time, pin } = context;
  const request = editInput(selection), principal = identity(options.principal);
  const confirmed = oid(options.confirmCandidate, request.scope.object_format);
  absolute(journal); absolute(candidatePath);
  if (contains(journal, candidatePath) || contains(candidatePath, journal)) fail('source_changes_overlapping_custody');
  const owned = ownSourceChangeInputs(packageBytes, expected, changes);
  const candidate = await loadSourceEdit(candidatePath, candidateHash, time.check);
  if (confirmed !== candidate.candidate_commit) fail('source_changes_candidate_confirmation');
  if (!canonical(request).equals(canonical(candidate.capture.request))) fail('source_changes_target_selection');
  const verified = await verifySourceCandidatePack(owned.packageBytes, owned.expected, owned.changes,
    candidate.capture, candidate.bundle, packOptions(context));
  time.check();
  // The ordinary owner reloads the SAME manifest hash before creating its
  // self-contained journal. A replaced pathname cannot substitute unchecked
  // bytes. Neither saved success flags nor an earlier inspection skip this check.
  const evidence = { ...verified.verification, candidate_manifest_sha256: candidateHash };
  try {
    const staged = await stageVerifiedSourceChanges(journal, candidatePath, candidateHash,
      owned.packageBytes, owned.expected, owned.changes, request,
      { confirmDraftSha256: pin, confirmCandidate: confirmed, principal, signal: time.signal, timeoutMs: time.remaining() });
    return { ...staged, binding: { ...staged.binding, bundle_objects_independently_verified: true }, pack_verification: evidence };
  } catch (error) {
    if (error.publication_unconfirmed) error.publication_unconfirmed = {
      ...error.publication_unconfirmed,
      binding: { ...error.publication_unconfirmed.binding, bundle_objects_independently_verified: true },
      pack_verification: evidence };
    throw error;
  }
}
