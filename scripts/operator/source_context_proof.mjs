// Independent native membership for saved context bytes. This does not attest
// search completeness, semantic relevance, author identity, or current authority.
import { archiveSelection, archiveLimits, captureSourcePaths, validatePathCapture,
  sourcePaths, oid, hexBytes, sha256, ARCHIVE_LIMITS, MAX_PATH_PROOF_FILES } from './source_archive.mjs';
import { fail, fields, integer, parse } from './source_archive_transport.mjs';

export const CONTEXT_PROOF_LIMIT = 160 * 1024 * 1024;
export const CONTEXT_INPUT_LIMIT = 12 * 1024 * 1024;
const SCHEMA = 'frankengit-context-source-proof-v1';
const encoded = value => Buffer.from(`${JSON.stringify(value)}\n`);
function pinned(bytes, hash, limit) {
  if (!Buffer.isBuffer(bytes) || bytes.length > limit || typeof hash !== 'string' ||
      !/^[0-9a-f]{64}$/.test(hash) || sha256(bytes) !== hash) fail('Proof input differs from its independently retained hash.');
}
// Parse original capture/HTTP bytes without changing full-width index IDs. Those
// IDs remain untrusted search evidence here; only safe source coordinates matter.
function contextPlan(bytes, hash, selected) {
  pinned(bytes, hash, CONTEXT_INPUT_LIMIT);
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), (_key, value, context) =>
    typeof value === 'number' && !Number.isSafeInteger(value) ? context.source : value); }
  catch { fail('Invalid saved context JSON.'); }
  const expected = archiveSelection(selected);
  if (value?.schema === 'frankengit-source-context-capture-v1') {
    if (value.endpoint !== expected.endpoint) fail('Saved context endpoint differs from independent selection.');
    value = value.native_response;
  }
  const source = value?.retrieval;
  if (value?.type !== 'source_context_initial' || value.schema_version !== 1 || value.profile !== 'source-initial-context-v1' ||
      value.read_only !== true || value.transaction_created !== false || value.source_material_untrusted !== true ||
      source?.type !== 'source_search_initial' || source.profile !== 'source-initial-retrieval-v1' || source.schema_version !== 1 ||
      source.read_only !== true || source.transaction_created !== false || !Array.isArray(value.files) ||
      value.files.length < 1 || value.files.length > MAX_PATH_PROOF_FILES || value.files.length !== value.returned_files) fail('Unsupported source context for byte proof.');
  if (['tenant_id', 'repository_id', 'repository_incarnation', 'object_format'].some(k => source[k] !== expected[k]) ||
      source.ref !== expected.ref || source.ref_hex !== Buffer.from(expected.ref).toString('hex') ||
      oid(source.source_commit, expected.object_format) !== expected.expected_commit ||
      (expected.expected_head !== null && source.snapshot_token !== expected.expected_head)) fail('Context changed the independently selected source.');
  // The saved context's observed head narrows an optional caller pin. It never
  // replaces the independent commit or supplies the network endpoint.
  const selection = archiveSelection({ ...expected, expected_head: source.snapshot_token });
  if (typeof source.source_rcr !== 'string' || !source.source_rcr.length || source.source_rcr.length > 256) fail('Invalid context source record.');
  const paths = sourcePaths(value.files.map(row => row?.path_hex));
  let count = 0, total = 0;
  const files = value.files.map(row => {
    const size = integer(row.source_bytes, 0, ARCHIVE_LIMITS.maxBlobBytes, 'context file size');
    if (!Array.isArray(row.excerpts) || !row.excerpts.length || row.excerpts.length > 128) fail('Invalid context excerpt inventory.');
    let end = -1;
    const excerpts = row.excerpts.map(part => {
      fields(part, ['byte_offset', 'untrusted_bytes_hex']);
      const bytes = hexBytes(part.untrusted_bytes_hex, 1024 * 1024, true);
      const offset = integer(part.byte_offset, 0, size, 'excerpt offset');
      if (offset <= end || bytes.length > size - offset || ++count > 128 || (total += bytes.length) > 1024 * 1024) fail('Invalid context excerpt extent or budget.');
      end = offset + bytes.length - 1;
      return { offset, bytes };
    });
    return { path_hex: row.path_hex, object_id: oid(row.blob, expected.object_format), size, excerpts };
  }).sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
  return { selection, paths, files, root: oid(source.root_tree, expected.object_format), rcr: source.source_rcr, excerptBytes: total };
}
function verify(capture, plan, check) {
  check(); const evidence = validatePathCapture(capture, plan.selection, plan.paths); check();
  if (evidence.root_tree !== plan.root || capture.source_rcr !== plan.rcr ||
      capture.snapshot_token !== plan.selection.expected_head) fail('Proof and context source observations differ.');
  const bodies = new Map(capture.files.map(row => [row.path_hex, row]));
  const files = plan.files.map(expected => {
    check(); const file = bodies.get(expected.path_hex);
    if (!file || !['file', 'executable'].includes(file.kind) || file.object_id !== expected.object_id || file.bytes.length !== expected.size) fail('Context file is not the committed regular source.');
    const excerpts = expected.excerpts.map(part => {
      check();
      if (!file.bytes.subarray(part.offset, part.offset + part.bytes.length).equals(part.bytes)) fail('Context excerpt differs from committed source bytes.');
      return { byte_offset: part.offset, bytes: part.bytes.length, sha256: sha256(part.bytes) };
    });
    return { path_hex: expected.path_hex, blob: file.object_id, kind: file.kind, source_bytes: file.bytes.length, excerpts };
  });
  return { type: 'source_context_proof', schema_version: 1, object_format: plan.selection.object_format,
    source_commit: plan.selection.expected_commit, root_tree: evidence.root_tree,
    verified_files: files, excerpt_bytes: plan.excerptBytes, full_blob_bytes: evidence.blob_bytes,
    parent_tree_bytes: evidence.tree_bytes, selected_path_membership_verified: true, excerpt_bytes_verified: true,
    complete_repository: false, search_evidence_verified: false, authority_verified: false,
    freshness_verified: false, agent_context_packet: false, source_material_untrusted: true };
}
function portable(capture) {
  return { schema: capture.schema, paths_hex: [...capture.paths_hex], selection: archiveSelection(capture.selection),
    snapshot_token: capture.snapshot_token, source_head: capture.source_head, source_rcr: capture.source_rcr,
    commit: { object_id: capture.commit.object_id, body_hex: capture.commit.body_hex },
    trees: capture.trees.map(row => ({ path_hex: row.path_hex, object_id: row.object_id, body_hex: row.body_hex }))
      .sort((a, b) => a.path_hex === b.path_hex ? 0 : a.path_hex === null ? -1 : b.path_hex === null ? 1 : a.path_hex < b.path_hex ? -1 : 1),
    files: capture.files.map(row => ({ path_hex: row.path_hex, object_id: row.object_id, kind: row.kind, body_hex: row.bytes.toString('hex') }))
      .sort((a, b) => a.path_hex < b.path_hex ? -1 : 1) };
}
function serialized(capture, hash) {
  const value = encoded({ schema: SCHEMA, context_sha256: hash, capture: portable(capture) });
  if (value.length > CONTEXT_PROOF_LIMIT) fail('Portable context proof exceeds its byte limit.');
  return value;
}
// A separate independent commit selection is mandatory even though the saved
// context also claims a commit. Read access remains the native server's job.
export async function captureContextProof(contextBytes, contextHash, selected, token, options = {}) {
  fields(options, ['limits', 'signal', 'ca'], []);
  const limits = archiveLimits({ maxBlobBytes: 8 * 1024 * 1024, maxTotalBlobBytes: 8 * 1024 * 1024, ...options.limits });
  const start = performance.now(), signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('Invalid proof cancellation signal.');
  const check = () => { signal?.throwIfAborted(); if (performance.now() - start >= limits.timeoutMs) fail('Context proof deadline exceeded.'); };
  check(); const plan = contextPlan(contextBytes, contextHash, selected); check();
  const remaining = Math.floor(limits.timeoutMs - (performance.now() - start));
  if (remaining < 1) fail('Context proof deadline exceeded.');
  const { capture, metrics } = await captureSourcePaths(plan.selection, token, plan.paths,
    { ...options, limits: { ...limits, timeoutMs: remaining } });
  const receipt = verify(capture, plan, check), bytes = serialized(capture, contextHash); check();
  return { bytes, receipt: { ...receipt, context_sha256: contextHash, proof_sha256: sha256(bytes), proof_bytes: bytes.length }, metrics };
}
// Offline verification redoes every native commitment and checks all original
// context ranges. The two independent file hashes bind the exact saved inputs.
export function inspectContextProof(bytes, expectedHash, contextBytes, contextHash, selected, check = () => {}) {
  check(); pinned(bytes, expectedHash, CONTEXT_PROOF_LIMIT);
  const plan = contextPlan(contextBytes, contextHash, selected), value = parse(bytes);
  fields(value, ['schema', 'context_sha256', 'capture']);
  if (value.schema !== SCHEMA || value.context_sha256 !== contextHash) fail('Proof belongs to another saved context.');
  const c = value.capture;
  fields(c, ['schema', 'paths_hex', 'selection', 'snapshot_token', 'source_head', 'source_rcr', 'commit', 'trees', 'files']);
  if (!Array.isArray(c.files) || c.files.length !== plan.files.length || !Array.isArray(c.trees) || c.trees.length > ARCHIVE_LIMITS.maxTrees) fail('Invalid proof inventory.');
  let total = 0;
  const capture = { ...c, files: c.files.map(row => {
    check(); fields(row, ['path_hex', 'object_id', 'kind', 'body_hex']);
    if (typeof row.body_hex !== 'string' || row.body_hex.length / 2 > ARCHIVE_LIMITS.maxTotalBlobBytes - total) fail('Proof blob byte limit exceeded.');
    const bytes = hexBytes(row.body_hex, ARCHIVE_LIMITS.maxBlobBytes, true);
    if ((total += bytes.length) > ARCHIVE_LIMITS.maxTotalBlobBytes) fail('Proof blob byte limit exceeded.');
    return { path_hex: row.path_hex, object_id: row.object_id, kind: row.kind, bytes };
  }) };
  const receipt = verify(capture, plan, check);
  if (!serialized(capture, contextHash).equals(bytes)) fail('Noncanonical portable context proof.');
  check(); return { ...receipt, context_sha256: contextHash, proof_sha256: expectedHash, proof_bytes: bytes.length };
}
