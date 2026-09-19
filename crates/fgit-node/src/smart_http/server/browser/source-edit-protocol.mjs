// Source-specific native coordinates and receipts. Shared transport/diff
// helpers do not replace source authorization, native validation, or head CAS.
import { fail, keys, record, integer, text, format, oid, branch, reference, binding, pinned,
  opaque, principal, form, utf8, unhex, hex, json } from './pulls-core.mjs';
import { BUNDLE_LIMIT, digest, checkedBundle, findBytes, joinBytes, comparisonEntries } from './pulls-candidate.mjs';
import { PATCH_LIMIT, sourcePath, fileMode } from './source-edit-patch.mjs';
export { digest, BUNDLE_LIMIT };
export const METADATA_LIMIT = 1024 * 1024;
export const PREPARE_LIMIT = BUNDLE_LIMIT + METADATA_LIMIT + 16 * 1024;
export function coordinates(fields) {
  keys(fields, ['ref', 'object_format', 'expected_commit', 'candidate_commit']);
  const result = { ref: branch(fields.ref), object_format: format(fields.object_format), expected_commit: oid(fields.expected_commit, fields.object_format) };
  if ('candidate_commit' in fields) {
    result.candidate_commit = oid(fields.candidate_commit, result.object_format);
    if (result.candidate_commit === result.expected_commit) fail('Candidate equals its parent.');
  }
  return result;
}
export function commitMetadata(value) {
  keys(value, ['author', 'committer', 'timestamp', 'message']); const result = {};
  for (const key of ['author', 'committer']) {
    result[key] = text(value[key], 1024, key, true);
    if (!/^[^<>\r\n]+ <[^<>\r\n]+>$/.test(result[key])) fail('Commit identities require Name <email>.');
  }
  result.timestamp = integer(value.timestamp, 'explicit timestamp');
  result.message = text(value.message, 64 * 1024, 'commit message');
  if (!result.message.trim()) fail('An explicit nonempty commit message is required.');
  return result;
}
export function noEffects(reply) {
  if (reply.read_only !== true || reply.objects_staged !== false || reply.transaction_created !== false ||
      reply.published !== false || reply.publication_authorized !== false) fail('Read-only source artifact claims publication or authority.');
}
export function matchReference(reply, ref) { reference(reply, 'ref'); if (reply.ref !== ref || reply.ref_hex !== hex(utf8.encode(ref))) fail('Source response selects another branch.'); }
export async function objectHash(kind, bytes, algorithm, crypto) {
  format(algorithm);
  if (!['blob', 'commit'].includes(kind) || !(bytes instanceof Uint8Array)) fail('Invalid native object bytes.');
  return hex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', joinBytes(utf8.encode(`${kind} ${bytes.length}\0`), bytes))));
}
export function sourceUpload(command, payload, kind, boundary) {
  if (!['patch', 'bundle'].includes(kind) || !(payload instanceof Uint8Array) || !payload.length ||
      payload.length > (kind === 'patch' ? PATCH_LIMIT : BUNDLE_LIMIT) || !/^[A-Za-z0-9._-]{1,70}$/.test(boundary)) fail('Invalid or oversized source upload.');
  const encoded = form(command), marker = utf8.encode(`--${boundary}`);
  if (findBytes(payload, marker) !== -1 || encoded.includes(`--${boundary}`)) fail('Source boundary collision.');
  return { contentType: `multipart/form-data; boundary=${boundary}`, bytes: joinBytes(utf8.encode(
    `--${boundary}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${encoded}\r\n--${boundary}\r\nContent-Disposition: form-data; name="${kind}"\r\nContent-Type: ${kind === 'patch' ? 'application/octet-stream' : 'application/x-git-bundle'}\r\n\r\n`), payload, utf8.encode(`\r\n--${boundary}--\r\n`)) };
}
function at(bytes, marker, offset) { return offset >= 0 && offset + marker.length <= bytes.length && marker.every((b, i) => bytes[offset + i] === b); }
export function sourceEnvelope(response) {
  const found = /^multipart\/mixed; boundary=(fg-source-[0-9a-f]{48}-[0-9a-f])$/.exec(response.type);
  if (!found || response.status !== 200 || !(response.value instanceof Uint8Array) || response.value.length > PREPARE_LIMIT) fail('Unsupported source preparation envelope.');
  const b = found[1], bytes = response.value;
  const opening = utf8.encode(`--${b}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n`);
  const middle = utf8.encode(`\r\n--${b}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`);
  const closing = utf8.encode(`\r\n--${b}--\r\n`);
  const split = findBytes(bytes, middle, opening.length, Math.min(bytes.length, opening.length + METADATA_LIMIT + middle.length));
  if (!at(bytes, opening, 0) || split < 0 || split - opening.length > METADATA_LIMIT || !at(bytes, closing, bytes.length - closing.length)) fail('Incomplete source preparation envelope.');
  const bundle = bytes.subarray(split + middle.length, bytes.length - closing.length); checkedBundle(bundle);
  if (findBytes(bundle, utf8.encode(`--${b}`)) !== -1) fail('Ambiguous source bundle boundary.');
  return { metadata: json(bytes.subarray(opening.length, split)), bundle: bundle.slice() };
}
export async function editManifest(edits, algorithm, crypto) {
  const out = [];
  for (const edit of edits) out.push({ path_hex: edit.path_hex,
    old_blob: edit.before === null ? null : await objectHash('blob', edit.before.bytes, algorithm, crypto),
    new_blob: edit.after === null ? null : await objectHash('blob', edit.after.bytes, algorithm, crypto),
    old_mode: edit.before?.mode ?? null, new_mode: edit.after?.mode ?? null });
  return out;
}
export async function prepared(response, fields, scope, patchSha, expectedPaths, crypto) {
  const { metadata: reply, bundle } = sourceEnvelope(response);
  binding(reply, scope); noEffects(reply); matchReference(reply, fields.ref);
  if (reply.type !== 'source_preparation' || oid(reply.source_commit, scope.format) !== fields.expected_commit ||
      reply.patch_sha256 !== patchSha || !Array.isArray(reply.paths) || !reply.paths.length || reply.paths.length > 512) fail('Prepared source does not match the patch and parent.');
  opaque(reply.source_rcr); integer(reply.object_count, 'prepared object count', 1);
  const candidate = oid(reply.candidate_commit, scope.format), tree = oid(reply.root_tree, scope.format);
  if (candidate === fields.expected_commit) fail('Candidate equals parent.');
  record(reply.bundle); const sha256 = await digest(bundle, crypto);
  if (reply.bundle.bytes !== bundle.length || reply.bundle.sha256 !== sha256) fail('Prepared bundle commitment mismatch.');
  const paths = new Map();
  for (const row of reply.paths) {
    sourcePath(row.path_hex); if (paths.has(row.path_hex)) fail('Duplicate prepared path.');
    const value = { path_hex: row.path_hex, old_blob: row.old_blob === null ? null : oid(row.old_blob, scope.format),
      new_blob: row.new_blob === null ? null : oid(row.new_blob, scope.format), new_mode: row.new_mode === null ? null : fileMode(row.new_mode) };
    integer(row.hunks, 'patch hunks');
    if ((value.new_blob === null) !== (value.new_mode === null) || (value.old_blob === null && value.new_blob === null)) fail('Invalid prepared file effect.');
    paths.set(row.path_hex, value);
  }
  if (expectedPaths !== null) {
    if (paths.size !== expectedPaths.length) fail('Prepared patch changed the requested path set.');
    for (const expected of expectedPaths) {
      const actual = paths.get(expected.path_hex);
      if (!actual || ['old_blob', 'new_blob', 'new_mode'].some(key => actual[key] !== expected[key])) fail('Prepared file differs from the queued edit.');
      actual.old_mode = expected.old_mode;
    }
  }
  return { fields: { ...coordinates(fields), candidate_commit: candidate }, scope, bundle, sha256, tree, paths: [...paths.values()], metadata: reply };
}
export async function inspected(reply, artifact, crypto) {
  const { fields, scope } = artifact, algorithm = scope.format;
  pinned(reply, scope); noEffects(reply); matchReference(reply, fields.ref);
  if (reply.type !== 'source_inspection' || reply.all_changed_paths !== true || reply.binary_bodies_included !== false ||
      oid(reply.expected_commit, algorithm) !== fields.expected_commit || oid(reply.candidate_commit, algorithm) !== fields.candidate_commit ||
      reply.bundle_bytes !== artifact.bundle.length || reply.bundle_sha256 !== artifact.sha256 || !Array.isArray(reply.parents) ||
      reply.parents.length !== 1 || oid(reply.parents[0], algorithm) !== fields.expected_commit) fail('Inspected source identity changed.');
  const bytes = unhex(reply.candidate_commit_body_hex, 2 * 1024 * 1024);
  if (await objectHash('commit', bytes, algorithm, crypto) !== fields.candidate_commit) fail('Native commit hash mismatch.');
  const separator = findBytes(bytes, new Uint8Array([10, 10])); if (separator < 0) fail('Malformed native commit.');
  const headers = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, separator)).split('\n');
  const parents = headers.filter(line => line.startsWith('parent ')), trees = headers.filter(line => line.startsWith('tree '));
  if (parents.length !== 1 || parents[0] !== `parent ${fields.expected_commit}` || trees.length !== 1 || trees[0] !== headers[0]) fail('Commit bytes do not match the inspected parent and tree.');
  const tree = oid(trees[0].slice(5), algorithm), comparison = record(reply.comparison);
  if (comparison.mode !== 'direct' || oid(comparison.after_tree, algorithm) !== tree || tree !== artifact.tree) fail('Inspected tree changed.');
  oid(comparison.before_tree, algorithm); comparisonEntries(comparison, algorithm);
  const byPath = new Map(comparison.entries.map(entry => [entry.path_hex, entry]));
  if (byPath.size !== artifact.paths.length) fail('Inspection changed the complete patch path set.');
  for (const expected of artifact.paths) {
    const row = byPath.get(expected.path_hex);
    if (!row || (row.before === null ? null : oid(row.before.oid, algorithm)) !== expected.old_blob ||
        (row.after === null ? null : oid(row.after.oid, algorithm)) !== expected.new_blob || (row.after?.mode ?? null) !== expected.new_mode ||
        ('old_mode' in expected && (row.before?.mode ?? null) !== expected.old_mode)) fail('Inspection changed a patch effect.');
  }
  return reply;
}
export function publication(reply, pending, status) {
  binding(reply, pending.scope); matchReference(reply, pending.fields.ref);
  principal(reply.principal_id); opaque(reply.tx_id); opaque(reply.decision_record); integer(reply.decision_sequence, 'decision sequence', 1);
  if (reply.type !== 'source_publication' || !['committed', 'refused'].includes(reply.outcome) ||
      status !== (reply.outcome === 'committed' ? 200 : 409) || reply.delivery_acknowledged !== null ||
      oid(reply.expected_commit, pending.scope.format) !== pending.fields.expected_commit ||
      oid(reply.candidate_commit, pending.scope.format) !== pending.fields.candidate_commit) fail('HTTP status is not the matching source decision.');
  if (reply.outcome === 'committed') { if (reply.refusal_code !== null) fail('Conflicting source outcome.'); } else opaque(reply.refusal_code);
  if (pending.observedTx && reply.tx_id !== pending.observedTx) fail('Source transaction changed.');
  if (pending.observedPrincipal && reply.principal_id !== pending.observedPrincipal) fail('Source principal changed.');
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    rcr: reply.outcome === 'committed' ? reply.decision_record : null, refusal: reply.refusal_code, deliveryAcknowledged: null };
}
export async function retryKey(root, fingerprint, scope, nonce, fields, upload, crypto) {
  const exact = JSON.stringify(['frankengit-source-apply-v1', root.origin, root.route, fingerprint,
    scope.tenant, scope.repository, scope.incarnation, scope.format, fields.ref, fields.expected_commit,
    fields.candidate_commit, nonce, upload.contentType, await digest(upload.bytes, crypto)]);
  return `fgsrc1-${nonce}-${await digest(utf8.encode(exact), crypto)}`;
}
