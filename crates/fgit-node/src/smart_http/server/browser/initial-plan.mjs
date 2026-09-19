// Reconstruct the complete initial Git closure from explicit file bytes. This
// verifies a native preparation artifact; only native admission can publish it.
import { fail, keys, record, copy, format, branch, snapshot, oid, integer, opaque,
  principal, pinned, binding, utf8, hex, unhex, json } from './pulls-core.mjs';
import { digest, joinBytes, findBytes, checkedBundle } from './pulls-candidate.mjs';
import { fullFilePatch, sourcePath, EDIT_LIMIT } from './source-edit-patch.mjs';
import { commitMetadata, noEffects, matchReference, PREPARE_LIMIT, METADATA_LIMIT } from './source-edit-protocol.mjs';
export { PREPARE_LIMIT };
export function initialFields(value, applying = false) {
  keys(value, applying ? ['ref', 'object_format', 'expected_absent', 'candidate_commit']
    : ['ref', 'object_format', 'expected_absent', 'expected_head']);
  if (value.expected_absent !== true) fail('Explicit branch absence is required; this operation cannot update a branch.');
  const fields = { ref: branch(value.ref), object_format: format(value.object_format), expected_absent: true };
  if (applying) fields.candidate_commit = oid(value.candidate_commit, fields.object_format);
  else if ('expected_head' in value) fields.expected_head = snapshot(value.expected_head);
  return fields;
}
export async function nativeHash(kind, bytes, algorithm, crypto) {
  format(algorithm);
  if (!['blob', 'tree', 'commit'].includes(kind) || !(bytes instanceof Uint8Array)) fail('Invalid native object.');
  const input = joinBytes(utf8.encode(`${kind} ${bytes.length}\0`), bytes);
  return hex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', input)));
}
const same = (a, b) => a.length === b.length && a.every((value, i) => value === b[i]);
const lexical = (a, b) => a < b ? -1 : a > b ? 1 : 0;
export async function initialPlan(files, suppliedMetadata, algorithm, crypto, checkpoint = () => {}) {
  format(algorithm); checkpoint();
  if (!Array.isArray(files) || !files.length || files.length > EDIT_LIMIT) fail('Choose 1 through 64 initial files.');
  // Validate/copy every file before the first await. Later editor changes must
  // not alter either the generated patch or the closure being checked.
  const patch = fullFilePatch(files.map(file => {
    keys(file, ['path_hex', 'bytes', 'mode']);
    return { path_hex: file.path_hex, before: null, after: { bytes: file.bytes, mode: file.mode } };
  }));
  const metadata = commitMetadata(suppliedMetadata), root = new Map(), objects = new Map(), manifest = [];
  let total = 0;
  async function emit(kind, body) {
    checkpoint(); const id = await nativeHash(kind, body, algorithm, crypto); checkpoint();
    const prior = objects.get(id);
    if (prior && (prior.kind !== kind || !same(prior.body, body))) fail('Native object identity collision.');
    if (!prior) {
      total += body.length;
      if (total > 8 * 1024 * 1024 || objects.size >= 8192) fail('Initial object closure exceeds browser limits.');
      objects.set(id, { kind, body });
    }
    return id;
  }
  for (const edit of patch.edits) {
    checkpoint();
    const bytes = edit.after.bytes, mode = edit.after.mode, blob = await emit('blob', bytes);
    const path = sourcePath(edit.path_hex), parts = []; let start = 0;
    for (let i = 0; i <= path.length; i++) if (i === path.length || path[i] === 47) { parts.push(path.slice(start, i)); start = i + 1; }
    let directory = root;
    for (const name of parts.slice(0, -1)) {
      const key = hex(name);
      if (!directory.has(key)) directory.set(key, { name, mode: 0o40000, children: new Map() });
      const child = directory.get(key);
      if (!child.children) fail('Overlapping initial paths.');
      directory = child.children;
    }
    const name = parts.at(-1), key = hex(name);
    if (directory.has(key)) fail('Duplicate or overlapping initial path.');
    directory.set(key, { name, mode, id: blob });
    manifest.push({ path_hex: edit.path_hex, blob, mode, bytes: bytes.length });
  }
  async function tree(directory) {
    const entries = [...directory.values()].sort((a, b) => lexical(hex(a.name) + (a.children ? '2f' : '00'), hex(b.name) + (b.children ? '2f' : '00')));
    const parts = [];
    for (const entry of entries) {
      checkpoint(); const id = entry.children ? await tree(entry.children) : entry.id;
      parts.push(utf8.encode(`${entry.mode.toString(8)} `), entry.name, new Uint8Array([0]), unhex(id, 32));
    }
    return emit('tree', joinBytes(...parts));
  }
  const rootTree = await tree(root);
  const commitBody = utf8.encode(`tree ${rootTree}\nauthor ${metadata.author} ${metadata.timestamp} +0000\ncommitter ${metadata.committer} ${metadata.timestamp} +0000\n\n${metadata.message}`);
  const commit = await emit('commit', commitBody), patchSha256 = await digest(patch.bytes, crypto); checkpoint();
  return { patch: patch.bytes, metadata, files: manifest, tree: rootTree, commit, commitBody, objectCount: objects.size, patchSha256 };
}
function at(bytes, marker, offset) {
  return offset >= 0 && offset + marker.length <= bytes.length && marker.every((b, i) => bytes[offset + i] === b);
}
export function initialEnvelope(response) {
  const match = /^multipart\/mixed; boundary=(fg-initial-[0-9a-f]{48}-[0-9a-f])$/.exec(response.type);
  const bytes = response.value;
  if (!match || response.status !== 200 || !(bytes instanceof Uint8Array) || bytes.length > PREPARE_LIMIT) fail('Invalid initial preparation envelope.');
  const b = match[1];
  const opening = utf8.encode(`--${b}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n`);
  const middle = utf8.encode(`\r\n--${b}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="initial.bundle"\r\n\r\n`);
  const closing = utf8.encode(`\r\n--${b}--\r\n`);
  const split = findBytes(bytes, middle, opening.length, Math.min(bytes.length, opening.length + METADATA_LIMIT + middle.length));
  if (!at(bytes, opening, 0) || split < 0 || split - opening.length > METADATA_LIMIT || !at(bytes, closing, bytes.length - closing.length)) fail('Incomplete initial preparation envelope.');
  const bundle = bytes.subarray(split + middle.length, bytes.length - closing.length); checkedBundle(bundle);
  if (findBytes(bundle, utf8.encode(`--${b}`)) !== -1) fail('Ambiguous initial bundle boundary.');
  return { metadata: json(bytes.subarray(opening.length, split)), bundle: bundle.slice() };
}
export async function verifyInitial(response, fields, plan, previousScope, crypto) {
  const { metadata: reply, bundle } = initialEnvelope(response);
  const selected = pinned(reply, previousScope, fields.expected_head ?? null);
  noEffects(reply); matchReference(reply, fields.ref);
  if (selected.binding.format !== fields.object_format || reply.type !== 'initial_source_preparation' || reply.expected_absent !== true ||
      reply.default_branch_changed !== false || !Array.isArray(reply.parents) || reply.parents.length ||
      !Array.isArray(reply.prerequisites) || reply.prerequisites.length || reply.patch_sha256 !== plan.patchSha256 ||
      oid(reply.candidate_commit, fields.object_format) !== plan.commit || oid(reply.root_tree, fields.object_format) !== plan.tree ||
      reply.object_count !== plan.objectCount || !same(unhex(reply.candidate_commit_body_hex, 128 * 1024), plan.commitBody)) fail('Native root commit does not match the complete submitted files and metadata.');
  if (!Array.isArray(reply.files) || reply.files.length !== plan.files.length) fail('Initial file manifest is incomplete.');
  for (let i = 0; i < plan.files.length; i++) {
    const expected = plan.files[i], actual = record(reply.files[i]);
    if (actual.path_hex !== expected.path_hex || oid(actual.blob, fields.object_format) !== expected.blob || actual.mode !== expected.mode || actual.bytes !== expected.bytes) fail('Initial file manifest changed a path, mode or blob.');
  }
  record(reply.bundle); const sha256 = await digest(bundle, crypto);
  if (reply.bundle.bytes !== bundle.length || reply.bundle.sha256 !== sha256) fail('Initial bundle commitment mismatch.');
  return { fields: initialFields({ ref: fields.ref, object_format: fields.object_format, expected_absent: true, candidate_commit: plan.commit }, true),
    scope: selected.binding, snapshot: selected.head, bundle, sha256, metadata: reply, files: copy(plan.files) };
}
export function initialPublication(reply, pending, status) {
  binding(reply, pending.scope); matchReference(reply, pending.fields.ref);
  principal(reply.principal_id); opaque(reply.tx_id); integer(reply.decision_sequence, 'decision sequence', 1);
  if (reply.type !== 'initial_source_publication' || reply.expected_absent !== true || reply.atomic !== true || reply.terminal !== true ||
      reply.default_branch_changed !== false || reply.receipt_confirms_transport_revalidation !== false ||
      oid(reply.candidate_commit, pending.scope.format) !== pending.fields.candidate_commit || !['committed', 'refused'].includes(reply.outcome) ||
      status !== (reply.outcome === 'committed' ? 200 : 409)) fail('Response is not the matching terminal initial-commit decision.');
  const decision = record(reply.decision);
  if (reply.outcome === 'committed') { keys(decision, ['repository_commit_id']); opaque(decision.repository_commit_id); }
  else { keys(decision, ['code', 'code_point', 'refusal_record_id']); opaque(decision.code); opaque(decision.refusal_record_id); integer(decision.code_point, 'refusal code', 0, 65535); }
  if ((pending.observedTx && reply.tx_id !== pending.observedTx) || (pending.observedPrincipal && reply.principal_id !== pending.observedPrincipal)) fail('Initial publication identity changed.');
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    rcr: decision.repository_commit_id ?? null, refusal: decision.code ?? null, defaultBranchChanged: false };
}
