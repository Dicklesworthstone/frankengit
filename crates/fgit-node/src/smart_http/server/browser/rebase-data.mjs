// Native linear rebase contracts. An explained prefix is never a candidate.
import { fail, record, keys, copy, integer, text, oid, branch, format, hex, unhex, utf8,
  pinned, binding, principal, opaque, form, json } from './pulls-core.mjs';
import { digest, joinBytes, findBytes } from './pulls-candidate.mjs';
import { sourceEnvelope, sourceUpload, objectHash } from './source-edit-protocol.mjs';
import { sourcePath } from './source-edit-patch.mjs';
export { sourceUpload, objectHash };
export const MAX_COMMITS = 32, MAX_CHOICES = 64, FILE_BYTES = 256 * 1024;
export const BUNDLE_BYTES = 8 * 1024 * 1024, RESOLUTION_BYTES = 1024 * 1024;
export const READ_BYTES = 8 * 1024 * 1024, PREPARE_BYTES = BUNDLE_BYTES + 1024 * 1024 + 16384;
const MODES = [0o040000, 0o100644, 0o100755, 0o120000, 0o160000];
const FALSE_FLAGS = ['objects_staged', 'transaction_created', 'published', 'publication_authorized'];
export function noEffects(reply) {
  if (reply.read_only !== true || FALSE_FLAGS.some(k => reply[k] !== false)) fail('Rebase read claims a mutation or authority.');
}
export function exactOid(value, algorithm) {
  if (oid(value, algorithm) !== value) fail('A full, unprefixed native object ID is required.');
  return value;
}
export function rootReply(reply, ref, algorithm, scope = null, head = null) {
  const selected = pinned(reply, scope, head);
  if (selected.binding.format !== algorithm || reply.type !== 'source_tree' ||
      reply.ref !== ref || reply.ref_hex !== hex(utf8.encode(ref)) || reply.path_hex !== null ||
      reply.after_hex !== null || reply.limit !== 1 || !Array.isArray(reply.entries) || reply.entries.length > 1 ||
      reply.read_only !== true || reply.transaction_created !== false || reply.published !== false) fail('Invalid immutable branch selection.');
  const tree = exactOid(reply.root_tree, algorithm), commit = exactOid(reply.source_commit, algorithm);
  if (reply.object_id !== tree) fail('Branch root tree changed.');
  opaque(reply.source_rcr);
  return { scope: selected.binding, head: selected.head, sourceHead: reply.source_head, tree, commit };
}
export function prepareCommand(selection, input) {
  keys(input, ['upstream', 'empty', 'committer', 'timestamp']);
  const { source, onto, scope, head } = selection;
  const committer = text(input.committer, 1024, 'rebase committer', true);
  if (!/^[^<>]+ <[^<>]+>$/.test(committer)) fail('Committer must use Name <email> syntax.');
  if (!['stop', 'drop', 'keep'].includes(input.empty)) fail('Choose an explicit empty-commit policy.');
  return { object_format: scope.format, profile: 'linear-v1', source_ref: branch(source.ref), onto_ref: branch(onto.ref),
    expected_source: source.commit, upstream: exactOid(input.upstream, scope.format), expected_onto: onto.commit,
    expected_head: head, empty: input.empty, committer, timestamp: integer(input.timestamp, 'explicit timestamp'),
    max_commits: MAX_COMMITS, max_conflicts: MAX_CHOICES, max_text_bytes: FILE_BYTES,
    max_objects: 4096, max_output_bytes: BUNDLE_BYTES };
}
function identity(value, algorithm) {
  if (value === null) return null;
  record(value);
  if (!MODES.includes(value.mode)) fail('Invalid conflict entry mode.');
  return { mode: value.mode, oid: exactOid(value.oid, algorithm) };
}
function conflict(raw, algorithm) {
  record(raw); sourcePath(raw.path_hex);
  if (!['content', 'binary', 'modify_delete', 'type_change', 'mode', 'opaque', 'attributes_require_driver'].includes(raw.kind)) fail('Invalid native conflict kind.');
  return { path_hex: raw.path_hex, kind: raw.kind,
    base: identity(raw.base, algorithm), ours: identity(raw.ours, algorithm), theirs: identity(raw.theirs, algorithm) };
}
function steps(reply, command, initialTree) {
  if (!Array.isArray(reply.steps) || reply.steps.length > MAX_COMMITS || reply.step_count !== reply.steps.length) fail('Incomplete rebase step list.');
  const seen = new Set(), rewritten = new Set();
  let parent = command.expected_onto, tree = initialTree;
  for (const step of reply.steps) {
    record(step); for (const k of ['original', 'rewritten', 'tree']) exactOid(step[k], command.object_format);
    if (seen.has(step.original) || step.original === command.upstream || !['replayed', 'preserved_empty', 'dropped_empty'].includes(step.kind)) fail('Invalid original-commit sequence.');
    seen.add(step.original);
    if (step.kind === 'dropped_empty') {
      if (command.empty !== 'drop' || step.rewritten !== parent || step.tree !== tree) fail('Dropped commit changed the candidate frontier.');
    } else {
      if (step.rewritten === parent || step.rewritten === command.expected_onto || rewritten.has(step.rewritten)) fail('Rewritten commit chain repeats an identity.');
      if (step.kind === 'preserved_empty' && step.tree !== tree) fail('Preserved empty commit changed its parent tree.');
      rewritten.add(step.rewritten);
    }
    parent = step.rewritten; tree = step.tree;
  }
  return { parent, tree, seen };
}
export async function prepared(response, selection, command, recipes, crypto, check) {
  check();
  let metadata, bundle = null;
  if (/^application\/json(?:\s*;|$)/i.test(response.type)) {
    if (!(response.value instanceof Uint8Array) || response.value.length > 1024 * 1024) fail('Oversized rebase stop report.');
    metadata = json(response.value);
  } else ({ metadata, bundle } = sourceEnvelope(response));
  const r = record(metadata), selected = pinned(r, selection.scope, command.expected_head);
  noEffects(r);
  if (r.type !== 'rebase_preparation' || r.profile !== 'linear-v1' ||
      r.source_ref !== command.source_ref || r.source_ref_hex !== hex(utf8.encode(command.source_ref)) ||
      r.onto_ref !== command.onto_ref || r.onto_ref_hex !== hex(utf8.encode(command.onto_ref)) ||
      r.expected_source !== command.expected_source || r.upstream !== command.upstream || r.onto !== command.expected_onto ||
      r.empty !== command.empty || r.committer !== command.committer || r.timestamp !== command.timestamp ||
      r.original_authors_preserved !== true || r.original_messages_preserved !== true ||
      r.original_signatures_copied !== false || r.author_identity_verified !== false) fail('Rebase report does not match the original request.');
  if (r.source_head !== selection.sourceHead) fail('Rebase authority identity changed.');
  const sequence = steps(r, command, selection.onto.tree);
  if (!Array.isArray(r.conflicts) || r.conflicts.length > MAX_CHOICES) fail('Invalid conflict list.');
  let previous = '';
  r.conflicts = r.conflicts.map(row => {
    const c = conflict(row, command.object_format);
    if (c.path_hex <= previous) fail('Duplicate or unordered conflict paths.');
    previous = c.path_hex; return c;
  });
  let artifact = null;
  if (r.state === 'clean') {
    if (response.status !== 200 || !bundle || bundle.length > BUNDLE_BYTES || r.series_complete !== true ||
        r.provisional_steps !== false || r.stopped_commit !== null || r.conflicts.length ||
        r.candidate_commit !== sequence.parent || r.root_tree !== sequence.tree ||
        (r.steps.length ? r.steps.at(-1).original !== command.expected_source : command.expected_source !== command.upstream)) fail('Incomplete or inconsistent final rebase candidate.');
    record(r.bundle); const sha256 = await digest(bundle, crypto); check();
    if (r.bundle.bytes !== bundle.length || r.bundle.sha256 !== sha256) fail('Rebase bundle commitment mismatch.');
    integer(r.generated_objects, 'generated objects', 0, 4096); integer(r.pack_objects, 'pack objects', 0, 4096);
    integer(r.borrowed_objects, 'borrowed objects', 0, r.pack_objects);
    artifact = { command: copy(command), scope: selected.binding, metadata: r, bundle, sha256 };
  } else {
    if (!['conflicted', 'became_empty'].includes(r.state) || response.status !== 409 || bundle !== null ||
        r.candidate_commit !== null || r.root_tree !== null || r.bundle !== null || r.series_complete !== false ||
        r.provisional_steps !== true || (r.state === 'conflicted') !== (r.conflicts.length > 0) ||
        (r.state === 'became_empty' && command.empty !== 'stop') || 'pack_objects' in r || 'generated_objects' in r) fail('Stopped rebase exposed a publishable prefix.');
    exactOid(r.stopped_commit, command.object_format);
    if (sequence.seen.has(r.stopped_commit) || r.stopped_commit === command.upstream || sequence.seen.has(command.expected_source)) fail('Invalid stopped original commit.');
  }
  verifyResolutions(r, recipes, command.object_format);
  check(); return { metadata: r, artifact };
}
export async function addResolutions(report, choices, previous, crypto, check) {
  if (!report || report.state !== 'conflicted') fail('Resolve an explicitly reported conflicted step first.');
  if (!Array.isArray(choices) || choices.length !== report.conflicts.length) fail('Choose a resolution for every reported path.');
  if (previous.some(r => r.original === report.stopped_commit)) fail('This original commit already has a recipe; restart explicitly.');
  const algorithm = report.object_format, selected = new Map();
  if (choices.length + previous.reduce((n, r) => n + r.paths.length, 0) > MAX_CHOICES) fail('Whole-series resolution budget exceeded.');
  let bytes = previous.reduce((n, r) => n + r.paths.reduce((m, p) => m + p.conflict.path_hex.length / 2 + (p.bytes?.length ?? 0), 0), 0);
  const paths = choices.map(value => {
    keys(value, ['path_hex', 'choice', 'mode', 'bytes']); sourcePath(value.path_hex);
    if (selected.has(value.path_hex)) fail('Duplicate resolution path.'); selected.set(value.path_hex, true);
    const c = report.conflicts.find(c => c.path_hex === value.path_hex);
    if (!c || !['base', 'ours', 'theirs', 'delete', 'file'].includes(value.choice)) fail('Resolution escaped the reported conflict.');
    bytes += c.path_hex.length / 2 + (value.choice === 'file' && value.bytes instanceof Uint8Array ? value.bytes.length : 0);
    if (bytes > RESOLUTION_BYTES) fail('Whole-series resolution budget exceeded.');
    const result = { conflict: copy(c), choice: value.choice };
    if (value.choice === 'file') {
      if (![0o100644, 0o100755].includes(value.mode) || !(value.bytes instanceof Uint8Array) || value.bytes.length > FILE_BYTES) fail('Choose bounded regular-file resolution bytes and mode.');
      result.mode = value.mode; result.bytes = value.bytes.slice();
    } else {
      if (value.mode !== undefined || value.bytes !== undefined) fail('A side choice cannot carry replacement content.');
      if (value.choice !== 'delete' && c[value.choice] === null) fail('The selected side is absent; choose deletion explicitly.');
    }
    return result;
  }).sort((a, b) => a.conflict.path_hex.localeCompare(b.conflict.path_hex));
  const all = [...copy(previous), { original: report.stopped_commit, paths }];
  if (bytes > RESOLUTION_BYTES || all.reduce((n, r) => n + r.paths.length, 0) > MAX_CHOICES) fail('Whole-series resolution budget exceeded.');
  for (const p of paths) {
    check(); p.result = p.choice === 'delete' ? null : p.choice === 'file'
      ? { mode: p.mode, oid: await objectHash('blob', p.bytes, algorithm, crypto) } : copy(p.conflict[p.choice]);
  }
  check(); return all;
}
function verifyResolutions(reply, recipes, algorithm) {
  if (!recipes.length) {
    if (['resolution_profile', 'resolutions', 'resolution_input_commits', 'resolution_consumed_commits'].some(k => k in reply)) fail('Unrequested resolution receipt.');
    return;
  }
  const positions = new Map(reply.steps.map((s, i) => [s.original, i]));
  if (reply.state === 'became_empty') positions.set(reply.stopped_commit, reply.steps.length);
  const expected = recipes.filter(r => positions.has(r.original)).sort((a, b) => positions.get(a.original) - positions.get(b.original));
  if (reply.resolution_profile !== 'original-commit-path-v1' || reply.resolution_input_commits !== recipes.length ||
      reply.resolution_consumed_commits !== expected.length || !Array.isArray(reply.resolutions) ||
      reply.resolutions.length !== expected.length || (reply.state === 'clean' && expected.length !== recipes.length)) fail('Incomplete whole-series resolution receipts.');
  for (let i = 0; i < expected.length; i++) {
    const wanted = expected[i], actual = record(reply.resolutions[i]);
    if (actual.original !== wanted.original || !Array.isArray(actual.paths) || actual.paths.length !== wanted.paths.length) fail('Resolution commit or path set changed.');
    for (let j = 0; j < wanted.paths.length; j++) {
      const p = wanted.paths[j], r = record(actual.paths[j]), c = conflict(r.conflict, algorithm);
      if (JSON.stringify(c) !== JSON.stringify(p.conflict) || r.choice !== p.choice ||
          JSON.stringify(identity(r.result, algorithm)) !== JSON.stringify(p.result)) fail('Resolution changed the requested side or exact file identity.');
    }
  }
}
export function resolutionUpload(command, recipes, nonce) {
  if (!/^[0-9a-f]{32}$/.test(nonce)) fail('Invalid resolution nonce.');
  const files = [], descriptors = [];
  for (const r of recipes) for (const p of r.paths) {
    let descriptor = `${r.original}:${p.conflict.path_hex}:${p.choice}`;
    if (p.choice === 'file') { descriptor += `:${p.mode.toString(8)}:file_${files.length}`; files.push(p.bytes); }
    descriptors.push(descriptor);
  }
  if (!descriptors.length || descriptors.length > MAX_CHOICES) fail('Invalid complete resolution set.');
  const commandBody = form({ ...command, resolution: descriptors });
  if (!files.length) return { body: commandBody, contentType: 'application/x-www-form-urlencoded' };
  const boundary = `fg-rebase-resolve-${nonce}`, marker = utf8.encode(`--${boundary}`);
  if (findBytes(utf8.encode(commandBody), marker) >= 0 || files.some(bytes => findBytes(bytes, marker) >= 0)) fail('Resolution boundary collision.');
  const parts = [utf8.encode(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${commandBody}\r\n`)];
  files.forEach((bytes, i) => parts.push(utf8.encode(`--${boundary}\r\nContent-Disposition: form-data; name="file_${i}"\r\nContent-Type: application/octet-stream\r\n\r\n`), bytes, utf8.encode('\r\n')));
  parts.push(utf8.encode(`--${boundary}--\r\n`));
  if (parts.reduce((n, p) => n + p.length, 0) > RESOLUTION_BYTES + 256 * 1024) fail('Resolution upload exceeds its complete byte limit.');
  return { body: joinBytes(...parts), contentType: `multipart/form-data; boundary=${boundary}` };
}
export function applyFields(value) {
  keys(value, ['profile', 'object_format', 'ref', 'expected_source', 'onto', 'candidate_commit']);
  if (value.profile !== 'linear-v1') fail('Unsupported rebase publication profile.');
  const result = { object_format: format(value.object_format), profile: 'linear-v1', ref: branch(value.ref) };
  for (const k of ['expected_source', 'onto', 'candidate_commit']) result[k] = exactOid(value[k], result.object_format);
  return result;
}
export function publication(reply, pending, status) {
  binding(reply, pending.scope); principal(reply.principal_id); opaque(reply.tx_id); opaque(reply.decision_record);
  integer(reply.decision_sequence, 'decision sequence', 1);
  const f = pending.fields;
  if (reply.type !== 'rebase_publication' || reply.ref !== f.ref || reply.ref_hex !== hex(utf8.encode(f.ref)) ||
      ['expected_source', 'onto', 'candidate_commit'].some(k => reply[k] !== f[k]) ||
      !['committed', 'refused'].includes(reply.outcome) || status !== (reply.outcome === 'committed' ? 200 : 409) ||
      reply.delivery_acknowledged !== null) fail('HTTP response is not this original rebase decision.');
  if (reply.outcome === 'committed') { if (reply.refusal_code !== null) fail('Conflicting rebase decisions.'); }
  else opaque(reply.refusal_code);
  if (pending.observedTx && pending.observedTx !== reply.tx_id) fail('Original rebase transaction changed.');
  if (pending.observedPrincipal && pending.observedPrincipal !== reply.principal_id) fail('Original rebase principal changed.');
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    rcr: reply.outcome === 'committed' ? reply.decision_record : null, refusal: reply.refusal_code, deliveryAcknowledged: null };
}
export async function retryKey(root, fingerprint, scope, nonce, fields, upload, crypto) {
  const value = JSON.stringify(['frankengit-rebase-apply-v1', root.origin, root.route, fingerprint,
    scope.tenant, scope.repository, scope.incarnation, scope.format, fields.ref, fields.expected_source,
    fields.onto, fields.candidate_commit, nonce, upload.contentType, await digest(upload.bytes, crypto)]);
  return `fgrb1-${nonce}-${await digest(utf8.encode(value), crypto)}`;
}
