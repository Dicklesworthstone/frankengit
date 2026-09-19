// One-commit replay is preparation, not authorization or a history rewrite.
// The existing source publisher admits the resulting single-parent candidate.
import { fail, keys, record, copy, integer, oid, format, branch, pinned, reference, utf8, hex, unhex, form, json } from './pulls-core.mjs';
import { digest, joinBytes, findBytes, comparisonEntries } from './pulls-candidate.mjs';
import { commitMetadata, noEffects, sourceEnvelope, objectHash, matchReference, PREPARE_LIMIT, METADATA_LIMIT } from './source-edit-protocol.mjs';
import { sourcePath, fileMode, FILE_LIMIT } from './source-edit-patch.mjs';
export { PREPARE_LIMIT, FILE_LIMIT };
export const CONFLICT_LIMIT = 64, RESOLUTION_LIMIT = 1024 * 1024;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export function replayCommand(direction, selected, input) {
  if (!['cherry-pick', 'revert'].includes(direction)) fail('Choose cherry-pick or revert.');
  keys(input, ['commit', 'mainline', 'author', 'committer', 'timestamp', 'message']);
  const algorithm = format(selected.object_format);
  const command = { profile: 'path-v1', object_format: algorithm,
    target_ref: branch(selected.target_ref), source_ref: branch(selected.source_ref),
    expected_target: oid(selected.expected_target, algorithm), expected_source: oid(selected.expected_source, algorithm),
    commit: oid(input.commit, algorithm), expected_head: selected.expected_head,
    ...commitMetadata({ author: input.author, committer: input.committer, timestamp: input.timestamp, message: input.message }),
    max_conflicts: CONFLICT_LIMIT, max_output_bytes: 8 * 1024 * 1024, max_text_bytes: FILE_LIMIT };
  if (input.mainline !== undefined && input.mainline !== null) command.mainline = integer(input.mainline, 'mainline parent', 1, 65535);
  form(command); return command;
}
function side(value, algorithm) {
  if (value === null) return null;
  record(value);
  if (![0o40000, 0o100644, 0o100755, 0o120000, 0o160000].includes(value.mode)) fail('Invalid conflict mode.');
  return { mode: value.mode, oid: oid(value.oid, algorithm) };
}
function conflict(value, algorithm) {
  record(value); sourcePath(value.path_hex);
  if (!['content', 'binary', 'modify_delete', 'type_change', 'mode', 'opaque', 'attributes_require_driver'].includes(value.kind)) fail('Unsupported conflict kind.');
  const result = { path_hex: value.path_hex, kind: value.kind,
    base: side(value.base, algorithm), ours: side(value.ours, algorithm), theirs: side(value.theirs, algorithm) };
  if (!result.base && !result.ours && !result.theirs) fail('Conflict has no source entries.');
  return result;
}
// Own every choice before hashing. An absent side is not an implicit deletion.
export async function resolutionChoices(metadata, input, algorithm, crypto, checkpoint = () => {}) {
  if (!Array.isArray(input) || input.length !== metadata.conflicts.length || !input.length || input.length > CONFLICT_LIMIT) fail('Choose one resolution for every conflict.');
  const conflicts = new Map(metadata.conflicts.map(c => [c.path_hex, c])), paths = new Set(); let total = 0;
  const choices = input.map(value => {
    keys(value, ['path_hex', 'choice', 'mode', 'bytes']);
    if (!conflicts.has(value.path_hex) || paths.has(value.path_hex)) fail('Missing, duplicate or non-conflict resolution path.');
    paths.add(value.path_hex);
    const chosen = { path_hex: value.path_hex, choice: value.choice, conflict: copy(conflicts.get(value.path_hex)) };
    if (value.choice === 'file') {
      fileMode(value.mode);
      if (!(value.bytes instanceof Uint8Array) || value.bytes.length > FILE_LIMIT) fail('Resolution file exceeds 256 KiB.');
      total += value.bytes.length;
      if (total > RESOLUTION_LIMIT) fail('Resolution files exceed the aggregate 1 MiB limit.');
      chosen.mode = value.mode; chosen.bytes = value.bytes.slice();
    } else {
      if ('mode' in value || 'bytes' in value) fail('Only a custom file carries bytes or mode.');
      if (!['base', 'ours', 'theirs', 'delete'].includes(value.choice)) fail('Select an explicit conflict resolution.');
      if (value.choice !== 'delete' && !chosen.conflict[value.choice]) fail('Selected side is absent; choose deletion explicitly.');
    }
    return chosen;
  }).sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
  for (const choice of choices) {
    checkpoint();
    choice.result = choice.choice === 'file' ? { mode: choice.mode, oid: await objectHash('blob', choice.bytes, algorithm, crypto) }
      : choice.choice === 'delete' ? null : choice.conflict[choice.choice];
    checkpoint();
  }
  return choices;
}
export function resolutionUpload(command, choices, nonce) {
  if (!/^[0-9a-f]{32}$/.test(nonce)) fail('Invalid resolution boundary nonce.');
  const files = [], descriptors = choices.map(c => {
    if (c.choice !== 'file') return `${c.path_hex}:${c.choice}`;
    const name = `file_${files.length}`; files.push({ name, bytes: c.bytes });
    return `${c.path_hex}:file:${c.mode.toString(8)}:${name}`;
  });
  const encoded = form({ ...command, resolution: descriptors });
  if (!files.length) return { body: encoded, contentType: 'application/x-www-form-urlencoded' };
  const boundary = `fg-replay-${nonce}`, marker = utf8.encode(`--${boundary}`);
  if (encoded.includes(`--${boundary}`) || files.some(f => findBytes(f.bytes, marker) !== -1)) fail('Resolution boundary collision.');
  const parts = [utf8.encode(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${encoded}\r\n`)];
  for (const file of files) parts.push(utf8.encode(`--${boundary}\r\nContent-Disposition: form-data; name="${file.name}"\r\nContent-Type: application/octet-stream\r\n\r\n`), file.bytes, utf8.encode('\r\n'));
  parts.push(utf8.encode(`--${boundary}--\r\n`));
  return { body: joinBytes(...parts), contentType: `multipart/form-data; boundary=${boundary}` };
}
export async function replayPrepared(response, direction, command, scope, crypto, previous = null, choices = null) {
  let metadata, bundle = null;
  if (/^application\/json(?:\s*;|$)/i.test(response.type)) {
    if (!(response.value instanceof Uint8Array) || response.value.length > METADATA_LIMIT) fail('Invalid replay metadata envelope.');
    metadata = json(response.value);
  } else ({ metadata, bundle } = sourceEnvelope(response));
  pinned(metadata, scope, command.expected_head); noEffects(metadata);
  reference(metadata, 'target_ref'); reference(metadata, 'source_ref');
  if (metadata.type !== 'replay_preparation' || metadata.profile !== 'path-v1' || metadata.direction !== direction ||
      metadata.target_ref !== command.target_ref || metadata.source_ref !== command.source_ref ||
      metadata.expected_target !== command.expected_target || metadata.expected_source !== command.expected_source ||
      metadata.selected_commit !== command.commit || metadata.author_identity_verified !== false) fail('Replay coordinates changed.');
  const algorithm = scope.format;
  if (metadata.selected_parent === null) { if (metadata.selected_mainline !== null || command.mainline !== undefined) fail('Root replay cannot have a mainline parent.'); }
  else {
    oid(metadata.selected_parent, algorithm); integer(metadata.selected_mainline, 'selected mainline', 1, 65535);
    if (metadata.selected_mainline !== (command.mainline ?? 1)) fail('Mainline changed or was selected implicitly.');
  }
  if (previous && (metadata.selected_parent !== previous.selected_parent || metadata.selected_mainline !== previous.selected_mainline)) fail('Resolved replay changed its original parent.');
  if (!Array.isArray(metadata.conflicts) || metadata.conflicts.length > CONFLICT_LIMIT) fail('Invalid replay conflicts.');
  let last = '';
  metadata.conflicts = metadata.conflicts.map(c => {
    const normalized = conflict(c, algorithm);
    if (normalized.path_hex <= last) fail('Unordered or duplicate replay conflicts.'); last = normalized.path_hex;
    return normalized;
  });
  if (choices !== null) {
    if (metadata.resolution_profile !== 'exact-path-resolutions-v1' || !Array.isArray(metadata.resolutions) || metadata.resolutions.length !== choices.length) fail('Incomplete resolution receipts.');
    for (let i = 0; i < choices.length; i++) {
      const actual = metadata.resolutions[i], expected = choices[i]; record(actual);
      if (!same(conflict(actual.conflict, algorithm), expected.conflict) || actual.choice !== expected.choice ||
          !same(side(actual.result, algorithm), expected.result)) fail('Native resolution changed a chosen path, side or file identity.');
    }
  } else if ('resolutions' in metadata || 'resolution_profile' in metadata) fail('Unrequested conflict resolution.');
  if (metadata.state === 'conflicted') {
    if (choices !== null || response.status !== 409 || !metadata.conflicts.length || bundle || metadata.bundle !== null || metadata.candidate_commit !== null || metadata.root_tree !== null) fail('Invalid conflicted replay.');
  } else if (metadata.state === 'no_change') {
    if (response.status !== 200 || metadata.conflicts.length || bundle || metadata.bundle !== null || metadata.candidate_commit !== null || metadata.root_tree !== null) fail('Invalid no-change replay.');
  } else if (metadata.state === (choices === null ? 'clean' : 'resolved')) {
    if (response.status !== 200 || !bundle || metadata.conflicts.length || !same(metadata.parents, [command.expected_target])) fail('Replay candidate lacks its single target parent.');
    const candidate = oid(metadata.candidate_commit, algorithm), tree = oid(metadata.root_tree, algorithm);
    if (candidate === command.expected_target) fail('Candidate equals original target.');
    integer(metadata.generated_objects, 'generated objects', 1, 10000);
    integer(metadata.pack_objects, 'pack objects', 1, 10000);
    integer(metadata.borrowed_objects, 'borrowed objects', 0, metadata.pack_objects);
    record(metadata.bundle); const sha256 = await digest(bundle, crypto);
    if (metadata.bundle.bytes !== bundle.length || metadata.bundle.sha256 !== sha256) fail('Replay bundle commitment changed.');
    return { metadata, artifact: { fields: { ref: command.target_ref, object_format: algorithm, expected_commit: command.expected_target, candidate_commit: candidate },
      scope: copy(scope), bundle, sha256, tree, command: copy(command), direction, metadata,
      choices: choices && choices.map(c => ({ path_hex: c.path_hex, before: c.conflict.ours, after: c.result })) } };
  } else fail('Unsupported or substituted replay state.');
  return { metadata, artifact: null };
}
export async function replayInspected(value, artifact, targetTree, crypto) {
  const reply = copy(value), { fields, scope, command } = artifact, algorithm = scope.format;
  pinned(reply, scope, command.expected_head); noEffects(reply); matchReference(reply, fields.ref);
  if (reply.type !== 'source_inspection' || reply.all_changed_paths !== true || reply.binary_bodies_included !== false ||
      reply.expected_commit !== fields.expected_commit || reply.candidate_commit !== fields.candidate_commit ||
      reply.bundle_bytes !== artifact.bundle.length || reply.bundle_sha256 !== artifact.sha256 || !same(reply.parents, [fields.expected_commit])) fail('Replay inspection changed its candidate, bundle or parent.');
  const body = unhex(reply.candidate_commit_body_hex, 2 * 1024 * 1024);
  const expected = utf8.encode(`tree ${artifact.tree}\nparent ${fields.expected_commit}\nauthor ${command.author} ${command.timestamp} +0000\ncommitter ${command.committer} ${command.timestamp} +0000\n\n${command.message}`);
  if (hex(body) !== hex(expected) || await objectHash('commit', body, algorithm, crypto) !== fields.candidate_commit) fail('Replay commit bytes changed explicit metadata, tree or parent.');
  const comparison = record(reply.comparison);
  if (comparison.mode !== 'direct' || comparison.before_tree !== targetTree || comparison.after_tree !== artifact.tree) fail('Replay inspection selected another tree.');
  comparisonEntries(comparison, algorithm);
  if (!comparison.entries.length) fail('A clean replay must have a tree effect.');
  const entries = new Map(comparison.entries.map(e => [e.path_hex, e]));
  for (const chosen of artifact.choices ?? []) {
    // Tree-side choices may expand into descendant entries. Native inspection
    // owns that reconstruction; regular-file and deletion results match here.
    if (chosen.before?.mode === 0o40000 || chosen.after?.mode === 0o40000) continue;
    const entry = entries.get(chosen.path_hex);
    if (entry ? !same(side(entry.after, algorithm), chosen.after) : !same(chosen.before, chosen.after)) fail('Inspected result does not contain the chosen resolution.');
  }
  return reply;
}
