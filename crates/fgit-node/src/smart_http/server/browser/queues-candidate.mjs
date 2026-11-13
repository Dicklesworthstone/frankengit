// Exact queue preparation, native full inspection and retained landing bytes.
// Queue selection is a guard; only the native coupled decision grants landing.
import { FORM_LIMIT, copy, fail, form, integer, keys, oid, pinned, record, text, unhex, utf8 } from './pulls-core.mjs';
import { checkedBundle, checkedPath, digest, inspectionReply, mergeProfile, multipart, preparationEnvelope } from './pulls-candidate.mjs';
import { COMMAND_LIMIT, normalizeQueueFields, queueCommand, queueInteger, queueReference, queueScope } from './queues-protocol.mjs';

function closed(value, names) {
  keys(value, names);
  if (names.some(name => !Object.hasOwn(value, name))) fail('Missing queue candidate field.');
}
function noEffects(reply) {
  if (reply.read_only !== true || reply.objects_staged !== false || reply.transaction_created !== false ||
      reply.published !== false || reply.merge_authorized !== false) fail('Queue preparation or inspection unexpectedly claims publication or authority.');
}
function subject(fields, algorithm) {
  return { object_format: algorithm, pull_request_version: fields.expected_pull_request_version, policy_epoch: fields.expected_policy_epoch,
    source_ref_hex: fields.source_ref_hex, target_ref_hex: fields.target_ref_hex,
    source_tip: fields.expected_source_tip, target_tip: fields.expected_target_tip };
}
export function queueCandidateSubject(raw, expected, number, algorithm) {
  closed(raw, ['pull_request', 'pull_request_version', 'policy_epoch', 'source_ref', 'source_ref_hex', 'target_ref', 'target_ref_hex', 'source_tip', 'target_tip']);
  if (raw.pull_request !== number || raw.pull_request_version !== expected.pull_request_version || raw.policy_epoch !== expected.policy_epoch ||
      queueReference(raw, 'source_ref') !== expected.source_ref_hex || queueReference(raw, 'target_ref') !== expected.target_ref_hex ||
      oid(raw.source_tip, algorithm) !== expected.source_tip || oid(raw.target_tip, algorithm) !== expected.target_tip) fail('Queue candidate subject changed; no implicit version, reference, policy or tip refresh.');
}
export function queuePreparationRequest(number, fields, metadata, scope) {
  queueInteger(number, 'queue number', 1); queueScope(scope);
  const normalized = normalizeQueueFields('land', fields, scope.format);
  keys(metadata, ['author', 'committer', 'timestamp', 'message', 'message_hex', 'profile']);
  const command = queueCommand('land', normalized, scope);
  for (const name of ['author', 'committer']) {
    command[name] = text(metadata[name], 1024, name, true);
    if (!/^[^<>\r\n]+ <[^<>\r\n]+>$/.test(command[name])) fail('Commit identities must use Name <email> syntax.');
  }
  command.timestamp = queueInteger(metadata.timestamp, 'commit timestamp', 1);
  if (Object.hasOwn(metadata, 'message') === Object.hasOwn(metadata, 'message_hex')) fail('Supply exactly one commit message encoding.');
  if (Object.hasOwn(metadata, 'message_hex')) {
    const bytes = unhex(metadata.message_hex, 64 * 1024);
    if (!bytes.length || bytes.includes(0)) fail('Commit message must be nonempty and contain no NUL bytes.');
    command.message_hex = metadata.message_hex;
  } else {
    command.message = text(metadata.message, 64 * 1024, 'commit message');
    if (!command.message.length) fail('An explicit nonempty commit message is required.');
  }
  command.profile = mergeProfile(metadata.profile ?? 'path-merge-v1');
  const body = form(command);
  if (utf8.encode(body).length > FORM_LIMIT) fail('Queue preparation form exceeds 256 KiB.');
  return { number, fields: normalized, profile: command.profile, command, body, path: `queues/${number}/prepare` };
}
// Validate the server's complete command, then preserve it byte for byte. A
// different form order is harmless; duplicates, additions and rewrites are not.
export function queueLandingForm(commandForm, fields, scope) {
  text(commandForm, COMMAND_LIMIT, 'queue candidate landing form', true);
  const expected = queueCommand('land-candidate', fields, scope), seen = new Set();
  for (const [name, value] of new URLSearchParams(commandForm)) {
    if (seen.has(name) || !Object.hasOwn(expected, name) || String(expected[name]) !== value) fail('Queue landing form changed its exact native guards or candidate.');
    seen.add(name);
  }
  if (seen.size !== Object.keys(expected).length) fail('Incomplete queue candidate landing form.');
  return commandForm;
}
export async function queuePreparationReply(response, request, scope, crypto) {
  const { metadata, bundle } = preparationEnvelope(response), selected = pinned(metadata, scope);
  noEffects(metadata); queueScope(selected.binding);
  closed(metadata, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
    'source_head', 'snapshot_token', 'profile', 'method', 'read_only', 'objects_staged', 'transaction_created', 'published', 'merge_authorized',
    'subject', 'queue', 'landing', 'state', 'candidate', 'bundle', 'conflicts', ...(metadata.state === 'conflicted' ? ['merge_base'] : [])]);
  closed(metadata.queue, ['number', 'expected_version']);
  if (metadata.type !== 'queue_merge_preparation' || metadata.profile !== request.profile || metadata.method !== 'merge-commit' ||
      metadata.queue.number !== request.number || metadata.queue.expected_version !== request.fields.expected_version ||
      !Array.isArray(metadata.conflicts)) fail('Preparation does not bind the selected queue head and native profile.');
  const expected = subject(request.fields, scope.format);
  queueCandidateSubject(metadata.subject, expected, request.fields.pull_request, scope.format);
  if (metadata.state === 'clean') {
    if (!bundle || response.status !== 200 || metadata.conflicts.length) fail('Clean queue preparation lacks its exact complete bundle.');
    closed(metadata.candidate, ['merge_base', 'commit', 'tree', 'new_object_count']); closed(metadata.bundle, ['bytes', 'sha256']);
    const fields = normalizeQueueFields('land-candidate', { ...request.fields, merge_base: metadata.candidate.merge_base, expected_commit: metadata.candidate.commit }, scope.format);
    oid(metadata.candidate.tree, scope.format); queueInteger(metadata.candidate.new_object_count, 'candidate object count', 1);
    if (metadata.bundle.bytes !== bundle.length || metadata.bundle.sha256 !== await digest(bundle, crypto)) fail('Queue candidate bundle commitment mismatch.');
    closed(metadata.landing, ['api_path', 'command_form']);
    if (metadata.landing.api_path !== `/api/v1/queues/${request.number}/land-candidate`) fail('Queue landing route changed.');
    const commandForm = queueLandingForm(metadata.landing.command_form, fields, scope);
    return { ...selected, metadata, artifact: { queue: request.number, number: fields.pull_request, scope: selected.binding,
      method: 'merge-commit', queueFields: fields, commandForm, fields: { ...expected, merge_base: fields.merge_base, candidate_commit: fields.expected_commit },
      bundle: bundle.slice(), sha256: metadata.bundle.sha256 } };
  }
  if (bundle || metadata.candidate !== null || metadata.bundle !== null || metadata.landing !== null) fail('Stopped queue preparation contains landing material.');
  if (metadata.state === 'already_up_to_date') {
    if (response.status !== 200 || metadata.conflicts.length) fail('Invalid up-to-date queue result.');
  } else if (metadata.state === 'conflicted') {
    if (response.status !== 409 || !metadata.conflicts.length || metadata.conflicts.length > 128) fail('Invalid bounded queue conflict result.');
    oid(metadata.merge_base, scope.format); let previous = '';
    for (const conflict of metadata.conflicts) {
      closed(conflict, ['path_hex', 'kind', 'base', 'ours', 'theirs']); checkedPath(conflict.path_hex);
      if (conflict.path_hex <= previous || !['content', 'binary', 'modify_delete', 'type_change', 'mode', 'opaque', 'attributes_require_driver'].includes(conflict.kind)) fail('Invalid queue conflict paths or type.');
      previous = conflict.path_hex;
      for (const side of ['base', 'ours', 'theirs']) if (conflict[side] !== null) {
        closed(conflict[side], ['mode', 'oid']); integer(conflict[side].mode, 'conflict mode', 1, 0xffffffff); oid(conflict[side].oid, scope.format);
      }
    }
  } else fail('Unsupported queue preparation state.');
  return { ...selected, metadata, artifact: null };
}
export function queueInspectionRequest(artifact, boundary) {
  // Raw ref alternatives are preserved across preparation, inspection and land.
  const command = form(artifact.fields), upload = multipart(command, artifact.bundle, boundary);
  return { ...upload, path: `pulls/${artifact.number}/inspect` };
}
export async function queueInspectionReply(reply, artifact, crypto) {
  return inspectionReply(reply, artifact, crypto, queueCandidateSubject);
}
export function queueCandidateRequest(number, fields, scope, commandForm, bundle, nonce) {
  queueInteger(number, 'queue number', 1); queueScope(scope); checkedBundle(bundle);
  if (typeof nonce !== 'string' || !/^[0-9a-f]{32}$/.test(nonce)) fail('Invalid queue candidate recovery nonce.');
  const normalized = normalizeQueueFields('land-candidate', fields, scope.format);
  queueLandingForm(commandForm, normalized, scope);
  const upload = multipart(commandForm, bundle, `fg-queue-${nonce}`);
  return { ...upload, number, action: 'land-candidate', path: `queues/${number}/land-candidate`, fields: normalized, body: commandForm };
}
export function queueCandidateSummary(artifact, metadata, inspection) {
  return { number: artifact.queue, pull_request: artifact.number, fields: copy(artifact.queueFields), scope: copy(artifact.scope),
    sha256: artifact.sha256, bundle_bytes: artifact.bundle.length, metadata: copy(metadata), inspection: copy(inspection) };
}
