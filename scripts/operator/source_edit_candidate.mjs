// External source-authoring client. Native Rust owns patch application, bundle
// validation and repository authority; this module never runs a Git engine.
import { createHash } from 'node:crypto';
import { SourceEditError, hash, fail, fields, integer, endpoint, parse, clock, upload, exchange } from './source_edit_wire.mjs';
export { SourceEditError, hash, parse } from './source_edit_wire.mjs';
export const EDIT_CAPTURE = 'frankengit-source-edit-capture-v1';
// An independently selected result root is retained as intent, never inferred
// from a preparation reply. A new capture profile prevents older readers from
// silently dropping that constraint; ordinary v1 captures keep their bytes.
export const EDIT_RESULT_CAPTURE = 'frankengit-source-edit-capture-v2';
const captureProfile = request => Object.hasOwn(request, 'expected_result_tree') ? EDIT_RESULT_CAPTURE : EDIT_CAPTURE;
export const BUNDLE_LIMIT = 8 * 1024 * 1024, CAPTURE_LIMIT = 10 * 1024 * 1024;
const PREPARE_LIMIT = BUNDLE_LIMIT + 1024 * 1024 + 16384;
export const canonical = value => Buffer.from(`${JSON.stringify(value)}\n`);
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export function identity(value) { if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('source_edit_identity'); return value; }
export function oid(value, format) {
  if (!['sha1', 'sha256'].includes(format) || typeof value !== 'string') fail('source_edit_oid');
  const raw = value.startsWith(`${format}:`) ? value.slice(format.length + 1) : value;
  if (!new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) fail('source_edit_oid');
  return raw;
}
function text(value, max, single = false) {
  if (typeof value !== 'string' || value.length > max || Buffer.byteLength(value) > max || /[\uD800-\uDFFF\0]/u.test(value) ||
      single && /[\x00-\x1f\x7f]/.test(value)) fail('source_edit_text');
  return value;
}
function opaque(value) { text(value, 256, true); if (!value.length || /\s/u.test(value)) fail('source_edit_opaque'); }
function path(value) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(value)) fail('source_edit_path');
  const bytes = Buffer.from(value, 'hex');
  if (bytes.includes(0) || bytes.toString('latin1').split('/').some(p => !p || p === '.' || p === '..')) fail('source_edit_path');
  return value;
}
export function editInput(value) {
  const required = ['endpoint', 'scope', 'ref', 'expected_commit', 'metadata', 'paths_hex'];
  fields(value, [...required, 'expected_result_tree'], required);
  fields(value.scope, ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format']);
  const scope = { tenant_id: identity(value.scope.tenant_id), repository_id: identity(value.scope.repository_id),
    repository_incarnation: identity(value.scope.repository_incarnation), object_format: value.scope.object_format };
  const ref = text(value.ref, 1024, true);
  if (!ref.startsWith('refs/heads/') || /[\s~^:?*\[\\]/u.test(ref) || ref.includes('..') || ref.includes('@{') || ref.endsWith('.') ||
      ref.split('/').some(p => !p || p.startsWith('.') || p.endsWith('.lock'))) fail('source_edit_branch');
  fields(value.metadata, ['author', 'committer', 'timestamp', 'message']);
  const metadata = {};
  for (const key of ['author', 'committer']) {
    metadata[key] = text(value.metadata[key], 1024, true);
    const match = /^([^<>]+) <([^<>]+)>$/.exec(metadata[key]); if (!match || !match[1].trim()) fail('source_edit_author');
  }
  metadata.timestamp = integer(value.metadata.timestamp, 1, Number.MAX_SAFE_INTEGER);
  metadata.message = text(value.metadata.message, 65536); if (!metadata.message.length) fail('source_edit_message');
  if (!Array.isArray(value.paths_hex) || !value.paths_hex.length || value.paths_hex.length > 64) fail('source_edit_paths');
  const paths = value.paths_hex.map(path).sort();
  if (new Set(paths).size !== paths.length || paths.some(p => paths.some(q => q !== p && p.startsWith(`${q}2f`)))) fail('source_edit_paths');
  // Copy and validate the optional primitive before any asynchronous I/O. Null,
  // undefined, the wrong hash domain and zero are refusals, not an opt-out.
  const result = Object.hasOwn(value, 'expected_result_tree')
    ? { expected_result_tree: oid(value.expected_result_tree, scope.object_format) } : {};
  return { endpoint: endpoint(value.endpoint), scope, ref, expected_commit: oid(value.expected_commit, scope.object_format), metadata, paths_hex: paths, ...result };
}
// The result constraint belongs to local intent/custody, not a new native form
// field. Preserve the existing server's closed grammar and publication rules.
export function editCoordinates(request, candidate) {
  return { object_format: request.scope.object_format, ref: request.ref, expected_commit: request.expected_commit,
    ...(candidate === undefined ? {} : { candidate_commit: candidate }) };
}
function selected(reply, request, type) {
  if (!reply || reply.type !== type || reply.schema_version !== 1 || Object.entries(request.scope).some(([k, v]) => reply[k] !== v) ||
      reply.ref !== request.ref || reply.ref_hex !== Buffer.from(request.ref).toString('hex')) fail('source_edit_scope');
  if (reply.read_only !== true || reply.objects_staged !== false || reply.transaction_created !== false ||
      reply.published !== false || reply.publication_authorized !== false) fail('source_edit_effect_claim');
}
export function decodePreparation(response) {
  const match = /^multipart\/mixed; boundary=(fg-source-[0-9a-f]{48}-[0-9a-f])$/.exec(response.type);
  if (!match || response.status !== 200 || response.bytes.length > PREPARE_LIMIT) fail('source_edit_preparation_mime');
  const b = match[1], bytes = response.bytes;
  const opening = Buffer.from(`--${b}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n`);
  const middle = Buffer.from(`\r\n--${b}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`);
  const close = Buffer.from(`\r\n--${b}--\r\n`), split = bytes.indexOf(middle, opening.length);
  if (!bytes.subarray(0, opening.length).equals(opening) || split < 0 || split - opening.length > 1048576 ||
      !bytes.subarray(-close.length).equals(close)) fail('source_edit_preparation_mime');
  const bundle = Buffer.from(bytes.subarray(split + middle.length, bytes.length - close.length));
  if (bundle.includes(Buffer.from(`--${b}`))) fail('source_edit_preparation_mime');
  return { preparation: parse(bytes.subarray(opening.length, split), 1048576), bundle };
}
function prepared(reply, bundle, request, patchHash) {
  fields(reply, ['type', 'schema_version', ...Object.keys(request.scope), 'ref', 'ref_hex', 'source_commit', 'source_rcr',
    'candidate_commit', 'root_tree', 'patch_sha256', 'object_count', 'read_only', 'objects_staged', 'transaction_created',
    'published', 'publication_authorized', 'bundle', 'paths']);
  selected(reply, request, 'source_preparation');
  const format = request.scope.object_format;
  if (oid(reply.source_commit, format) !== request.expected_commit || reply.patch_sha256 !== patchHash) fail('source_edit_patch_binding');
  opaque(reply.source_rcr); integer(reply.object_count, 1, 10000);
  const candidate = oid(reply.candidate_commit, format), tree = oid(reply.root_tree, format);
  // A well-formed, genuine Git candidate can still be the wrong requested
  // result. Refuse it before inspection/upload; offline replay checks this same
  // predicate before any candidate is eligible for staging or dispatch.
  if (Object.hasOwn(request, 'expected_result_tree') && tree !== request.expected_result_tree) fail('source_edit_result_tree_mismatch');
  if (candidate === request.expected_commit || !Buffer.isBuffer(bundle) || !bundle.length || bundle.length > BUNDLE_LIMIT) fail('source_edit_candidate');
  fields(reply.bundle, ['bytes', 'sha256']);
  if (reply.bundle.bytes !== bundle.length || reply.bundle.sha256 !== hash(bundle)) fail('source_edit_bundle_hash');
  const magic = Buffer.from(format === 'sha1' ? '# v2 git bundle\n' : '# v3 git bundle\n');
  if (!bundle.subarray(0, magic.length).equals(magic)) fail('source_edit_bundle_format');
  if (!Array.isArray(reply.paths) || reply.paths.length !== request.paths_hex.length) fail('source_edit_changed_paths');
  const paths = new Map();
  for (const row of reply.paths) {
    fields(row, ['path_hex', 'old_blob', 'new_blob', 'new_mode', 'hunks']); path(row.path_hex); integer(row.hunks, 0, 4096);
    if (paths.has(row.path_hex) || !request.paths_hex.includes(row.path_hex)) fail('source_edit_changed_paths');
    const old = row.old_blob === null ? null : oid(row.old_blob, format), next = row.new_blob === null ? null : oid(row.new_blob, format);
    if (old === null && next === null || (next === null ? row.new_mode !== null : ![0o100644, 0o100755].includes(row.new_mode))) fail('source_edit_mode');
    paths.set(row.path_hex, { old, next, mode: row.new_mode });
  }
  return { candidate, tree, paths };
}
function entry(value, format) {
  if (value === null) return null;
  fields(value, ['mode', 'oid']); if (![0o100644, 0o100755].includes(value.mode)) fail('source_edit_mode');
  return { mode: value.mode, oid: oid(value.oid, format) };
}
function span(value, hex, total) {
  fields(value, ['byte_start', 'byte_end', 'line_start', 'line_count']);
  for (const key of ['byte_start', 'byte_end']) integer(value[key], 0, total);
  integer(value.line_start, 0, Number.MAX_SAFE_INTEGER); integer(value.line_count, 0, 1048576);
  if (typeof hex !== 'string' || hex.length > 2 * 1048576 || !/^(?:[0-9a-f]{2})*$/.test(hex) || value.byte_end - value.byte_start !== hex.length / 2) fail('source_edit_span');
  const bytes = Buffer.from(hex, 'hex'), lines = bytes.reduce((n, b) => n + Number(b === 10), 0) + Number(bytes.length > 0 && bytes.at(-1) !== 10);
  if (lines !== value.line_count) fail('source_edit_span');
}
function inspection(reply, request, preparation, bundle, artifact) {
  fields(reply, ['type', 'schema_version', ...Object.keys(request.scope), 'ref', 'ref_hex', 'source_head', 'snapshot_token',
    'expected_commit', 'candidate_commit', 'parents', 'bundle_bytes', 'bundle_sha256', 'read_only', 'objects_staged',
    'transaction_created', 'published', 'publication_authorized', 'all_changed_paths', 'binary_bodies_included', 'candidate_commit_body_hex', 'comparison']);
  selected(reply, request, 'source_inspection'); const format = request.scope.object_format;
  opaque(reply.source_head);
  if (typeof reply.snapshot_token !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(reply.snapshot_token) ||
      Number(reply.snapshot_token.split(':')[1]) > 65535 || oid(reply.expected_commit, format) !== request.expected_commit ||
      oid(reply.candidate_commit, format) !== artifact.candidate || !Array.isArray(reply.parents) || reply.parents.length !== 1 ||
      oid(reply.parents[0], format) !== request.expected_commit || reply.bundle_bytes !== bundle.length || reply.bundle_sha256 !== hash(bundle) ||
      reply.all_changed_paths !== true || reply.binary_bodies_included !== false) fail('source_edit_inspection_binding');
  if (typeof reply.candidate_commit_body_hex !== 'string' || reply.candidate_commit_body_hex.length > 2 * 131072 ||
      !/^(?:[0-9a-f]{2})+$/.test(reply.candidate_commit_body_hex)) fail('source_edit_commit_body');
  const body = Buffer.from(reply.candidate_commit_body_hex, 'hex'), m = request.metadata;
  const expected = Buffer.from(`tree ${artifact.tree}\nparent ${request.expected_commit}\nauthor ${m.author} ${m.timestamp} +0000\ncommitter ${m.committer} ${m.timestamp} +0000\n\n${m.message}`);
  if (!body.equals(expected) || createHash(format).update(`commit ${body.length}\0`).update(body).digest('hex') !== artifact.candidate) fail('source_edit_commit_body');
  const c = fields(reply.comparison, ['mode', 'before_tree', 'after_tree', 'entry_count', 'entries']); oid(c.before_tree, format);
  if (c.mode !== 'direct' || oid(c.after_tree, format) !== artifact.tree || !Array.isArray(c.entries) ||
      c.entries.length !== c.entry_count || c.entries.length !== artifact.paths.size) fail('source_edit_comparison');
  let previous = '';
  for (const row of c.entries) {
    fields(row, ['path_hex', 'kind', 'before', 'after', 'content']); path(row.path_hex);
    const expected = artifact.paths.get(row.path_hex), before = entry(row.before, format), after = entry(row.after, format);
    if (row.path_hex <= previous || !expected || (before?.oid ?? null) !== expected.old || (after?.oid ?? null) !== expected.next ||
        (after?.mode ?? null) !== expected.mode) fail('source_edit_comparison'); previous = row.path_hex;
    const kind = before === null ? 'added' : after === null ? 'deleted' : before.mode !== after.mode ? 'mode_changed' : 'modified';
    if (row.kind !== kind) fail('source_edit_change_kind');
    const content = row.content;
    if (content?.type === 'text') {
      fields(content, ['type', 'algorithm', 'additions', 'deletions', 'before_bytes', 'after_bytes', 'hunks']);
      text(content.algorithm, 128, true);
      for (const key of ['additions', 'deletions', 'before_bytes', 'after_bytes']) integer(content[key], 0, 1048576);
      if (!Array.isArray(content.hunks) || content.hunks.length > 4096) fail('source_edit_hunks');
      let oldEnd = 0, newEnd = 0;
      for (const hunk of content.hunks) {
        fields(hunk, ['old', 'new', 'before_hex', 'after_hex']);
        span(hunk.old, hunk.before_hex, content.before_bytes); span(hunk.new, hunk.after_hex, content.after_bytes);
        if (hunk.old.byte_start < oldEnd || hunk.new.byte_start < newEnd) fail('source_edit_hunk_order');
        oldEnd = hunk.old.byte_end; newEnd = hunk.new.byte_end;
      }
    } else if (content?.type === 'binary') {
      fields(content, ['type', 'before_bytes', 'after_bytes', 'body_included']);
      integer(content.before_bytes, 0, 1048576); integer(content.after_bytes, 0, 1048576);
      if (content.body_included !== false) fail('source_edit_binary');
    } else {
      fields(content, ['type', 'content_read']);
      if (!['identical', 'object_only'].includes(content.type) || content.content_read !== false) fail('source_edit_content');
      if (content.type === 'identical' && (!before || !after || before.oid !== after.oid)) fail('source_edit_identical');
    }
  }
}
export function validateSourceEdit(value, suppliedBundle) {
  fields(value, ['schema', 'request', 'patch_sha256', 'patch_bytes', 'preparation', 'inspection']);
  if (![EDIT_CAPTURE, EDIT_RESULT_CAPTURE].includes(value.schema) || !/^[0-9a-f]{64}$/.test(value.patch_sha256)) fail('source_edit_capture');
  integer(value.patch_bytes, 1, 1048576);
  if (!Buffer.isBuffer(suppliedBundle) || suppliedBundle.length > BUNDLE_LIMIT) fail('source_edit_bundle_limit');
  const request = editInput(value.request), bytes = canonical(value);
  if (value.schema !== captureProfile(request) || bytes.length > CAPTURE_LIMIT || !equal(request, value.request)) fail('source_edit_capture');
  const capture = parse(bytes, CAPTURE_LIMIT), bundle = Buffer.from(suppliedBundle);
  const artifact = prepared(capture.preparation, bundle, request, capture.patch_sha256);
  inspection(capture.inspection, request, capture.preparation, bundle, artifact);
  return { capture, bundle, candidate_commit: artifact.candidate, native_bundle_validation_observed: true,
    bundle_objects_independently_verified: false, publication_authorized: false };
}
export async function captureSourceEdit(value, patch, credential, options = {}) {
  const request = editInput(value), time = clock(options); time.check();
  if (!Buffer.isBuffer(patch) || !patch.length || patch.length > 1048576) fail('source_edit_patch_limit');
  const bytes = Buffer.from(patch), patchHash = hash(bytes);
  const first = await exchange(request.endpoint, credential, 'prepare', upload({ ...editCoordinates(request), ...request.metadata }, bytes, 'patch'), time,
    Math.min(PREPARE_LIMIT, time.maxWireBytes));
  time.check(); const { preparation, bundle } = decodePreparation(first);
  const artifact = prepared(preparation, bundle, request, patchHash), remaining = time.maxWireBytes - first.bytes.length;
  if (remaining < 1) fail('source_edit_wire_budget');
  const second = await exchange(request.endpoint, credential, 'inspect', upload(editCoordinates(request, artifact.candidate), bundle, 'bundle'), time, Math.min(8388608, remaining));
  time.check();
  const capture = { schema: captureProfile(request), request, patch_sha256: patchHash, patch_bytes: bytes.length,
    preparation, inspection: parse(second.bytes, 8388608) };
  const verified = validateSourceEdit(capture, bundle); time.check();
  return { ...verified, metrics: { requests: 2, response_bytes: first.bytes.length + second.bytes.length } };
}