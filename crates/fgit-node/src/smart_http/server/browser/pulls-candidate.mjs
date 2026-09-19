// Binary candidate transport and inspection. Bundle hashes bind transport bytes;
// the native engine still owns Git closure, policy, review and publication.
import { FORM_LIMIT, REPLY_LIMIT, utf8, fail, record, keys, integer, text, oid, unhex, hex, subject, SUBJECT_FIELDS,
  matchSubject, pinned, json, form } from './pulls-core.mjs';
export const BUNDLE_LIMIT = 16 * 1024 * 1024; // Deliberately narrower than the native 64 MiB envelope.
export const METADATA_LIMIT = 2 * 1024 * 1024;
export const PREPARATION_LIMIT = BUNDLE_LIMIT + METADATA_LIMIT + 16 * 1024;
export const digest = async (bytes, crypto) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
export function joinBytes(...parts) {
  const size = parts.reduce((total, part) => total + part.length, 0), out = new Uint8Array(size); let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
// KMP bounds hostile boundary scanning to linear work, including repeated prefixes.
export function findBytes(bytes, marker, start = 0, end = bytes.length) {
  if (!marker.length) fail('Empty boundary.');
  const prefix = new Uint32Array(marker.length); let matched = 0;
  for (let i = 1; i < marker.length; i += 1) {
    while (matched && marker[i] !== marker[matched]) matched = prefix[matched - 1];
    if (marker[i] === marker[matched]) matched += 1; prefix[i] = matched;
  }
  matched = 0;
  for (let i = start; i < end; i += 1) {
    while (matched && bytes[i] !== marker[matched]) matched = prefix[matched - 1];
    if (bytes[i] === marker[matched]) matched += 1;
    if (matched === marker.length) return i + 1 - marker.length;
  }
  return -1;
}
function at(bytes, marker, offset) {
  return offset >= 0 && offset + marker.length <= bytes.length && marker.every((byte, index) => byte === bytes[offset + index]);
}
export function checkedBundle(bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > BUNDLE_LIMIT) fail('Candidate bundle must contain 1 byte through 16 MiB.');
  return bytes;
}
export function multipart(command, bundle, boundary) {
  checkedBundle(bundle);
  if (typeof command !== 'string' || command.length > FORM_LIMIT || !/^[A-Za-z0-9-_.]{1,70}$/.test(boundary)) fail('Invalid candidate upload.');
  const marker = utf8.encode(`--${boundary}`), encoded = utf8.encode(command);
  if (findBytes(bundle, marker) !== -1 || findBytes(encoded, marker) !== -1) fail('Candidate boundary collision.');
  return { contentType: `multipart/form-data; boundary=${boundary}`, bytes: joinBytes(
    utf8.encode(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${command}\r\n--${boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="candidate.bundle"\r\nContent-Type: application/x-git-bundle\r\n\r\n`),
    bundle, utf8.encode(`\r\n--${boundary}--\r\n`)) };
}
export function makeBoundary(command, bundle, crypto) {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const boundary = `fg-browser-${hex(crypto.getRandomValues(new Uint8Array(24)))}`;
    if (findBytes(bundle, utf8.encode(`--${boundary}`)) === -1 && !command.includes(`--${boundary}`)) return boundary;
  }
  fail('Could not allocate a collision-free upload boundary.');
}
export function preparationCommand(fields, metadata) {
  keys(fields, SUBJECT_FIELDS); keys(metadata, ['author', 'committer', 'timestamp', 'message']);
  const result = subject(fields);
  for (const name of ['author', 'committer']) {
    result[name] = text(metadata[name], 1024, name, true);
    if (!/^[^<>\r\n]+ <[^<>\r\n]+>$/.test(result[name])) fail('Commit identities must use Name <email> syntax.');
  }
  result.timestamp = integer(metadata.timestamp, 'commit timestamp');
  result.message = text(metadata.message, 64 * 1024, 'commit message');
  if (!result.message.trim()) fail('A nonempty explicit commit message is required.');
  form(result); return result;
}
function noEffects(reply) {
  if (reply.read_only !== true || reply.objects_staged !== false || reply.transaction_created !== false || reply.published !== false || reply.merge_authorized !== false) fail('Candidate response unexpectedly claims authority or publication.');
}
export function checkedPath(value) {
  const bytes = unhex(value, 4096);
  if (!bytes.length || bytes.includes(0) || bytes[0] === 47 || bytes.at(-1) === 47) fail('Invalid changed path.');
  // Byte paths are never decoded as filesystem paths or navigation URLs.
  let start = 0;
  for (let i = 0; i <= bytes.length; i += 1) if (i === bytes.length || bytes[i] === 47) {
    const part = bytes.subarray(start, i);
    if (!part.length || (part.length <= 2 && part.every(byte => byte === 46))) fail('Invalid changed path component.');
    start = i + 1;
  }
}
function entryIdentity(value, algorithm) {
  if (value === null) return;
  record(value); integer(value.mode, 'entry mode', 1, 0xffffffff); oid(value.oid, algorithm);
}
export async function preparationReply(response, number, expected, scope, crypto, expectResolved = false) {
  let metadata, bundle = null;
  if (/^application\/json(?:\s*;|$)/i.test(response.type)) {
    if (response.value.length > METADATA_LIMIT) fail('Preparation metadata exceeds limit.');
    metadata = json(response.value);
  } else {
    const match = /^multipart\/mixed; boundary=(fg-prepare-[0-9a-f]{48}-[0-9a-f])$/.exec(response.type);
    if (!match || response.status !== 200) fail('Unsupported candidate response envelope.');
    const boundary = match[1], bytes = response.value;
    const opening = utf8.encode(`--${boundary}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n`);
    const middle = utf8.encode(`\r\n--${boundary}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`);
    const closing = utf8.encode(`\r\n--${boundary}--\r\n`);
    const split = findBytes(bytes, middle, opening.length, Math.min(bytes.length, opening.length + METADATA_LIMIT + middle.length));
    if (!at(bytes, opening, 0) || split < 0 || split - opening.length > METADATA_LIMIT || !at(bytes, closing, bytes.length - closing.length)) fail('Incomplete or ambiguous candidate MIME envelope.');
    metadata = json(bytes.subarray(opening.length, split));
    bundle = bytes.subarray(split + middle.length, bytes.length - closing.length);
    checkedBundle(bundle);
    if (findBytes(bundle, utf8.encode(`--${boundary}`)) !== -1) fail('Ambiguous binary candidate boundary.');
  }
  const selected = pinned(metadata, scope); noEffects(metadata);
  if (metadata.type !== 'merge_preparation' || metadata.profile !== 'path-merge-v1' || !Array.isArray(metadata.conflicts)) fail('Unsupported merge preparation.');
  matchSubject(metadata.subject, expected, number, selected.binding.format, 'pull_request');
  if ((metadata.state === 'resolved') !== expectResolved) fail('Preparation and explicit resolution cannot substitute for one another.');
  if (metadata.state === 'clean' || metadata.state === 'resolved') {
    if (!bundle || metadata.conflicts.length || response.status !== 200) fail('Clean preparation lacks its exact bundle.');
    record(metadata.candidate); record(metadata.bundle);
    const fields = { ...subject(expected), merge_base: oid(metadata.candidate.merge_base, scope.format), candidate_commit: oid(metadata.candidate.commit, scope.format) };
    oid(metadata.candidate.tree, scope.format); integer(metadata.candidate.new_object_count, 'candidate objects', 1);
    if (metadata.bundle.bytes !== bundle.length || metadata.bundle.sha256 !== await digest(bundle, crypto)) fail('Candidate bundle commitment mismatch.');
    return { metadata, artifact: { number, scope: selected.binding, fields, bundle: bundle.slice(), sha256: metadata.bundle.sha256 } };
  }
  if (bundle || metadata.candidate !== null || metadata.bundle !== null) fail('Noncandidate response contains candidate material.');
  if (metadata.state === 'already_up_to_date') {
    if (response.status !== 200 || metadata.conflicts.length) fail('Invalid up-to-date result.');
  } else if (metadata.state === 'conflicted') {
    if (response.status !== 409 || !metadata.conflicts.length || metadata.conflicts.length > 128) fail('Invalid conflict result.');
    oid(metadata.merge_base, scope.format); let previous = '';
    for (const conflict of metadata.conflicts) {
      checkedPath(conflict.path_hex);
      if (conflict.path_hex <= previous || !['content', 'binary', 'modify_delete', 'type_change', 'mode', 'opaque', 'attributes_require_driver'].includes(conflict.kind)) fail('Invalid conflict paths or type.');
      previous = conflict.path_hex;
      for (const side of ['base', 'ours', 'theirs']) entryIdentity(conflict[side], scope.format);
    }
  } else fail('Unsupported preparation state.');
  return { metadata, artifact: null };
}
function span(value, bytes, total, previous) {
  record(value);
  integer(value.byte_start, 'hunk offset', previous, total); integer(value.byte_end, 'hunk end', value.byte_start, total);
  integer(value.line_start, 'hunk line'); integer(value.line_count, 'hunk line count');
  const count = bytes.reduce((n, byte) => n + Number(byte === 10), 0) + Number(bytes.length > 0 && bytes.at(-1) !== 10);
  if (value.byte_end - value.byte_start !== bytes.length || count !== value.line_count || !Number.isSafeInteger(value.line_start + count)) fail('Invalid hunk byte or line span.');
  return value.byte_end;
}
export async function inspectionReply(reply, artifact, crypto) {
  const selected = pinned(reply, artifact.scope); noEffects(reply);
  if (reply.type !== 'candidate_inspection' || reply.all_changed_paths !== true || reply.binary_bodies_included !== false ||
      reply.comparison_profile !== 'full-tree-direct-path-myers-v1' || reply.context_lines !== 3) fail('Unsupported or incomplete candidate inspection.');
  const fields = artifact.fields, algorithm = fields.object_format;
  matchSubject(reply.subject, fields, artifact.number, algorithm, 'pull_request');
  if (oid(reply.merge_base, algorithm) !== fields.merge_base || oid(reply.candidate_commit, algorithm) !== fields.candidate_commit ||
      !Array.isArray(reply.parents) || reply.parents.length !== 2 || oid(reply.parents[0], algorithm) !== fields.target_tip || oid(reply.parents[1], algorithm) !== fields.source_tip) fail('Inspected candidate or parent identities changed.');
  if (!Array.isArray(reply.prerequisites) || reply.prerequisites.length > 64) fail('Invalid bundle prerequisites.');
  for (const id of reply.prerequisites) oid(id, algorithm);
  record(reply.bundle);
  if (reply.bundle.bytes !== artifact.bundle.length || reply.bundle.sha256 !== artifact.sha256) fail('Inspection does not bind the uploaded bundle.');
  for (const name of ['pack_bytes', 'pack_objects', 'expanded_bytes', 'closure_objects', 'transport_only_objects']) integer(reply.bundle[name], name);
  const commitBody = unhex(reply.candidate_commit_body_hex, 2 * 1024 * 1024);
  const commit = joinBytes(utf8.encode(`commit ${commitBody.length}\0`), commitBody);
  const actual = hex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', commit)));
  if (actual !== fields.candidate_commit) fail('Native candidate commit bytes do not match their object identity.');
  const comparison = record(reply.comparison);
  if (comparison.mode !== 'direct' || oid(comparison.before, algorithm) !== fields.target_tip || oid(comparison.after, algorithm) !== fields.candidate_commit ||
      !Array.isArray(comparison.entries) || comparison.entries.length > 512 || comparison.entry_count !== comparison.entries.length) fail('Incomplete or wrong candidate comparison.');
  oid(comparison.before_tree, algorithm); oid(comparison.after_tree, algorithm);
  comparisonEntries(comparison, algorithm);
  return { ...selected, reply };
}

// Shared byte-only diff validation. Each caller retains its own authority and subject checks.
export function comparisonEntries(comparison, algorithm) {
  record(comparison);
  if (!Array.isArray(comparison.entries) || comparison.entries.length > 512 || comparison.entry_count !== comparison.entries.length) fail('Incomplete comparison entries.');
  let previous = '';
  for (const entry of comparison.entries) {
    checkedPath(entry.path_hex); if (entry.path_hex <= previous) fail('Unordered or duplicate changed paths.'); previous = entry.path_hex;
    if (!['added', 'deleted', 'modified', 'mode_changed', 'type_changed'].includes(entry.kind)) fail('Invalid change kind.');
    entryIdentity(entry.before, algorithm); entryIdentity(entry.after, algorithm);
    const content = record(entry.content);
    switch (content.type) {
      case 'identical': case 'object_only': if (content.content_read !== false) fail('Object-only content claims a text read.'); break;
      case 'binary':
        integer(content.before_bytes, 'binary size'); integer(content.after_bytes, 'binary size');
        if (content.body_included !== false) fail('Unexpected binary body.'); break;
      case 'text': {
        text(content.algorithm, 128, 'diff algorithm', true);
        for (const name of ['additions', 'deletions', 'before_bytes', 'after_bytes']) integer(content[name], name);
        if (!Array.isArray(content.hunks) || content.hunks.length > 4096) fail('Invalid text hunks.');
        let oldEnd = 0, newEnd = 0;
        for (const hunk of content.hunks) {
          oldEnd = span(hunk.old, unhex(hunk.before_hex, REPLY_LIMIT), content.before_bytes, oldEnd);
          newEnd = span(hunk.new, unhex(hunk.after_hex, REPLY_LIMIT), content.after_bytes, newEnd);
        }
        break;
      }
      default: fail('Unknown content type cannot be presented as an empty diff.');
    }
  }
}
