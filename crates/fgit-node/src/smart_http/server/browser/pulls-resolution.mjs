// Explicit resolutions are candidate construction, never a vote or publication.
// Native resolve reconstructs the tree; this client checks the selected choices
// and returned identities before passing the actual bundle to native inspection.
import { keys, record, integer, oid, form, utf8, hex, unhex, fail, copy, SUBJECT_FIELDS, subject, matchSubject } from './pulls-core.mjs';
import { FORM_LIMIT } from './pulls-core.mjs';
import { preparationCommand, joinBytes, findBytes, checkedPath } from './pulls-candidate.mjs';
export const RESOLUTION_FILE_LIMIT = 1024 * 1024;
export const RESOLUTION_CONTENT_LIMIT = 16 * 1024 * 1024;
export const RESOLUTION_UPLOAD_LIMIT = RESOLUTION_CONTENT_LIMIT + FORM_LIMIT + 64 * 1024;
const SIDES = ['base', 'ours', 'theirs'];
const KINDS = ['content', 'binary', 'modify_delete', 'type_change', 'mode', 'opaque', 'attributes_require_driver'];
function identity(value, algorithm) {
  if (value === null) return null;
  record(value);
  return { mode: integer(value.mode, 'resolution entry mode', 1, 0xffffffff), oid: oid(value.oid, algorithm) };
}
function sameIdentity(left, right, algorithm) {
  return JSON.stringify(identity(left, algorithm)) === JSON.stringify(identity(right, algorithm));
}
function resolutionPath(value) {
  checkedPath(value);
  const bytes = unhex(value, 4096);
  let start = 0;
  for (let end = 0; end <= bytes.length; end += 1) if (end === bytes.length || bytes[end] === 47) {
    const part = bytes.subarray(start, end);
    if (part.length === 4 && part[0] === 46 && (part[1] | 32) === 103 && (part[2] | 32) === 105 && (part[3] | 32) === 116) fail('Reserved .git path component.');
    start = end + 1;
  }
  return bytes;
}
function conflictRows(report, fields) {
  record(report);
  if (report.state !== 'conflicted' || report.type !== 'merge_preparation' || report.profile !== 'path-merge-v1' ||
      report.read_only !== true || report.objects_staged !== false || report.transaction_created !== false ||
      report.published !== false || report.merge_authorized !== false || report.candidate !== null || report.bundle !== null ||
      !Array.isArray(report.conflicts) || !report.conflicts.length || report.conflicts.length > 128) fail('A complete read-only conflict report is required.');
  matchSubject(report.subject, fields, report.subject.pull_request, fields.object_format, 'pull_request');
  oid(report.merge_base, fields.object_format);
  integer(report.subject.pull_request, 'PR number', 1);
  let previous = '';
  const names = new Set(report.conflicts.map(row => row.path_hex));
  return report.conflicts.map(row => {
    record(row); const path = resolutionPath(row.path_hex);
    for (let i = 0; i < path.length; i += 1) if (path[i] === 47 && names.has(hex(path.subarray(0, i)))) fail('Overlapping resolution paths.');
    if (row.path_hex <= previous || !KINDS.includes(row.kind)) fail('Invalid conflict ordering or kind.');
    previous = row.path_hex;
    return { path_hex: row.path_hex, kind: row.kind, ...Object.fromEntries(SIDES.map(side => [side, identity(row[side], fields.object_format)])) };
  });
}
async function blobId(bytes, algorithm, crypto) {
  const framed = joinBytes(utf8.encode(`blob ${bytes.length}\0`), bytes);
  return hex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
}
// Deterministic part names are labels, never repository paths or local filenames.
// All bytes are copied before the first await; subsequent editor/file mutations
// cannot change the submitted content or its expected result hash.
export async function resolutionUpload(report, fields, metadata, choices, crypto) {
  keys(fields, SUBJECT_FIELDS);
  const selected = subject(fields), rows = conflictRows(report, selected);
  const command = preparationCommand(selected, metadata);
  command.merge_base = oid(report.merge_base, selected.object_format);
  if (!Array.isArray(choices) || choices.length !== rows.length) fail('Choose one resolution for every conflicted path.');
  const byPath = new Map();
  for (const choice of choices) {
    record(choice);
    keys(choice, choice.choice === 'file' ? ['path_hex', 'choice', 'mode', 'bytes'] : ['path_hex', 'choice']);
    resolutionPath(choice.path_hex);
    if (byPath.has(choice.path_hex)) fail('Duplicate resolution path.');
    byPath.set(choice.path_hex, choice);
  }
  let retainedBytes = 0;
  const files = [], expected = [], descriptors = [];
  for (const row of rows) {
    const choice = byPath.get(row.path_hex);
    if (!choice) fail('Resolution set names a clean path or leaves a conflict unresolved.');
    retainedBytes += row.path_hex.length / 2;
    let result = null;
    if (SIDES.includes(choice.choice)) {
      result = row[choice.choice];
      if (result === null) fail('Selected conflict side is absent; choose delete explicitly.');
      descriptors.push(`${row.path_hex}:${choice.choice}`);
    } else if (choice.choice === 'delete') {
      descriptors.push(`${row.path_hex}:delete`);
    } else if (choice.choice === 'file') {
      if (!['100644', '100755'].includes(choice.mode) || !(choice.bytes instanceof Uint8Array) || choice.bytes.length > RESOLUTION_FILE_LIMIT) fail('A resolved regular file must be at most 1 MiB with explicit mode 100644 or 100755.');
      retainedBytes += choice.bytes.length;
      if (retainedBytes > RESOLUTION_CONTENT_LIMIT) fail('Resolution content exceeds the 16 MiB browser limit.');
      const name = `file_${files.length}`, bytes = choice.bytes.slice();
      files.push({ name, bytes, index: expected.length });
      result = { mode: Number.parseInt(choice.mode, 8), oid: null };
      descriptors.push(`${row.path_hex}:file:${choice.mode}:${name}`);
    } else fail('Every conflict requires an explicit supported resolution choice.');
    if (retainedBytes > RESOLUTION_CONTENT_LIMIT) fail('Resolution content exceeds the 16 MiB browser limit.');
    expected.push({ ...copy(row), choice: choice.choice, result: copy(result) });
  }
  command.resolution = descriptors;
  const encoded = form(command);
  // Read-only requests have no idempotency key. The MIME boundary is transport
  // framing only; it neither identifies nor authorizes a transaction.
  let boundary = null;
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const candidate = `fg-resolution-${hex(crypto.getRandomValues(new Uint8Array(24)))}`;
    const marker = utf8.encode(`--${candidate}`);
    if (!encoded.includes(`--${candidate}`) && files.every(file => findBytes(file.bytes, marker) === -1)) { boundary = candidate; break; }
  }
  if (boundary === null) fail('Could not allocate a collision-free resolution boundary.');
  let bytes, contentType;
  if (!files.length) {
    bytes = utf8.encode(encoded); contentType = 'application/x-www-form-urlencoded';
  } else {
    const parts = [utf8.encode(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${encoded}\r\n`)];
    for (const file of files) parts.push(utf8.encode(`--${boundary}\r\nContent-Disposition: form-data; name="${file.name}"\r\nContent-Type: application/octet-stream\r\n\r\n`), file.bytes, utf8.encode('\r\n'));
    parts.push(utf8.encode(`--${boundary}--\r\n`));
    if (parts.reduce((sum, part) => sum + part.length, 0) > RESOLUTION_UPLOAD_LIMIT) fail('Resolution upload exceeds limit.');
    bytes = joinBytes(...parts); contentType = `multipart/form-data; boundary=${boundary}`;
  }
  for (const file of files) expected[file.index].result.oid = await blobId(file.bytes, selected.object_format, crypto);
  return { bytes, contentType, expected: { fields: selected, number: report.subject.pull_request, merge_base: command.merge_base, rows: expected } };
}
export function verifyResolutionResult(metadata, expected) {
  if (metadata.state !== 'resolved' || metadata.resolution_profile !== 'exact-path-resolutions-v1' ||
      !Array.isArray(metadata.resolutions) || metadata.resolutions.length !== expected.rows.length ||
      oid(metadata.candidate.merge_base, expected.fields.object_format) !== expected.merge_base) fail('Native resolution did not return the complete requested result.');
  const algorithm = expected.fields.object_format;
  matchSubject(metadata.subject, expected.fields, expected.number, algorithm, 'pull_request');
  for (let index = 0; index < expected.rows.length; index += 1) {
    const actual = record(metadata.resolutions[index]), wanted = expected.rows[index];
    if (actual.path_hex !== wanted.path_hex || actual.kind !== wanted.kind || actual.choice !== wanted.choice ||
        ![...SIDES, 'result'].every(side => sameIdentity(actual[side], wanted[side], algorithm))) fail('Native resolution changed a path, side, choice, mode or content identity.');
  }
}
