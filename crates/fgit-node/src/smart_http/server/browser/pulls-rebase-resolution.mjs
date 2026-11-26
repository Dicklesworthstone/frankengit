// A PR rebase recipe belongs to one original commit and one observed snapshot.
// Every request reconstructs the whole suffix; an explained prefix grants no
// review or publication authority.
import { copy, keys, record, oid, subject, snapshot, pinned, matchSubject, form, utf8, hex, fail } from './pulls-core.mjs';
import { joinBytes, findBytes } from './pulls-candidate.mjs';
import { rebasePreparationCommand, REBASE_MAX_COMMITS } from './pulls-rebase.mjs';
import { resolutionIdentity, resolutionPath, RESOLUTION_FILE_LIMIT, RESOLUTION_CONTENT_LIMIT, RESOLUTION_UPLOAD_LIMIT } from './pulls-resolution.mjs';

const MAX_CHOICES = 128;
const SIDES = ['base', 'ours', 'theirs'];
const KINDS = ['content', 'binary', 'modify_delete', 'type_change', 'mode', 'opaque', 'attributes_require_driver'];
const MODES = [0o040000, 0o100644, 0o100755, 0o120000, 0o160000];

function identity(value, algorithm) {
  const result = resolutionIdentity(value, algorithm);
  if (result !== null && !MODES.includes(result.mode)) fail('Unsupported native conflict mode.');
  return result;
}
function conflict(value, algorithm) {
  record(value); resolutionPath(value.path_hex);
  if (!KINDS.includes(value.kind)) fail('Unsupported rebase conflict kind.');
  return { path_hex: value.path_hex, kind: value.kind,
    base: identity(value.base, algorithm), ours: identity(value.ours, algorithm), theirs: identity(value.theirs, algorithm) };
}
function conflicts(report, command, head) {
  const selected = pinned(report, null, snapshot(head));
  if (selected.binding.format !== command.object_format || report.type !== 'pull_request_rebase_preparation' ||
      report.method !== 'rebase' || report.profile !== 'path-v1' || report.state !== 'conflicted' ||
      report.read_only !== true || report.objects_staged !== false || report.transaction_created !== false ||
      report.published !== false || report.merge_authorized !== false || report.candidate_commit !== null ||
      report.bundle !== null || report.series_complete !== false || report.provisional_steps !== true ||
      report.committer !== command.committer || report.timestamp !== command.timestamp ||
      report.empty_policy !== command.empty || oid(report.merge_base, command.object_format) !== command.upstream ||
      !Array.isArray(report.conflicts) || !report.conflicts.length || report.conflicts.length > MAX_CHOICES) {
    fail('Resolve only a complete conflicted rebase at the original snapshot.');
  }
  matchSubject(report.subject, command, report.subject.pull_request, command.object_format, 'pull_request');
  const names = new Set(report.conflicts.map(row => row.path_hex));
  let previous = '';
  return report.conflicts.map(value => {
    const row = conflict(value, command.object_format), path = resolutionPath(row.path_hex);
    if (row.path_hex <= previous) fail('Conflicts must have unique ordered paths.');
    for (let i = 0; i < path.length; i += 1) if (path[i] === 47 && names.has(hex(path.subarray(0, i)))) fail('Overlapping rebase conflict paths.');
    previous = row.path_hex; return row;
  });
}

// Snapshot all file bytes and count the cumulative budget before the first
// asynchronous hash. Later editor or caller mutations cannot change a recipe.
export async function rebaseResolutionUpload(report, command, head, previous, choices, crypto, check = () => {}) {
  check();
  const algorithm = command.object_format;
  command = rebasePreparationCommand(subject(command), {
    upstream: command.upstream, committer: command.committer, timestamp: command.timestamp, empty: command.empty,
  });
  const rows = conflicts(report, command, head), original = oid(report.stopped_commit, algorithm);
  if (!Array.isArray(previous) || previous.length >= REBASE_MAX_COMMITS ||
      previous.some(recipe => recipe.original === original) || original === command.upstream) fail('Original commit already resolved or outside the selected suffix.');
  if (!Array.isArray(choices) || choices.length !== rows.length) fail('Choose every conflict at this original commit.');
  let count = 0, bytes = 0;
  for (const recipe of previous) {
    oid(recipe.original, algorithm);
    if (!Array.isArray(recipe.paths) || !recipe.paths.length) fail('Invalid retained rebase recipe.');
    for (const path of recipe.paths) {
      count += 1; bytes += path.conflict.path_hex.length / 2 + (path.bytes?.length ?? 0);
    }
  }
  if (count + rows.length > MAX_CHOICES || bytes > RESOLUTION_CONTENT_LIMIT) fail('Whole-series resolution budget exceeded.');
  const recipes = copy(previous), byPath = new Map();
  for (const choice of choices) {
    keys(choice, choice.choice === 'file' ? ['path_hex', 'choice', 'mode', 'bytes'] : ['path_hex', 'choice']);
    resolutionPath(choice.path_hex);
    if (byPath.has(choice.path_hex)) fail('Duplicate rebase resolution path.');
    byPath.set(choice.path_hex, choice);
  }
  const paths = rows.map(row => {
    const chosen = byPath.get(row.path_hex);
    if (!chosen) fail('Resolution set names a clean path or omits a conflict.');
    bytes += row.path_hex.length / 2;
    const result = { conflict: row, choice: chosen.choice };
    if (chosen.choice === 'file') {
      if (!['100644', '100755'].includes(chosen.mode) || !(chosen.bytes instanceof Uint8Array) ||
          chosen.bytes.length > RESOLUTION_FILE_LIMIT) fail('Resolved files require bounded exact bytes and an explicit regular-file mode.');
      bytes += chosen.bytes.length;
      result.mode = chosen.mode; result.bytes = chosen.bytes.slice(); result.result = null;
    } else if (chosen.choice === 'delete') result.result = null;
    else if (SIDES.includes(chosen.choice)) {
      if (row[chosen.choice] === null) fail('The selected side is absent; choose deletion explicitly.');
      result.result = copy(row[chosen.choice]);
    } else fail('Choose an explicit side, deletion, or resolved file.');
    if (bytes > RESOLUTION_CONTENT_LIMIT) fail('Whole-series resolution budget exceeded.');
    return result;
  });
  recipes.push({ original, paths });
  for (const path of paths) if (path.choice === 'file') {
    check();
    const framed = joinBytes(utf8.encode('blob ' + path.bytes.length + '\0'), path.bytes);
    const digest = await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', framed);
    check(); path.result = { mode: Number.parseInt(path.mode, 8), oid: hex(new Uint8Array(digest)) };
  }
  return rebaseRecipeUpload(command, head, recipes, crypto, check);
}

// Re-encode already validated cumulative recipes when an explicit empty-policy
// continuation changes only the command. Callers must reconstruct saved recipes
// from their original conflict observations before using this transport helper.
export function rebaseRecipeUpload(command, head, recipes, crypto, check = () => {}) {
  check();
  command = rebasePreparationCommand(subject(command), {
    upstream: command.upstream, committer: command.committer, timestamp: command.timestamp, empty: command.empty,
  });
  snapshot(head);
  const files = [], descriptors = [];
  let bytes = 0;
  for (const recipe of recipes) for (const path of recipe.paths) {
    check();
    bytes += path.conflict.path_hex.length / 2 + (path.bytes?.length ?? 0);
    if (bytes > RESOLUTION_CONTENT_LIMIT || descriptors.length >= MAX_CHOICES) fail('Whole-series resolution budget exceeded.');
    let value = recipe.original + ':' + path.conflict.path_hex + ':' + path.choice;
    if (path.choice === 'file') { value += ':' + path.mode + ':file_' + files.length; files.push(path.bytes); }
    descriptors.push(value);
  }
  if (!descriptors.length) fail('Original-commit resolution recipes are required.');
  const encoded = form({ ...command, expected_head: head, resolution: descriptors });
  if (!files.length) return { bytes: utf8.encode(encoded), contentType: 'application/x-www-form-urlencoded', recipes };
  let boundary = null;
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const candidate = 'fg-pr-rebase-resolve-' + hex(crypto.getRandomValues(new Uint8Array(24)));
    const marker = utf8.encode('--' + candidate);
    if (!encoded.includes('--' + candidate) && files.every(file => findBytes(file, marker) === -1)) { boundary = candidate; break; }
  }
  if (!boundary) fail('Could not select unambiguous resolution framing.');
  const parts = [utf8.encode('--' + boundary + '\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n' + encoded + '\r\n')];
  files.forEach((file, index) => parts.push(
    utf8.encode('--' + boundary + '\r\nContent-Disposition: form-data; name="file_' + index + '"\r\nContent-Type: application/octet-stream\r\n\r\n'),
    file, utf8.encode('\r\n')));
  parts.push(utf8.encode('--' + boundary + '--\r\n'));
  if (parts.reduce((total, part) => total + part.length, 0) > RESOLUTION_UPLOAD_LIMIT) fail('Resolution upload exceeds its bounded envelope.');
  check();
  return { bytes: joinBytes(...parts), contentType: 'multipart/form-data; boundary=' + boundary, recipes };
}

export function verifyRebaseResolutions(report, recipes, algorithm) {
  if (!recipes.length) {
    if (['resolution_profile', 'resolution_input_commits', 'resolution_consumed_commits', 'resolutions'].some(key => key in report)) fail('Unexpected rebase resolution receipt.');
    return;
  }
  const positions = new Map(report.steps.map((step, index) => [oid(step.original, algorithm), index]));
  if (report.state === 'became_empty') positions.set(oid(report.stopped_commit, algorithm), report.steps.length);
  // The browser submits only recipes for successive observed stops. Every
  // submitted recipe must be consumed, even if a later step still conflicts.
  if (recipes.some(recipe => !positions.has(recipe.original)) ||
      report.resolution_profile !== 'original-commit-path-v1' ||
      report.resolution_input_commits !== recipes.length || report.resolution_consumed_commits !== recipes.length ||
      !Array.isArray(report.resolutions) || report.resolutions.length !== recipes.length) fail('Incomplete whole-series resolution receipt.');
  const expected = [...recipes].sort((left, right) => positions.get(left.original) - positions.get(right.original));
  for (let index = 0; index < expected.length; index += 1) {
    const wanted = expected[index], actual = record(report.resolutions[index]);
    if (oid(actual.original, algorithm) !== wanted.original || !Array.isArray(actual.paths) ||
        actual.paths.length !== wanted.paths.length) fail('Resolved original commit or path set changed.');
    for (let i = 0; i < wanted.paths.length; i += 1) {
      const before = wanted.paths[i], after = record(actual.paths[i]);
      if (JSON.stringify(conflict(after.conflict, algorithm)) !== JSON.stringify(before.conflict) ||
          after.choice !== before.choice || JSON.stringify(identity(after.result, algorithm)) !== JSON.stringify(before.result)) {
        fail('Resolution changed an observed conflict, requested choice, or exact file identity.');
      }
    }
  }
}
