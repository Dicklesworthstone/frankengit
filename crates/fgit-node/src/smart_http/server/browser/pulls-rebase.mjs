// Rebase is inspected as a complete ordered series. A final-tree diff alone
// cannot disclose intermediate changes or establish the reviewed candidate.
import { keys, record, integer, text, oid, subject, SUBJECT_FIELDS, form, pinned, matchSubject,
  fail, unhex, hex, utf8 } from './pulls-core.mjs';
import { preparationEnvelope, digest, checkedPath, comparisonEntries, joinBytes } from './pulls-candidate.mjs';

export const REBASE_MAX_COMMITS = 256;
const COMMIT_BYTES = 2 * 1024 * 1024;
const SERIES_BYTES = 16 * 1024 * 1024;

function noEffects(reply) {
  if (reply.read_only !== true || reply.objects_staged !== false || reply.transaction_created !== false ||
      reply.published !== false || reply.merge_authorized !== false) fail('Rebase response unexpectedly claims publication or authority.');
}

export function rebasePreparationCommand(fields, metadata) {
  keys(fields, SUBJECT_FIELDS); keys(metadata, ['upstream', 'committer', 'timestamp', 'empty']);
  const selected = subject(fields), upstream = oid(metadata.upstream, selected.object_format);
  const committer = text(metadata.committer, 1024, 'rebase committer', true);
  if (!/^[^<>\r\n]+ <[^<>\r\n]+>$/.test(committer)) fail('Committer must use Name <email> syntax.');
  if (!['stop', 'drop', 'keep'].includes(metadata.empty)) fail('Choose an explicit empty-commit policy.');
  if (upstream === selected.source_tip || selected.source_tip === selected.target_tip) fail('Rebase requires a nonempty source suffix and distinct tips.');
  const result = { ...selected, profile: 'path-v1', upstream, committer,
    timestamp: integer(metadata.timestamp, 'commit timestamp'), empty: metadata.empty };
  form(result); return result;
}

export async function rebasePreparationReply(response, number, command, scope, crypto) {
  const { metadata, bundle } = preparationEnvelope(response), selected = pinned(metadata, scope);
  noEffects(metadata);
  if (metadata.type !== 'pull_request_rebase_preparation' || metadata.profile !== 'path-v1' || metadata.method !== 'rebase' ||
      metadata.committer !== command.committer || metadata.timestamp !== command.timestamp || metadata.empty_policy !== command.empty ||
      oid(metadata.merge_base, scope.format) !== command.upstream) fail('Rebase preparation changed its method or explicit inputs.');
  matchSubject(metadata.subject, command, number, scope.format, 'pull_request');
  if (!Array.isArray(metadata.steps) || metadata.steps.length > REBASE_MAX_COMMITS || metadata.step_count !== metadata.steps.length ||
      metadata.series_complete !== (metadata.state === 'clean') || metadata.provisional_steps !== (metadata.state !== 'clean') ||
      !Array.isArray(metadata.conflicts)) fail('Invalid rebase step or conflict list.');
  const originals = new Set(), rewrittenIds = new Set(); let previous = command.target_tip, tree = null, retained = 0;
  for (const step of metadata.steps) {
    record(step);
    const original = oid(step.original, scope.format), rewritten = oid(step.rewritten, scope.format), nextTree = oid(step.tree, scope.format);
    if (originals.has(original) || !['replayed', 'preserved_empty', 'dropped_empty'].includes(step.kind)) fail('Invalid or duplicate rebase step.');
    originals.add(original);
    if (step.kind === 'dropped_empty') {
      if (command.empty !== 'drop' || rewritten !== previous || (tree !== null && nextTree !== tree)) fail('Dropped rebase step changed the retained history.');
    } else {
      if (rewritten === command.target_tip || rewrittenIds.has(rewritten)) fail('Retained rebase step did not create a distinct commit.');
      rewrittenIds.add(rewritten);
      retained += 1;
    }
    previous = rewritten; tree = nextTree;
  }
  if (metadata.state === 'clean') {
    if (response.status !== 200 || !bundle || !retained || metadata.conflicts.length || metadata.stopped_commit !== null ||
        oid(metadata.steps.at(-1).original, scope.format) !== command.source_tip ||
        oid(metadata.candidate_commit, scope.format) !== previous || previous === command.target_tip ||
        oid(metadata.root_tree, scope.format) !== tree) fail('Incomplete rebase candidate or step accounting.');
    record(metadata.bundle);
    if (metadata.bundle.bytes !== bundle.length || metadata.bundle.sha256 !== await digest(bundle, crypto)) fail('Rebase bundle commitment mismatch.');
    return { metadata, artifact: { number, scope: selected.binding, method: 'rebase',
      fields: { ...subject(command), merge_base: command.upstream, candidate_commit: previous },
      bundle: bundle.slice(), sha256: metadata.bundle.sha256 } };
  }
  if (response.status !== 409 || bundle || metadata.bundle !== null || metadata.candidate_commit !== null ||
      metadata.steps.length >= REBASE_MAX_COMMITS) fail('Stopped rebase unexpectedly contains a publishable artifact.');
  const stopped = oid(metadata.stopped_commit, scope.format);
  if (originals.has(stopped)) fail('Stopped rebase commit was already completed.');
  if (metadata.state === 'became_empty') {
    if (command.empty !== 'stop' || metadata.conflicts.length) fail('Invalid empty-commit stop.');
  } else if (metadata.state === 'conflicted') {
    if (!metadata.conflicts.length || metadata.conflicts.length > 128) fail('Invalid rebase conflicts.');
    let previousPath = '';
    for (const conflict of metadata.conflicts) {
      checkedPath(conflict.path_hex);
      if (conflict.path_hex <= previousPath || !['content', 'binary', 'modify_delete', 'type_change', 'mode', 'opaque', 'attributes_require_driver'].includes(conflict.kind)) fail('Invalid rebase conflict path or kind.');
      previousPath = conflict.path_hex;
      for (const side of ['base', 'ours', 'theirs']) if (conflict[side] !== null) {
        record(conflict[side]); integer(conflict[side].mode, 'entry mode', 1, 0xffffffff); oid(conflict[side].oid, scope.format);
      }
    }
  } else fail('Unsupported rebase preparation state.');
  return { metadata, artifact: null };
}

// Parse only native headers, not continuation lines or text in the message.
// Ancestry, bundle coverage and actual tree contents remain native checks.
function commitHeaders(body, algorithm) {
  const headers = { parents: [], tree: null }; let start = 0;
  while (start < body.length) {
    const newline = body.indexOf(10, start), end = newline < 0 ? body.length : newline;
    if (end === start) break;
    const line = body.subarray(start, end);
    for (const name of ['tree', 'parent']) {
      const prefix = utf8.encode(`${name} `);
      if (prefix.every((byte, index) => byte === line[index])) {
        const bytes = line.subarray(prefix.length), width = algorithm === 'sha1' ? 40 : 64;
        if (bytes.length !== width) fail('Invalid native rebase commit header.');
        const id = oid(String.fromCharCode(...bytes).toLowerCase(), algorithm);
        if (name === 'parent') headers.parents.push(id);
        else { if (headers.tree !== null) fail('Duplicate native tree header.'); headers.tree = id; }
      }
    }
    start = end + 1;
  }
  return headers;
}

export async function rebaseInspectionReply(reply, artifact, crypto) {
  const selected = pinned(reply, artifact.scope), fields = artifact.fields, algorithm = fields.object_format;
  noEffects(reply);
  if (artifact.method !== 'rebase' || reply.type !== 'pull_request_rebase_inspection' || reply.method !== 'rebase' ||
      reply.profile !== 'verified-linear-series-v1' || reply.scope !== 'all_paths_all_commits' || reply.complete !== true ||
      reply.all_changed_paths !== true || reply.all_rewritten_commits !== true || reply.replay_equivalence_verified !== false ||
      reply.binary_bodies_included !== false || reply.context_lines !== 3 ||
      reply.comparison_profile !== 'full-tree-direct-path-myers-v1') fail('Rebase inspection does not cover the complete series.');
  matchSubject(reply.subject, fields, artifact.number, algorithm, 'pull_request');
  if (oid(reply.merge_base, algorithm) !== fields.merge_base || oid(reply.candidate_commit, algorithm) !== fields.candidate_commit ||
      fields.source_tip === fields.target_tip || fields.merge_base === fields.source_tip || fields.candidate_commit === fields.target_tip ||
      !Array.isArray(reply.commits) || !reply.commits.length || reply.commits.length > REBASE_MAX_COMMITS ||
      reply.commit_count !== reply.commits.length || !Array.isArray(reply.prerequisites) || reply.prerequisites.length !== 1 ||
      oid(reply.prerequisites[0], algorithm) !== fields.target_tip) fail('Rebase inspection changed the candidate or series bounds.');
  record(reply.bundle);
  if (reply.bundle.bytes !== artifact.bundle.length || reply.bundle.sha256 !== artifact.sha256) fail('Rebase inspection does not bind the uploaded bundle.');
  for (const name of ['pack_bytes', 'pack_objects', 'expanded_bytes', 'closure_objects', 'transport_only_objects']) integer(reply.bundle[name], name);
  if (reply.bundle.pack_bytes > reply.bundle.bytes || reply.bundle.transport_only_objects > reply.bundle.pack_objects) fail('Invalid rebase bundle accounting.');
  let changes = 0, hunks = 0, payload = 0, bodies = 0, textFiles = 0;
  function comparison(value, before, after) {
    record(value);
    if (value.mode !== 'direct' || oid(value.before, algorithm) !== before || oid(value.after, algorithm) !== after) fail('Rebase comparison changed its commit coordinates.');
    oid(value.before_tree, algorithm); oid(value.after_tree, algorithm);
    comparisonEntries(value, algorithm);
    changes += value.entries.length;
    for (const entry of value.entries) {
      payload += entry.path_hex.length / 2;
      if (entry.content.type === 'text') {
        textFiles += 1;
        hunks += entry.content.hunks.length;
        for (const hunk of entry.content.hunks) payload += (hunk.before_hex.length + hunk.after_hex.length) / 2;
      }
    }
    if (changes > 512 || hunks > 4096 || textFiles > 64 || payload > 2 * 1024 * 1024) fail('Rebase comparisons exceed the aggregate review budget.');
    return value;
  }
  const source = comparison(reply.source_comparison, fields.source_tip, fields.candidate_commit);
  const seen = new Set(); let previous = fields.target_tip, previousTree = null;
  for (const step of reply.commits) {
    record(step);
    const id = oid(step.commit, algorithm), parent = oid(step.parent, algorithm), tree = oid(step.tree, algorithm);
    if (parent !== previous || seen.has(id) || id === fields.target_tip) fail('Rebase commits are not one complete ordered parent chain.');
    const body = unhex(step.commit_hex, COMMIT_BYTES); bodies += body.length;
    if (!body.length || bodies > SERIES_BYTES) fail('Rebase commit bodies exceed the series budget.');
    const actual = hex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256',
      joinBytes(utf8.encode(`commit ${body.length}\0`), body))));
    const native = commitHeaders(body, algorithm);
    if (actual !== id || native.tree !== tree || native.parents.length !== 1 || native.parents[0] !== parent) fail('Rebase native commit bytes do not match their identity, tree or parent.');
    const delta = comparison(step.comparison, parent, id);
    if (oid(delta.after_tree, algorithm) !== tree || (previousTree !== null && oid(delta.before_tree, algorithm) !== previousTree)) fail('Rebase comparisons do not follow the verified trees.');
    seen.add(id); previous = id; previousTree = tree;
  }
  if (previous !== fields.candidate_commit || previousTree !== oid(source.after_tree, algorithm)) fail('Rebase inspection omitted the final candidate or changed its tree.');
  return { ...selected, reply };
}
