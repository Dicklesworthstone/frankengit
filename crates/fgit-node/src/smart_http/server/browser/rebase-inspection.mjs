// Validate complete native reports and each actual Git commit body. This does
// not replay patches, authenticate the server, or prove original-message fidelity.
import { fail, keys, record, integer, hex, unhex, utf8, pinned } from './pulls-core.mjs';
import { findBytes } from './pulls-candidate.mjs';
import { sourcePath } from './source-edit-patch.mjs';
import { noEffects, exactOid, objectHash, FILE_BYTES } from './rebase-data.mjs';
export const INSPECT_OPTIONS = Object.freeze({ context_lines: 3, max_changes: 128,
  max_text_files: 64, max_blob_bytes: FILE_BYTES, max_output_bytes: 1024 * 1024, max_hunks: 512 });
const modes = ['040000', '100644', '100755', '120000', '160000'];
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
function entry(value, algorithm) {
  if (value === null) return null;
  keys(value, ['object_id', 'mode']);
  if (!modes.includes(value.mode)) fail('Invalid native diff mode.');
  return { mode: value.mode, object_id: exactOid(value.object_id, algorithm) };
}
function charge(budget, field, count, maximum) {
  budget[field] += count; integer(budget[field], `aggregate rebase ${field}`, 0, maximum);
}
function span(value, bytes, size, previous, check) {
  record(value); integer(value.byte_start, 'hunk start', previous, size);
  integer(value.byte_end, 'hunk end', value.byte_start, size);
  integer(value.line_start, 'hunk first line', 0, size); integer(value.line_count, 'hunk line count', 0, size);
  let lines = Number(bytes.length > 0 && bytes.at(-1) !== 10);
  for (let i = 0; i < bytes.length; i++) { if (i % 4096 === 0) check(); if (bytes[i] === 10) lines++; }
  if (value.byte_end - value.byte_start !== bytes.length || value.line_count !== lines ||
      (value.byte_start === 0 && value.line_start !== 0) || value.line_start + lines > size ||
      (bytes.length > 0 && value.byte_end < size && bytes.at(-1) !== 10)) fail('Inconsistent native hunk byte coordinates.');
  return value.byte_end;
}
function comparison(reply, expected, budget, check) {
  const { command: c, scope, head, sourceHead, before, after, beforeTree, afterTree } = expected;
  pinned(reply, scope, head);
  if (reply.type !== 'source_diff' || reply.profile !== 'native-tree-review-v1' || reply.source_head !== sourceHead ||
      reply.mode !== 'direct' || reply.pull_request !== null || reply.read_only !== true ||
      reply.transaction_created !== false || reply.published !== false || reply.approval_created !== false ||
      reply.complete !== true || reply.line_origin !== 0 || reply.context_lines !== 3 ||
      reply.before_ref_hex !== hex(utf8.encode(c.source_ref)) || reply.after_ref_hex !== hex(utf8.encode(c.source_ref)) ||
      reply.requested_before !== before || reply.compared_before !== before || reply.requested_after !== after ||
      reply.before_tree !== beforeTree || reply.after_tree !== afterTree ||
      !Array.isArray(reply.path_prefixes_hex) || reply.path_prefixes_hex.length ||
      !Array.isArray(reply.entries) || reply.entry_count !== reply.entries.length) fail('Wrong or incomplete full-series comparison.');
  charge(budget, 'changes', reply.entries.length, INSPECT_OPTIONS.max_changes);
  let previous = '';
  for (const r of reply.entries) {
    check(); record(r); sourcePath(r.path_hex);
    if (r.path_hex <= previous) fail('Diff paths are duplicate or unordered.'); previous = r.path_hex;
    charge(budget, 'bytes', r.path_hex.length / 2, INSPECT_OPTIONS.max_output_bytes);
    const a = entry(r.before, scope.format), b = entry(r.after, scope.format);
    const kind = !a && b ? 'added' : a && !b ? 'deleted' : a && b
      ? (Number.parseInt(a.mode, 8) & 0o170000) !== (Number.parseInt(b.mode, 8) & 0o170000) ? 'type_changed'
        : a.mode !== b.mode ? 'mode_changed' : a.object_id !== b.object_id ? 'modified' : null : null;
    if (r.kind !== kind || kind === null) fail('Diff entry contradicts its identities or mode.');
    const content = record(r.content), blob = e => e && ['100644', '100755', '120000'].includes(e.mode);
    if (content.kind === 'identical') {
      keys(content, ['kind']);
      if (!blob(a) || !blob(b) || a.object_id !== b.object_id) fail('Nonidentical content labeled identical.');
    } else if (content.kind === 'object_only') {
      keys(content, ['kind']); if (blob(a) || blob(b)) fail('Blob diff omitted its content classification.');
    } else if (content.kind === 'binary' || content.kind === 'text') {
      keys(content, content.kind === 'binary' ? ['kind', 'before_bytes', 'after_bytes']
        : ['kind', 'before_bytes', 'after_bytes', 'algorithm', 'additions', 'deletions', 'hunks']);
      const n = integer(content.before_bytes, 'before bytes', 0, FILE_BYTES), m = integer(content.after_bytes, 'after_bytes', 0, FILE_BYTES);
      if ((!blob(a) && n !== 0) || (!blob(b) && m !== 0) || (!blob(a) && !blob(b))) fail('Non-file diff disclosed file bytes.');
      if (content.kind === 'text') {
        if (typeof content.algorithm !== 'string' || content.algorithm.length > 128) fail('Invalid native diff algorithm.');
        integer(content.additions, 'added lines', 0, m); integer(content.deletions, 'deleted lines', 0, n);
        if (!Array.isArray(content.hunks)) fail('Missing native text hunks.');
        charge(budget, 'files', 1, INSPECT_OPTIONS.max_text_files);
        charge(budget, 'hunks', content.hunks.length, INSPECT_OPTIONS.max_hunks);
        let old = 0, next = 0;
        for (const h of content.hunks) {
          check(); record(h);
          const beforeBytes = unhex(h.before_hex, FILE_BYTES), afterBytes = unhex(h.after_hex, FILE_BYTES);
          charge(budget, 'bytes', beforeBytes.length + afterBytes.length, INSPECT_OPTIONS.max_output_bytes);
          old = span(h.old, beforeBytes, n, old, check); next = span(h.new, afterBytes, m, next, check);
        }
      }
    } else fail('Unsupported native diff content.');
  }
}
export async function verifyCommit(commit, parent, tree, command, crypto, check) {
  const bytes = unhex(commit.body_hex, FILE_BYTES); check();
  if (await objectHash('commit', bytes, command.object_format, crypto) !== commit.commit) fail('Rewritten Git commit hash mismatch.');
  check();
  const split = findBytes(bytes, new Uint8Array([10, 10]));
  if (split < 0) fail('Missing native commit header boundary.');
  const rows = []; let start = 0;
  for (let i = 0; i <= split; i++) if (i === split || bytes[i] === 10) { rows.push(bytes.subarray(start, i)); start = i + 1; }
  const begins = (row, prefix) => eq(row.subarray(0, prefix.length), utf8.encode(prefix));
  if (!eq(rows[0], utf8.encode(`tree ${tree}`)) || !eq(rows[1], utf8.encode(`parent ${parent}`)) ||
      rows.filter(r => begins(r, 'tree ')).length !== 1 || rows.filter(r => begins(r, 'parent ')).length !== 1 ||
      rows.filter(r => begins(r, 'author ')).length !== 1 || rows.filter(r => begins(r, 'committer ')).length !== 1 ||
      !rows.some(r => eq(r, utf8.encode(`committer ${command.committer} ${command.timestamp} +0000`))) ||
      rows.some(r => begins(r, 'gpgsig ') || begins(r, 'gpgsig-sha256 ') || begins(r, 'mergetag '))) fail('Rewritten commit bytes changed parent, tree, committer, or signature policy.');
  check(); return bytes.length;
}
export async function inspectReply(reply, artifact, selection, crypto, check) {
  const { command: c, scope, metadata: p } = artifact;
  const pin = pinned(reply, scope, c.expected_head); noEffects(reply);
  if (reply.type !== 'rebase_inspection' || reply.profile !== 'linear-v1' || reply.source_head !== p.source_head ||
      reply.expected_source !== c.expected_source || reply.onto !== c.expected_onto || reply.candidate_commit !== p.candidate_commit ||
      reply.source_ref_hex !== hex(utf8.encode(c.source_ref)) || reply.onto_ref_hex !== hex(utf8.encode(c.onto_ref)) ||
      reply.approval_created !== false || reply.replay_equivalence_verified !== false || reply.complete !== true ||
      reply.all_changed_paths !== true || reply.all_rewritten_commits !== true || reply.binary_bodies_included !== false) fail('Inspection does not bind the complete requested rebase.');
  const bundle = record(reply.bundle);
  if (bundle.bytes !== artifact.bundle.length || bundle.sha256 !== artifact.sha256 || bundle.pack_objects !== p.pack_objects) fail('Inspection did not inspect the actual prepared bundle.');
  integer(bundle.pack_bytes, 'pack byte count', 0, bundle.bytes); integer(bundle.pack_objects, 'pack objects', 0, 4096);
  integer(bundle.transport_only_objects, 'transport-only objects', 0, bundle.pack_objects);
  integer(bundle.expanded_bytes, 'expanded bytes', 0, 64 * 1024 * 1024); integer(bundle.closure_objects, 'closure objects', 0, 100_000);
  const wanted = p.steps.filter(s => s.kind !== 'dropped_empty');
  if (bundle.pack_objects < wanted.length) fail('Bundle cannot contain all rewritten commits.');
  if (!Array.isArray(reply.commits) || reply.commit_count !== reply.commits.length || reply.commits.length !== wanted.length) fail('Incomplete rewritten-commit inspection.');
  const budget = { changes: 0, files: 0, hunks: 0, bytes: 0, bodies: 0 };
  const common = { command: c, scope, head: pin.head, sourceHead: p.source_head };
  comparison(reply.net_change, { ...common, before: c.expected_source, after: p.candidate_commit,
    beforeTree: selection.source.tree, afterTree: p.root_tree }, budget, check);
  let parent = c.expected_onto, tree = selection.onto.tree;
  for (let i = 0; i < wanted.length; i++) {
    check(); const row = record(reply.commits[i]), step = wanted[i];
    if (row.index !== i || row.commit !== step.rewritten || row.parent !== parent || row.tree !== step.tree) fail('Inspected rebase chain differs from the complete prepared steps.');
    charge(budget, 'bodies', await verifyCommit(row, parent, row.tree, c, crypto, check), 2 * 1024 * 1024);
    comparison(row.diff, { ...common, before: parent, after: row.commit, beforeTree: tree, afterTree: row.tree }, budget, check);
    parent = row.commit; tree = row.tree;
  }
  if (parent !== p.candidate_commit || tree !== p.root_tree) fail('Inspection ended before the final candidate.');
  check(); return reply;
}
