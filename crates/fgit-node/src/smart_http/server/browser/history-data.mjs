// Native history is derived read data, not author authentication or write authority.
import { fail, record, integer, text, format, oid, binding, snapshot, opaque, utf8, hex, unhex } from './pulls-core.mjs';
import { findBytes, joinBytes } from './pulls-candidate.mjs';
export const HISTORY_LIMITS = Object.freeze({ reply: 8 * 1024 * 1024, commits: 4096, edges: 16384,
  metadata: 4 * 1024 * 1024, commitBytes: 65536, blob: 1024 * 1024, lines: 20000, comparisons: 128 });
export function fullRef(value) {
  text(value, 1024, 'reference', true);
  if (!value.startsWith('refs/') || /[\x00-\x20\x7f~^:?*\[\\]/u.test(value) || value.includes('..') || value.includes('@{') ||
      value.endsWith('.') || value.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) fail('A complete native reference is required.');
  return value;
}
export function bytePath(value, root = false) {
  if (value === null && root) return null;
  const bytes = unhex(value, 4096);
  if (!bytes.length || bytes.includes(0)) fail('An exact nonempty repository path is required.');
  let start = 0, depth = 0;
  for (let i = 0; i <= bytes.length; i++) if (i === bytes.length || bytes[i] === 47) {
    const part = bytes.subarray(start, i);
    if (++depth > 64 || !part.length || (part.length <= 2 && part.every(byte => byte === 46))) fail('Invalid repository path component.');
    start = i + 1;
  }
  return value;
}
export function readOnly(reply) {
  record(reply);
  if (reply.read_only !== true || reply.transaction_created !== false || reply.published !== false) fail('History unexpectedly claims publication.');
}
export function selected(reply, request, previous = null, historicalCommit = null) {
  readOnly(reply);
  const scope = binding(reply, previous?.scope), head = snapshot(reply.snapshot_token);
  opaque(reply.source_head);
  if (scope.format !== request.object_format || reply.ref_hex !== hex(utf8.encode(request.ref))) fail('Source reference or hash domain changed.');
  const tip = oid(reply.source_commit, scope.format);
  if (previous && (head !== previous.head || tip !== (historicalCommit ?? previous.tip))) fail('Source snapshot moved. Reopen explicitly.');
  return { ref: request.ref, object_format: scope.format, scope, head, tip };
}
export async function nativeHash(kind, bytes, algorithm, crypto) {
  format(algorithm);
  if (!['blob', 'commit'].includes(kind) || !(bytes instanceof Uint8Array) || bytes.length > HISTORY_LIMITS.blob) fail('Invalid native hashing request.');
  return hex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256',
    joinBytes(utf8.encode(`${kind} ${bytes.length}\0`), bytes))));
}
// Preserve arbitrary message/identity bytes. Only tree/parent headers are decoded
// as ASCII IDs; signature continuation lines are never mistaken for headers.
export async function commitRecord(row, algorithm, crypto, check = () => {}) {
  record(row); check();
  const id = oid(row.object_id, algorithm), tree = oid(row.tree, algorithm), bytes = unhex(row.body_hex, HISTORY_LIMITS.commitBytes);
  if (!Array.isArray(row.parents) || row.parents.length > HISTORY_LIMITS.edges) fail('Invalid commit parents.');
  const parents = row.parents.map(value => oid(value, algorithm));
  if (parents.includes(id)) fail('Self-referential history.');
  if (await nativeHash('commit', bytes, algorithm, crypto) !== id) fail('Commit bytes do not match their native identity.');
  check();
  const split = findBytes(bytes, Uint8Array.of(10, 10));
  if (split < 0) fail('Malformed commit headers.');
  const headers = [], rawParents = []; let at = 0, rawTree = null;
  while (at <= split) {
    const end = bytes.indexOf(10, at), stop = end < 0 || end > split ? split : end;
    const line = bytes.subarray(at, stop);
    const prefix = name => name.every((b, i) => line[i] === b);
    if (prefix(utf8.encode('tree ')) || prefix(utf8.encode('parent '))) {
      const isTree = line[0] === 116, width = isTree ? 5 : 7;
      const raw = new TextDecoder('utf-8', { fatal: true }).decode(line.subarray(width));
      if (!new RegExp(`^[0-9a-fA-F]{${algorithm === 'sha1' ? 40 : 64}}$`).test(raw)) fail('Invalid commit reference header.');
      if (isTree) { if (rawTree !== null || at !== 0) fail('Ambiguous commit tree.'); rawTree = raw.toLowerCase(); }
      else rawParents.push(raw.toLowerCase());
    }
    headers.push(hex(line)); if (stop === split) break; at = stop + 1;
  }
  if (rawTree !== tree || JSON.stringify(rawParents) !== JSON.stringify(parents)) fail('Commit summary disagrees with its original headers.');
  return { id, tree, parents, body_hex: row.body_hex, headers_hex: headers, message_hex: hex(bytes.subarray(split + 2)) };
}
export async function logPage(reply, request, previous, options, crypto, check) {
  const selection = selected(reply, request, previous), { after, limit, path_hex } = options;
  if (reply.author_identity_verified !== false || reply.type !== (path_hex === null ? 'source_log' : 'source_path_log') ||
      reply.ordering !== 'child-before-parent-native-id-v1' || reply.page_complete !== true || reply.after !== after || reply.limit !== limit) fail('Invalid native history page.');
  if (path_hex !== null && (reply.path_hex !== path_hex || reply.path_selection !== 'changed-against-any-parent-v1' ||
      reply.total_commits_scope !== 'matching-path' || reply.history_simplified !== false || reply.renames_followed !== false)) fail('Path history selection changed.');
  integer(reply.total_commits, 'history count', path_hex === null ? 1 : 0, HISTORY_LIMITS.commits);
  if (after > reply.total_commits || !Array.isArray(reply.commits) || reply.commits.length !== Math.min(limit, reply.total_commits - after)) fail('Incomplete history page.');
  const end = after + reply.commits.length;
  if (reply.next_after !== (end < reply.total_commits ? end : null)) fail('Invalid history continuation.');
  const seen = new Set(), commits = []; let metadata = 0;
  for (const row of reply.commits) {
    if (typeof row?.body_hex !== 'string' || (metadata += row.body_hex.length / 2) > HISTORY_LIMITS.metadata) fail('Commit metadata budget exceeded.');
    const commit = await commitRecord(row, selection.object_format, crypto, check);
    if (seen.has(commit.id) || commit.parents.some(parent => seen.has(parent))) fail('Duplicate or non-topological commit page.');
    seen.add(commit.id); commits.push(commit);
  }
  if (path_hex === null && after === 0 && commits[0]?.id !== selection.tip) fail('History does not start at its selected tip.');
  check(); return { selection, commits, after, limit, path_hex, total: reply.total_commits, next: reply.next_after, raw: reply };
}
export async function blamePage(reply, selection, query, crypto, check) {
  selected(reply, selection, selection);
  if (reply.type !== 'source_blame' || reply.author_identity_verified !== false || reply.profile !== 'exact-lines-all-parents-v1' ||
      reply.scope !== 'same_path' || reply.range_complete !== true || reply.line_origin !== 0 || reply.path_hex !== query.path_hex ||
      reply.first_line !== query.first) fail('Invalid native blame selection.');
  integer(reply.total_lines, 'file lines', 0, HISTORY_LIMITS.lines);
  integer(reply.end_line, 'range end', query.first, reply.total_lines);
  if (reply.end_line !== (query.end ?? reply.total_lines) || !Array.isArray(reply.lines) || reply.lines.length !== reply.end_line - query.first) fail('Incomplete blame range.');
  oid(reply.tree, selection.object_format); const blob = oid(reply.blob, selection.object_format);
  integer(reply.graph_commits, 'ancestry count', 1, HISTORY_LIMITS.commits);
  integer(reply.comparisons, 'line comparisons', 0, HISTORY_LIMITS.comparisons);
  if (reply.max_diff_work !== 1000000 || !Array.isArray(reply.algorithms) || reply.algorithms.length > HISTORY_LIMITS.comparisons ||
      new Set(reply.algorithms).size !== reply.algorithms.length) fail('Invalid blame work report.');
  for (const algorithm of reply.algorithms) text(algorithm, 128, 'diff algorithm', true);
  const content = unhex(reply.content_hex, HISTORY_LIMITS.blob);
  if (content.includes(0)) fail('Binary content is outside native line blame.');
  integer(reply.content_byte_start, 'content offset', 0, HISTORY_LIMITS.blob - content.length);
  if (!Array.isArray(reply.origins) || reply.origins.length > HISTORY_LIMITS.commits) fail('Invalid origin set.');
  const origins = new Map(); let metadata = 0, last = '';
  for (const row of reply.origins) {
    if (typeof row?.body_hex !== 'string' || (metadata += row.body_hex.length / 2) > HISTORY_LIMITS.metadata) fail('Origin metadata budget exceeded.');
    const origin = await commitRecord(row, selection.object_format, crypto, check);
    if (origin.id <= last) fail('Unordered or duplicate blame origins.'); last = origin.id; origins.set(origin.id, origin);
  }
  let cursor = reply.content_byte_start; const used = new Set(), lines = [];
  for (let i = 0; i < reply.lines.length; i++) {
    check(); const line = record(reply.lines[i]);
    if (line.line !== query.first + i || line.byte_start !== cursor) fail('Gap in attributed content.');
    integer(line.byte_end, 'line end', cursor + 1, reply.content_byte_start + content.length);
    integer(line.origin_line, 'origin line', 0, HISTORY_LIMITS.lines - 1);
    integer(line.origin_byte_start, 'origin byte offset', 0, HISTORY_LIMITS.blob);
    integer(line.origin_byte_end, 'origin byte end', line.origin_byte_start + 1, HISTORY_LIMITS.blob);
    const origin = oid(line.origin_commit, selection.object_format), originBlob = oid(line.origin_blob, selection.object_format);
    if (!origins.has(origin) || line.byte_end - cursor !== line.origin_byte_end - line.origin_byte_start) fail('Invalid line origin.');
    const bytes = content.subarray(cursor - reply.content_byte_start, line.byte_end - reply.content_byte_start);
    if (bytes.subarray(0, bytes.length - 1).includes(10) || (line.line + 1 < reply.total_lines && bytes.at(-1) !== 10)) fail('Attribution row is not exactly one native line.');
    lines.push({ ...line, origin_commit: origin, origin_blob: originBlob, content_hex: hex(bytes) });
    cursor = line.byte_end; used.add(origin);
  }
  if (cursor !== reply.content_byte_start + content.length || used.size !== origins.size) fail('Unused origins or unattributed content.');
  if (query.first === 0 && reply.content_byte_start !== 0) fail('Full-prefix blame has an offset.');
  const full = query.first === 0 && reply.end_line === reply.total_lines;
  if (full && await nativeHash('blob', content, selection.object_format, crypto) !== blob) fail('Complete blame contents do not match the native blob.');
  check(); return { selection, query, lines, origins: [...origins.values()], total: reply.total_lines, fullBlobVerified: full, raw: reply };
}
export async function historicalPage(reply, selection, query, crypto, check) {
  readOnly(reply);
  if (reply.schema_version !== 1 || reply.type !== 'historical_source' || reply.selection !== 'visible-ref-ancestor-v1' ||
      oid(reply.source_ref_tip, selection.object_format) !== selection.tip || oid(reply.at_commit, selection.object_format) !== query.commit) fail('Historical ancestor selection changed.');
  const source = record(reply.source);
  selected(source, selection, selection, query.commit);
  if (source.path_hex !== query.path_hex) fail('Historical path changed.');
  const object = oid(source.object_id, selection.object_format), tree = oid(source.root_tree, selection.object_format); opaque(source.source_rcr);
  if (query.kind === 'tree') {
    if (source.type !== 'source_tree' || source.after_hex !== query.after || source.limit !== query.limit ||
        !Array.isArray(source.entries) || source.entries.length > query.limit || (query.path_hex === null && object !== tree)) fail('Invalid historical directory.');
    let last = query.after ?? '';
    for (const entry of source.entries) {
      bytePath(entry.name_hex);
      if (unhex(entry.name_hex).includes(47) || entry.name_hex <= last || !['file', 'executable', 'directory', 'symlink', 'gitlink'].includes(entry.kind)) fail('Invalid historical directory entry.');
      last = entry.name_hex; oid(entry.object_id, selection.object_format);
    }
    if (source.next_after_hex !== null && (source.entries.length !== query.limit || source.next_after_hex !== last)) fail('Invalid historical directory continuation.');
  } else {
    if (source.type !== 'source_blob' || source.offset !== query.offset || source.symlink_followed !== false ||
        !['file', 'executable', 'symlink'].includes(source.kind)) fail('Invalid historical file.');
    integer(source.total_bytes, 'historical file bytes', query.offset, 16 * 1024 * 1024);
    const bytes = unhex(source.content_hex, query.limit), end = query.offset + bytes.length;
    if (source.returned_bytes !== bytes.length || bytes.length !== Math.min(query.limit, source.total_bytes - query.offset) ||
        source.next_offset !== (end < source.total_bytes ? end : null)) fail('Incomplete historical file range.');
    if (query.offset === 0 && end === source.total_bytes && await nativeHash('blob', bytes, selection.object_format, crypto) !== object) fail('Historical bytes do not match their native object.');
  }
  check(); return { selection, query, source, raw: reply };
}
