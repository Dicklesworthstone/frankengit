// Native-shaped HTTP doubles; not a live node or a second ancestry authorizer.
// Native object hashes are independently computed with Node's crypto library.
import { createHash, webcrypto } from 'node:crypto';
export const crypto = webcrypto, token = 'c'.repeat(64), href = 'https://forge.example/team/repo.git/ui/history/';
export const bytes = text => new TextEncoder().encode(text);
export const hex = value => Buffer.from(value).toString('hex');
export const hash = (kind, value, algorithm = 'sha1') => createHash(algorithm).update(`${kind} ${value.length}\0`).update(value).digest('hex');
export const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
export function commit(tree, parents, message, algorithm) {
  const body = Buffer.concat([bytes(`tree ${tree}\n${parents.map(p => `parent ${p}\n`).join('')}author Untrusted <u@example.invalid> 1 +0000\ncommitter Untrusted <u@example.invalid> 1 +0000\n\n`), bytes(message)]);
  return { object_id: hash('commit', body, algorithm), tree, parents, body_hex: hex(body) };
}
export function fixture(algorithm = 'sha1', path = '66696c65') {
  const old = bytes('one\r\ntwo'), current = bytes('ONE\r\ntwo'), oldBlob = hash('blob', old, algorithm), blob = hash('blob', current, algorithm);
  const treeOf = id => hash('tree', Buffer.concat([bytes('100644 '), Buffer.from(path, 'hex'), Buffer.from([0]), Buffer.from(id, 'hex')]), algorithm);
  const base = commit(treeOf(oldBlob), [], 'root\n', algorithm), tip = commit(treeOf(blob), [base.object_id], 'change\n', algorithm);
  const records = [tip, base], head = `alg:1:${'b'.repeat(64)}`, ref = 'refs/heads/main';
  const scope = { tenant: '1'.repeat(32), repository: '2'.repeat(32), incarnation: '3'.repeat(32), format: algorithm };
  const common = { schema_version: 1, tenant_id: scope.tenant, repository_id: scope.repository, repository_incarnation: scope.incarnation,
    object_format: algorithm, source_head: 'authority-head', snapshot_token: head, ref_hex: hex(bytes(ref)), source_commit: tip.object_id,
    read_only: true, transaction_created: false, published: false };
  const calls = [], config = { mutate: null, respond: null };
  function log(form) {
    const selected = form.has('path_hex'), queryPath = form.get('path_hex'), all = selected && queryPath !== path ? [] : records;
    const after = Number(form.get('after') ?? 0), limit = Number(form.get('limit') ?? 20), end = Math.min(after + limit, all.length);
    return { ...common, type: selected ? 'source_path_log' : 'source_log', author_identity_verified: false,
      ...(selected ? { path_hex: queryPath, path_selection: 'changed-against-any-parent-v1', total_commits_scope: 'matching-path', history_simplified: false, renames_followed: false } : {}),
      ordering: 'child-before-parent-native-id-v1', page_complete: true, after, limit, total_commits: all.length,
      next_after: end < all.length ? end : null, commits: all.slice(after, end) };
  }
  function blame(form) {
    const first = Number(form.get('line_start') ?? 0), end = Number(form.get('line_end') ?? 2), spans = [0, 5, 8];
    const lines = [
      { line: 0, byte_start: 0, byte_end: 5, origin_commit: tip.object_id, origin_blob: blob, origin_line: 0, origin_byte_start: 0, origin_byte_end: 5 },
      { line: 1, byte_start: 5, byte_end: 8, origin_commit: base.object_id, origin_blob: oldBlob, origin_line: 1, origin_byte_start: 5, origin_byte_end: 8 },
    ].slice(first, end);
    const ids = new Set(lines.map(line => line.origin_commit));
    return { ...common, type: 'source_blame', author_identity_verified: false, profile: 'exact-lines-all-parents-v1', scope: 'same_path',
      range_complete: true, line_origin: 0, tree: tip.tree, blob, path_hex: path, total_lines: 2, first_line: first, end_line: end,
      content_byte_start: spans[first], content_hex: hex(current.subarray(spans[first], spans[end])), graph_commits: 2,
      comparisons: 1, max_diff_work: 1000000, algorithms: ['Myers'],
      origins: records.filter(row => ids.has(row.object_id)).sort((a, b) => a.object_id < b.object_id ? -1 : 1), lines };
  }
  function historical(form, kind) {
    const at = form.get('at_commit'), isBase = at === base.object_id, body = isBase ? old : current, commit = isBase ? base : tip;
    const source = { ...common, source_commit: at, source_rcr: 'rcr-selected', root_tree: commit.tree, path_hex: form.get('path_hex') };
    if (kind === 'tree') Object.assign(source, { type: 'source_tree', object_id: commit.tree, after_hex: form.get('after_hex'), limit: Number(form.get('limit')),
      next_after_hex: null, entries: form.has('after_hex') ? [] : [{ name_hex: path, object_id: isBase ? oldBlob : blob, kind: 'file' }] });
    else {
      const offset = Number(form.get('offset')), limit = Number(form.get('limit')), content = body.subarray(offset, offset + limit), end = offset + content.length;
      Object.assign(source, { type: 'source_blob', object_id: isBase ? oldBlob : blob, kind: 'file', total_bytes: body.length,
        offset, returned_bytes: content.length, next_offset: end < body.length ? end : null, content_hex: hex(content), symlink_followed: false });
    }
    return { type: 'historical_source', schema_version: 1, selection: 'visible-ref-ancestor-v1', source_ref_tip: tip.object_id, at_commit: at,
      read_only: true, transaction_created: false, published: false, source };
  }
  const fetchImpl = async (url, options) => {
    const endpoint = new URL(url).pathname.split('/api/v1/source/')[1], form = new URLSearchParams(options.body);
    const call = { endpoint, url: String(url), form, options }; calls.push(call);
    if (config.respond) return config.respond(call);
    let value;
    if (endpoint === 'log') value = log(form);
    else if (endpoint === 'blame') value = blame(form);
    else if (['historical-tree', 'historical-blob'].includes(endpoint)) value = historical(form, endpoint.slice(11));
    else throw new Error(`Unexpected fixture endpoint ${endpoint}`);
    value = structuredClone(value); await config.mutate?.(value, call); return json(value);
  };
  return { algorithm, path, old, current, oldBlob, blob, base, tip, records, head, ref, scope, common, calls, config, log, blame, historical, fetchImpl };
}
export function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { resolve, promise }; }
