// Actual HTTP sockets; replies model the inspected native schema, NOT Rust fg.
// Object bytes/hashes originate here independently of the archive implementation.
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
export const token = 'a'.repeat(64);
export const nativeHash = (kind, bytes, algorithm) => createHash(algorithm).update(Buffer.from(`${kind} ${bytes.length}\0`)).update(bytes).digest('hex');
export const hex = bytes => Buffer.from(bytes).toString('hex');
export function repository(format = 'sha1', definitions = [
  { path: 'README.md', data: Buffer.from('hello\r\nworld\n') },
  { path: 'src/main.rs', kind: 'executable', data: Buffer.from('fn main() {}\n') },
  { path: 'link', kind: 'symlink', data: Buffer.from('../outside') },
  { path: 'vendor', kind: 'gitlink', target: 'b'.repeat(format === 'sha1' ? 40 : 64) },
]) {
  const root = { kind: 'directory', children: new Map() }, dirs = new Map(), files = new Map();
  for (const definition of definitions) {
    const path = Buffer.from(definition.path), parts = []; let start = 0;
    for (let end = 0; end <= path.length; end++) if (end === path.length || path[end] === 47) { parts.push(path.subarray(start, end)); start = end + 1; }
    let dir = root;
    for (const name of parts.slice(0, -1)) {
      const key = hex(name); if (!dir.children.has(key)) dir.children.set(key, { name, kind: 'directory', children: new Map() });
      dir = dir.children.get(key);
    }
    const name = parts.at(-1), kind = definition.kind ?? 'file';
    dir.children.set(hex(name), { name, kind, ...(kind === 'directory' ? { children: new Map() } : { data: definition.data, id: definition.target }) });
  }
  const mode = { directory: '40000', file: '100644', executable: '100755', symlink: '120000', gitlink: '160000' };
  function visit(directory, prefix) {
    for (const child of directory.children.values()) {
      const path = prefix === null ? child.name : Buffer.concat([prefix, Buffer.from('/'), child.name]);
      if (child.kind === 'directory') visit(child, path);
      else if (child.kind !== 'gitlink') { child.id = nativeHash('blob', child.data, format); files.set(hex(path), child); }
    }
    const rows = [...directory.children.values()];
    rows.sort((a, b) => Buffer.compare(Buffer.concat([a.name, Buffer.from(a.kind === 'directory' ? '/' : '\0')]),
      Buffer.concat([b.name, Buffer.from(b.kind === 'directory' ? '/' : '\0')])));
    directory.body = Buffer.concat(rows.map(row => Buffer.concat([Buffer.from(mode[row.kind] + ' '), row.name, Buffer.from([0]), Buffer.from(row.id, 'hex')])));
    directory.id = nativeHash('tree', directory.body, format); dirs.set(prefix === null ? null : hex(prefix), directory);
  }
  visit(root, null);
  const body = Buffer.from(`tree ${root.id}\nauthor Example <e@example.invalid> 1 +0000\ncommitter Example <e@example.invalid> 1 +0000\n\nsource archive\n`);
  const commit = nativeHash('commit', body, format), snapshot = `alg:2:${'d'.repeat(64)}`;
  const scope = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format };
  const common = { schema_version: 1, ...scope, source_head: 'fixture-source-head', source_commit: `${format}:${commit}`,
    ref: 'refs/heads/main', ref_hex: hex('refs/heads/main'), snapshot_token: snapshot,
    read_only: true, transaction_created: false, published: false };
  function answer(operation, form) {
    if (operation === 'log') return { ...common, type: 'source_log', author_identity_verified: false, page_complete: true,
      ordering: 'child-before-parent-native-id-v1', after: 0, limit: 1, total_commits: 1, next_after: null,
      commits: [{ object_id: `${format}:${commit}`, tree: `${format}:${root.id}`, parents: [], body_hex: hex(body) }] };
    const path = form.get('path_hex'), base = { ...common, source_rcr: 'fixture-rcr', root_tree: `${format}:${root.id}`, path_hex: path };
    if (operation === 'tree') {
      const dir = dirs.get(path), after = form.get('after_hex'), limit = Number(form.get('limit'));
      const all = [...dir.children.values()].sort((a, b) => Buffer.compare(a.name, b.name)).filter(row => after === null || hex(row.name) > after);
      const entries = all.slice(0, limit).map(row => ({ name_hex: hex(row.name), object_id: `${format}:${row.id}`, kind: row.kind }));
      return { ...base, type: 'source_tree', object_id: `${format}:${dir.id}`, after_hex: after, limit,
        next_after_hex: all.length > limit ? entries.at(-1).name_hex : null, entries };
    }
    const file = files.get(path), offset = Number(form.get('offset')), limit = Number(form.get('limit')), data = file.data.subarray(offset, offset + limit);
    return { ...base, type: 'source_blob', object_id: `${format}:${file.id}`, kind: file.kind, symlink_followed: false,
      total_bytes: file.data.length, offset, returned_bytes: data.length, next_offset: offset + data.length < file.data.length ? offset + data.length : null,
      content_hex: hex(data) };
  }
  return { format, dirs, files, root, body, commit, snapshot, scope, common, answer };
}
export async function fixture(t, options = {}) {
  const repo = repository(options.format, options.definitions), calls = [], control = {};
  const server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const form = new URLSearchParams(Buffer.concat(chunks).toString()), operation = request.url?.split('/api/v1/source/')[1];
    const call = { method: request.method, url: request.url, headers: request.headers, operation, form }; calls.push(call);
    if (request.method !== 'POST' || !['log', 'tree', 'blob'].includes(operation) || request.headers.authorization !== `Bearer ${token}` || request.headers['idempotency-key']) {
      response.writeHead(403); response.end(); return;
    }
    if (form.get('expected_commit') !== repo.commit || (form.has('expected_head') && form.get('expected_head') !== repo.snapshot)) { response.writeHead(409); response.end('{}'); return; }
    if (control.respond) { await control.respond(request, response, call); return; }
    const value = structuredClone(repo.answer(operation, form)); await control.mutate?.(value, call);
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  const endpoint = `http://127.0.0.1:${server.address().port}/repo.git`;
  return { repo, calls, control, server, selection: { endpoint, ...repo.scope, ref: 'refs/heads/main', expected_commit: repo.commit } };
}
