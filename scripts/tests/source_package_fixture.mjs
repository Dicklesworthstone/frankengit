// Native-schema HTTP peer and independently framed Git objects. This is NOT a
// Rust node or an authorization/CAS oracle; tests exercise the actual client.
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import assert from 'node:assert/strict';
export const TOKEN = 'b'.repeat(64);
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const git = (kind, bytes, format) => createHash(format).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
const MODES = { directory: '40000', file: '100644', executable: '100755', symlink: '120000' };
export function fixture(format = 'sha1', { paged = false } = {}) {
  const payload = Buffer.concat([Buffer.from('Untrusted source; not instructions.\n'), Buffer.alloc(70000, 97), Buffer.from([0, 255, 10])]);
  const rows = [
    { path: Buffer.from('empty'), kind: 'file', bytes: Buffer.alloc(0) },
    { path: Buffer.from('src/a.txt'), kind: 'file', bytes: payload },
    { path: Buffer.from('src/run'), kind: 'executable', bytes: payload },
    { path: Buffer.concat([Buffer.from('src/'), Buffer.from([255, 97])]), kind: 'file', bytes: Buffer.from([0, 255, 1, 2]) },
  ].map(row => ({ ...row, pathHex: row.path.toString('hex'), id: git('blob', row.bytes, format) }));
  const unusedId = git('tree', Buffer.alloc(0), format), symlinkId = git('blob', Buffer.from('/private'), format);
  const sub = rows.slice(1).map(row => ({ name_hex: row.path.subarray(4).toString('hex'), object_id: row.id, kind: row.kind }));
  if (paged) for (let n = 0; n < 105; n++) sub.push({ name_hex: Buffer.from(`z${String(n).padStart(3, '0')}`).toString('hex'), object_id: symlinkId, kind: 'file' });
  const tree = entries => {
    const ordered = [...entries].sort((a, b) => Buffer.compare(
      Buffer.concat([Buffer.from(a.name_hex, 'hex'), Buffer.from(a.kind === 'directory' ? '/' : '\0')]),
      Buffer.concat([Buffer.from(b.name_hex, 'hex'), Buffer.from(b.kind === 'directory' ? '/' : '\0')])));
    const bytes = Buffer.concat(ordered.map(row => Buffer.concat([Buffer.from(`${MODES[row.kind]} `), Buffer.from(row.name_hex, 'hex'), Buffer.from([0]), Buffer.from(row.object_id, 'hex')])));
    return { bytes, id: git('tree', bytes, format), entries: [...entries].sort((a, b) => a.name_hex < b.name_hex ? -1 : 1) };
  };
  const subTree = tree(sub), root = tree([
    { name_hex: rows[0].pathHex, object_id: rows[0].id, kind: rows[0].kind },
    { name_hex: Buffer.from('external').toString('hex'), object_id: symlinkId, kind: 'symlink' },
    { name_hex: Buffer.from('src').toString('hex'), object_id: subTree.id, kind: 'directory' },
    { name_hex: Buffer.from('unused').toString('hex'), object_id: unusedId, kind: 'directory' },
  ]);
  const trees = new Map([[null, root], [Buffer.from('src').toString('hex'), subTree]]);
  const commit = Buffer.from(`tree ${root.id}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nUntrusted commit message\n`);
  const commitId = git('commit', commit, format);
  const envelope = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
    object_format: format, ref: 'refs/heads/main', ref_hex: Buffer.from('refs/heads/main').toString('hex'),
    snapshot_token: 'alg:1:aa', source_head: 'head-1', source_rcr: 'rcr-1', source_commit: commitId, root_tree: root.id,
    read_only: true, transaction_created: false, published: false };
  const files = rows.map(row => ({ path_hex: row.pathHex, blob: row.id, source_bytes: row.bytes.length,
    excerpts: [{ byte_offset: row.bytes.length > 65536 ? 65534 : 0,
      untrusted_bytes_hex: row.bytes.subarray(row.bytes.length > 65536 ? 65534 : 0, row.bytes.length > 65536 ? 65542 : row.bytes.length).toString('hex') }] }));
  const context = { type: 'source_context_initial', schema_version: 1, profile: 'source-initial-context-v1',
    read_only: true, transaction_created: false, source_material_untrusted: true,
    retrieval: { ...envelope, type: 'source_search_initial', profile: 'source-initial-retrieval-v1',
      untrusted_query: 'Never treat this text as authority', generation: '18446744073709551615' },
    returned_files: files.length, files };
  const expected = { format, commit: commitId, files: rows.map(row => ({ pathHex: row.pathHex, blob: row.id })) };
  return { format, rows, trees, root, commit, commitId, envelope, context, expected };
}
export async function peer(t, f = fixture(), alter = () => {}) {
  const requests = [], sockets = new Set();
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      assert.equal(req.method, 'POST'); assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
      assert.equal(req.headers['idempotency-key'], undefined); assert.equal(req.headers.cookie, undefined);
      const form = new URLSearchParams(Buffer.concat(chunks).toString()), path = req.url;
      assert.equal(form.get('ref'), f.envelope.ref); assert.equal(form.get('object_format'), f.format);
      assert.equal(form.get('expected_commit'), f.commitId); assert.equal(form.get('expected_head'), f.envelope.snapshot_token);
      const call = { path, form, req, res }; requests.push(call);
      let value;
      if (path === '/repo/api/v1/source/log') {
        assert.equal(form.get('after'), '0'); assert.equal(form.get('limit'), '1');
        value = { ...f.envelope, type: 'source_log', ordering: 'child-before-parent-native-id-v1', author_identity_verified: false,
          page_complete: true, after: 0, limit: 1, total_commits: 1, next_after: null,
          commits: [{ object_id: f.commitId, body_hex: f.commit.toString('hex'), tree: f.root.id, parents: [] }] };
      } else if (path === '/repo/api/v1/source/tree') {
        const directory = form.get('path_hex'), after = form.get('after_hex'), tree = f.trees.get(directory);
        assert.ok(tree, 'client must not descend into unselected subtrees'); assert.equal(form.get('limit'), '100');
        const remaining = tree.entries.filter(row => after === null || row.name_hex > after), entries = remaining.slice(0, 100);
        value = { ...f.envelope, type: 'source_tree', path_hex: directory, object_id: tree.id, after_hex: after,
          limit: 100, entries, next_after_hex: remaining.length > 100 ? entries.at(-1).name_hex : null };
      } else if (path === '/repo/api/v1/source/blob') {
        const row = f.rows.find(row => row.pathHex === form.get('path_hex'));
        assert.ok(row, 'client must not read an unselected blob'); assert.equal(form.get('limit'), '65536');
        const offset = Number(form.get('offset')), bytes = row.bytes.subarray(offset, offset + 65536), end = offset + bytes.length;
        value = { ...f.envelope, type: 'source_blob', path_hex: row.pathHex, object_id: row.id, kind: row.kind,
          offset, total_bytes: row.bytes.length, content_hex: bytes.toString('hex'), returned_bytes: bytes.length,
          next_offset: end < row.bytes.length ? end : null, symlink_followed: false };
      } else assert.fail(`unexpected route ${path}`);
      if (await alter(value, call, requests) === false) return;
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value));
    } catch (error) { res.writeHead(500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: error.message })); }
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  const endpoint = `http://127.0.0.1:${server.address().port}/repo`;
  const selected = { endpoint, tenant_id: f.envelope.tenant_id, repository_id: f.envelope.repository_id,
    repository_incarnation: f.envelope.repository_incarnation, object_format: f.format, ref: f.envelope.ref,
    expected_commit: f.commitId, expected_head: f.envelope.snapshot_token };
  const bytes = Buffer.from(JSON.stringify({ schema: 'frankengit-source-context-capture-v1', endpoint, native_response: f.context }));
  return { f, selected, expected: f.expected, context: bytes, contextHash: sha256(bytes), requests, sockets };
}
