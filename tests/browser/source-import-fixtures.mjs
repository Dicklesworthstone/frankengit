// Independent native object construction and explicit HTTP doubles. No Rust
// engine or real browser is executed by this fixture.
import { createHash, webcrypto } from 'node:crypto';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
export const crypto = webcrypto, token = '7'.repeat(64);
export const href = 'http://127.0.0.1:9418/repo.git/ui/source/';
export const bytes = text => new TextEncoder().encode(text);
export const hex = data => Buffer.from(data).toString('hex');
export const pathHex = text => hex(bytes(text));
export function hash(kind, body, algorithm = 'sha1') {
  return createHash(algorithm).update(`${kind} ${body.length}\0`).update(body).digest('hex');
}
export function entry(path = 'file.txt', content = 'before\n', mode = 0o100644) {
  return { path_hex: pathHex(path), bytes: typeof content === 'string' ? bytes(content) : content, mode };
}
export function upload(name, content = 'new\n', relative = '') {
  const data = typeof content === 'string' ? bytes(content) : content;
  return { name, webkitRelativePath: relative, size: data.length, reads: 0,
    async arrayBuffer() { this.reads++; return data.slice().buffer; } };
}
export function inventory(entries, algorithm) {
  const directories = new Map(), files = new Map(), root = new Map();
  for (const item of entries) {
    const pieces = Buffer.from(item.path_hex, 'hex').toString('latin1').split('/');
    let dir = root;
    for (const name of pieces.slice(0, -1)) {
      if (!dir.has(name)) dir.set(name, new Map());
      dir = dir.get(name);
    }
    const value = { ...item, object_id: hash('blob', item.bytes, algorithm) };
    files.set(item.path_hex, value); dir.set(pieces.at(-1), value);
  }
  function build(dir, prefix) {
    const rows = [...dir].map(([name, value]) => {
      const name_hex = Buffer.from(name, 'latin1').toString('hex');
      const full = prefix ? `${prefix}2f${name_hex}` : name_hex;
      if (value instanceof Map) return { name_hex, object_id: build(value, full), kind: 'directory', mode: '40000' };
      return { name_hex, object_id: value.object_id,
        kind: ({ [0o100644]: 'file', [0o100755]: 'executable', [0o120000]: 'symlink', [0o160000]: 'gitlink' })[value.mode], mode: value.mode.toString(8) };
    });
    const treeOrder = [...rows].sort((a, b) => Buffer.compare(
      Buffer.concat([Buffer.from(a.name_hex, 'hex'), Buffer.from(a.kind === 'directory' ? '/' : '\0')]),
      Buffer.concat([Buffer.from(b.name_hex, 'hex'), Buffer.from(b.kind === 'directory' ? '/' : '\0')])));
    const body = Buffer.concat(treeOrder.flatMap(r => [Buffer.from(r.mode + ' '), Buffer.from(r.name_hex, 'hex'), Buffer.from([0]), Buffer.from(r.object_id, 'hex')]));
    const id = hash('tree', body, algorithm);
    directories.set(prefix || null, { id, rows: rows.sort((a, b) => a.name_hex < b.name_hex ? -1 : 1) });
    return id;
  }
  const tree = build(root, ''), body = bytes(`tree ${tree}\nauthor A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\nfixture\n`);
  return { tree, commit: hash('commit', body, algorithm), files, directories, commitBody: body };
}
export function fixture(entries = [entry()], algorithm = 'sha1') {
  const store = inventory(entries, algorithm), calls = [], config = { tree: null, blob: null, wait: null, status: null };
  const common = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: algorithm,
    ref: 'refs/heads/main', ref_hex: pathHex('refs/heads/main'), source_head: 'head-test', snapshot_token: `alg:2:${'4'.repeat(64)}`,
    source_rcr: 'rcr-original', source_commit: store.commit, root_tree: store.tree, read_only: true, transaction_created: false, published: false };
  async function fetchImpl(url, options) {
    const endpoint = new URL(url).pathname.split('/api/v1/')[1], command = new URLSearchParams(options.body);
    calls.push({ endpoint, command, options }); if (config.wait) await config.wait(endpoint, command);
    const status = typeof config.status === 'function' ? config.status(endpoint, command) : config.status;
    if (status) return new Response('{}', { status, headers: { 'Content-Type': 'application/json' } });
    let reply;
    if (endpoint === 'source/tree') {
      const path = command.get('path_hex'), after = command.get('after_hex'), limit = Number(command.get('limit'));
      const directory = store.directories.get(path);
      if (!directory) throw new Error('Unexpected directory read');
      const rows = directory.rows.filter(r => after === null || r.name_hex > after).slice(0, limit);
      reply = { ...common, type: 'source_tree', path_hex: path, after_hex: after, limit, object_id: directory.id,
        entries: rows.map(({mode, ...row}) => row), next_after_hex: rows.length === limit ? rows.at(-1).name_hex : null };
      await config.tree?.(reply, command);
    } else if (endpoint === 'source/blob') {
      const value = store.files.get(command.get('path_hex'));
      if (!value) throw new Error('Unexpected absent blob read');
      const length = Math.min(Number(command.get('limit')), value.bytes.length);
      reply = { ...common, type: 'source_blob', path_hex: value.path_hex, object_id: value.object_id,
        kind: value.mode === 0o100755 ? 'executable' : 'file', offset: 0, total_bytes: value.bytes.length,
        returned_bytes: length, content_hex: hex(value.bytes.subarray(0, length)), next_offset: length < value.bytes.length ? length : null, symlink_followed: false };
      await config.blob?.(reply, command);
    } else throw new Error(`Unexpected import mutation ${endpoint}`);
    return new Response(JSON.stringify(reply), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  return { ...store, entries, common, algorithm, calls, config, fetchImpl };
}
export async function setup(entries, algorithm = 'sha1', options = {}) {
  const f = fixture(entries, algorithm), c = new SourceEditClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl, ...options });
  await c.connect(token); await c.select(f.common.ref, algorithm); f.calls.length = 0;
  return { f, c };
}
