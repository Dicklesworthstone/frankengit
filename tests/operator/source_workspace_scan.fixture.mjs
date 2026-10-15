import { mkdtemp, mkdir, writeFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { scanSourceWorkspace, encodeWorkspaceScan as encode, workspaceScanHash as hash } from '../../scripts/operator/source_workspace_scan.mjs';
const rootScope = { roots_hex: [''] };
const nativeHash = (type, body, format) => createHash(format).update(`${type} ${body.length}\0`).update(body).digest('hex');
// Real native tree/commit/blob bytes in the existing package/workspace formats.
// This builds inputs independently; these tests cover filesystem discovery and
// pinned custody, not the shared native membership verifier or Rust admission.
export async function fixture(t, initial = [{ path: 'src/a', body: 'old\n' }, { path: 'README', body: 'read\n' }], format = 'sha1') {
  const parent = await mkdtemp(join(tmpdir(), 'fg-scan-')); await chmod(parent, 0o700);
  t.after(() => rm(parent, { recursive: true, force: true }));
  const root = join(parent, 'work'); await mkdir(root, { mode: 0o700 }); await mkdir(join(root, 'files'), { mode: 0o700 });
  const input = initial.map(f => ({ path: Buffer.from(f.path), body: Buffer.from(f.body), executable: f.executable ?? false })).sort((a, b) => Buffer.compare(a.path, b.path));
  const tree = new Map(), files = [], blobs = new Map();
  for (const f of input) {
    const id = nativeHash('blob', f.body, format), parts = f.path.toString('latin1').split('/'); let node = tree;
    for (const part of parts.slice(0, -1)) { if (!node.has(part)) node.set(part, new Map()); node = node.get(part); }
    node.set(parts.at(-1), { id, executable: f.executable }); blobs.set(id, f.body.toString('hex'));
    files.push({ path_hex: f.path.toString('hex'), blob: id, executable: f.executable, bytes: f.body.length });
    let dir = Buffer.from(`${root}/files`);
    for (const part of parts.slice(0, -1)) { dir = Buffer.concat([dir, Buffer.from('/'), Buffer.from(part, 'latin1')]); await mkdir(dir, { recursive: true, mode: 0o700 }); }
    await writeFile(Buffer.concat([dir, Buffer.from('/'), Buffer.from(parts.at(-1), 'latin1')]), f.body, { mode: f.executable ? 0o700 : 0o600 });
  }
  const trees = [];
  function build(node, pathHex = null) {
    const rows = [...node].sort(([a, av], [b, bv]) => Buffer.compare(Buffer.from(a + (av instanceof Map ? '/' : ''), 'latin1'), Buffer.from(b + (bv instanceof Map ? '/' : ''), 'latin1')));
    const body = Buffer.concat(rows.map(([name, item]) => {
      const nameHex = Buffer.from(name, 'latin1').toString('hex'), sub = item instanceof Map;
      const id = sub ? build(item, pathHex === null ? nameHex : `${pathHex}2f${nameHex}`) : item.id;
      return Buffer.concat([Buffer.from(`${sub ? '40000' : item.executable ? '100755' : '100644'} `), Buffer.from(name, 'latin1'), Buffer.from([0]), Buffer.from(id, 'hex')]);
    }));
    const id = nativeHash('tree', body, format); trees.push({ pathHex, oid: id, bodyHex: body.toString('hex') }); return id;
  }
  const rootTree = build(tree), body = Buffer.from(`tree ${rootTree}\nauthor Test <test@example.invalid> 0 +0000\ncommitter Test <test@example.invalid> 0 +0000\n\nbase\n`);
  const commit = nativeHash('commit', body, format);
  const expected = { format, commit, files: files.map(f => ({ pathHex: f.path_hex, blob: f.blob })) };
  const pkg = { schema: 'frankengit-selected-source-package-v1', membership: {
    schema: 'frankengit-context-membership-proof-v1', objectFormat: format, commit: { oid: commit, bodyHex: body.toString('hex') },
    trees: trees.sort((a, b) => a.pathHex === null ? -1 : b.pathHex === null ? 1 : a.pathHex < b.pathHex ? -1 : 1),
    files: files.map(f => ({ pathHex: f.path_hex, blob: f.blob, kind: f.executable ? 'executable' : 'file' })),
  }, blobs: [...blobs].sort().map(([oid, bytesHex]) => ({ oid, bytesHex })) };
  const src = encode(pkg), exp = encode(expected), manifest = { schema: 'frankengit-selected-source-workspace-v1',
    package_sha256: hash(src), package_bytes: src.length, expected_sha256: hash(exp), expected_bytes: exp.length,
    object_format: format, source_commit: commit, root_tree: rootTree, files };
  const pin = hash(encode(manifest));
  for (const [name, bytes] of [['source.json', src], ['expected.json', exp], ['manifest.json', encode(manifest)]]) await writeFile(join(root, name), bytes, { mode: 0o600 });
  const local = s => Buffer.concat([Buffer.from(`${root}/files/`), Buffer.from(s)]);
  const put = async (p, body, mode = 0o600) => writeFile(local(p), body, { mode });
  return { root, parent, pin, manifest, pkg, expected, local, put,
    scan: (scope = rootScope, options = {}) => scanSourceWorkspace(root, pin, scope, options) };
}
