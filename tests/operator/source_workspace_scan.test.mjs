import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, rename, chmod, symlink, link } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { scanSourceWorkspace, workspaceScanScope, selectionFromWorkspaceScan, workspaceObservations,
  checkWorkspaceObservations, encodeWorkspaceScan as encode, workspaceScanHash as hash } from '../../scripts/operator/source_workspace_scan.mjs';

const hex = s => Buffer.from(s).toString('hex'), rootScope = { roots_hex: [''] };
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
for (const format of ['sha1', 'sha256']) test(`${format}: discover modified, deleted, unselected and unchanged without mutating inputs`, async t => {
  const f = await fixture(t, undefined, format), before = await readFile(join(f.root, 'manifest.json'));
  await f.put('src/a', 'new\n'); await rm(f.local('README')); await f.put('new', Buffer.from([0, 255, 10]));
  const report = await f.scan({ ...rootScope, include_unselected: true });
  assert.deepEqual(report.scan.entries.map(r => r.state), ['deleted', 'unselected', 'modified']);
  const selection = selectionFromWorkspaceScan(report, report.scan_sha256, { byte_profile: 'binary-safe-v1', patch_profile: 'bounded-line-hunks-v1' });
  assert.equal(selection.paths_hex.length, 3); assert.equal(selection.observations[0].sha256, null);
  assert.equal(selection.observations[1].sha256, hash(Buffer.from([0, 255, 10])));
  assert.deepEqual(await readFile(join(f.root, 'manifest.json')), before);
  assert.equal(report.scan.native_membership_reverified, false); assert.equal(report.scan.repository_changed, false);
  assert.equal(report.scan.absence_verified, false);
});
test('unselected files are visible but excluded from capture unless explicitly included', async t => {
  const f = await fixture(t); await f.put('new', 'new'); await f.put('src/a', 'edited');
  const r = await f.scan(), s = selectionFromWorkspaceScan(r, r.scan_sha256);
  assert.deepEqual(s.paths_hex, [hex('src/a')]); assert.equal(r.scan.entries.find(e => e.path_hex === hex('new')).state, 'unselected');
});
test('directory scopes and explicit exclusions cannot imply deletion outside the scope', async t => {
  const f = await fixture(t); await rm(f.local('README')); await f.put('src/a', 'changed');
  await mkdir(f.local('src/build'), { mode: 0o755 }); await symlink('/etc', f.local('src/build/unsafe'));
  const r = await f.scan({ roots_hex: [hex('src')], exclude_hex: [hex('src/build')] });
  assert.deepEqual(r.scan.entries.map(e => e.path_hex), [hex('src/a')]);
  const omitted = await f.scan({ ...rootScope, exclude_hex: [hex('src')] });
  assert.deepEqual(omitted.scan.entries.map(e => e.path_hex), [hex('README')]);
});
test('removing a complete materialized directory discovers its selected deletions', async t => {
  const f = await fixture(t, [{ path: 'one/two/a', body: 'a' }, { path: 'one/two/b', body: 'b' }, { path: 'keep', body: 'k' }]);
  await rm(f.local('one'), { recursive: true });
  const r = await f.scan({ roots_hex: [hex('one/two')] }); assert.deepEqual(r.scan.entries.map(r => r.state), ['deleted', 'deleted']);
});
test('empty/missing selected directory is idle, not implicit file creation', async t => {
  const f = await fixture(t); const r = await f.scan({ roots_hex: [hex('missing')] }); assert.deepEqual(r.scan.entries, []);
  assert.throws(() => selectionFromWorkspaceScan(r, r.scan_sha256), /capture_count/);
});
test('mode-only changes are discovered; identical replacement bytes preserve review identity', async t => {
  const f = await fixture(t); await chmod(f.local('src/a'), 0o700); const a = await f.scan();
  assert.equal(a.scan.entries.find(r => r.path_hex === hex('src/a')).state, 'modified');
  await f.put('temp', 'old\n', 0o700); await rename(f.local('temp'), f.local('src/a'));
  const b = await f.scan(); assert.deepEqual(a, b);
});
test('byte paths remain exact through directory enumeration and hashing', async t => {
  const path = Buffer.from([0xff, 47, 0xfe]); const f = await fixture(t, [{ path, body: Buffer.from([255, 0]) }]);
  await f.put(path, Buffer.from([254, 0])); const r = await f.scan();
  assert.equal(r.scan.entries[0].path_hex, 'ff2ffe'); assert.equal(r.scan.entries[0].after.sha256, hash(Buffer.from([254, 0])));
});
for (const [name, setup] of [
  ['file symlink', async f => { await rm(f.local('src/a')); await symlink('/etc/passwd', f.local('src/a')); }],
  ['directory symlink', async f => { await rename(f.local('src'), f.local('old')); await symlink(f.local('old'), f.local('src')); }],
  ['hardlink', async f => link(f.local('src/a'), f.local('copy'))],
  ['writable file', async f => chmod(f.local('src/a'), 0o666)],
  ['excess execute permissions', async f => chmod(f.local('src/a'), 0o711)],
  ['nonprivate directory', async f => chmod(f.local('src'), 0o755)],
  ['FIFO', async f => { await rm(f.local('src/a')); execFileSync('mkfifo', [f.local('src/a')]); }],
  ['dot git', async f => { await mkdir(f.local('.git'), { mode: 0o700 }); }],
]) test(`refuses ${name} without reading through it`, async t => { const f = await fixture(t); await setup(f); await assert.rejects(f.scan()); });
for (const name of ['manifest.json', 'source.json', 'expected.json']) test(`retained ${name} corruption is not accepted as a new baseline`, async t => {
  const f = await fixture(t); await writeFile(join(f.root, name), '{}\n'); await assert.rejects(f.scan());
});
test('unknown manifest fields and package/blob mismatch refuse even with a caller-supplied replacement pin', async t => {
  const f = await fixture(t); f.manifest.extra = true; await writeFile(join(f.root, 'manifest.json'), encode(f.manifest));
  await assert.rejects(scanSourceWorkspace(f.root, hash(encode(f.manifest)), rootScope));
});
for (const [field, limit] of [['entries', 1], ['directories', 1], ['files', 1], ['fileBytes', 1], ['totalBytes', 1], ['pathsBytes', 1], ['reportBytes', 1]])
  test(`${field} exhaustion refuses rather than returning a partial report`, async t => { const f = await fixture(t); await assert.rejects(f.scan(rootScope, { limits: { [field]: limit } })); });
test('directory entry cap also charges excluded names', async t => {
  const f = await fixture(t); await assert.rejects(f.scan({ ...rootScope, exclude_hex: [hex('README'), hex('src')] }, { limits: { entries: 1 } }), /entry_budget/);
});
test('capture ceiling never silently selects the first 32 changes', async t => {
  const f = await fixture(t); for (let i = 0; i < 33; i++) await f.put(`new${i}`, 'x');
  const r = await f.scan({ ...rootScope, include_unselected: true }); assert.throws(() => selectionFromWorkspaceScan(r, r.scan_sha256), /capture_count/);
});
for (const scope of [{}, { roots_hex: [] }, { roots_hex: ['', hex('src')] }, { roots_hex: ['2e2e'] }, { roots_hex: ['2f'] },
  { roots_hex: ['00'] }, { roots_hex: [hex('.Git')] }, { roots_hex: ['AA'] }, { roots_hex: ['0'] },
  { roots_hex: [hex('a')], exclude_hex: [hex('b')] }, { roots_hex: [''], exclude_hex: [''] },
  { roots_hex: [''], include_unselected: 1 }, { roots_hex: [''], ignore_git: true }])
  test(`closed directory scope refuses ${JSON.stringify(scope)}`, () => assert.throws(() => workspaceScanScope(scope)));
test('a stopped caller cannot begin observation', async t => {
  const f = await fixture(t), c = new AbortController(); c.abort(); await assert.rejects(f.scan(rootScope, { signal: c.signal }));
});
test('mid-observation cancellation closes the directory and file handles', async t => {
  const f = await fixture(t), c = new AbortController(); let checkpoints = 0;
  await assert.rejects(f.scan(rootScope, { signal: c.signal, check: () => { if (++checkpoints === 40) c.abort(); } }));
  assert.equal((await f.scan()).scan.entries.length, 2);
});
test('a late content change invalidates the entire report', async t => {
  const f = await fixture(t); let changed = false, count = 0;
  // A second complete baseline read cannot hide a file mutation during its
  // final observation sweep: use a checkpoint near the end of the same scan.
  await f.scan(rootScope, { check: () => { count++; } }); let now = 0;
  await assert.rejects(f.scan(rootScope, { check: () => { if (++now === count - 3) { writeFileSync(f.local('src/a'), 'late'); changed = true; } } }), /changed/);
  assert(changed);
});
test('root path aliases and changed reviewed scope/pins are refused', async t => {
  const f = await fixture(t); await f.put('src/a', 'changed'); const r = await f.scan();
  await assert.rejects(scanSourceWorkspace(`${f.root}/.`, f.pin, rootScope));
  await assert.rejects(scanSourceWorkspace(f.root, '0'.repeat(64), rootScope));
  const copy = structuredClone(r); copy.scan.scope.include_unselected = true;
  assert.throws(() => selectionFromWorkspaceScan(copy, r.scan_sha256), /approval/);
  assert.throws(() => selectionFromWorkspaceScan(r, '0'.repeat(64)), /approval/);
});
test('observations enforce exact content, mode and absence at capture reread', () => {
  const paths = [hex('a'), hex('b')], rows = workspaceObservations([
    { path_hex: paths[0], sha256: hash(Buffer.from('x')), bytes: 1, executable: false },
    { path_hex: paths[1], sha256: null, bytes: 0, executable: null },
  ], paths);
  const good = () => new Map([[paths[0], { bytes: Buffer.from('x'), executable: false }], [paths[1], null]]);
  checkWorkspaceObservations(rows, good());
  for (const change of [m => m.get(paths[0]).bytes.fill(121), m => m.get(paths[0]).executable = true,
    m => m.set(paths[0], null), m => m.set(paths[1], { bytes: Buffer.alloc(0), executable: false }), m => m.delete(paths[1])]) {
    const m = good(); change(m); assert.throws(() => checkWorkspaceObservations(rows, m), /changed/);
  }
  assert.throws(() => workspaceObservations(rows, [...paths].reverse()));
  assert.throws(() => workspaceObservations([{ ...rows[0], bytes: -1 }, rows[1]], paths));
  assert.throws(() => workspaceObservations([rows[0], { ...rows[1], executable: false }], paths));
});
test('scan is independent of directory insertion order', async t => {
  const f = await fixture(t); await f.put('z', 'z'); await f.put('b', 'b'); const first = await f.scan();
  await rm(f.local('z')); await rm(f.local('b')); await f.put('b', 'b'); await f.put('z', 'z');
  assert.deepEqual(await f.scan(), first);
});
for (const format of ['sha1', 'sha256']) test(`${format}: real scan CLI emits the same pinned report as the production module`, async t => {
  const f = await fixture(t, undefined, format), scopePath = join(f.parent, 'scope.json');
  await f.put('src/a', 'edited'); await f.put('new', 'new');
  const scope = { ...rootScope, include_unselected: true }; await writeFile(scopePath, encode(scope), { mode: 0o600 });
  const expected = await f.scan(scope);
  const bytes = execFileSync(process.execPath, ['scripts/fg_source_workspace_scan.mjs', 'scan', '--workspace', f.root, '--sha256', f.pin, '--scope', scopePath], { cwd: new URL('../..', import.meta.url), timeout: 10000 });
  assert.deepEqual(JSON.parse(bytes), expected);
});
test('real CLI refuses invalid scope, extra flags, nonprivate inputs, and unknown operations', async t => {
  const f = await fixture(t), scopePath = join(f.parent, 'scope.json'); await writeFile(scopePath, encode(rootScope), { mode: 0o600 });
  const args = ['scripts/fg_source_workspace_scan.mjs', 'scan', '--workspace', f.root, '--sha256', f.pin, '--scope', scopePath];
  const bad = [args.concat(['--force', 'true']), [args[0], 'capture'], args.concat(['--scope', scopePath])];
  for (const a of bad) assert.throws(() => execFileSync(process.execPath, a, { cwd: new URL('../..', import.meta.url), stdio: 'pipe' }), e => e.status === 2);
  await chmod(scopePath, 0o644); assert.throws(() => execFileSync(process.execPath, args, { cwd: new URL('../..', import.meta.url), stdio: 'pipe' }), e => e.status === 2);
});
