import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile, readFile, rm, rename, chmod, symlink, link } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanSourceWorkspace, workspaceScanScope, selectionFromWorkspaceScan, workspaceObservations,
  checkWorkspaceObservations, prepareWorkspaceScanCapture, workspaceScanCapturer, encodeWorkspaceScan as encode, workspaceScanHash as hash } from '../../scripts/operator/source_workspace_scan.mjs';

const hex = s => Buffer.from(s).toString('hex'), rootScope = { roots_hex: [''] };
import { fixture } from './source_workspace_scan.fixture.mjs';
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
for (const path of [Buffer.from('😀/🦀\n'), Buffer.from([0xff, 47, 0xfe])]) test(`byte paths remain exact through directory enumeration and hashing: ${path.toString('hex')}${process.platform === 'darwin' && path[0] === 0xff ? ' (typed host refusal)' : ''}`, async t => {
  if (process.platform === 'darwin' && path[0] === 0xff) {
    const f = await fixture(t);
    await assert.rejects(f.scan({ roots_hex: [path.toString('hex')] }),
      { code: 'source_workspace_scan_host_path_unrepresentable' });
    // The scope check must precede I/O: an absent root cannot turn the raw
    // request into an ENOENT or an apparently complete empty scan.
    await assert.rejects(scanSourceWorkspace(join(f.parent,'absent'), f.pin, { roots_hex: [path.toString('hex')] }),
      { code: 'source_workspace_scan_host_path_unrepresentable' });
    t.diagnostic('UNSUPPORTED_HOST_PATH: typed scope refusal before scan; exact raw-path scan runs on Linux, representable byte twin runs here.');
    return;
  }
  const f = await fixture(t, [{ path, body: Buffer.from([255, 0]) }]);
  await f.put(path, Buffer.from([254, 0])); const r = await f.scan();
  assert.equal(r.scan.entries[0].path_hex, path.toString('hex')); assert.equal(r.scan.entries[0].after.sha256, hash(Buffer.from([254, 0])));
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
  // This fixture has nine recorded names. Mutate before the final two-check
  // sweep of those names, independent of directory enumeration order.
  await f.scan(rootScope, { check: () => { count++; } }); let now = 0;
  await assert.rejects(f.scan(rootScope, { check: () => { if (++now === count - 20) { writeFileSync(f.local('src/a'), 'late'); changed = true; } } }), /changed/);
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
for (const format of ['sha1', 'sha256']) test(`${format}: reviewed scan becomes exact guarded selection through real select CLI`, async t => {
  const f = await fixture(t, undefined, format); await f.put('src/a', Buffer.from([255, 0, 10])); await rm(f.local('README')); await f.put('new', 'n');
  const report = await f.scan({ ...rootScope, include_unselected: true }), scanFile = join(f.parent, 'scan.json');
  await writeFile(scanFile, encode(report), { mode: 0o600 });
  const profiles = { byte_profile: 'binary-safe-v1', patch_profile: 'bounded-line-hunks-v1' };
  const wanted = await prepareWorkspaceScanCapture(f.root, f.pin, report, report.scan_sha256, profiles);
  const bytes = execFileSync(process.execPath, ['scripts/fg_source_workspace_scan.mjs', 'select', '--workspace', f.root, '--sha256', f.pin,
    '--scan', scanFile, '--approve-scan-sha256', report.scan_sha256, '--byte-profile', 'binary-safe-v1', '--patch-profile', 'bounded-line-hunks-v1'],
    { cwd: new URL('../..', import.meta.url), timeout: 10000 });
  assert.deepEqual(JSON.parse(bytes), wanted); assert.equal(wanted.observations.length, 3);
});
for (const [name, change] of [
  ['content', async f => f.put('src/a', 'later')], ['mode', async f => chmod(f.local('src/a'), 0o700)],
  ['deletion', async f => rm(f.local('src/a'))], ['additional unselected file', async f => f.put('new', 'new')],
  ['previously unchanged file', async f => f.put('README', 'later')],
]) test(`fresh selection rejects ${name} since review without capture effects`, async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(); await change(f);
  let called = false; const capture = workspaceScanCapturer(async () => { called = true; });
  await assert.rejects(capture(f.root, f.pin, r, r.scan_sha256, join(f.parent, 'out')), /stale/); assert.equal(called, false);
});
test('out-of-scope edits do not invalidate or broaden a reviewed selection', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan({ roots_hex: [hex('src')] });
  await f.put('README', 'outside'); await f.put('new-outside', 'outside');
  const selection = await prepareWorkspaceScanCapture(f.root, f.pin, r, r.scan_sha256);
  assert.deepEqual(selection.paths_hex, [hex('src/a')]);
});
function captureReply(root, pin, selection, out, commit) {
  return { type: 'source_workspace_change_capture', directory: out, workspace_sha256: pin,
    capture_sha256: hash(encode(selection)), draft_sha256: hash(Buffer.from('kernel fixture draft')),
    source_commit: commit, selected_path_count: selection.paths_hex.length, changed_path_count: selection.paths_hex.length,
    unchanged_path_count: 0, selected_files_only: true, source_material_untrusted: true, repository_changed: false };
}
test('capture composition uses exact paths/observations/profiles and one remaining deadline', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(), out = join(f.parent, 'capture'); let calls = 0;
  const capture = workspaceScanCapturer(async (root, pin, selection, output, options) => {
    calls++; assert.equal(root, f.root); assert.equal(pin, f.pin); assert.equal(output, out);
    assert.deepEqual(selection, selectionFromWorkspaceScan(r, r.scan_sha256, { patch_profile: 'bounded-line-hunks-v1' }));
    assert(options.timeoutMs > 0 && options.timeoutMs <= 10000); options.check();
    return captureReply(root, pin, selection, output, f.manifest.source_commit);
  });
  const result = await capture(f.root, f.pin, r, r.scan_sha256, out, { patch_profile: 'bounded-line-hunks-v1' }, { timeoutMs: 10000 });
  assert.equal(calls, 1); assert.equal(result.reviewed_scan_sha256, r.scan_sha256);
});
test('capturer preserves native uncertainty and never retries an output operation', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(); let calls = 0;
  const native = new Error('source_workspace_capture_readback'); native.publication_unconfirmed = { directory: join(f.parent, 'out'), capture_sha256: 'a'.repeat(64) };
  const capture = workspaceScanCapturer(async () => { calls++; throw native; });
  await assert.rejects(capture(f.root, f.pin, r, r.scan_sha256, native.publication_unconfirmed.directory), e => e === native);
  assert.equal(calls, 1);
});
test('completed local capture remains a known result after late cancellation', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(), c = new AbortController();
  const capture = workspaceScanCapturer(async (...args) => { c.abort(); return { ...captureReply(...args.slice(0, 4), f.manifest.source_commit), stop_requested: true }; });
  const result = await capture(f.root, f.pin, r, r.scan_sha256, join(f.parent, 'out'), {}, { signal: c.signal });
  assert.equal(result.capture.stop_requested, true); assert.equal(result.reviewed_scan_sha256, r.scan_sha256);
});
test('a mismatched successful capture reply is retained as unconfirmed, not accepted', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(), out = join(f.parent, 'out');
  const capture = workspaceScanCapturer(async (...args) => ({ ...captureReply(...args.slice(0, 4), f.manifest.source_commit), source_commit: '0'.repeat(40) }));
  await assert.rejects(capture(f.root, f.pin, r, r.scan_sha256, out), e => e.publication_unconfirmed?.directory === out);
});
test('invalid scope, changed workspace binding and overlapping outputs refuse before capture', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(); let calls = 0;
  const capture = workspaceScanCapturer(async () => { calls++; });
  for (const output of [f.root, join(f.root, 'nested'), f.parent]) await assert.rejects(capture(f.root, f.pin, r, r.scan_sha256, output));
  await assert.rejects(capture(f.root, '0'.repeat(64), r, r.scan_sha256, join(f.parent, 'out')), /subject/);
  assert.equal(calls, 0);
});
for (const [name, change] of [
  ['unknown state', r => r.scan.entries[0].state = 'passed'], ['forged deletion', r => r.scan.entries[0].state = 'deleted'],
  ['duplicate path', r => r.scan.entries.push(r.scan.entries[0])], ['extra row field', r => r.scan.entries[0].force = true],
  ['missing digest', r => r.scan.entries[0].after.sha256 = null], ['invalid count', r => r.scan.entries[0].after.bytes = -1],
  ['empty slot', r => { r.scan.entries[0].before = null; r.scan.entries[0].after = null; }],
  ['authority claim', r => r.scan.native_membership_reverified = true], ['unknown root field', r => r.scan.token = 'secret'],
  ['moved outside scope', r => r.scan.scope.roots_hex = [hex('other')]],
]) test(`review decoding refuses ${name} even with recalculated local checksums`, async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(); change(r);
  r.scan_sha256 = hash(encode(r.scan)); assert.throws(() => selectionFromWorkspaceScan(r, r.scan_sha256));
});
test('async scan preflight owns inputs; caller mutations cannot replace approved observations', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(), original = structuredClone(r);
  const operation = prepareWorkspaceScanCapture(f.root, f.pin, r, r.scan_sha256);
  r.scan.scope.include_unselected = true; r.scan.entries[1].after.sha256 = '0'.repeat(64);
  assert.deepEqual(await operation, selectionFromWorkspaceScan(original, original.scan_sha256));
});
