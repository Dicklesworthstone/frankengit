// Complete production archive/transport imports and real sockets. The peer is
// an explicit native-schema fixture, not a Rust fg server or authority oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureSource, captureSourcePaths, validateCapture, validatePathCapture, sourcePaths } from '../../scripts/operator/source_archive.mjs';
import { fixture, token, hex } from './fixtures/source_archive_native.mjs';
const clone = value => { const next = structuredClone(value); next.files.forEach(f => f.bytes = Buffer.from(f.bytes)); return next; };
const definitions = [
  { path: 'a/unselected/huge', data: Buffer.alloc(65536, 3) },
  { path: 'src/one.rs', data: Buffer.from('pub fn One() {}\r\n') },
  { path: 'src/nested/two.rs', data: Buffer.from('pub fn Two() {}\n') },
  { path: 'src/sibling', data: Buffer.alloc(65536, 4) },
  { path: 'src2/unrelated', data: Buffer.alloc(65536, 5) },
];
for (const format of ['sha1', 'sha256']) {
  test(`${format}: selected paths prove membership without fetching unrelated trees or blobs`, async t => {
    const f = await fixture(t, { format, definitions }), paths = [hex('src/one.rs'), hex('src/nested/two.rs')];
    const { capture, metrics } = await captureSourcePaths(f.selection, token, paths);
    const verified = validatePathCapture(capture, f.selection, paths);
    assert.equal(verified.complete_repository, false); assert.deepEqual(verified.verified_paths_hex, [...paths].sort());
    assert.equal(verified.root_tree, f.repo.root.id); assert.equal(verified.files, 2); assert.equal(verified.directories, 3);
    assert.deepEqual(f.calls.filter(c => c.operation === 'tree').map(c => c.form.get('path_hex')), [null, hex('src'), hex('src/nested')]);
    assert.deepEqual(f.calls.filter(c => c.operation === 'blob').map(c => c.form.get('path_hex')).sort(), paths.sort());
    for (const file of capture.files) assert.deepEqual(file.bytes, f.repo.files.get(file.path_hex).data);
    for (const call of f.calls) { assert.equal(call.form.get('expected_commit'), f.repo.commit); assert.equal(call.headers['idempotency-key'], undefined); }
    assert.equal(metrics.requests, 6); assert.equal(metrics.blob_bytes, 33);
    assert.throws(() => validateCapture(capture), /fields|Unsupported/);
    const full = await captureSource(f.selection, token); assert.equal(validateCapture(full.capture).files, 5);
    assert.throws(() => validatePathCapture(full.capture, f.selection, paths));
    const root = await mkdtemp(join(tmpdir(), 'fg-sparse-git-')); t.after(() => rm(root, { recursive: true, force: true }));
    execFileSync('git', ['init', '--quiet', `--object-format=${format}`, root]);
    for (const [kind, rows] of [['commit', [capture.commit]], ['tree', capture.trees], ['blob', capture.files]]) for (const row of rows) {
      assert.equal(execFileSync('git', ['-C', root, 'hash-object', '-t', kind, '--stdin'],
        { input: row.bytes ?? Buffer.from(row.body_hex, 'hex') }).toString().trim(), row.object_id);
    }
  });
  test(`${format}: raw paths, shared trees, executable and empty blobs retain exact identities`, async t => {
    const defs = [{ path: Buffer.from('src/\xff', 'latin1'), kind: 'executable', data: Buffer.alloc(0) },
      { path: 'src/other', data: Buffer.alloc(0) }, { path: 'src2/ignore', data: Buffer.from('other') }];
    const f = await fixture(t, { format, definitions: defs }), paths = defs.slice(0, 2).map(d => hex(d.path));
    const { capture, metrics } = await captureSourcePaths(f.selection, token, paths);
    assert.equal(validatePathCapture(capture, f.selection, paths).blob_bytes, 0);
    assert.equal(metrics.blob_requests, 1); assert.equal(metrics.deduplicated_files, 1);
    assert.equal(capture.files.find(row => row.path_hex === paths[0]).kind, 'executable');
  });
  test(`${format}: all requested bodies must exist before blob acquisition begins`, async t => {
    const f = await fixture(t);
    for (const paths of [[hex('missing')], [hex('src/missing')], [hex('src')], [hex('vendor')], [hex('link/child')]]) {
      const before = f.calls.length;
      await assert.rejects(captureSourcePaths(f.selection, token, paths), /Missing|requires a file/);
      assert.ok(!f.calls.slice(before).some(c => c.operation === 'blob'));
    }
    const { capture } = await captureSourcePaths(f.selection, token, [hex('link')]);
    assert.equal(capture.files[0].kind, 'symlink'); assert.equal(capture.files[0].bytes.toString(), '../outside');
    assert.equal(validatePathCapture(capture, f.selection, [hex('link')]).files, 1);
  });
}

test('sparse proofs reject grafts, missing parents, unrelated material and independently changed roots/paths', async t => {
  const f = await fixture(t, { definitions }), paths = [hex('src/nested/two.rs')];
  const { capture } = await captureSourcePaths(f.selection, token, paths);
  for (const mutate of [c => c.trees.pop(), c => c.files.pop(), c => c.files[0].bytes[0] ^= 1,
    c => c.trees[0].body_hex += '00', c => c.commit.body_hex += '00', c => c.files[0].path_hex = hex('src/fake'),
    c => c.trees.push(c.trees[0]), c => c.files.push(c.files[0]), c => c.files[0].kind = 'executable',
    c => c.paths_hex.push(hex('src/one.rs')), c => c.selection.expected_commit = 'f'.repeat(40)]) {
    const changed = clone(capture); mutate(changed); assert.throws(() => validatePathCapture(changed, f.selection, paths));
  }
  for (const patch of [{ expected_commit: 'e'.repeat(40) }, { repository_incarnation: 'e'.repeat(32) },
    { endpoint: 'https://other.example/repo.git' }, { expected_head: `alg:2:${'e'.repeat(64)}` }]) {
    assert.throws(() => validatePathCapture(capture, { ...f.selection, ...patch }, paths));
  }
  assert.throws(() => validatePathCapture(capture, f.selection, [hex('src/one.rs')]));
  const full = (await captureSource(f.selection, token)).capture;
  const changed = clone(capture); changed.files.push(full.files.find(row => row.path_hex === hex('src/one.rs')));
  assert.throws(() => validatePathCapture(changed, f.selection, paths), /extra/);
  const extra = clone(capture); extra.trees.push(full.trees.find(row => row.path_hex === hex('src2')));
  assert.throws(() => validatePathCapture(extra, f.selection, paths), /extra/);
});

test('a self-consistent selected blob cannot replace another path in a commitment-checked parent', async t => {
  const f = await fixture(t, { definitions }), paths = [hex('src/one.rs'), hex('src/nested/two.rs')];
  const { capture } = await captureSourcePaths(f.selection, token, paths); const c = clone(capture);
  c.files[0].bytes = Buffer.from(c.files[1].bytes); c.files[0].object_id = c.files[1].object_id;
  assert.throws(() => validatePathCapture(c, f.selection, paths), /membership/);
});

test('logical budgets count every selected file despite blob deduplication; exact boundaries remain permitted', async t => {
  const f = await fixture(t, { definitions: [{ path: 'a', data: Buffer.alloc(19, 7) }, { path: 'b', data: Buffer.alloc(19, 7) }] });
  const paths = [hex('a'), hex('b')], { capture, metrics } = await captureSourcePaths(f.selection, token, paths);
  const v = validatePathCapture(capture, f.selection, paths);
  const limits = { maxEntries: v.entries.length, maxTrees: v.directories, maxTreeBytes: v.tree_bytes,
    maxBlobBytes: 19, maxTotalBlobBytes: 38, maxRequests: metrics.requests };
  await captureSourcePaths(f.selection, token, paths, { limits });
  for (const key of Object.keys(limits).filter(k => limits[k] > 1)) {
    await assert.rejects(captureSourcePaths(f.selection, token, paths, { limits: { ...limits, [key]: limits[key] - 1 } }), key);
  }
  assert.equal(metrics.deduplicated_files, 1); assert.equal(metrics.blob_bytes, 38);
  capture.files[0].bytes[0] = 1; assert.equal(capture.files[1].bytes[0], 7);
});

test('a paged parent must reconstruct every entry even when only one file is requested', async t => {
  const defs = Array.from({ length: 105 }, (_, i) => ({ path: `f${String(i).padStart(3, '0')}`, data: Buffer.from(`${i}`) }));
  const f = await fixture(t, { definitions: defs }), paths = [hex('f104')];
  const { capture } = await captureSourcePaths(f.selection, token, paths);
  assert.equal(capture.files.length, 1); assert.equal(f.calls.filter(c => c.operation === 'tree').length, 2);
  assert.equal(f.calls.filter(c => c.operation === 'blob').length, 1);
  f.control.mutate = (r, c) => { if (c.operation === 'tree' && c.form.has('after_hex')) r.entries.shift(); };
  await assert.rejects(captureSourcePaths(f.selection, token, paths), /native tree/);
});

for (const [label, mutate] of [
  ['scope', r => r.repository_id = 'e'.repeat(32)], ['head', r => r.snapshot_token = `alg:2:${'e'.repeat(64)}`],
  ['commit', r => r.source_commit = 'e'.repeat(40)], ['root', r => r.root_tree = 'e'.repeat(40)],
  ['record', r => r.source_rcr = 'other'], ['payload', r => r.content_hex = 'ff' + r.content_hex.slice(2)],
  ['follow symlink', r => r.symlink_followed = true], ['kind', r => r.kind = 'symlink'],
]) test(`sparse acquisition refuses changed ${label} without returning a prefix`, async t => {
  const f = await fixture(t); f.control.mutate = (r, c) => { if (c.operation === 'blob') mutate(r); };
  await assert.rejects(captureSourcePaths(f.selection, token, [hex('README.md')]));
});

test('paths and caller options are detached before the first await; malformed input never opens a socket', async t => {
  const f = await fixture(t), paths = [hex('README.md')], options = { limits: { maxTotalBlobBytes: 20 } };
  const running = captureSourcePaths(f.selection, token, paths, options);
  paths[0] = hex('link'); options.limits.maxTotalBlobBytes = 1;
  const result = await running; assert.equal(result.capture.files[0].path_hex, hex('README.md'));
  const before = f.calls.length;
  for (const paths of [[], [hex('a'), hex('a')], [hex('../b')], ['zz'], [hex('src'), hex('src/a')],
    Array.from({ length: 33 }, (_, i) => hex(String(i)))]) {
    await assert.rejects(captureSourcePaths(f.selection, token, paths));
  }
  await assert.rejects(captureSourcePaths(f.selection, token, [hex('link')], { reuse: result.capture }));
  assert.equal(f.calls.length, before);
  // Bytes 0x12,0xf0 contain hex digits "2f" across a nibble boundary, not a slash.
  assert.deepEqual(sourcePaths(['12f0']), ['12f0']);
});

for (const status of [301, 401, 403, 409, 413, 429, 503]) test(`HTTP ${status} refuses sparse read without retries`, async t => {
  const f = await fixture(t); f.control.respond = (_req, res) => { res.writeHead(status); res.end('{}'); };
  await assert.rejects(captureSourcePaths(f.selection, token, [hex('README.md')]), e => e.status === status);
  assert.equal(f.calls.length, 1);
});

test('cancellation and an overall deadline drain the read instead of yielding partial proof', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(captureSourcePaths(f.selection, token, [hex('README.md')], { signal: stop.signal }));
  assert.equal(f.calls.length, 0);
  f.control.mutate = () => new Promise(resolve => setTimeout(resolve, 40));
  await assert.rejects(captureSourcePaths(f.selection, token, [hex('src/main.rs')], { limits: { timeoutMs: 65 } }), /deadline/);
  assert.ok(f.calls.length <= 2);
});
