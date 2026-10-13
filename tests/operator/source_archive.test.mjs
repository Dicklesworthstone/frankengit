import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureSource, validateCapture, archiveSelection, ARCHIVE_LIMITS, treeBody } from '../../scripts/operator/source_archive.mjs';
import { fixture, token, hex, nativeHash } from './fixtures/source_archive_native.mjs';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

for (const format of ['sha1', 'sha256']) {
  test(`${format}: complete snapshot preserves every tree, file, executable, symlink and gitlink`, async t => {
    const f = await fixture(t, { format }); const { capture, metrics } = await captureSource(f.selection, token);
    const report = validateCapture(capture);
    assert.equal(report.root_tree, f.repo.root.id); assert.equal(report.files, 3); assert.equal(report.directories, 2); assert.equal(report.gitlinks, 1);
    for (const row of capture.files) assert.deepEqual(row.bytes, f.repo.files.get(row.path_hex).data);
    assert.equal(capture.commit.body_hex, hex(f.repo.body)); assert.equal(capture.snapshot_token, f.repo.snapshot);
    assert.equal(metrics.requests, 6); assert.ok(metrics.wire_bytes > metrics.blob_bytes);
    assert.equal(JSON.stringify(capture).includes(token), false);
    for (const call of f.calls) {
      assert.equal(call.method, 'POST'); assert.equal(call.headers['idempotency-key'], undefined);
      assert.equal(call.headers.cookie, undefined); assert.equal(call.headers['accept-encoding'], 'identity');
      assert.equal(call.form.get('expected_commit'), f.repo.commit);
      if (call.operation !== 'log') assert.equal(call.form.get('expected_head'), f.repo.snapshot);
    }
    assert.deepEqual(f.calls.map(c => c.operation), ['log', 'tree', 'tree', 'blob', 'blob', 'blob']);
  });
  test(`${format}: independently installed Git hashes the exact captured tree and commit bytes`, async t => {
    const root = await mkdtemp(join(tmpdir(), 'fg-archive-oracle-')); t.after(() => rm(root, { recursive: true, force: true }));
    execFileSync('git', ['init', '--quiet', `--object-format=${format}`, root]);
    const f = await fixture(t, { format, definitions: [{ path: 'a/z', data: Buffer.from('z') }, { path: 'a.c', data: Buffer.from('x') }, { path: 'a0', data: Buffer.alloc(0) }] });
    const { capture } = await captureSource(f.selection, token);
    for (const row of [...capture.trees.map(row => ({ ...row, type: 'tree' })), { ...capture.commit, type: 'commit' }]) {
      const actual = execFileSync('git', ['-C', root, 'hash-object', '-t', row.type, '--stdin'], { input: Buffer.from(row.body_hex, 'hex') }).toString().trim();
      assert.equal(row.object_id, actual);
    }
    assert.ok(Buffer.from(capture.trees[0].body_hex, 'hex').indexOf(Buffer.from('a.c\0')) < Buffer.from(capture.trees[0].body_hex, 'hex').indexOf(Buffer.from('a\0')));
  });
  test(`${format}: full files spanning several native ranges are checked before return`, async t => {
    const data = Buffer.alloc(2 * 1024 * 1024 + 17, 0xa7), f = await fixture(t, { format, definitions: [{ path: 'binary', data }] });
    const result = await captureSource(f.selection, token); assert.deepEqual(result.capture.files[0].bytes, data);
    assert.deepEqual(f.calls.filter(c => c.operation === 'blob').map(c => c.form.get('offset')), ['0', '1048576', '2097152']);
    assert.equal(result.metrics.blob_bytes, data.length);
  });
}

test('empty root and empty files are complete, not unavailable', async t => {
  for (const definitions of [[], [{ path: 'empty', data: Buffer.alloc(0) }], [{ path: 'empty-dir', kind: 'directory' }]]) {
    const f = await fixture(t, { definitions }), result = await captureSource(f.selection, token);
    assert.equal(validateCapture(result.capture).blob_bytes, 0);
  }
});
test('paged trees retain raw name cursors and byte-only paths without decoding them', async t => {
  const definitions = Array.from({ length: 105 }, (_, i) => ({ path: `f${String(i).padStart(3, '0')}`, data: Buffer.from(String(i)) }));
  definitions.push({ path: Buffer.from([0xff]), data: Buffer.from([0, 255, 10]) });
  const f = await fixture(t, { definitions }), result = await captureSource(f.selection, token);
  const reads = f.calls.filter(c => c.operation === 'tree'); assert.equal(reads.length, 2);
  assert.equal(reads[1].form.get('after_hex'), hex('f099'));
  assert.equal(result.capture.files.find(row => row.path_hex === 'ff').bytes[1], 255);
});

for (const [name, mutate] of [
  ['repository', r => r.repository_id = '9'.repeat(32)], ['incarnation', r => r.repository_incarnation = '9'.repeat(32)],
  ['format', r => r.object_format = 'sha256'], ['commit', r => r.source_commit = 'e'.repeat(40)],
  ['reference', r => r.ref_hex = hex('refs/heads/other')], ['authority head', r => r.snapshot_token = `alg:2:${'e'.repeat(64)}`],
  ['effect', r => r.published = true], ['tree', r => r.root_tree = 'e'.repeat(40)], ['source record', r => r.source_rcr = 'changed'],
]) test(`a changed ${name} never produces a successful source prefix`, async t => {
  const f = await fixture(t); f.control.mutate = (r, c) => { if (c.operation === 'blob') mutate(r); };
  await assert.rejects(captureSource(f.selection, token));
});
for (const [name, mutate] of [
  ['missing', r => r.entries.pop()], ['duplicate', r => r.entries.push(r.entries[0])], ['unsorted', r => r.entries.reverse()],
  ['mode', r => r.entries[0].kind = 'directory'], ['different object', r => r.entries[0].object_id = 'e'.repeat(40)],
  ['traversal', r => r.entries[0].name_hex = hex('../outside')], ['unknown type', r => r.entries[0].kind = 'socket'],
  ['bad continuation', r => r.next_after_hex = r.entries[0].name_hex], ['missing page count', r => r.limit = 99],
]) test(`${name} directory entry refuses before any blob read`, async t => {
  const f = await fixture(t); f.control.mutate = (r, c) => { if (c.operation === 'tree') mutate(r); };
  await assert.rejects(captureSource(f.selection, token)); assert.ok(!f.calls.some(c => c.operation === 'blob'));
});
for (const [name, mutate] of [
  ['body hash', r => r.commits[0].body_hex += '00'], ['summary tree', r => r.commits[0].tree = 'e'.repeat(40)],
  ['summary parents', r => r.commits[0].parents = ['e'.repeat(40)]], ['missing commit', r => r.commits = []],
  ['ordering', r => r.ordering = 'date'], ['incomplete page', r => r.page_complete = false],
]) test(`invalid initial ${name} refuses before tree discovery`, async t => {
  const f = await fixture(t); f.control.mutate = mutate; await assert.rejects(captureSource(f.selection, token)); assert.equal(f.calls.length, 1);
});
for (const [name, mutate] of [
  ['payload', r => r.content_hex = '00' + r.content_hex.slice(2)], ['kind', r => r.kind = 'symlink'],
  ['range offset', r => r.offset++], ['range count', r => r.returned_bytes++], ['continuation', r => r.next_offset = 1],
  ['symlink traversal', r => r.symlink_followed = true], ['path', r => r.path_hex = hex('other')],
]) test(`invalid blob ${name} cannot escape as a complete result`, async t => {
  const f = await fixture(t, { definitions: [{ path: 'file', data: Buffer.from('content') }] });
  f.control.mutate = (r, c) => { if (c.operation === 'blob') mutate(r); };
  await assert.rejects(captureSource(f.selection, token));
});
test('corruption and source size drift in the final file range withhold all accumulated bytes', async t => {
  for (const mutate of [r => r.content_hex = 'ff' + r.content_hex.slice(2), r => r.total_bytes--]) {
    const f = await fixture(t, { definitions: [{ path: 'file', data: Buffer.alloc(1024 * 1024 + 2, 10) }] });
    f.control.mutate = (r, c) => { if (c.operation === 'blob' && Number(c.form.get('offset')) > 0) mutate(r); };
    await assert.rejects(captureSource(f.selection, token)); assert.equal(f.calls.length, 4);
  }
});
test('explicit expected commit and snapshot pins are never refreshed', async t => {
  const f = await fixture(t);
  await assert.rejects(captureSource({ ...f.selection, expected_commit: 'f'.repeat(40) }, token), e => e.status === 409);
  await assert.rejects(captureSource({ ...f.selection, expected_head: `alg:2:${'f'.repeat(64)}` }, token), e => e.status === 409);
  assert.equal(f.calls.length, 2);
});
test('exact budgets permit the near-identical case and one-unit shortfalls refuse', async t => {
  const f = await fixture(t), { capture, metrics } = await captureSource(f.selection, token), report = validateCapture(capture);
  const exact = { maxEntries: report.entries.length, maxTrees: report.directories, maxTreeBytes: report.tree_bytes,
    maxBlobBytes: Math.max(...capture.files.map(r => r.bytes.length)), maxTotalBlobBytes: report.blob_bytes, maxRequests: metrics.requests };
  await captureSource(f.selection, token, { limits: exact });
  for (const key of Object.keys(exact)) if (exact[key] > 1) await assert.rejects(captureSource(f.selection, token, { limits: { ...exact, [key]: exact[key] - 1 } }), key);
});
test('depth, request and total wire limits are aggregate rather than reset per read', async t => {
  const f = await fixture(t);
  await assert.rejects(captureSource(f.selection, token, { limits: { maxDepth: 1 } }), /depth/);
  await assert.rejects(captureSource(f.selection, token, { limits: { maxRequests: 1 } }), /request budget/);
  await assert.rejects(captureSource(f.selection, token, { limits: { maxWireBytes: 100 } }), /wire budget/);
});
test('one deadline covers the full acquisition, not a fresh timeout per response', async t => {
  const f = await fixture(t); f.control.mutate = () => sleep(40);
  await assert.rejects(captureSource(f.selection, token, { limits: { timeoutMs: 110 } }), /deadline/);
  assert.ok(f.calls.length <= 3);
});
test('abort before connection and during an active socket never yields partial output', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(captureSource(f.selection, token, { signal: stop.signal })); assert.equal(f.calls.length, 0);
  const active = new AbortController(); f.control.mutate = () => new Promise(resolve => setTimeout(resolve, 100));
  const run = captureSource(f.selection, token, { signal: active.signal }); setTimeout(() => active.abort(), 20);
  await assert.rejects(run, /cancel/); assert.equal(f.calls.length, 1);
});
for (const code of [301, 401, 403, 404, 409, 413, 429, 503]) test(`HTTP ${code} is not an empty archive or an automatic retry`, async t => {
  const f = await fixture(t); f.control.respond = (_req, res) => { res.writeHead(code, { Location: '/leak' }); res.end('{}'); };
  await assert.rejects(captureSource(f.selection, token), error => error.status === code); assert.equal(f.calls.length, 1);
});
test('HTML, encoded responses, malformed UTF-8 and oversized framing are refused', async t => {
  for (const [headers, data] of [[{ 'Content-Type': 'text/html' }, '{}'],
    [{ 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, '{}'],
    [{ 'Content-Type': 'application/json' }, Buffer.from([255])],
    [{ 'Content-Type': 'application/json', 'Content-Length': '9999999' }, '{}']]) {
    const f = await fixture(t); f.control.respond = (_req, res) => { res.writeHead(200, headers); res.end(data); };
    await assert.rejects(captureSource(f.selection, token));
  }
});
test('public capture mutation cannot bypass complete membership checks at export', async t => {
  const f = await fixture(t), { capture } = await captureSource(f.selection, token);
  for (const change of [r => r.files.pop(), r => r.trees.pop(), r => r.files[0].bytes[0] ^= 1,
    r => r.trees[0].body_hex += '00', r => r.files.push(r.files[0]), r => r.trees.push(r.trees[0]),
    r => r.selection.expected_commit = 'e'.repeat(40), r => r.files[0].path_hex = hex('other')]) {
    // structuredClone normalizes Buffer to Uint8Array; restore Buffer only for valid input shape.
    const c = structuredClone(capture); c.files.forEach(row => row.bytes = Buffer.from(row.bytes)); change(c);
    assert.throws(() => validateCapture(c));
  }
});
test('invalid selectors, credentials and budget inflation refuse without a socket', async t => {
  const f = await fixture(t);
  for (const patch of [{ endpoint: 'http://example.com/repo.git' }, { endpoint: f.selection.endpoint + '?token=secret' },
    { ref: 'HEAD' }, { ref: 'refs/heads/../other' }, { expected_commit: '0'.repeat(40) }, { object_format: 'md5' },
    { principal_id: '4'.repeat(32) }]) assert.throws(() => archiveSelection({ ...f.selection, ...patch }));
  await assert.rejects(captureSource(f.selection, 'bad'));
  await assert.rejects(captureSource(f.selection, token, { limits: { maxEntries: ARCHIVE_LIMITS.maxEntries + 1 } }));
  assert.equal(f.calls.length, 0);
});
test('native special Git ordering is not API raw-name ordering', () => {
  const format = 'sha1', id = nativeHash('blob', Buffer.from('x'), format);
  const body = treeBody([{ name_hex: hex('a'), kind: 'directory', object_id: id }, { name_hex: hex('a.c'), kind: 'file', object_id: id }], format);
  assert.equal(body.subarray(0, 11).toString(), '100644 a.c\0');
});
