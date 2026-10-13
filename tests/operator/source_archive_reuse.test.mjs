// Complete production acquisition over actual HTTP; native replies are fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { captureSource, validateCapture } from '../../scripts/operator/source_archive.mjs';
import { fixture, repository, token, hex } from './fixtures/source_archive_native.mjs';

const copy = capture => ({ ...structuredClone(capture), files: capture.files.map(file => ({ ...file, bytes: Buffer.from(file.bytes) })) });
const operations = f => f.calls.map(call => call.operation);
function metrics(result) {
  const m = result.metrics;
  assert.equal(m.blob_bytes, m.downloaded_blob_bytes + m.reused_blob_bytes + m.deduplicated_blob_bytes);
  assert.equal(m.blob_bytes, validateCapture(result.capture).blob_bytes);
}
function advance(f, definitions) {
  const next = repository(f.repo.format, definitions);
  next.snapshot = `alg:2:${'e'.repeat(64)}`;
  next.common.snapshot_token = next.snapshot; next.common.source_head = 'later-source-head';
  const answer = next.answer;
  next.answer = (operation, form) => {
    const value = answer(operation, form);
    if (operation !== 'log') value.source_rcr = 'later-rcr';
    return value;
  };
  Object.assign(f.repo, next); f.selection.expected_commit = next.commit; f.calls.length = 0;
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: unchanged capture rechecks commit and all trees with zero blob transfers`, async t => {
    const f = await fixture(t, { format }), cold = await captureSource(f.selection, token); f.calls.length = 0;
    const warm = await captureSource(f.selection, token, { reuse: cold.capture });
    assert.deepEqual(warm.capture, cold.capture);
    assert.deepEqual(operations(f), ['log', 'tree', 'tree']);
    assert.equal(warm.metrics.reused_files, 3); assert.equal(warm.metrics.blob_requests, 0);
    assert.equal(warm.metrics.reused_blob_bytes, cold.metrics.blob_bytes);
    assert.equal(warm.metrics.downloaded_blob_bytes, 0); assert.ok(warm.metrics.wire_bytes < cold.metrics.wire_bytes);
    metrics(warm);
    for (const call of f.calls) {
      assert.equal(call.headers.authorization, `Bearer ${token}`); assert.equal(call.headers['idempotency-key'], undefined);
      assert.equal(call.form.get('expected_commit'), f.repo.commit);
      if (call.operation !== 'log') assert.equal(call.form.get('expected_head'), f.repo.snapshot);
    }
  });
  test(`${format}: new commit downloads only changed content and preserves current rename, mode and deletion`, async t => {
    const f = await fixture(t, { format }), old = await captureSource(f.selection, token);
    const readme = old.capture.files.find(file => file.path_hex === hex('README.md')).bytes;
    const code = old.capture.files.find(file => file.path_hex === hex('src/main.rs')).bytes;
    advance(f, [{ path: 'renamed/doc', kind: 'symlink', data: readme }, { path: 'src/main.rs', kind: 'file', data: code },
      { path: 'new', data: Buffer.from('new content') }, { path: 'alias', kind: 'executable', data: code }]);
    const warm = await captureSource(f.selection, token, { reuse: old.capture });
    assert.notEqual(warm.capture.commit.object_id, old.capture.commit.object_id);
    assert.equal(warm.capture.source_rcr, 'later-rcr'); assert.equal(warm.capture.source_head, 'later-source-head');
    assert.equal(warm.capture.snapshot_token, f.repo.snapshot);
    assert.deepEqual(f.calls.filter(call => call.operation === 'blob').map(call => call.form.get('path_hex')), [hex('new')]);
    assert.equal(warm.metrics.reused_files, 3); assert.equal(warm.metrics.downloaded_blob_bytes, 11);
    assert.equal(warm.capture.files.find(file => file.path_hex === hex('renamed/doc')).kind, 'symlink');
    assert.equal(warm.capture.files.find(file => file.path_hex === hex('src/main.rs')).kind, 'file');
    assert.ok(!warm.capture.files.some(file => file.path_hex === hex('link') || file.path_hex === hex('README.md')));
    metrics(warm);
    const cold = await captureSource(f.selection, token); assert.deepEqual(warm.capture, cold.capture);
  });
  test(`${format}: repeated fresh blobs fetch once, but each path counts toward logical size`, async t => {
    const data = Buffer.from('same bytes'), f = await fixture(t, { format, definitions: [
      { path: 'a', data }, { path: 'b', kind: 'executable', data }, { path: 'dir/c', kind: 'symlink', data }] });
    const result = await captureSource(f.selection, token);
    assert.equal(result.metrics.blob_requests, 1); assert.equal(result.metrics.downloaded_blob_bytes, data.length);
    assert.equal(result.metrics.deduplicated_files, 2); assert.equal(result.metrics.deduplicated_blob_bytes, 2 * data.length);
    assert.equal(result.metrics.reused_files, 0); metrics(result);
    const original = Buffer.from(result.capture.files[1].bytes); result.capture.files[0].bytes[0] ^= 1;
    assert.deepEqual(result.capture.files[1].bytes, original);
    await assert.rejects(captureSource(f.selection, token, { limits: { maxTotalBlobBytes: data.length * 3 - 1 } }), /Blob bytes/);
    await captureSource(f.selection, token, { limits: { maxTotalBlobBytes: data.length * 3 } });
  });
  test(`${format}: empty payloads, raw paths and gitlinks retain complete membership`, async t => {
    const f = await fixture(t, { format, definitions: [{ path: Buffer.from([255]), data: Buffer.alloc(0) },
      { path: 'empty', data: Buffer.alloc(0) }, { path: 'submodule', kind: 'gitlink', target: 'b'.repeat(format === 'sha1' ? 40 : 64) }] });
    const first = await captureSource(f.selection, token); assert.equal(first.metrics.blob_requests, 1);
    f.calls.length = 0; const next = await captureSource(f.selection, token, { reuse: first.capture });
    assert.equal(next.metrics.reused_files, 2); assert.equal(next.metrics.reused_blob_bytes, 0);
    assert.equal(validateCapture(next.capture).gitlinks, 1); assert.deepEqual(next.capture, first.capture);
    assert.deepEqual(operations(f), ['log', 'tree']); metrics(next);
  });
  test(`${format}: already possessed multi-range file uses no content requests`, async t => {
    const f = await fixture(t, { format, definitions: [{ path: 'large', data: Buffer.alloc(1024 * 1024 + 19, 7) }] });
    const old = await captureSource(f.selection, token); assert.equal(old.metrics.blob_requests, 2); f.calls.length = 0;
    const warm = await captureSource(f.selection, token, { reuse: old.capture });
    assert.deepEqual(operations(f), ['log', 'tree']); assert.deepEqual(warm.capture, old.capture); metrics(warm);
  });
}
for (const [name, mutate] of [
  ['file bytes', c => c.files[0].bytes[0] ^= 1], ['unused file bytes', c => c.files.at(-1).bytes[0] ^= 1],
  ['commit bytes', c => c.commit.body_hex += '00'], ['tree bytes', c => c.trees[0].body_hex += '00'],
  ['missing file', c => c.files.pop()], ['missing tree', c => c.trees.pop()], ['extra file', c => c.files.push(c.files[0])],
  ['path mapping', c => c.files[0].path_hex = hex('wrong')], ['kind', c => c.files[0].kind = 'socket'],
]) test(`corrupt prior ${name} refuses before any current network request`, async t => {
  const f = await fixture(t), old = await captureSource(f.selection, token), changed = copy(old.capture);
  advance(f, []); mutate(changed);
  await assert.rejects(captureSource(f.selection, token, { reuse: changed })); assert.equal(f.calls.length, 0);
});
for (const key of ['endpoint', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format']) {
  test(`prior ${key} scope cannot be mixed into another source`, async t => {
    const f = await fixture(t), old = await captureSource(f.selection, token); f.calls.length = 0;
    const selection = { ...f.selection, [key]: key === 'endpoint' ? f.selection.endpoint + '.other'
      : key === 'object_format' ? 'sha256' : 'f'.repeat(32) };
    if (key === 'object_format') selection.expected_commit = 'b'.repeat(64);
    await assert.rejects(captureSource(selection, token, { reuse: old.capture }), /scope/); assert.equal(f.calls.length, 0);
  });
}
test('current reference may differ; old ref and head are never sent as current selection', async t => {
  const f = await fixture(t), old = await captureSource(f.selection, token); f.calls.length = 0;
  const ref = 'refs/heads/another'; f.selection.ref = ref; f.repo.common.ref = ref; f.repo.common.ref_hex = hex(ref);
  const current = await captureSource(f.selection, token, { reuse: old.capture });
  for (const call of f.calls) assert.equal(call.form.get('ref'), ref);
  assert.equal(current.capture.selection.ref, ref); assert.equal(current.metrics.reused_files, 3);
});
test('caller mutation after starting cannot alter the retained reuse source or output buffers', async t => {
  const f = await fixture(t), old = await captureSource(f.selection, token), expected = copy(old.capture);
  const running = captureSource(f.selection, token, { reuse: old.capture });
  for (const file of old.capture.files) file.bytes.fill(0);
  old.capture.files.length = 0; old.capture.trees.length = 0; old.capture.commit.body_hex = '';
  const current = await running; assert.deepEqual(current.capture, expected);
  current.capture.files[0].bytes.fill(0);
  assert.notDeepEqual(current.capture.files[0].bytes, expected.files[0].bytes);
});
test('fresh tree omission is not repaired from a valid older tree', async t => {
  const f = await fixture(t), old = await captureSource(f.selection, token); f.calls.length = 0;
  f.control.mutate = (value, call) => { if (call.operation === 'tree') value.entries.pop(); };
  await assert.rejects(captureSource(f.selection, token, { reuse: old.capture }), /reconstruct/);
  assert.deepEqual(operations(f), ['log', 'tree']);
});
for (const [name, change] of [
  ['snapshot', v => v.snapshot_token = `alg:2:${'f'.repeat(64)}`], ['incarnation', v => v.repository_incarnation = 'f'.repeat(32)],
  ['root', v => v.root_tree = 'f'.repeat(40)], ['publication', v => v.published = true],
]) test(`current ${name} mismatch still refuses with all blobs cached`, async t => {
  const f = await fixture(t), old = await captureSource(f.selection, token); f.calls.length = 0;
  f.control.mutate = (value, call) => { if (call.operation === 'tree') change(value); };
  await assert.rejects(captureSource(f.selection, token, { reuse: old.capture })); assert.deepEqual(operations(f), ['log', 'tree']);
});
for (const status of [401, 403, 409, 429, 503]) test(`HTTP ${status} does not fall back to an offline archive`, async t => {
  const f = await fixture(t), old = await captureSource(f.selection, token); f.calls.length = 0;
  f.control.respond = (_request, response) => { response.writeHead(status); response.end('{}'); };
  await assert.rejects(captureSource(f.selection, token, { reuse: old.capture }), error => error.status === status);
  assert.deepEqual(operations(f), ['log']);
});
test('tight current limits still count every reused path and file size', async t => {
  const f = await fixture(t), old = await captureSource(f.selection, token), proof = validateCapture(old.capture);
  const max = Math.max(...old.capture.files.map(file => file.bytes.length));
  const exact = { maxTotalBlobBytes: proof.blob_bytes, maxBlobBytes: max, maxRequests: 3 };
  const result = await captureSource(f.selection, token, { reuse: old.capture, limits: exact }); metrics(result);
  for (const key of Object.keys(exact)) await assert.rejects(captureSource(f.selection, token,
    { reuse: old.capture, limits: { ...exact, [key]: exact[key] - 1 } }));
});
test('a larger valid base does not enlarge or unnecessarily restrict a smaller selected snapshot', async t => {
  const f = await fixture(t), old = await captureSource(f.selection, token);
  advance(f, [{ path: 'only', data: Buffer.from('new') }]);
  const result = await captureSource(f.selection, token, { reuse: old.capture,
    limits: { maxEntries: 1, maxTrees: 1, maxBlobBytes: 3, maxTotalBlobBytes: 3 } });
  assert.equal(result.metrics.reused_files, 0); assert.equal(result.capture.files.length, 1); metrics(result);
});
test('cancelled reused acquisition and operation-wide deadlines return no prefix', async t => {
  const f = await fixture(t), old = await captureSource(f.selection, token); f.calls.length = 0;
  const stopped = new AbortController(); stopped.abort();
  await assert.rejects(captureSource(f.selection, token, { reuse: old.capture, signal: stopped.signal })); assert.equal(f.calls.length, 0);
  f.control.mutate = () => new Promise(resolve => setTimeout(resolve, 50));
  await assert.rejects(captureSource(f.selection, token, { reuse: old.capture, limits: { timeoutMs: 110 } }), /deadline/);
  assert.ok(f.calls.length <= 3);
});
test('malformed reuse is refused, not quietly converted into a cold acquisition', async t => {
  const f = await fixture(t);
  for (const reuse of [null, {}, [], 'archive path']) await assert.rejects(captureSource(f.selection, token, { reuse }));
  assert.equal(f.calls.length, 0);
});
