// Production client and WebCrypto; native source responses are contract fixtures, not fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, harness, hex, jsonResponse, token } from './history-compare-fixtures.mjs';
const MIB = 1024 * 1024;
const expected = f => ({ object_id: f.tag(f.afterBlob), root_tree: f.tag(f.afterTree), kind: 'file', total_bytes: f.afterBody.length });
const read = (h, value = expected(h.f)) => h.client.downloadHistorical(h.f.after, hex('src/file.bin'), value);
const make = (algorithm = 'sha1', size = 2 * MIB + 17) => fixture(algorithm, { after: Buffer.alloc(size, 173) });
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: whole historical files span native ranges and verify one complete Git blob`, async () => {
    const h = harness(make(algorithm)); await h.open(); const selection = h.client.selection;
    const result = await read(h); assert.deepEqual(Buffer.from(result.bytes), h.f.afterBody);
    assert.equal(result.fullBlobVerified, true); assert.equal(result.object_id, h.f.afterBlob); assert.equal(result.pages, 3);
    assert.equal(result.raw.type, 'browser_historical_file_verification'); assert.equal(result.raw.total_bytes, h.f.afterBody.length);
    assert.equal(JSON.stringify(result.raw).includes(token), false); assert.equal(result.raw.content_hex, undefined);
    const calls = h.calls.slice(1); assert.deepEqual(calls.map(call => Number(call.form.get('offset'))), [0, MIB, 2 * MIB]);
    for (const call of calls) {
      assert.equal(call.form.get('limit'), String(MIB)); assert.equal(call.form.get('ref'), h.f.afterRef);
      assert.equal(call.form.get('expected_head'), selection.head); assert.equal(call.form.get('expected_ref_tip'), h.f.after);
      assert.equal(call.form.get('at_commit'), h.f.after); assert.equal(call.form.get('path_hex'), hex('src/file.bin'));
      assert.equal(call.headers['Idempotency-Key'], undefined); assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error');
    }
    assert.deepEqual(h.client.selection, selection);
  });
  test(`${algorithm}: empty historical files still require a complete response and native hash`, async () => {
    const h = harness(make(algorithm, 0)); await h.open(); const result = await read(h);
    assert.equal(result.bytes.length, 0); assert.equal(result.pages, 1); assert.equal(result.fullBlobVerified, true);
    assert.equal(result.object_id, h.f.afterBlob); assert.equal(h.calls.length, 2);
  });
  test(`${algorithm}: corruption in a later range cannot release partial or unverified bytes`, async () => {
    const f = make(algorithm), h = harness(f, call => {
      if (!call.url.endsWith('/historical-blob')) return null;
      const reply = f.historical(call.form);
      if (Number(call.form.get('offset')) >= MIB) reply.source.content_hex = 'aa'.repeat(reply.source.returned_bytes);
      return jsonResponse(reply);
    }); await h.open(); await assert.rejects(read(h), /blob identity/); assert.equal(h.calls.length, 4);
  });
}
for (const kind of ['file', 'executable', 'symlink']) test(`historical ${kind} payloads stay byte-exact without following links`, async () => {
  const f = fixture('sha256', { after: Buffer.from([0, 255, 13, 10, 47, 46, 46]) });
  const h = harness(f, call => {
    if (!call.url.endsWith('/historical-blob')) return null;
    const reply = f.historical(call.form); reply.source.kind = kind; return jsonResponse(reply);
  }); await h.open(); const result = await read(h, { ...expected(f), kind });
  assert.deepEqual(Buffer.from(result.bytes), f.afterBody); assert.equal(result.kind, kind);
});

test('eight MiB is supported in exactly eight ranges, without enlarging a single native read', async () => {
  const h = harness(make('sha256', 8 * MIB)); await h.open(); const result = await read(h);
  assert.equal(result.pages, 8); assert.equal(result.bytes.length, 8 * MIB); assert.equal(result.object_id, h.f.afterBlob);
});

test('invalid or oversized download expectations refuse before any source request', async () => {
  const h = harness(); await h.open();
  for (const patch of [{ total_bytes: 8 * MIB + 1 }, { total_bytes: -1 }, { kind: 'gitlink' }, { kind: 'directory' },
    { object_id: '0'.repeat(40) }, { root_tree: 'sha256:' + 'a'.repeat(64) }, { force: true }]) {
    await assert.rejects(read(h, { ...expected(h.f), ...patch }));
  }
  await assert.rejects(read(h, {})); await assert.rejects(h.client.downloadHistorical(h.f.after, hex('../unsafe'), expected(h.f)));
  assert.equal(h.calls.length, 1);
});

const changed = [
  ['blob', r => { r.source.object_id = 'e'.repeat(40); }],
  ['root tree', r => { r.source.root_tree = 'e'.repeat(40); }],
  ['kind', r => { r.source.kind = 'symlink'; }],
  ['record', r => { r.source.source_rcr = 'other-rcr'; }],
  ['authority display', r => { r.source.source_head = 'other-head'; }],
  ['snapshot', r => { r.source.snapshot_token = `alg:2:${'e'.repeat(64)}`; }],
  ['incarnation', r => { r.source.repository_incarnation = 'other'; }],
  ['path', r => { r.source.path_hex = hex('other'); }],
  ['range', r => { r.source.offset++; }],
  ['continuation', r => { r.source.next_offset = null; }],
];
for (const [label, alter] of changed) test(`a later changed ${label} refuses the complete download`, async () => {
  const f = make(), h = harness(f, call => {
    if (!call.url.endsWith('/historical-blob')) return null;
    const reply = f.historical(call.form); if (Number(call.form.get('offset')) > 0) alter(reply); return jsonResponse(reply);
  }); await h.open(); await assert.rejects(read(h)); assert.equal(h.calls.length, 3);
});

test('a coherent size substitution cannot rewrite the preview selected by the caller', async () => {
  const f = make(), h = harness(f); await h.open();
  await assert.rejects(read(h, { ...expected(f), total_bytes: f.afterBody.length - 1 }), /expectation/);
  assert.equal(h.calls.length, 2);
});

test('HTTP failure partway through does not retry or return an accumulated prefix', async () => {
  const f = make(), h = harness(f, call => call.url.endsWith('/historical-blob') && Number(call.form.get('offset')) > 0 ? jsonResponse({}, 503) : null);
  await h.open(); await assert.rejects(read(h), e => e.status === 503); assert.equal(h.calls.length, 3);
});

test('cancellation fences an in-flight later range and prevents the final hash result', async () => {
  let finish, started; const gate = new Promise(resolve => { finish = resolve; }), entered = new Promise(resolve => { started = resolve; });
  const f = make(), h = harness(f, call => {
    if (call.url.endsWith('/historical-blob') && Number(call.form.get('offset')) > 0) { started(call); return gate; }
    return null;
  }); await h.open(); const pending = read(h), rejected = assert.rejects(pending); const call = await entered;
  h.client.cancel(); finish(jsonResponse(f.historical(call.form))); await rejected;
  assert.equal(h.calls.length, 3); assert.equal(h.client.connected, true);
});

test('all range reads share one deadline, not a fresh budget per response', async () => {
  const f = make(); let reads = 0;
  const h = harness(f, async call => {
    if (!call.url.endsWith('/historical-blob')) return null;
    reads++; await new Promise(resolve => setTimeout(resolve, 35)); return jsonResponse(f.historical(call.form));
  }, { timeoutMs: 60 }); await h.open(); await assert.rejects(read(h)); assert.ok(reads < 3);
});

test('the expectation is copied before asynchronous intake', async () => {
  const h = harness(make()); await h.open(); const value = expected(h.f), pending = read(h, value);
  value.object_id = 'e'.repeat(40); value.total_bytes = 1; value.kind = 'symlink';
  const result = await pending; assert.equal(result.object_id, h.f.afterBlob); assert.equal(result.total_bytes, h.f.afterBody.length);
});

test('current authentication loss discards the selection and no further ranges are issued', async () => {
  const f = make(), h = harness(f, call => call.url.endsWith('/historical-blob') && Number(call.form.get('offset')) > 0 ? jsonResponse({}, 401) : null);
  await h.open(); await assert.rejects(read(h), e => e.status === 401); assert.equal(h.client.connected, false);
  assert.equal(h.client.selection, null); assert.equal(h.calls.length, 3);
});

test('an oversized encoded page is refused before consuming its body', async () => {
  const f = make(), h = harness(f, call => call.url.endsWith('/historical-blob')
    ? jsonResponse({}, 200, { 'Content-Length': String(2 * MIB + 65536 + 1) }) : null);
  await h.open(); await assert.rejects(read(h), /byte limit/); assert.equal(h.calls.length, 2);
});
