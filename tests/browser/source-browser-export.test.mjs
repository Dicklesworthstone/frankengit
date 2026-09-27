import test from 'node:test';
import assert from 'node:assert/strict';
import { collectVerifiedBlob, sourceBinding, mount, MAX_FILE_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/browser.mjs';
import { fixture, webcrypto, response, PAGE, dom, location, waitFor, queuedFetch } from './source-browser-fixtures.mjs';
const expected = f => ({ id: f.oid, kind: f.blob().kind, total: f.bytes.length });
const collect = (f, read = fields => f.blob(Number(fields.offset)), options = {}) => collectVerifiedBlob(
  f.selected, sourceBinding(f.common, f.selected), f.path, expected(f), read, { cryptoImpl: webcrypto, ...options });
async function opened(f, extra, options = {}) {
  const d = dom(), calls = []; d.get('format').value = f.format;
  const client = mount(d.document, location, queuedFetch([f.tree(), f.blob(), ...extra], calls),
    { cryptoImpl: webcrypto, urlApi: d.urlApi, ...options });
  d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
  await waitFor(() => d.buttons('content').length === 1); d.buttons('content')[0].click();
  await waitFor(() => d.buttons('content').some(b => b.textContent === 'Verify complete file for download'));
  return { ...d, calls, client, verify: () => d.buttons('content').find(b => b.textContent === 'Verify complete file for download').click() };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: export assembles all ranges including binary UTF-8 boundaries`, async () => {
    const bytes = Buffer.alloc(PAGE + 13, 97); bytes.set([0, 255, 226, 130, 172, 10], PAGE - 2);
    const f = fixture(format, bytes), calls = [];
    const result = await collect(f, fields => { calls.push(fields); return f.blob(Number(fields.offset)); });
    assert.deepEqual(result.bytes, f.bytes); assert.equal(result.pages, 2);
    assert.equal(result.blobVerified, true); assert.equal(result.authorityVerified, false);
    assert.deepEqual(calls.map(f => f.offset), ['0', String(PAGE)]);
    for (const fields of calls) {
      assert.equal(fields.expected_head, f.common.snapshot_token); assert.equal(fields.expected_commit, f.common.source_commit);
      assert.equal(fields.path_hex, f.path); assert.equal(fields.limit, String(PAGE));
    }
  });
  test(`${format}: empty, executable and symlink exports retain exact bytes and kind`, async () => {
    for (const [bytes, kind] of [[Buffer.alloc(0), 'file'], [Buffer.from('#!/bin/sh\n'), 'executable'], [Buffer.from('../../secret'), 'symlink']]) {
      const f = fixture(format, bytes, kind), result = await collect(f);
      assert.deepEqual(result.bytes, f.bytes); assert.equal(result.kind, kind); assert.equal(result.pages, 1);
    }
  });
  test(`${format}: actual source-browser controls download the whole verified file`, async () => {
    const f = fixture(format, Buffer.alloc(PAGE + 7, 255)), d = await opened(f, [f.blob(), f.blob(PAGE)]);
    d.verify(); assert.equal(d.urls.size, 0);
    await waitFor(() => d.get('status').textContent.startsWith('Complete file verified.'));
    const button = d.buttons('content').find(b => b.textContent === 'Download verified file bytes');
    assert.ok(button); button.click();
    assert.equal(d.urls.size, 1); assert.equal(d.document.downloads.length, 1);
    const download = d.document.downloads[0]; assert.equal(download.filename, 'source.bin');
    assert.deepEqual(new Uint8Array(await d.urls.get(download.href).arrayBuffer()), f.bytes);
    assert.ok(d.get('content').textContent.includes('not an authority signature'));
    button.click(); assert.equal(d.urls.size, 1);
    d.document.defaultView.emit('pagehide');
    assert.equal(d.urls.size, 0); assert.equal(d.revoked.length, 1); assert.equal(d.get('content').textContent, '');
    button.click(); assert.equal(d.document.downloads.length, 2);
    assert.deepEqual(d.calls.map(c => c.fields.get('offset')), [null, '0', '0', String(PAGE)]);
  });
}
test('the exact 8 MiB and 128-page export limit works; one extra byte refuses before a read', async () => {
  const f = fixture('sha256', Buffer.alloc(MAX_FILE_BYTES, 0x81)); let reads = 0;
  const result = await collect(f, fields => { reads++; return f.blob(Number(fields.offset)); });
  assert.equal(result.bytes.length, MAX_FILE_BYTES); assert.equal(reads, 128); assert.equal(result.pages, 128);
  const tooLarge = { ...expected(f), total: MAX_FILE_BYTES + 1 };
  await assert.rejects(collectVerifiedBlob(f.selected, sourceBinding(f.common, f.selected), f.path, tooLarge,
    () => { throw new Error('must not read'); }), /byte limit/);
});
test('smaller export budgets and missing source/file identities refuse without allocation', async () => {
  const f = fixture('sha1', Buffer.from('ab'));
  assert.deepEqual((await collect(f, undefined, { maxBytes: 2 })).bytes, f.bytes);
  await assert.rejects(collect(f, undefined, { maxBytes: 1 }), /byte limit/);
  for (const maxBytes of [0, -1, MAX_FILE_BYTES + 1, 1.5, Infinity]) await assert.rejects(collect(f, undefined, { maxBytes }), /bounded/);
  await assert.rejects(collectVerifiedBlob(f.selected, null, f.path, expected(f), () => f.blob()), /pinned/);
  await assert.rejects(collectVerifiedBlob(f.selected, sourceBinding(f.common, f.selected), f.path, null, () => f.blob()), /pinned/);
});
test('all later-page source, file and range changes refuse rather than return partial bytes', async () => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 65));
  for (const change of [{ tenant_id: 'foreign' }, { repository_id: 'foreign' }, { repository_incarnation: 'new' },
    { source_head: 'new' }, { source_rcr: 'new' }, { root_tree: 'd'.repeat(40) }, { source_commit: 'd'.repeat(40) },
    { snapshot_token: `alg:2:${'d'.repeat(64)}` }, { ref_hex: '61' }, { ref: 'refs/heads/other' },
    { object_id: 'e'.repeat(40) }, { kind: 'symlink' }, { total_bytes: PAGE + 2 }, { offset: 0 },
    { content_hex: '' }, { next_offset: PAGE + 1 }, { returned_bytes: 2 }, { symlink_followed: true }]) {
    let reads = 0;
    await assert.rejects(collect(f, fields => { reads++; const offset = Number(fields.offset); return { ...f.blob(offset), ...(offset ? change : {}) }; }), undefined, JSON.stringify(change));
    assert.equal(reads, 2);
  }
});
test('tampering with a single later byte fails the native digest', async () => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 65));
  await assert.rejects(collect(f, fields => Number(fields.offset) ? { ...f.blob(PAGE), content_hex: '42' } : f.blob()), /verification failed/);
});
test('caller changes after the first await cannot change the pinned selection', async () => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 65)), selected = { ...f.selected }, source = sourceBinding(f.common, f.selected), wanted = expected(f);
  const calls = [];
  const result = await collectVerifiedBlob(selected, source, f.path, wanted, async fields => {
    calls.push({ ...fields }); selected.reference = 'refs/heads/other'; source.head = 'other'; wanted.id = 'e'.repeat(40);
    return f.blob(Number(fields.offset));
  }, { cryptoImpl: webcrypto });
  assert.deepEqual(result.bytes, f.bytes);
  for (const call of calls) { assert.equal(call.ref, f.selected.reference); assert.equal(call.expected_head, f.common.snapshot_token); }
});
test('cancellation at every collector checkpoint prevents returning a verified export', async () => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 65)); let points = 0;
  await collect(f, undefined, { checkpoint: () => { points++; } });
  assert.equal(points, 7);
  for (let at = 1; at <= points; at++) {
    let n = 0;
    await assert.rejects(collect(f, undefined, { checkpoint: () => { if (++n === at) throw new Error('cancelled'); } }), /cancelled/);
    assert.equal(n, at);
  }
});
test('canceling a stalled export drains its response and leaves no downloadable object', async () => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 65)); let cancelled = 0;
  const stream = new ReadableStream({ cancel() { cancelled++; } });
  const d = await opened(f, [f.blob(), () => new Response(stream, { headers: { 'Content-Type': 'application/json' } })]);
  d.verify(); await waitFor(() => d.calls.length === 4);
  d.client.cancel(); await waitFor(() => cancelled === 1 && !stream.locked);
  assert.equal(d.urls.size, 0); assert.equal(d.get('content').textContent, '');
  assert.match(d.get('status').textContent, /canceled/); assert.equal(stream.locked, false);
});
test('no partial export, retry or download follows a failed later HTTP read', async () => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 65));
  for (const status of [401, 403, 404, 409, 429, 503]) {
    const d = await opened(f, [f.blob(), () => response({ error: 'refused' }, { status })]);
    d.verify(); await waitFor(() => d.calls.length === 4 && !d.get('status').textContent.startsWith('Reading'));
    assert.equal(d.get('content').textContent, ''); assert.equal(d.urls.size, 0); assert.equal(d.document.downloads.length, 0);
    assert.equal(d.calls.length, 4);
  }
});
test('the export operation deadline is not renewed by successful pages', async t => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 65));
  // Advance only the monotonic clock: host load cannot consume the first
  // page's allowance, and a per-page deadline reset would wrongly succeed.
  let now = performance.now();
  t.mock.method(performance, 'now', () => now);
  const elapsed = offset => () => { now += 30_000; return response(f.blob(offset)); };
  const d = await opened(f, [elapsed(0), elapsed(PAGE)], { timeoutMs: 45_000 });
  d.verify();
  for (let turn = 0; turn < 100 && !/timed out/.test(d.get('status').textContent); turn++) await new Promise(setImmediate);
  assert.match(d.get('status').textContent, /timed out/);
  assert.equal(d.urls.size, 0); assert.equal(d.get('content').textContent, ''); assert.equal(d.calls.length, 4);
});
test('changing connection settings during export discards results and preserves entered text', async () => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 65)); let finish;
  const d = await opened(f, [f.blob(), () => new Promise(resolve => { finish = resolve; })]);
  d.verify(); await waitFor(() => finish);
  d.get('reference').value = 'refs/heads/new'; d.get('reference').emit('input'); finish(response(f.blob(PAGE)));
  await new Promise(r => setTimeout(r, 10));
  assert.equal(d.get('reference').value, 'refs/heads/new'); assert.equal(d.get('content').textContent, ''); assert.equal(d.urls.size, 0);
  assert.match(d.get('status').textContent, /Connection settings changed/);
});
test('symlink download is inert target data and uses no repository-provided filename', async () => {
  const f = fixture('sha1', Buffer.from('../../outside'), 'symlink', Buffer.from('<file>.txt'));
  const d = await opened(f, [f.blob()]); d.verify();
  await waitFor(() => d.get('status').textContent.startsWith('Complete file verified.'));
  d.buttons('content').find(b => b.textContent === 'Download verified file bytes').click();
  assert.equal(d.document.downloads[0].filename, 'symlink-target.bin');
  assert.deepEqual(new Uint8Array(await d.urls.values().next().value.arrayBuffer()), f.bytes);
  assert.ok(d.get('content').textContent.includes('no link is followed or created'));
  d.client.disconnect(); assert.equal(d.urls.size, 0);
});
test('stale detached controls cannot restart a download after disconnect', async () => {
  const f = fixture(), d = await opened(f, []), old = d.buttons('content')[0];
  d.client.disconnect(); old.click(); await new Promise(r => setTimeout(r, 5));
  assert.equal(d.calls.length, 2); assert.equal(d.get('content').textContent, '');
});
