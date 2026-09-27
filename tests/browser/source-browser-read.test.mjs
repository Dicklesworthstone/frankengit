import test from 'node:test';
import assert from 'node:assert/strict';
import { sourceBinding, blobPage, verifyBlob, boundedJson, mount } from '../../crates/fgit-node/src/smart_http/server/browser/browser.mjs';
import { fixture, webcrypto, response, PAGE, dom, location, waitFor, queuedFetch } from './source-browser-fixtures.mjs';

for (const format of ['sha1', 'sha256']) {
  test(`${format}: whole-file identity hashes Git framing, binary data and empty files`, async () => {
    for (const bytes of [Buffer.alloc(0), Buffer.from([0, 255, 13, 10, 60, 62]), Buffer.from('source\n')]) {
      const f = fixture(format, bytes);
      assert.equal(await verifyBlob(f.bytes, format, f.oid, webcrypto), f.oid);
      const different = Uint8Array.from([...f.bytes, 1]);
      await assert.rejects(verifyBlob(different, format, f.oid, webcrypto), /verification failed/);
    }
  });
  test(`${format}: source binding refuses each independently changed coordinate`, () => {
    const f = fixture(format), binding = sourceBinding(f.common, f.selected);
    for (const key of ['tenant_id', 'repository_id', 'repository_incarnation', 'source_head', 'source_rcr', 'ref', 'ref_hex', 'source_commit', 'root_tree', 'snapshot_token']) {
      const changed = { ...f.common, [key]: key.endsWith('commit') || key === 'root_tree' ? 'd'.repeat(format === 'sha1' ? 40 : 64)
        : key === 'snapshot_token' ? `alg:2:${'f'.repeat(64)}` : `${f.common[key]}1` };
      assert.throws(() => sourceBinding(changed, f.selected, binding), undefined, key);
    }
    assert.deepEqual(sourceBinding(f.common, f.selected, binding), binding);
  });
  test(`${format}: complete-page previews verify before rendering native source`, async () => {
    const f = fixture(format, Buffer.from('<b>inert</b>\n')), d = dom(), calls = [];
    d.get('format').value = format;
    mount(d.document, location, queuedFetch([f.tree(), f.blob()], calls), { cryptoImpl: webcrypto });
    d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
    await waitFor(() => d.buttons('content').length === 1);
    d.buttons('content')[0].click();
    await waitFor(() => d.get('content').textContent.includes('Complete native blob verified'));
    assert.ok(d.get('content').textContent.includes('<b>inert</b>'));
    assert.equal(d.get('content').all().some(e => e.tagName === 'B'), false);
    assert.equal(calls[1].fields.get('expected_head'), f.common.snapshot_token);
    assert.equal(calls[1].fields.get('expected_commit'), f.common.source_commit);
    assert.equal(d.get('token').value, '');
    d.document.defaultView.emit('pagehide');
    assert.equal(d.get('content').textContent, '');
  });
}
test('invalid snapshot tokens, disclosure flags and incomplete identities refuse', () => {
  const f = fixture();
  for (const token of ['alg:0:' + 'a'.repeat(64), 'alg:65536:' + 'a'.repeat(64), 'alg:2:0', 'alg:2:' + '0'.repeat(64), 'alg:2:' + 'a'.repeat(31)]) {
    assert.throws(() => sourceBinding({ ...f.common, snapshot_token: token }, f.selected));
  }
  for (const key of ['tenant_id', 'repository_id', 'repository_incarnation', 'source_head', 'source_rcr']) {
    for (const value of [null, '', '\0', 'a'.repeat(257)]) assert.throws(() => sourceBinding({ ...f.common, [key]: value }, f.selected));
  }
  for (const [key, value] of [['read_only', false], ['published', true], ['transaction_created', true]]) {
    assert.throws(() => sourceBinding({ ...f.common, [key]: value }, f.selected));
  }
});
test('file ranges retain directory identity and reject holes, changed sizes and kinds', () => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 1)), source = sourceBinding(f.common, f.selected);
  const expected = { id: f.oid, kind: 'file', total: f.bytes.length };
  assert.equal(blobPage(f.blob(), f.selected, source, f.path, 0, expected).next, PAGE);
  assert.equal(blobPage(f.blob(PAGE), f.selected, source, f.path, PAGE, expected).next, null);
  for (const change of [{ object_id: 'd'.repeat(40) }, { kind: 'executable' }, { total_bytes: PAGE + 2 },
    { offset: 1 }, { returned_bytes: 0 }, { next_offset: null }, { content_hex: '' }, { symlink_followed: true }, { path_hex: '61' }]) {
    assert.throws(() => blobPage({ ...f.blob(), ...change }, f.selected, source, f.path, 0, expected));
  }
  for (const path of ['', '2f61', '612f', '2e2e2f61', '2e4749542f61', '612f2f62', '00', '612f'.repeat(64) + '62']) {
    assert.throws(() => blobPage({ ...f.blob(), path_hex: path }, f.selected, source, path, 0));
  }
});
test('symlink payload is data; gitlinks and directories cannot masquerade as files', async () => {
  const f = fixture('sha256', Buffer.from('../../outside'), 'symlink'), source = sourceBinding(f.common, f.selected);
  const page = blobPage(f.blob(), f.selected, source, f.path, 0);
  assert.equal(await verifyBlob(page.bytes, f.format, page.id, webcrypto), f.oid);
  for (const kind of ['gitlink', 'directory', 'unknown']) assert.throws(() => blobPage({ ...f.blob(), kind }, f.selected, source, f.path, 0));
});
test('missing crypto, oversized files and cancellation never claim verification', async () => {
  const f = fixture();
  await assert.rejects(verifyBlob(f.bytes, f.format, f.oid, {}), /WebCrypto/);
  await assert.rejects(verifyBlob(new Uint8Array(8 * 1024 * 1024 + 1), f.format, f.oid, webcrypto), /8 MiB/);
  let probes = 0;
  await assert.rejects(verifyBlob(f.bytes, f.format, f.oid, webcrypto, () => { if (++probes === 2) throw new Error('cancelled'); }), /cancelled/);
  assert.equal(probes, 2);
});
test('bounded JSON enforces exact Content-Length and byte limits', async () => {
  assert.deepEqual(await boundedJson(response({ ok: true })), { ok: true });
  for (const length of ['01', '-1', '100', '0', '1'.repeat(50)]) {
    await assert.rejects(boundedJson(new Response('{}', { headers: { 'Content-Length': length } })), /length/);
  }
  assert.deepEqual(await boundedJson(new Response('{}'), 2), {});
  await assert.rejects(boundedJson(new Response('{}'), 1), /byte limit/);
  await assert.rejects(boundedJson(new Response(Uint8Array.from([255]))));
});
test('aborting a stalled response cancels its reader and releases the lock', async () => {
  let cancelled = 0;
  const stream = new ReadableStream({ cancel() { cancelled++; } }), control = new AbortController();
  const reading = boundedJson(new Response(stream), 32, control.signal);
  control.abort(); await assert.rejects(reading, /abort/i);
  assert.equal(cancelled, 1); assert.equal(stream.locked, false);
});
test('corrupted complete bytes and changed directory-selected identities never render', async () => {
  for (const change of [{ content_hex: '61616161616161' }, { object_id: 'd'.repeat(40) }, { kind: 'executable' }]) {
    const f = fixture(), d = dom();
    mount(d.document, location, queuedFetch([f.tree(), { ...f.blob(), ...change }]), { cryptoImpl: webcrypto });
    d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
    await waitFor(() => d.buttons('content').length === 1); d.buttons('content')[0].click();
    await waitFor(() => /failed|changed|range/.test(d.get('status').textContent));
    assert.equal(d.get('content').textContent, '');
  }
});
test('range previews are not labeled verified and continuation binds file length', async () => {
  const f = fixture('sha1', Buffer.alloc(PAGE + 1, 97)), d = dom();
  const changed = { ...f.blob(PAGE), total_bytes: PAGE + 2 };
  mount(d.document, location, queuedFetch([f.tree(), f.blob(), changed]), { cryptoImpl: webcrypto });
  d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
  await waitFor(() => d.buttons('content').length === 1); d.buttons('content')[0].click();
  await waitFor(() => d.buttons('paging').length === 1);
  assert.ok(d.get('content').textContent.includes('Unverified byte-range preview'));
  d.buttons('paging')[0].click(); await waitFor(() => /length changed/.test(d.get('status').textContent));
  assert.equal(d.get('content').textContent, '');
});
test('disconnect during digest cannot restore a superseded source preview', async () => {
  const f = fixture(), d = dom(); let complete;
  const cryptoImpl = { subtle: { digest() { return new Promise(resolve => { complete = resolve; }); } } };
  mount(d.document, location, queuedFetch([f.tree(), f.blob()]), { cryptoImpl });
  d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
  await waitFor(() => d.buttons('content').length === 1); d.buttons('content')[0].click();
  await waitFor(() => complete); d.get('disconnect').click(); complete(Buffer.from(f.oid, 'hex'));
  await new Promise(r => setTimeout(r, 10));
  assert.equal(d.get('content').textContent, ''); assert.match(d.get('status').textContent, /Disconnected/);
});
test('whole operation deadline cancels a stalled response without accepting a snapshot', async () => {
  const d = dom(); let cancelled = 0;
  mount(d.document, location, async () => new Response(new ReadableStream({ cancel() { cancelled++; } }),
    { headers: { 'Content-Type': 'application/json' } }), { timeoutMs: 20 });
  d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
  await waitFor(() => /timed out/.test(d.get('status').textContent));
  assert.equal(cancelled, 1); assert.equal(d.get('snapshot').textContent, '');
});
test('source shell refuses insecure remote origins and URL credential/query injection', () => {
  for (const href of ['http://example.invalid/repo.git/ui/', 'https://user:password@example.invalid/repo.git/ui/',
    'https://example.invalid/repo.git/ui/?token=secret', 'https://example.invalid/repo.git/ui/#x']) {
    assert.throws(() => mount(dom().document, new URL(href)));
  }
  assert.doesNotThrow(() => mount(dom().document, new URL('https://example.invalid/repo.git/ui/')));
});
