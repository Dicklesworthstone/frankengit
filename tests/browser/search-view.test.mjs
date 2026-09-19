import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { mount, display, preview, readQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-view.mjs';
import { TOKEN, HREF, fixture, encode, response } from './search-fixtures.mjs';
import { dom, tick } from './search-dom-fixture.mjs';

async function setup(f = fixture(), options = {}) {
  const d = dom(); const view = mount(d.document, new URL(HREF), { ...f.options, ...options, urlApi: d.urlApi });
  d.get('token').value = TOKEN; d.get('format').value = f.algorithm;
  await view.connect(); d.get('query').value = 'needle';
  return { ...d, view, f };
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: the real page/client search-to-file flow verifies before preview or download`, async () => {
    const d = await setup(fixture(algorithm));
    assert.equal(d.get('token').value, ''); assert.equal(d.f.calls.length, 0);
    assert.equal(d.get('submit-search').disabled, false);
    await d.view.search();
    assert.match(d.get('results').textContent, /2 returned matches/);
    assert.match(d.get('snapshot').textContent, /Snapshot alg:1:/);
    const open = d.buttons('results').find(b => b.textContent.includes('src/code.rs'));
    assert.ok(open); open.click();
    while (!d.get('file').textContent) await tick();
    assert.match(d.get('file').textContent, /Native blob verified/);
    assert.match(d.get('file').textContent, /Literal bytes, excerpt and coordinates reproduced/);
    assert.equal(d.document.focused, d.get('file'));
    d.buttons('file').find(b => b.textContent.startsWith('Download')).click();
    assert.equal(d.document.downloads.length, 1);
    const downloaded = d.document.downloads[0]; assert.equal(downloaded.download, 'snapshot-source.bin');
    assert.deepEqual(Buffer.from(await d.urls.get(downloaded.href).arrayBuffer()), d.f.files[0].body);
    d.view.disconnect(); assert.equal(d.urls.size, 0); assert.deepEqual(d.revoked, [downloaded.href]);
    for (const id of ['results', 'file', 'snapshot']) assert.equal(d.get(id).textContent, '');
    assert.equal(d.get('query').value, ''); assert.equal(d.get('submit-search').disabled, true);
  });
}
test('batch input preserves order, duplicates and independent limited/complete status', async () => {
  const d = await setup(); d.get('mode').value = 'batch'; d.get('mode').emit('change');
  d.get('query').value = 'needle\nabsent\nneedle\n'; d.get('max-matches').value = '1';
  await d.view.search();
  assert.equal(d.get('results').textContent.match(/Limited: 1 matches/g).length, 2);
  assert.match(d.get('results').textContent, /Server reports complete: 0 matches/);
  assert.match(d.get('results').textContent, /One shared source scan/);
  assert.match(d.get('status').textContent, /limited results/);
  const fields = new URLSearchParams(d.f.calls[0].body);
  assert.deepEqual(fields.getAll('needle_hex'), [encode('needle'), encode('absent'), encode('needle')]);
  d.view.disconnect();
});
test('hex queries and prefixes expose binary matches without decoding path bytes', async () => {
  const d = await setup(fixture('sha256', [[Buffer.from([0x73, 0x2f, 0xff]), Buffer.from([0, 255, 10])]]));
  d.get('encoding').value = 'hex'; d.get('query').value = '00ff';
  d.get('prefix-encoding').value = 'hex'; d.get('prefixes').value = '73';
  await d.view.search(); assert.match(d.get('results').textContent, /s\/\\xff/);
  await d.view.openMatch(0, 0); assert.match(d.get('file').textContent, /Native blob verified \(sha256\)/);
  assert.equal(new URLSearchParams(d.f.calls.at(-1).body).get('path_hex'), '732fff'); d.view.disconnect();
});
test('regex mode shows its own work semantics, long-span truncation and zero-length marker', async () => {
  const d = await setup(fixture('sha1', [['empty', '\n'], ['long', `${'a'.repeat(9000)}\n`]]));
  d.get('mode').value = 'regex'; d.get('mode').emit('input'); d.get('query').value = '.*';
  assert.equal(d.get('max-steps').disabled, false); assert.equal(d.get('regex-help').hidden, false);
  await d.view.search(); assert.match(d.get('results').textContent, /native VM steps/);
  await d.view.openMatch(0, 0); assert.match(d.get('file').textContent, /zero-length span/);
  assert.equal(d.get('file').descendants().find(e => e.tagName === 'MARK').textContent, '▏');
  await d.view.openMatch(0, 1); assert.match(d.get('file').textContent, /match continues beyond this preview/);
  assert.match(d.get('file').textContent, /not re-evaluated here/);
  const pre = d.get('file').descendants().find(e => e.tagName === 'PRE'); assert.ok(pre.textContent.length <= 4096);
  d.get('mode').value = 'literal'; d.get('mode').emit('change');
  assert.equal(d.get('max-steps').disabled, true); assert.equal(d.get('regex-help').hidden, true); d.view.disconnect();
});
test('HTML/SVG/terminal controls and bidi in source remain inert escaped data', async () => {
  const name = '<img src=x onerror=alert(1)>\u202e.rs', content = '<script>needle</script>\u202e\x1b[31m\n';
  const d = await setup(fixture('sha1', [[name, content]]));
  await d.view.search(); await d.view.openMatch(0, 0);
  assert.match(d.get('results').textContent, /<img src=x/);
  assert.match(d.get('file').textContent, /<script>/);
  assert.match(d.get('file').textContent, /\\u\{202e\}/);
  assert.equal(d.get('file').textContent.includes('\u202e'), false);
  for (const id of ['file', 'results']) assert.ok(!d.get(id).descendants().some(e => ['IMG', 'SCRIPT', 'SVG', 'IFRAME'].includes(e.tagName)));
  d.view.disconnect();
});
test('each query-control edit discards results and downloads but keeps the old snapshot pinned', async () => {
  for (const id of ['mode', 'encoding', 'case', 'query', 'prefixes', 'prefix-encoding', 'max-matches', 'max-file-bytes', 'max-bytes', 'max-steps']) {
    const d = await setup(); await d.view.search(); await d.view.openMatch(0, 0);
    d.buttons('file')[0].click(); const pin = d.get('snapshot').textContent;
    d.get(id).emit('input');
    assert.equal(d.get('results').textContent, ''); assert.equal(d.get('file').textContent, ''); assert.equal(d.urls.size, 0);
    assert.equal(d.get('snapshot').textContent, pin); assert.match(d.get('status').textContent, /Query changed/); d.view.disconnect();
  }
});
test('explicit snapshot release requires another search and does not fetch or adopt a new incarnation', async () => {
  const d = await setup(); await d.view.search(); const count = d.f.calls.length;
  d.view.refresh(); assert.equal(d.f.calls.length, count); assert.equal(d.get('results').textContent, '');
  assert.match(d.get('snapshot').textContent, /next successful search/);
  d.f.identity.repository_incarnation = 'foreign'; await d.view.search();
  assert.equal(d.get('results').textContent, ''); assert.match(d.get('status').textContent, /incarnation changed/); d.view.disconnect();
});
test('connection settings changes require explicit reconnection and remove old result handles', async () => {
  for (const id of ['reference', 'format', 'token']) {
    const d = await setup(); await d.view.search(); const old = d.buttons('results')[0], count = d.f.calls.length;
    d.get(id).emit('change'); old.click(); await tick();
    assert.equal(d.f.calls.length, count); assert.equal(d.get('submit-search').disabled, true);
    assert.equal(d.get('snapshot').textContent, ''); d.view.disconnect();
  }
});
test('invalid form input sends nothing and cannot leave a previous successful view visible', async () => {
  const invalid = [d => { d.get('query').value = ''; }, d => { d.get('max-matches').value = '4097'; },
    d => { d.get('encoding').value = 'hex'; d.get('query').value = '0A'; }, d => { d.get('prefixes').value = '../secret'; },
    d => { d.get('max-bytes').value = 'NaN'; }, d => { d.get('mode').value = 'batch'; d.get('query').value = 'a\n'.repeat(33); }];
  for (const change of invalid) {
    const d = await setup(); await d.view.search(); const count = d.f.calls.length;
    change(d); await d.view.search(); assert.equal(d.f.calls.length, count); assert.equal(d.get('results').textContent, '');
    assert.equal(d.get('submit-search').disabled, false); d.view.disconnect();
  }
});
test('search errors are never displayed as no-match success and revoked credentials clear the page', async () => {
  for (const code of [401, 403, 409, 413, 429, 503]) {
    const d = await setup(); await d.view.search(); d.f.setIntercept(() => response({ secret: TOKEN }, code));
    await d.view.search();
    assert.equal(d.get('results').textContent, ''); assert.equal(d.get('status').textContent.includes(TOKEN), false);
    assert.equal(d.get('status').textContent.includes('scan complete'), false);
    if (code === 401) { assert.equal(d.get('submit-search').disabled, true); assert.equal(d.get('query').value, ''); }
    d.view.disconnect();
  }
});
test('a corrupt file response never displays verified bytes or offers a download', async () => {
  const d = await setup(); await d.view.search();
  d.f.setIntercept(r => { r.content_hex = '00' + r.content_hex.slice(2); return response(r); });
  await d.view.openMatch(0, 0); assert.equal(d.get('file').textContent, ''); assert.equal(d.urls.size, 0);
  assert.match(d.get('status').textContent, /verification failed/); d.view.disconnect();
});
test('paging retained results is local and stale page controls cannot resurrect discarded queries', async () => {
  const d = await setup(fixture('sha1', [['many', 'needle\n'.repeat(105)]]));
  d.get('max-matches').value = '110'; await d.view.search(); const count = d.f.calls.length;
  let next = d.buttons('results').find(b => b.textContent === 'Next results'); assert.ok(next); next.click();
  assert.match(d.get('results').textContent, /51–100 of 105/); assert.equal(d.f.calls.length, count);
  next = d.buttons('results').find(b => b.textContent === 'Next results'); next.click();
  assert.match(d.get('results').textContent, /101–105 of 105/);
  const old = d.buttons('results')[0]; d.get('query').emit('input'); old.click(); await tick();
  assert.equal(d.get('results').textContent, ''); assert.equal(d.f.calls.length, count); d.view.disconnect();
});
test('cancel/edit/disconnect/pagehide suppress late search replies even if fetch ignores cancellation', async () => {
  for (const action of [d => d.view.cancel(), d => d.get('query').emit('input'), d => d.view.disconnect(), d => d.document.defaultView.emit('pagehide')]) {
    const d = await setup(); let release;
    d.f.setIntercept(r => new Promise(resolve => { release = () => resolve(response(r)); }));
    const pending = d.view.search(); assert.equal(d.get('cancel').disabled, false);
    action(d); const status = d.get('status').textContent; release(); await pending;
    assert.equal(d.get('results').textContent, ''); assert.equal(d.get('status').textContent, status);
    assert.equal(d.get('cancel').disabled, true); d.view.disconnect();
  }
});
test('a superseded search cannot replace a newer result or completion message', async () => {
  const d = await setup(); let release;
  d.f.setIntercept(r => new Promise(resolve => { release = () => resolve(response(r)); })); const first = d.view.search();
  d.f.setIntercept(null); d.get('query').value = 'absent'; await d.view.search();
  const text = d.get('results').textContent; release(); await first;
  assert.equal(d.get('results').textContent, text); assert.match(text, /0 returned matches/); d.view.disconnect();
});
test('a late file page or native hash cannot put source bytes back after query edits', async () => {
  for (const stage of ['http', 'hash']) {
    let release;
    const cryptoImpl = { subtle: { async digest(algorithm, data) {
      if (stage === 'hash' && Buffer.from(data).subarray(0, 5).toString() === 'blob ') await new Promise(resolve => { release = resolve; });
      return webcrypto.subtle.digest(algorithm, data);
    } } };
    const d = await setup(fixture(), { cryptoImpl }); await d.view.search();
    if (stage === 'http') d.f.setIntercept(r => new Promise(resolve => { release = () => resolve(response(r)); }));
    const pending = d.view.openMatch(0, 0); while (!release) await tick();
    d.get('query').emit('input'); release(); await pending;
    assert.equal(d.get('file').textContent, ''); assert.equal(d.urls.size, 0); d.view.disconnect();
  }
});
test('forms prevent default navigation and the page has no external assets or inline execution', async () => {
  const d = await setup();
  assert.equal(d.get('search-form').emit('submit').defaultPrevented, true); await tick();
  assert.equal(d.get('connection').emit('submit').defaultPrevented, true); await tick();
  assert.ok(d.html.includes('type="password"')); assert.ok(d.html.includes('aria-live="polite"'));
  assert.ok(!/<script\s*>|\son\w+=|https?:\/\//i.test(d.html));
  d.view.disconnect();
});
test('escaped preview length is bounded and retains exact byte span even in split UTF-8', () => {
  const bytes = Buffer.from('é'.repeat(5000)); const p = preview(bytes, { offset: 161, length: 9000 });
  assert.equal(p.end - p.start, 4096); assert.equal(p.truncated, true);
  assert.ok(p.before.includes('\\x')); assert.ok(!display(Buffer.from('\u202e\0\x1b')).includes('\u202e'));
  const d = dom(); d.get('mode').value = 'batch'; d.get('query').value = ' a \r\nb\r\n';
  assert.deepEqual(readQuery(d.document).needlesHex, [encode(' a '), encode('b')]);
});
