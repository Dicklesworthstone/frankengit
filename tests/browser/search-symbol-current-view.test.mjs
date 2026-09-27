// Real page handlers, production client and WebCrypto with native-format wire
// fixtures. This is not a live Rust service or a browser accessibility test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mount, readQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-view.mjs';
import { symbolQuery, initialQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { dom, tick } from './search-dom-fixture.mjs';
import { currentFixture, currentTransport, token, href, hex, response, deferred, webcrypto } from './search-symbol-current-fixtures.mjs';

async function setup(f = currentFixture(), intercept, options = {}) {
  const page = dom(), wire = currentTransport(f, intercept);
  const ui = mount(page.document, { href }, { ...wire.options, urlApi: page.urlApi, ...options });
  page.get('token').value = token; page.get('format').value = f.source.object_format;
  await ui.connect();
  page.get('mode').value = 'symbols'; page.get('query').value = Buffer.from(f.input.nameHex, 'hex').toString();
  page.get('mode').emit('change');
  return { ...page, ...wire, ui, f, revalidate() { page.get('index-source-mode').value = 'revalidated'; page.get('index-source-mode').emit('change'); } };
}
async function until(predicate) {
  for (let i = 0; i < 100 && !predicate(); i++) await tick();
  assert.ok(predicate(), 'expected asynchronous UI transition');
}
const clear = p => {
  assert.equal(p.get('results').textContent, ''); assert.equal(p.get('file').textContent, ''); assert.equal(p.urls.size, 0);
};

test('source selection defaults to strict and is available only for standalone indexes', async () => {
  const p = await setup();
  assert.equal(p.get('index-source-mode').value, 'exact');
  assert.equal(p.get('index-source-mode').disabled, false); assert.equal(p.get('index-source-help').hidden, false);
  assert.equal(symbolQuery(readQuery(p.document)).sourceMode, undefined);
  p.revalidate(); p.get('case').value = 'ascii-insensitive';
  assert.equal(symbolQuery(readQuery(p.document)).sourceMode, 'revalidated');
  assert.equal(p.get('case').disabled, true); assert.equal(p.get('index-payload').disabled, true);
  for (const mode of ['literal', 'batch', 'regex', 'initial', 'indexed-content', 'indexed-path', 'symbols']) {
    p.get('mode').value = mode; p.get('mode').emit('change');
    const indexed = ['indexed-content', 'indexed-path', 'symbols'].includes(mode);
    assert.equal(p.get('index-source-mode').disabled, !indexed, mode);
    assert.equal(p.get('index-source-help').hidden, !indexed, mode);
    assert.equal(readQuery(p.document).sourceMode, indexed ? 'revalidated' : undefined, mode);
    if (mode === 'initial') assert.equal(initialQuery(readQuery(p.document)).symbol, null);
  }
  assert.equal(p.calls.length, 0); p.ui.disconnect();
});
test('the form preserves raw paths and case-sensitive declaration filters in revalidated requests', async () => {
  const f = currentFixture('sha256', { name: 'type', raw: true, path: Buffer.from('src/\xff.rs', 'latin1') }), p = await setup(f);
  p.revalidate(); p.get('encoding').value = 'hex'; p.get('query').value = hex('ty');
  p.get('symbol-match').value = 'prefix'; p.get('symbol-kind').value = 'struct';
  p.get('prefix-encoding').value = 'hex'; p.get('prefixes').value = f.row.path_hex;
  p.get('max-matches').value = '1'; p.get('max-bytes').value = '1000'; p.get('index-work').value = '10000';
  await p.ui.search();
  assert.equal(p.buttons('results').length, 1);
  const fields = p.calls[0].fields;
  assert.equal(fields.get('source_mode'), 'revalidated'); assert.equal(fields.get('name_hex'), hex('ty'));
  assert.equal(fields.get('match'), 'prefix'); assert.deepEqual(fields.getAll('kind'), ['struct']);
  assert.deepEqual(fields.getAll('path_prefix_hex'), [f.row.path_hex]); assert.equal(fields.get('max_bytes'), '1000');
  for (const field of ['after', 'index_number', 'case', 'principal', 'max_payload_bytes']) assert.equal(fields.has(field), false, field);
  assert.equal(p.calls[0].options.headers['Idempotency-Key'], undefined); p.ui.disconnect();
});
for (const format of ['sha1', 'sha256']) {
  test(`${format}: submitted form and result button navigate current source before verified download`, async () => {
    const f = currentFixture(format, { name: 'type', raw: true, prefix: '// file\n' + '\n'.repeat(65536),
      path: Buffer.from('src/<img>\x1b\xff.rs', 'latin1') }), p = await setup(f);
    p.revalidate(); assert.equal(p.get('search-form').emit('submit').defaultPrevented, true);
    await until(() => p.buttons('results').length === 1);
    const output = p.get('results').textContent;
    for (const text of [f.current.snapshot_token, f.current.source_rcr, f.current.forge_position_root,
      f.indexed.snapshot_token, f.indexed.source_rcr, f.indexed.forge_position_root]) assert.ok(output.includes(text));
    assert.match(output, /Original index provenance/); assert.match(output, /not a locally verified authority proof/);
    assert.ok(p.get('snapshot').textContent.includes(f.current.snapshot_token));
    assert.equal(p.get('snapshot').textContent.includes(f.indexed.snapshot_token), false);
    assert.equal(p.get('results').descendants().some(e => e.tagName === 'IMG'), false);
    assert.equal(output.includes('\x1b'), false);
    p.buttons('results')[0].click(); await until(() => p.buttons('file').length === 1);
    assert.equal(p.calls.length, 3); assert.equal(p.get('file').descendants().find(e => e.tagName === 'MARK').textContent, 'type');
    assert.match(p.get('file').textContent, /File read at current source snapshot/);
    assert.ok(p.get('file').textContent.includes(f.current.source_rcr));
    for (const call of p.calls.slice(1)) assert.equal(call.fields.get('expected_head'), f.current.snapshot_token);
    p.buttons('file')[0].click(); assert.equal(p.document.downloads[0].download, 'snapshot-source.bin');
    assert.deepEqual(new Uint8Array(await [...p.urls.values()][0].arrayBuffer()), new Uint8Array(f.body));
    p.ui.disconnect(); clear(p);
  });
}
test('strict success and same-source revalidation keep honest distinctness labels', async () => {
  const f = currentFixture(); Object.assign(f.current, f.indexed); const p = await setup(f);
  await p.ui.search(); assert.equal(p.calls[0].fields.has('source_mode'), false);
  assert.equal(p.get('results').textContent.includes('Current source snapshot'), false);
  p.revalidate(); await p.ui.search();
  assert.match(p.get('results').textContent, /at its original source snapshot/);
  assert.equal(p.calls[1].fields.get('expected_head'), f.indexed.snapshot_token);
  assert.equal(p.calls[1].fields.get('minimum_index_number'), '1'); p.ui.disconnect();
});
test('changed metadata requires explicit source release, not just a mode switch', async () => {
  const p = await setup(); await p.ui.search(); const pin = p.get('snapshot').textContent;
  p.revalidate(); await p.ui.search(); clear(p);
  assert.match(p.get('status').textContent, /snapshot changed/); assert.equal(p.get('snapshot').textContent, pin);
  assert.equal(p.calls.length, 2); assert.equal(p.calls[1].fields.get('expected_head'), p.f.indexed.snapshot_token);
  p.get('refresh').click(); assert.match(p.get('snapshot').textContent, /Retained symbol checkpoint 1/);
  await p.ui.search(); assert.equal(p.calls.length, 3);
  assert.equal(p.calls[2].fields.has('expected_head'), false); assert.equal(p.calls[2].fields.get('minimum_index_number'), '1');
  assert.equal(p.buttons('results').length, 1); assert.ok(p.get('snapshot').textContent.includes(p.f.current.snapshot_token)); p.ui.disconnect();
});
test('mode changes revoke downloads and detached controls cannot resurrect discarded results', async () => {
  const p = await setup(); p.revalidate(); await p.ui.search(); await p.ui.openSymbol(0);
  const oldResult = p.buttons('results')[0], oldDownload = p.buttons('file')[0]; oldDownload.click();
  assert.equal(p.urls.size, 1); const pin = p.get('snapshot').textContent;
  p.get('index-source-mode').value = 'exact'; p.get('index-source-mode').emit('change'); clear(p);
  oldResult.click(); oldDownload.click(); await tick();
  assert.equal(p.calls.length, 2); assert.equal(p.document.downloads.length, 1);
  assert.equal(p.get('snapshot').textContent, pin); assert.equal(p.revoked.length, 1); p.ui.disconnect();
});
test('changing source mode cancels an in-flight query and blocks its late provenance display', async () => {
  const gate = deferred(), entered = deferred(), p = await setup(undefined, () => { entered.resolve(); return gate.promise; });
  p.revalidate(); const waiting = p.ui.search(); await entered.promise;
  p.get('index-source-mode').value = 'exact'; p.get('index-source-mode').emit('input');
  gate.resolve(response(p.f.wrapper())); await waiting; clear(p);
  assert.equal(p.calls[0].options.signal.aborted, true); assert.match(p.get('status').textContent, /Query changed/);
  assert.equal(p.get('snapshot').textContent.includes('Retained'), false); p.ui.disconnect();
});
test('canceling a pending native digest never enables a verified file or download', async () => {
  const ready = deferred(), gate = deferred();
  const cryptoImpl = { subtle: { async digest(algorithm, bytes) {
    const actual = await webcrypto.subtle.digest(algorithm, bytes);
    if (Buffer.from(bytes).subarray(0, 5).toString() === 'blob ') { ready.resolve(); await gate.promise; }
    return actual;
  } } };
  const p = await setup(undefined, undefined, { cryptoImpl }); p.revalidate(); await p.ui.search();
  const pending = p.ui.openSymbol(0); await ready.promise; p.get('cancel').click(); gate.resolve(); await pending;
  assert.equal(p.get('file').textContent, ''); assert.equal(p.urls.size, 0);
  assert.match(p.get('status').textContent, /canceled/); assert.equal(p.calls.length, 2); p.ui.disconnect();
});
test('page exit clears private provenance, checkpoints, query text and live download URLs', async () => {
  const p = await setup(); p.revalidate(); await p.ui.search(); await p.ui.openSymbol(0); p.buttons('file')[0].click();
  p.document.defaultView.emit('pagehide'); clear(p);
  for (const id of ['token', 'query', 'prefixes', 'initial-symbol-name']) assert.equal(p.get(id).value, '');
  assert.equal(p.get('snapshot').textContent, ''); assert.equal(p.get('submit-search').disabled, true);
  await p.ui.search(); assert.equal(p.calls.length, 2);
});
test('stale diagnosis is mode-specific, with no retry, scan, or empty successful view', async () => {
  for (const [mode, source, pattern] of [['symbols', 'exact', /Choose Revalidate unchanged Git source explicitly/],
    ['symbols', 'revalidated', /conflicting provenance/], ['initial', 'revalidated', /Combined retrieval requires an exact/]]) {
    const p = await setup(undefined, () => response({ error: 'symbol_index_stale', message: '<img>' }, 409));
    p.get('mode').value = mode; p.get('index-source-mode').value = source;
    if (mode === 'initial') p.get('initial-symbol-name').value = 'Thing';
    p.get('mode').emit('change'); await p.ui.search(); clear(p);
    assert.match(p.get('status').textContent, pattern); assert.equal(p.get('status').textContent.includes('<img>'), false);
    assert.equal(p.calls.length, 1); assert.equal(p.calls[0].fields.get('source_mode'), mode === 'symbols' && source === 'revalidated' ? 'revalidated' : null);
    p.ui.disconnect();
  }
});
test('missing, corrupt, over-budget, denied and revoked indexes cannot retain results or downloads', async () => {
  for (const status of [401, 403, 404, 409, 413, 503]) {
    let refusal = false;
    const p = await setup(undefined, () => refusal ? response({ error: 'symbol_index_uninitialized' }, status) : null);
    p.revalidate(); await p.ui.search(); await p.ui.openSymbol(0); p.buttons('file')[0].click();
    refusal = true; await p.ui.search(); clear(p); assert.equal(p.calls.length, 3);
    if (status === 401) { assert.equal(p.get('snapshot').textContent, ''); assert.equal(p.get('submit-search').disabled, true); }
    else assert.match(p.get('snapshot').textContent, /Retained symbol checkpoint 1/);
    p.ui.disconnect();
  }
});
test('malformed newer receipts cannot update displayed checkpoints or retain a prior download', async () => {
  const f = currentFixture(); let broken = false;
  const p = await setup(f, call => {
    if (!broken || !call.url.endsWith('search-symbols-index')) return null;
    const reply = f.wrapper(); reply.result.index_number = 9; reply.indexed_source.source_commit = 'f'.repeat(40);
    return response(reply);
  });
  p.revalidate(); await p.ui.search(); await p.ui.openSymbol(0); p.buttons('file')[0].click(); const pin = p.get('snapshot').textContent;
  broken = true; await p.ui.search(); clear(p); assert.equal(p.get('snapshot').textContent, pin);
  assert.match(p.get('status').textContent, /native source changed/); p.ui.disconnect();
});
test('unsafe numeric generation refuses before a checkpoint or source reaches the page', async () => {
  const f = currentFixture(); f.reply.index_number = Number.MAX_SAFE_INTEGER + 1;
  const p = await setup(f); p.revalidate(); await p.ui.search(); clear(p);
  assert.match(p.get('status').textContent, /safe integers/); assert.equal(p.get('snapshot').textContent.includes('Retained'), false);
  assert.equal(p.calls.length, 1); p.ui.disconnect();
});
test('empty and truncated revalidated results retain provenance but never fabricate continuation', async () => {
  for (const empty of [true, false]) {
    const f = currentFixture();
    if (empty) Object.assign(f.reply, { matches: [], returned_matches: 0, indexed_files: 0, indexed_declarations: 0, indexed_source_bytes: 0, tables_read: 0 });
    else Object.assign(f.reply, { indexed_declarations: 2, complete: false, completion: 'match_limit' });
    const p = await setup(f); p.revalidate(); p.get('max-matches').value = '1'; await p.ui.search();
    assert.match(p.get('results').textContent, /Original indexed snapshot/);
    assert.equal(p.buttons('results').length, empty ? 0 : 1);
    assert.equal(p.buttons('results').some(button => /Next/.test(button.textContent)), false);
    assert.match(p.get('status').textContent, empty ? /complete/ : /truncated/); p.ui.disconnect();
  }
});
test('native byte corruption and old source pages cannot enable any file download', async () => {
  for (const change of [r => { r.content_hex = '00' + r.content_hex.slice(2); }, r => { r.source_rcr = 'source-rcr-A'; }]) {
    const f = currentFixture(), p = await setup(f, call => {
      if (!call.url.endsWith('/blob')) return null;
      const reply = f.currentFile(0); change(reply); return response(reply);
    });
    p.revalidate(); await p.ui.search(); await p.ui.openSymbol(0);
    assert.equal(p.get('file').textContent, ''); assert.equal(p.buttons('file').length, 0); assert.equal(p.urls.size, 0);
    assert.equal(p.calls.length, 2); assert.equal(p.get('status').textContent.includes('coordinates verified'), false); p.ui.disconnect();
  }
});
test('provenance text remains inert and its bidi controls are escaped', async () => {
  const f = currentFixture(); f.current.source_rcr = '<img>\u202e'; f.current.forge_position_root = '<script>';
  const p = await setup(f); p.revalidate(); await p.ui.search();
  assert.ok(p.get('results').textContent.includes('<img>\\u{202e}')); assert.ok(p.get('results').textContent.includes('<script>'));
  assert.equal(p.get('results').descendants().some(node => ['IMG', 'SCRIPT'].includes(node.tagName)), false);
  assert.equal(p.get('results').textContent.includes('\u202e'), false); p.ui.disconnect();
});
test('invalid source modes and form limits refuse before issuing a request', async () => {
  const p = await setup(); p.get('index-source-mode').value = 'automatic'; await p.ui.search();
  assert.equal(p.calls.length, 0); clear(p);
  p.revalidate(); p.get('max-matches').value = '101'; await p.ui.search(); assert.equal(p.calls.length, 0); clear(p);
  p.get('max-matches').value = '100'; await p.ui.search(); assert.equal(p.calls.length, 1); assert.equal(p.buttons('results').length, 1); p.ui.disconnect();
});
