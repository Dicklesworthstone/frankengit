// Execute the shipped form/controller and real WebCrypto using the repository's
// observable DOM and source-derived wire fixtures; not browser layout or live fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mount, readQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-view.mjs';
import { initialQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { dom, tick } from './search-dom-fixture.mjs';
import { clone, fixture, hex, response, fileReply, webcrypto } from './search-initial-fixtures.mjs';

function setup(f = fixture(), handler = null, combined = true) {
  const d = dom(), calls = [];
  d.get('format').value = f.format;
  if (combined) d.get('mode').value = 'initial';
  d.get('query').value = 'Needle'; d.get('prefixes').value = 'src';
  d.get('initial-symbol-name').value = f.input.symbol ? 'Needle' : '';
  d.get('initial-symbol-policy').value = f.input.symbol?.policy ?? 'optional';
  for (const [field, value] of [['max-matches', f.input.maxMatches], ['index-work', f.input.maxWork],
    ['index-payload', f.input.maxPayloadBytes], ['initial-result-bytes', f.input.maxResultBytes]]) d.get(field).value = String(value);
  const actions = mount(d.document, { href: 'https://forge.example/repo.git/ui/search/' }, { cryptoImpl: webcrypto, urlApi: d.urlApi,
    fetchImpl: async (url, init) => {
      const call = { path: new URL(url).pathname.split('/api/v1/')[1], fields: new URLSearchParams(init.body), init }; calls.push(call);
      if (handler) { const r = await handler(call, calls.length); if (r !== undefined) return r; }
      if (call.path === 'source/search-initial') return response(f.reply);
      if (call.path === 'source/blob') {
        const file = f.files.find(file => file.pathHex === call.fields.get('path_hex'));
        assert.ok(file, 'only the selected fixture file can be read');
        return response(fileReply(f, file, Number(call.fields.get('offset'))));
      }
      assert.fail(`Unexpected extra request: ${call.path}`);
    } });
  const connect = async () => { d.get('token').value = 'a'.repeat(64); await actions.connect(); };
  const section = channel => d.get('results').children.find(el => el.attributes['aria-label'] ===
    (channel === 'symbols' ? 'Combined declaration results' : `Combined ${channel} results`));
  const hitButtons = channel => section(channel).descendants().filter(el => el.tagName === 'BUTTON');
  return { d, f, calls, actions, connect, section, hitButtons };
}
async function until(done) {
  for (let i = 0; i < 200; i++) { if (done()) return; await tick(); }
  assert.fail('controller did not reach its expected bounded state');
}
const set = (d, id, value) => { d.get(id).value = value; d.get(id).emit('input'); };

test('combined controls are opt-in and never imply lexical revalidation or source-scan limits', () => {
  const h = setup(fixture(), null, false), { d } = h;
  assert.equal(d.get('mode').value, 'literal'); assert.equal(d.get('initial-controls').hidden, true);
  assert.equal(d.get('initial-result-bytes').disabled, true); assert.equal(d.get('initial-symbol-name').disabled, true);
  assert.match(d.html, /value="initial">Combined indexed search/);
  assert.ok(!d.html.includes('<script>')); assert.equal((d.html.match(/<script /g) ?? []).length, 1);
  set(d, 'initial-symbol-name', ''); set(d, 'mode', 'initial');
  for (const id of ['case', 'max-bytes', 'index-source-mode', 'max-steps', 'symbol-match', 'symbol-kind', 'initial-symbol-policy']) assert.equal(d.get(id).disabled, true, id);
  for (const id of ['index-work', 'index-payload', 'max-file-bytes', 'initial-symbol-name', 'initial-result-bytes']) assert.equal(d.get(id).disabled, false, id);
  assert.equal(d.get('initial-controls').hidden, false); assert.equal(d.get('initial-help').hidden, false);
  set(d, 'initial-symbol-name', 'Needle');
  for (const id of ['symbol-match', 'symbol-kind', 'initial-symbol-policy']) assert.equal(d.get(id).disabled, false, id);
  set(d, 'mode', 'symbols'); assert.equal(d.get('initial-controls').hidden, true); assert.equal(d.get('initial-result-bytes').disabled, true);
  assert.equal(d.get('symbol-match').disabled, false); assert.equal(d.get('max-bytes').disabled, false);
  set(d, 'mode', 'indexed-path'); assert.equal(d.get('index-source-mode').disabled, false); assert.equal(d.get('symbol-match').disabled, true);
  assert.equal(h.calls.length, 0);
});

test('form keeps lexical words and the separate declaration name case and encoding distinct', () => {
  const { d } = setup();
  set(d, 'query', 'Needle\nNEEDLE\n'); set(d, 'symbol-match', 'prefix'); set(d, 'symbol-kind', 'function');
  set(d, 'initial-symbol-policy', 'required');
  d.get('index-source-mode').value = 'revalidated'; d.get('max-bytes').value = 'invalid-disabled-value';
  const q = initialQuery(readQuery(d.document));
  assert.deepEqual(q.termsHex, [hex('needle')]);
  assert.deepEqual(q.symbol, { nameHex: hex('Needle'), match: 'prefix', kinds: ['function'], policy: 'required' });
  assert.equal('sourceMode' in q, false); assert.equal('maxBytes' in q, false);
  set(d, 'encoding', 'hex'); set(d, 'query', hex('Needle')); set(d, 'initial-symbol-name', hex('Needle'));
  assert.deepEqual(initialQuery(readQuery(d.document)), q);
  set(d, 'initial-symbol-name', ''); assert.equal(initialQuery(readQuery(d.document)).symbol, null);
});

test('submitting the actual form makes one request and renders a checked generation vector', async () => {
  const h = setup(), { d } = h;
  d.get('token').value = 'a'.repeat(64);
  assert.equal(d.get('connection').emit('submit').defaultPrevented, true);
  await until(() => !d.get('submit-search').disabled);
  assert.equal(d.get('token').value, ''); assert.equal(h.calls.length, 0);
  assert.equal(d.get('search-form').emit('submit').defaultPrevented, true);
  await until(() => h.calls.length === 1 && d.get('cancel').disabled);
  assert.match(d.get('status').textContent, /Combined query complete/);
  assert.deepEqual(h.calls.map(c => c.path), ['source/search-initial']);
  const form = h.calls[0].fields;
  assert.equal(form.get('max_work'), '997'); assert.equal(form.get('max_payload_bytes'), '3001');
  assert.equal(form.get('symbol_name_hex'), hex('Needle')); assert.equal(form.get('term_hex'), hex('needle'));
  assert.equal(form.get('source_mode'), null); assert.equal(form.get('max_file_bytes'), null);
  assert.match(d.get('results').textContent, /Lexical generation 7/); assert.match(d.get('results').textContent, /Symbol generation 4/);
  assert.match(d.get('results').textContent, /successful-channel/); assert.match(d.get('snapshot').textContent, /Retained symbol checkpoint 4/);
  for (const channel of ['content', 'path', 'symbols']) assert.equal(h.hitButtons(channel).length, 2);
  assert.equal(d.get('file').children.length, 0); assert.equal(d.document.downloads.length, 0);
});

for (const format of ['sha1', 'sha256']) test(`${format} channel buttons verify full files and expose downloads only afterwards`, async () => {
  const h = setup(fixture({ format })), { d } = h; await h.connect(); await h.actions.search();
  assert.equal(d.buttons('file').length, 0);
  for (const channel of ['content', 'path', 'symbols']) {
    h.hitButtons(channel)[0].click();
    await until(() => d.buttons('file').some(b => b.textContent === 'Download verified file bytes'));
    assert.match(d.get('file').textContent, /Native blob verified/);
    assert.ok(d.get('file').textContent.includes(`Opened the ${channel} channel`));
    assert.equal(h.calls.at(-1).fields.get('expected_head'), h.f.source.snapshot_token);
    assert.equal(h.calls.at(-1).fields.get('expected_commit'), h.f.source.source_commit);
    if (channel === 'symbols') assert.match(d.get('file').textContent, /Full declaration-name bytes/);
    else assert.match(d.get('file').textContent, /first whole-word spans reproduced/);
    const download = d.buttons('file').find(b => b.textContent === 'Download verified file bytes'); download.click();
    const last = d.document.downloads.at(-1);
    assert.equal(last.download, 'snapshot-source.bin'); assert.ok(d.urls.has(last.href));
    assert.deepEqual(new Uint8Array(await d.urls.get(last.href).arrayBuffer()), h.f.files[0].bytes);
    assert.equal(d.document.focused, d.get('file'));
  }
  assert.equal(h.calls.length, 4); assert.equal(d.revoked.length, 2);
  assert.match(d.get('results').textContent, /6 results across combined channels/);
});

for (const reason of ['stale', 'uninitialized']) test(`optional ${reason} declarations stay labeled unavailable while lexical buttons work`, async () => {
  const h = setup(fixture({ symbols: reason })), { d } = h; await h.connect(); await h.actions.search();
  assert.match(d.get('status').textContent, /incomplete/);
  assert.match(h.section('symbols').textContent, new RegExp(`Declaration channel unavailable: ${reason}`));
  assert.match(h.section('symbols').textContent, /not an empty successful result/); assert.equal(h.hitButtons('symbols').length, 0);
  assert.match(d.get('snapshot').textContent, /Retained index checkpoint 7/); assert.ok(!d.get('snapshot').textContent.includes('Retained symbol checkpoint'));
  h.hitButtons('content')[0].click(); await until(() => d.buttons('file').length > 0);
  assert.equal(h.calls.length, 2); assert.equal(h.calls[1].path, 'source/blob');
});

test('omitted symbol name means a two-channel request, not a fabricated empty symbol result', async () => {
  const h = setup(fixture({ symbols: 'not_requested' })); await h.connect(); await h.actions.search();
  assert.equal(h.calls[0].fields.get('symbol_name_hex'), null);
  assert.match(h.section('symbols').textContent, /Declaration channel not requested/);
  assert.equal(h.hitButtons('symbols').length, 0); assert.match(h.d.get('status').textContent, /Combined query complete/);
});

test('truncated combined channels have no standalone continuation button or implicit extra request', async () => {
  const h = setup(fixture({ limit: 1 })); await h.connect(); await h.actions.search();
  assert.match(h.d.get('status').textContent, /incomplete/);
  for (const channel of ['content', 'path']) assert.match(h.section(channel).textContent, /combined channel is truncated/);
  assert.match(h.section('symbols').textContent, /Limited declaration prefix/);
  assert.ok(!h.d.buttons('results').some(b => b.textContent.includes('Next')));
  await h.actions.nextIndexed(); assert.equal(h.calls.length, 1);
});

test('required or checkpointed symbol refusals clear results but keep exact source and checkpoints', async () => {
  let refuse = false;
  const h = setup(fixture(), () => refuse ? response({ error: 'symbol_index_stale' }, 409) : undefined);
  await h.connect(); await h.actions.search(); const before = h.d.get('snapshot').textContent;
  refuse = true; set(h.d, 'initial-symbol-policy', 'required'); await h.actions.search();
  assert.equal(h.calls.length, 2); assert.equal(h.calls[1].fields.get('minimum_symbol_number'), '4');
  assert.equal(h.calls[1].fields.get('symbol_policy'), 'required');
  assert.equal(h.d.get('snapshot').textContent, before); assert.equal(h.d.get('results').children.length, 0);
  assert.match(h.d.get('status').textContent, /exact source snapshot/);
  assert.ok(!h.d.get('status').textContent.includes('complete'));
});

test('wrong joined receipts cannot render a partial new answer or advance a retained floor', async () => {
  const f = fixture(), h = setup(f); await h.connect(); await h.actions.search();
  const before = h.d.get('snapshot').textContent;
  f.reply.path.selected_index_number = 8; f.reply.path.selected_index_token = `alg:2:${'f'.repeat(64)}`;
  f.reply.symbols.result.snapshot_token = `alg:2:${'e'.repeat(64)}`;
  await h.actions.search();
  assert.equal(h.d.get('results').children.length, 0); assert.equal(h.d.get('snapshot').textContent, before);
  assert.match(h.d.get('status').textContent, /snapshot changed/i); assert.equal(h.calls.length, 2);
});

test('editing combined options invalidates results without silently releasing the snapshot', async () => {
  const h = setup(); await h.connect(); await h.actions.search(); const before = h.d.get('snapshot').textContent;
  const oldButton = h.hitButtons('content')[0];
  set(h.d, 'initial-result-bytes', '1000'); oldButton.click();
  assert.equal(h.d.get('results').children.length, 0); assert.equal(h.d.get('snapshot').textContent, before); assert.equal(h.calls.length, 1);
  set(h.d, 'initial-result-bytes', '0'); await h.actions.search(); assert.equal(h.calls.length, 1);
  assert.match(h.d.get('status').textContent, /Invalid/);
});

test('query changes and pagehide prevent delayed verified files from reviving discarded state', async () => {
  for (const action of ['change', 'pagehide']) {
    let release, started;
    const called = new Promise(resolve => { started = resolve; });
    const h = setup(fixture(), call => {
      if (call.path === 'source/blob') { started(); return new Promise(resolve => { release = resolve; }); }
    });
    await h.connect(); await h.actions.search();
    const pending = h.actions.openInitial('content', 0); await called;
    if (action === 'change') set(h.d, 'initial-symbol-name', 'Other'); else h.d.document.defaultView.emit('pagehide');
    release(response(fileReply(h.f, h.f.files[0]))); await pending;
    assert.equal(h.d.get('file').children.length, 0); assert.equal(h.d.get('results').children.length, 0);
    assert.equal(h.d.urls.size, 0); assert.equal(h.d.document.downloads.length, 0);
    if (action === 'pagehide') { assert.equal(h.d.get('initial-symbol-name').value, ''); assert.equal(h.d.get('snapshot').textContent, ''); }
  }
});

test('pagehide revokes verified downloads and clears the extra declaration input and all visible state', async () => {
  const h = setup(); await h.connect(); await h.actions.search(); await h.actions.openInitial('symbols', 0);
  h.d.buttons('file').find(b => b.textContent === 'Download verified file bytes').click();
  assert.equal(h.d.urls.size, 1); h.d.document.defaultView.emit('pagehide');
  assert.equal(h.d.urls.size, 0); assert.equal(h.d.revoked.length, 1);
  for (const id of ['token', 'query', 'prefixes', 'initial-symbol-name']) assert.equal(h.d.get(id).value, '');
  for (const id of ['snapshot', 'results', 'file']) assert.equal(h.d.get(id).textContent, '');
  assert.equal(h.d.get('submit-search').disabled, true);
});

test('untrusted result paths stay literal and bidi-escaped in all combined sections', async () => {
  const f = fixture(), path = 'src/<img onerror=alert(1)>\u202e/needle.rs';
  f.files[0].path = path; f.files[0].pathHex = hex(path);
  for (const channel of ['content', 'path']) {
    f.reply[channel].hits[0].path_hex = hex(path);
    if (channel === 'path') f.reply[channel].hits[0].spans[0].byte_offset = Buffer.byteLength(path.slice(0, path.indexOf('needle')));
  }
  f.reply.symbols.result.matches[0].path_hex = hex(path);
  f.reply.retained_result_bytes += 3 * (Buffer.byteLength(path) - Buffer.byteLength('src/needle.rs'));
  const h = setup(f); await h.connect(); await h.actions.search();
  const text = h.d.get('results').textContent;
  assert.match(text, /<img onerror=alert\(1\)>/); assert.ok(text.includes('\\u{202e}')); assert.ok(!text.includes('\u202e'));
  assert.ok(!h.d.get('results').descendants().some(el => ['IMG', 'SCRIPT', 'IFRAME'].includes(el.tagName)));
  assert.equal(h.calls.length, 1);
});
