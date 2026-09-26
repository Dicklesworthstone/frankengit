// Observable DOM/controller integration with real WebCrypto and wire fixtures.
// This is not browser layout/accessibility or an executed native HTTP service.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mount, readQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-view.mjs';
import { symbolQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { dom, tick } from './search-dom-fixture.mjs';
import { fixture, hex, transport, response, token, href, deferred } from './search-symbol-fixtures.mjs';
async function setup(f = fixture(), intercept) {
  const page = dom(), env = transport(f, intercept);
  const ui = mount(page.document, { href }, { ...env.options, urlApi: page.urlApi });
  page.get('token').value = token; page.get('format').value = f.source.object_format;
  await ui.connect(); page.get('mode').value = 'symbols'; page.get('query').value = Buffer.from(f.input.nameHex, 'hex').toString();
  page.get('mode').emit('change'); return { ...page, ...env, ui, f };
}
async function until(predicate) {
  for (let i = 0; i < 100 && !predicate(); i++) await tick();
  assert.ok(predicate(), 'expected asynchronous UI transition');
}
test('declaration controls are explicit and cannot inherit lexical folding or revalidation', async () => {
  const p = await setup(); assert.equal(p.get('token').value, '');
  assert.equal(p.get('symbol-controls').hidden, false); assert.equal(p.get('symbol-help').hidden, false);
  assert.equal(p.get('case').disabled, true); assert.equal(p.get('index-source-mode').disabled, true);
  assert.equal(p.get('index-payload').disabled, true); assert.equal(p.get('index-work').disabled, false);
  p.get('case').value = 'ascii-insensitive'; p.get('index-source-mode').value = 'revalidated';
  p.get('symbol-kind').value = 'struct'; p.get('symbol-match').value = 'prefix';
  const q = symbolQuery(readQuery(p.document));
  assert.equal(q.nameHex, hex('Thing')); assert.equal(q.match, 'prefix'); assert.deepEqual(q.kinds, ['struct']);
  assert.equal('sourceMode' in q, false); assert.equal('case' in q, false); assert.equal('maxPayloadBytes' in q, false);
  p.get('mode').value = 'literal'; p.get('mode').emit('change');
  assert.equal(p.get('symbol-controls').hidden, true); assert.equal(p.get('symbol-match').disabled, true); assert.equal(p.get('case').disabled, false);
  p.ui.disconnect();
});
for (const format of ['sha1', 'sha256']) {
  test(`${format}: submitted form, result button, verified preview and download use the production path`, async () => {
    const f = fixture(format, { name: 'type', raw: true, path: Buffer.from('src/<img>\x1b\xff.rs', 'latin1') }), p = await setup(f);
    const submitted = p.get('search-form').emit('submit'); assert.equal(submitted.defaultPrevented, true);
    await until(() => p.buttons('results').length === 1);
    assert.equal(p.calls.length, 1); assert.equal(p.get('submit-search').disabled, false);
    assert.match(p.get('results').textContent, /struct r#type/); assert.match(p.get('results').textContent, /No source blobs were scanned/);
    assert.match(p.get('snapshot').textContent, /Retained symbol checkpoint/);
    assert.equal(p.get('results').descendants().some(e => e.tagName === 'IMG'), false);
    assert.equal(p.get('results').textContent.includes('\x1b'), false);
    p.buttons('results')[0].click(); await until(() => p.buttons('file').length === 1);
    assert.match(p.get('file').textContent, /Full declaration-name bytes/);
    assert.match(p.get('file').textContent, /not verified here/);
    const mark = p.get('file').descendants().find(e => e.tagName === 'MARK'); assert.equal(mark.textContent, 'type');
    p.buttons('file')[0].click(); assert.equal(p.document.downloads[0].download, 'snapshot-source.bin');
    const blob = [...p.urls.values()][0]; assert.deepEqual(Buffer.from(await blob.arrayBuffer()), f.body);
    p.get('symbol-kind').value = 'enum'; p.get('symbol-kind').emit('change');
    assert.equal(p.get('results').textContent, ''); assert.equal(p.get('file').textContent, ''); assert.equal(p.urls.size, 0);
    assert.match(p.get('snapshot').textContent, /Snapshot alg:/); p.ui.disconnect();
  });
}
test('truncated declarations never expose a fake server continuation', async () => {
  const f = fixture(); f.reply.indexed_declarations = 2; f.reply.complete = false; f.reply.completion = 'match_limit';
  const p = await setup(f); p.get('max-matches').value = '1'; await p.ui.search();
  assert.match(p.get('results').textContent, /no continuation cursor/);
  assert.equal(p.buttons('results').length, 1); assert.equal(p.buttons('results').some(b => b.textContent.includes('Next')), false);
  assert.match(p.get('status').textContent, /truncated/); assert.equal(p.calls.length, 1); p.ui.disconnect();
});
test('stale index diagnosis does not release pins, rebuild, retry or present an empty result', async () => {
  let stale = false; const p = await setup(fixture(), () => stale ? response({ error: 'symbol_index_stale', message: '<img>' }, 409) : null);
  await p.ui.search(); const pin = p.get('snapshot').textContent; stale = true; await p.ui.search();
  assert.match(p.get('status').textContent, /lexical revalidation does not apply/);
  assert.equal(p.get('status').textContent.includes('<img>'), false); assert.equal(p.get('results').textContent, '');
  assert.equal(p.get('snapshot').textContent, pin); assert.equal(p.calls.length, 2);
  p.ui.refresh(); assert.match(p.get('snapshot').textContent, /Retained symbol checkpoint/); p.ui.disconnect();
});
test('a changed kind or name cancels the pending search and blocks late DOM installation', async () => {
  const gate = deferred(), entered = deferred(); const p = await setup(fixture(), () => { entered.resolve(); return gate.promise; });
  const waiting = p.ui.search(); await entered.promise; p.get('symbol-match').value = 'prefix'; p.get('symbol-match').emit('change');
  gate.resolve(response(p.f.reply)); await waiting;
  assert.equal(p.get('results').textContent, ''); assert.equal(p.get('snapshot').textContent.includes('source-head-A'), false);
  assert.match(p.get('status').textContent, /Query changed/); assert.equal(p.calls.length, 1); p.ui.disconnect();
});
test('disconnect during file navigation discards pending verification and all credentials', async () => {
  const gate = deferred(), entered = deferred(); let delayFile = false;
  const p = await setup(fixture(), call => {
    if (delayFile && call.url.endsWith('/blob')) { entered.resolve(); return gate.promise; }
    return null;
  });
  await p.ui.search(); delayFile = true; const waiting = p.ui.openSymbol(0); await entered.promise;
  p.document.defaultView.emit('pagehide'); gate.resolve(response(p.f.file(0))); await waiting;
  assert.equal(p.get('file').textContent, ''); assert.equal(p.get('results').textContent, ''); assert.equal(p.get('snapshot').textContent, '');
  assert.equal(p.get('token').value, ''); assert.equal(p.get('query').value, ''); assert.equal(p.get('submit-search').disabled, true);
  assert.equal(p.document.downloads.length, 0);
});
test('all browser imports remain in the existing native static-asset allowlist', () => {
  const base = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
  const allowed = new Set(['search.mjs', 'search-view.mjs', 'search-data.mjs', 'search-index.mjs', 'search-current.mjs', 'pulls-core.mjs']);
  for (const name of allowed) {
    const code = readFileSync(new URL(name, base), 'utf8');
    for (const match of code.matchAll(/from '\.\/([^']+)'/g)) assert.ok(allowed.has(match[1]), match[1]);
    for (const sink of ['innerHTML', 'document.write', 'localStorage', 'sessionStorage']) assert.equal(code.includes(sink), false, `${name}: ${sink}`);
  }
  const html = readFileSync(new URL('search.html', base), 'utf8');
  for (const id of ['symbol-controls', 'symbol-match', 'symbol-kind', 'symbol-help']) assert.ok(html.includes(`id="${id}"`));
  assert.equal(html.includes('<script>'), false);
});
