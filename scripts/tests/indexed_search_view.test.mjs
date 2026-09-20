// The shipped DOM controller, transport and validators run together. Only DOM,
// download URLs and HTTP replies are fixtures; no live node/browser claim.
// Reconciled onto b8db1231: preserve openIndexed/nextIndexed, dynamic page
// controls, all-term previews and the existing 100-document bound.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { mount, readQuery, display } from '../../crates/fgit-node/src/smart_http/server/browser/search-view.mjs';
import { indexQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { token, href, document as indexedDocument, page, input, blobPage, response, hex, utf8, webcrypto, indexToken, source } from './indexed_search_fixture.mjs';

const html = await readFile(new URL('../../crates/fgit-node/src/smart_http/server/browser/search.html', import.meta.url), 'utf8');
class Element {
  constructor(tag = 'div') { this.tag = tag; this.value = ''; this.children = []; this.listeners = new Map(); this.disabled = false; this.hidden = false; this.attributes = {}; this.ownText = ''; }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(c => c.textContent ?? String(c)).join(''); }
  addEventListener(type, listener) { const list = this.listeners.get(type) ?? []; list.push(listener); this.listeners.set(type, list); }
  emit(type) { for (const listener of this.listeners.get(type) ?? []) listener({ target: this, preventDefault() {} }); }
  append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
  replaceChildren(...children) { this.ownText = ''; this.children = []; this.append(...children); }
  setAttribute(key, value) { this.attributes[key] = value; }
  focus() { this.focused = true; }
  click() { this.clicked = true; this.emit('click'); }
  remove() { this.parent.children = this.parent.children.filter(child => child !== this); }
  all(tag) { return this.children.flatMap(c => [ ...(c.tag === tag ? [c] : []), ...(c.all?.(tag) ?? []) ]); }
}
function dom() {
  const controls = new Map();
  for (const match of html.matchAll(/<([a-z][a-z0-9-]*)\b[^>]*\bid="([^"]+)"[^>]*>/g)) {
    assert.ok(!controls.has(match[2]), `duplicate HTML ID ${match[2]}`);
    const element = new Element(match[1]);
    element.value = match[0].match(/\bvalue="([^"]*)"/)?.[1] ?? '';
    element.disabled = /\sdisabled(?:\s|>)/.test(match[0]); element.hidden = /\shidden(?:\s|>)/.test(match[0]);
    controls.set(match[2], element);
  }
  const get = id => { assert.ok(controls.has(id), `missing shipped control ${id}`); return controls.get(id); };
  for (const [id, value] of Object.entries({ mode: 'indexed-content', encoding: 'utf8', case: 'exact',
    'prefix-encoding': 'utf8', format: 'sha1', token, query: 'Alpha\nBETA' })) get(id).value = value;
  const events = new Element();
  return { get, controls, document: { getElementById: get, createElement: tag => new Element(tag), defaultView: events }, events };
}
function fixture({ docs = [indexedDocument()], complete = true, respond, mode = 'indexed-content', queryText = 'Alpha\nBETA', limit = '100' } = {}) {
  const d = dom(), calls = [], urls = new Map(), revoked = [];
  d.get('mode').value = mode; d.get('query').value = queryText; d.get('max-matches').value = limit;
  const q = indexQuery(readQuery(d.document));
  const app = mount(d.document, { href }, { cryptoImpl: webcrypto,
    urlApi: { createObjectURL(blob) { const url = `blob:fixture-${urls.size}`; urls.set(url, blob); return url; }, revokeObjectURL(url) { revoked.push(url); } },
    fetchImpl: async (url, init) => {
      const call = { path: url.pathname, fields: new URLSearchParams(init.body), init }; calls.push(call);
      if (respond) return respond(call, calls.length, q);
      if (call.path.endsWith('/search-index')) return response(page(q, docs, { complete, next_after: complete ? null : docs.at(-1).raw.document_id,
        indexed_documents: docs.length + Number(!complete), indexed_source_bytes: docs.reduce((n, d) => n + d.bytes.length, 0) + Number(!complete) }));
      const found = docs.find(item => item.raw.path_hex === call.fields.get('path_hex'));
      assert.ok(found, 'file must come from returned hit'); return response(blobPage(found, call.fields));
    } });
  return { ...d, app, q, docs, calls, urls, revoked, status: () => d.get('status').textContent,
    results: () => d.get('results').textContent, file: () => d.get('file').textContent,
    next: () => d.get('results').all('button').find(button => button.textContent === 'Next indexed page') };
}
function assertReadCalls(calls) {
  for (const { path, init } of calls) {
    assert.ok(path.endsWith('/search-index') || path.endsWith('/blob'));
    assert.equal(init.method, 'POST'); assert.equal(init.headers['Idempotency-Key'], undefined);
    assert.equal(init.credentials, 'omit'); assert.equal(init.redirect, 'error');
  }
}
for (const [mode, channel] of [['indexed-content', 'content'], ['indexed-path', 'path']]) test(`${mode}: closed form semantics, normalized AND terms and independent budgets`, () => {
  const d = dom(); d.get('mode').value = mode; d.get('query').value = 'BETA\nalpha\nALPHA\n';
  // Disabled scalar controls cannot influence the indexed request.
  for (const id of ['case', 'max-bytes', 'max-steps']) d.get(id).value = 'not-applicable';
  const q = indexQuery(readQuery(d.document));
  assert.equal(q.channel, channel); assert.deepEqual(q.termsHex, [hex(utf8.encode('alpha')), hex(utf8.encode('beta'))]);
  assert.equal(q.maxWork, 16 * 1024 * 1024); assert.equal(q.maxPayloadBytes, 32 * 1024 * 1024);
});
for (const [value, encoding] of [['a b', 'utf8'], ['a\n\nB', 'utf8'], ['α', 'utf8'], ['0g', 'hex'], ['00', 'hex'], ['61\n'.repeat(33), 'hex']]) {
  test(`indexed form refuses ${JSON.stringify(value.slice(0, 20))} (${encoding})`, () => {
    const d = dom(); d.get('query').value = value; d.get('encoding').value = encoding;
    assert.throws(() => indexQuery(readQuery(d.document)));
  });
}
test('indexed controls disable scan-only options without silently changing the literal default in HTML', () => {
  const f = fixture();
  assert.match(html, /id="mode"><option value="literal"/);
  for (const id of ['case', 'max-bytes', 'max-steps']) assert.equal(f.get(id).disabled, true);
  for (const id of ['index-work', 'index-payload']) assert.equal(f.get(id).disabled, false);
  assert.equal(f.get('index-help').hidden, false); assert.equal(f.next(), undefined);
  f.get('mode').value = 'literal'; f.get('mode').emit('change');
  assert.equal(f.get('case').disabled, false); assert.equal(f.get('index-help').hidden, true);
  assert.equal(f.get('index-work').disabled, true);
});
test('content search renders index counters, verifies every term and downloads exact file bytes', async () => {
  const f = fixture(); await f.app.connect(); assert.equal(f.get('token').value, '');
  await f.app.search();
  assert.match(f.results(), /1 indexed documents/); assert.match(f.results(), /not a live source scan/);
  assert.equal(f.next(), undefined);
  assert.match(f.results(), /Queried index 2/);
  await f.app.openIndexed(0);
  assert.match(f.file(), /Native blob verified/); assert.match(f.file(), /beta: content bytes \[12, 16\); line 1, byte column 13/);
  assert.equal(f.get('file').all('mark')[1].textContent, 'beta');
  f.get('file').all('button').find(b => b.textContent === 'Download verified file bytes').click();
  assert.equal(f.urls.size, 1); assert.deepEqual(new Uint8Array(await [...f.urls.values()][0].arrayBuffer()), f.docs[0].bytes);
  f.app.refresh(); assert.equal(f.revoked.length, 1); assert.equal(f.file(), '');
  assert.match(f.get('snapshot').textContent, /Retained index checkpoint 2/); assertReadCalls(f.calls);
});
test('path search verifies empty file while describing only path coordinates', async () => {
  const doc = indexedDocument({ path: 'src/ALPHA_beta.rs', bytes: new Uint8Array(), spans: [{query_index: 0, byte_offset: 4, byte_length: 10}] });
  const f = fixture({ mode: 'indexed-path', queryText: 'alpha_beta', docs: [doc] });
  await f.app.connect(); await f.app.search(); await f.app.openIndexed(0);
  assert.match(f.file(), /0 complete file bytes/); assert.match(f.file(), /Path terms are not content matches/);
  assert.match(f.file(), /alpha_beta: path bytes \[4, 14\)/); assert.doesNotMatch(f.file(), /; line [0-9]/);
  assert.equal(f.get('file').all('mark')[0].textContent, 'ALPHA_beta'); assertReadCalls(f.calls);
});
test('next-page control keeps exact index, source and query while replacing the bounded page', async () => {
  const first = indexedDocument(), second = indexedDocument({ id: 4, path: 'src/z.rs' });
  const f = fixture({ limit: '1', respond: (call, n, q) => response(page(q, [n === 1 ? first : second], {
    after: n === 1 ? null : 1, complete: n > 1, next_after: n === 1 ? 1 : null,
    indexed_documents: 2, indexed_source_bytes: first.bytes.length + second.bytes.length,
  })) });
  await f.app.connect(); await f.app.search(); assert.equal(f.next().disabled, false);
  await f.app.nextIndexed(); assert.equal(f.calls.length, 2);
  const fields = f.calls[1].fields;
  assert.equal(fields.get('index_token'), indexToken); assert.equal(fields.get('index_number'), '2'); assert.equal(fields.get('after'), '1');
  assert.ok(fields.get('expected_head')); assert.ok(fields.get('expected_commit'));
  assert.deepEqual(fields.getAll('term_hex'), f.q.termsHex);
  assert.match(f.results(), /src\/z.rs/); assert.doesNotMatch(f.results(), /src\/a.rs/);
  assert.equal(f.next(), undefined);
  await f.app.nextIndexed(); assert.equal(f.calls.length, 2); assertReadCalls(f.calls);
});
for (const [code, message] of [['source_index_uninitialized', /operator to build/], ['source_index_stale', /reconcile/], ['index_checkpoint_unavailable', /operator must recover/]]) {
  test(`${code}: stable explicit diagnostic with no scan/build/retry`, async () => {
    const f = fixture({ respond: () => response({ error: code, message: '<script>untrusted advice</script>' }, 409) });
    await f.app.connect(); await f.app.search();
    assert.match(f.status(), message); assert.doesNotMatch(f.status(), /untrusted advice/);
    assert.equal(f.results(), ''); assert.equal(f.calls.length, 1); assert.equal(f.next(), undefined); assertReadCalls(f.calls);
  });
}
test('503 does not present a failed index as an empty successful search', async () => {
  const f = fixture({ respond: () => response({ error: 'unavailable' }, 503) });
  await f.app.connect(); await f.app.search(); assert.match(f.status(), /failed verification/); assert.equal(f.results(), ''); assert.equal(f.calls.length, 1);
});
test('changing query invalidates the old continuation and stale result buttons', async () => {
  const f = fixture({ docs: [indexedDocument()], complete: false, limit: '1' });
  await f.app.connect(); await f.app.search();
  const oldButton = f.get('results').all('button')[0];
  f.get('query').value = 'changed'; f.get('query').emit('input'); oldButton.click(); await f.app.nextIndexed();
  assert.equal(f.results(), ''); assert.equal(f.calls.length, 1); assert.equal(f.next(), undefined);
});
test('cancelling a late indexed page never repopulates data or changes pins', async () => {
  let resolve; const first = indexedDocument();
  const f = fixture({ limit: '1', respond: (call, n, q) => n === 1
    ? response(page(q, [first], { complete: false, next_after: 1, indexed_documents: 2 }))
    : new Promise(done => { resolve = () => done(response(page(q, [], { after: 1 }))); }) });
  await f.app.connect(); await f.app.search(); const pin = f.get('snapshot').textContent;
  const work = f.app.nextIndexed(); assert.equal(f.next(), undefined);
  f.app.cancel(); resolve(); await work;
  assert.equal(f.results(), ''); assert.equal(f.get('snapshot').textContent, pin); assert.match(f.status(), /canceled/);
  assert.equal(f.calls.length, 2);
});
test('page exit wipes token, query, source data, download URL and all selection pins', async () => {
  const f = fixture(); await f.app.connect(); await f.app.search(); await f.app.openIndexed(0);
  f.get('file').all('button')[0].click(); f.events.emit('pagehide');
  for (const id of ['token', 'query', 'prefixes']) assert.equal(f.get(id).value, '');
  for (const id of ['file', 'snapshot', 'results']) assert.equal(f.get(id).textContent, '');
  assert.equal(f.revoked.length, 1); assert.equal(f.get('submit-search').disabled, true);
});
test('full-hash verification fails before any preview or download is exposed', async () => {
  const doc = indexedDocument();
  const f = fixture({ respond: (call, n, q) => response(n === 1 ? page(q, [doc]) : blobPage(doc, call.fields, { content_hex: hex(utf8.encode('ALPHA alpha zeta\n')) })) });
  await f.app.connect(); await f.app.search(); await f.app.openIndexed(0);
  assert.match(f.status(), /native blob identity mismatch/); assert.equal(f.file(), ''); assert.equal(f.urls.size, 0);
});
test('result rendering escapes hostile paths, terminal controls and bidi bytes', async () => {
  const path = 'src/<img onerror=x>\u202e\u001b.rs';
  const f = fixture({ docs: [indexedDocument({ path })] }); await f.app.connect(); await f.app.search();
  assert.match(f.results(), /<img onerror=x>/); assert.match(f.results(), /\\u\{202e\}/); assert.match(f.results(), /\\u\{1b\}/);
  assert.equal(f.get('results').all('img').length, 0);
  assert.equal(display(Uint8Array.of(255, 0)), '\\xff\\x00');
});
test('the retained 100-document page is bounded and discarded document buttons cannot reopen it', async () => {
  const docs = Array.from({ length: 100 }, (_, i) => indexedDocument({ id: i + 1, path: `src/${String(i).padStart(3, '0')}.rs` }));
  const f = fixture({ docs }); await f.app.connect(); await f.app.search();
  assert.equal(f.get('results').all('article').length, 100); assert.equal(f.next(), undefined);
  const old = f.get('results').all('button')[0];
  f.app.refresh(); old.click(); assert.equal(f.results(), ''); assert.equal(f.calls.length, 1);
});
test('shipped HTML keeps forms external-script-only and exposes both independent index limits', () => {
  assert.doesNotMatch(html, /<script>|on(?:click|submit)=/);
  for (const id of ['index-work', 'index-payload', 'index-help']) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(html, /value="indexed-content"/); assert.match(html, /value="indexed-path"/);
});
for (const mode of ['literal', 'batch', 'regex']) test(`${mode}: legacy nonempty search, rendering and verified navigation still work`, async () => {
  const doc = indexedDocument();
  const f = fixture({ respond: (call) => {
    if (call.path.endsWith('/blob')) return response(blobPage(doc, call.fields));
    const row = { path_hex: doc.raw.path_hex, blob: doc.raw.blob, byte_offset: 0, match_length: 5,
      line: 1, byte_column: 1, excerpt_offset: 0, excerpt_hex: hex(doc.bytes.subarray(0, -1)) };
    const group = { complete: true, completion: 'complete', returned_matches: 1, matches: [row] };
    const reply = { ...source(), ...group, type: 'source_search', profile: 'literal-bytes-v1', case: 'exact', max_matches: 100,
      files_selected: 1, files_read: 1, bytes_read: doc.bytes.length, bytes_searched: doc.bytes.length, non_regular_entries: 0 };
    if (mode === 'batch') Object.assign(reply, { type: 'source_search_batch', profile: 'literal-bytes-batch-v1', shared_scan: true,
      query_count: 1, path_prefixes_hex: [], results: [{ ...group, query_index: 0, needle_hex: hex(utf8.encode('ALPHA')) }] });
    if (mode === 'regex') {
      row.match_truncated_in_excerpt = false;
      Object.assign(reply, { type: 'source_search_regex', profile: 'byte-regex-lines-v1', pattern_hex: hex(utf8.encode('ALPHA')),
        match_policy: 'leftmost-longest-per-line', max_steps: 67108864, path_prefix_hex: [], vm_steps: 10, program_states: 6, lines_searched: 1 });
    }
    return response(reply);
  } });
  f.get('mode').value = mode; f.get('query').value = 'ALPHA'; f.get('mode').emit('change');
  await f.app.connect(); await f.app.search();
  assert.match(f.results(), /1 returned matches/); assert.equal(f.next(), undefined);
  await f.app.openMatch(0, 0); assert.match(f.file(), /Native blob verified/);
  assert.equal(f.get('file').all('mark')[0].textContent, 'ALPHA');
  assert.equal(f.calls[0].path.endsWith(`/source/${{literal:'search',batch:'search-batch',regex:'search-regex'}[mode]}`), true);
});
test('SHA-256 indexed UI uses the published native client without narrowing to SHA-1', async () => {
  const doc = indexedDocument({ algorithm: 'sha256' });
  const f = fixture({ respond: (call, n, q) => response(call.path.endsWith('/search-index')
    ? page(q, [doc], {}, 'sha256') : blobPage(doc, call.fields)) });
  f.get('format').value = 'sha256'; await f.app.connect(); await f.app.search(); await f.app.openIndexed(0);
  assert.match(f.file(), /Native blob verified \(sha256\)/); assert.equal(f.get('file').all('mark')[0].textContent, 'ALPHA');
});
test('indexed form honors the existing 100-document cap and independent file-navigation budget', async () => {
  const f = fixture(); assert.equal(f.get('max-file-bytes').disabled, false); assert.equal(f.get('max-matches').max, '100');
  f.get('max-file-bytes').value = '1'; await f.app.connect(); await f.app.search();
  assert.match(f.results(), /1 indexed documents/); await f.app.openIndexed(0);
  assert.match(f.status(), /navigation byte limit/); assert.equal(f.calls.length, 1); assert.equal(f.file(), '');
  f.get('max-matches').value = '101'; f.get('max-matches').emit('input'); await f.app.search();
  assert.match(f.status(), /indexed page limit/); assert.equal(f.calls.length, 1);
});
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: indexed line navigation preserves byte columns and term order across CRLF and UTF-8`, async () => {
  const doc = indexedDocument({ algorithm, bytes: utf8.encode('é BETA\r\nxx ALPHA'),
    spans: [{ query_index: 0, byte_offset: 12, byte_length: 5 }, { query_index: 1, byte_offset: 3, byte_length: 4 }] });
  const f = fixture({ respond: call => response(call.path.endsWith('/search-index')
    ? page(indexQuery(input()), [doc], {}, algorithm) : blobPage(doc, call.fields)) });
  f.get('format').value = algorithm;
  await f.app.connect(); await f.app.search(); await f.app.openIndexed(0);
  assert.match(f.file(), /alpha: content bytes \[12, 17\); line 2, byte column 4/);
  assert.match(f.file(), /beta: content bytes \[3, 7\); line 1, byte column 4/);
  assert.deepEqual(f.get('file').all('mark').map(mark => mark.textContent), ['ALPHA', 'BETA']);
  assertReadCalls(f.calls);
});
