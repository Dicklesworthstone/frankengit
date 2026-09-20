// DOM and native HTTP doubles. Executes the real mounted search controller/client.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { mount, readQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-view.mjs';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { query } from '../../crates/fgit-node/src/smart_http/server/browser/search-data.mjs';
import { crypto, token, href, hex, fixture, json, deferred } from './search-index-fixtures.mjs';
class Element {
  constructor(tag, doc) { this.tagName = tag.toUpperCase(); this.doc = doc; this.children = []; this.listeners = new Map(); this.value = ''; this.disabled = false; this.hidden = false; this._text = ''; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent ?? String(c)).join(''); }
  append(...nodes) { for (const n of nodes) { n.parent = this; this.children.push(n); } }
  replaceChildren(...nodes) { this._text = ''; this.children = []; this.append(...nodes); }
  addEventListener(name, fn) { const listeners = this.listeners.get(name) ?? []; listeners.push(fn); this.listeners.set(name, listeners); }
  emit(name) { for (const fn of this.listeners.get(name) ?? []) fn({ preventDefault() {} }); }
  click() { if (this.disabled) return; if (this.tagName === 'A') this.doc.downloads.push({ href: this.href, name: this.download }); this.emit('click'); }
  setAttribute(name, value) { this[name] = value; }
  focus() { this.doc.focused = this; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); }
}
const controls = ['submit-search','refresh','cancel','mode','max-steps','regex-help','query-help','snapshot','token','query','prefixes',
  'reference','format','connection','search-form','disconnect','case','max-bytes','index-work','index-payload','index-help','max-matches',
  'max-file-bytes','prefix-encoding','encoding','results','file','status'];
function document() {
  const doc = { downloads: [], getElementById(id) { return this.elements.get(id) ?? null; }, createElement(tag) { return new Element(tag, this); } };
  doc.elements = new Map(controls.map(id => [id, new Element('div', doc)])); doc.defaultView = new Element('window', doc);
  const values = { token, reference: 'refs/heads/main', format: 'sha1', mode: 'indexed-content', case: 'exact', encoding: 'utf8', query: 'BETA\nALPHA\nbeta\n',
    prefixes: '', 'prefix-encoding': 'utf8', 'max-matches': '1', 'max-file-bytes': '8388608', 'max-bytes': '67108864', 'max-steps': '67108864',
    'index-work': '16777216', 'index-payload': '33554432' };
  for (const [id, value] of Object.entries(values)) doc.getElementById(id).value = value;
  return doc;
}
function all(root) { return [root, ...root.children.flatMap(all)]; }
function buttons(doc, region) { return all(doc.getElementById(region)).filter(e => e.tagName === 'BUTTON'); }
async function mounted(f = fixture()) {
  const doc = document(); doc.getElementById('format').value = f.algorithm;
  const blobs = [], revoked = [], urlApi = { createObjectURL(b) { blobs.push(b); return 'blob:test-' + blobs.length; }, revokeObjectURL(v) { revoked.push(v); } };
  const ui = mount(doc, { href }, { fetchImpl: f.fetchImpl, cryptoImpl: crypto, urlApi });
  assert.equal(doc.getElementById('submit-search').disabled, true); await ui.connect();
  return { doc, ui, f, blobs, revoked, get: id => doc.getElementById(id) };
}
const tick = () => new Promise(setImmediate);
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: one search page exposes index pins, exact next pages and verified byte downloads`, async () => {
  const { doc, ui, f, get, blobs, revoked } = await mounted(fixture(algorithm));
  assert.equal(get('token').value, ''); assert.equal(f.calls.length, 0); await ui.search();
  assert.match(get('results').textContent, /alpha AND beta/); assert.match(get('results').textContent, /Queried index 7/);
  assert.match(get('snapshot').textContent, /Retained index checkpoint 7/);
  assert.match(get('results').textContent, /more remain/); assert(buttons(doc, 'results').some(b => b.textContent === 'Next indexed page'));
  await ui.openIndexed(0); assert.match(get('file').textContent, /All reported first whole-word spans reproduced in content/);
  assert.equal(all(get('file')).filter(e => e.tagName === 'MARK').length, 2);
  buttons(doc, 'file').find(b => b.textContent === 'Download verified file bytes').click();
  assert.deepEqual(Buffer.from(await blobs[0].arrayBuffer()), f.docs[0].bytes); assert.equal(doc.downloads[0].name, 'snapshot-source.bin');
  await ui.nextIndexed(); assert.equal(f.calls.at(-1).params.get('after'), '1'); assert.equal(get('file').textContent, ''); assert.equal(revoked.length, 1);
  await ui.nextIndexed(); assert.match(get('results').textContent, /query complete; 3 matching documents visited/);
  assert(!buttons(doc, 'results').some(b => b.textContent === 'Next indexed page'));
});
test('indexed controls retain separate work budgets and whole-word semantics', async () => {
  const { get } = await mounted();
  assert(get('case').disabled); assert(get('max-bytes').disabled); assert(!get('index-help').hidden);
  assert(!get('index-work').disabled); assert.equal(get('max-matches').max, '100');
  assert.match(get('query-help').textContent, /ASCII case is folded/);
  get('mode').value = 'regex'; get('mode').emit('change');
  assert(!get('case').disabled); assert(!get('max-steps').disabled); assert(get('index-work').disabled); assert(get('index-help').hidden);
  assert.equal(get('max-matches').max, '4096');
});
test('query form reads exact byte prefixes and canonical numbers, never silently trims words', async () => {
  const doc = document(); doc.getElementById('encoding').value = 'hex'; doc.getElementById('query').value = '414c504841\n62657461';
  doc.getElementById('prefix-encoding').value = 'hex'; doc.getElementById('prefixes').value = '7372632fff';
  const q = readQuery(doc); assert.deepEqual(q.termsHex, ['414c504841', '62657461']); assert.deepEqual(q.prefixesHex, ['7372632fff']);
  assert.equal(q.maxWork, 16777216); assert(!('maxBytes' in q)); assert(!('case' in q));
  doc.getElementById('index-work').value = '01'; assert.throws(() => readQuery(doc));
});
test('invalid indexed inputs clear old results without dispatching a request', async () => {
  const { get, ui, f } = await mounted(); await ui.search();
  get('query').value = 'alpha.*'; get('query').emit('input'); await ui.search();
  assert.equal(f.calls.length, 1); assert.equal(get('results').textContent, ''); assert.match(get('status').textContent, /whole ASCII/);
});
test('path hits highlight the filename, not unrelated content positions, and support empty files', async () => {
  const f = fixture('sha1', [{ path: Buffer.from('src/ALPHA.txt'), bytes: Buffer.alloc(0) }]);
  const { get, ui, blobs, doc } = await mounted(f); get('mode').value = 'indexed-path'; get('query').value = 'src\nalpha';
  get('mode').emit('change'); await ui.search(); await ui.openIndexed(0);
  assert.match(get('file').textContent, /spans reproduced in path/); assert.match(get('file').textContent, /Path terms are not content matches/);
  assert(all(get('file')).filter(e => e.tagName === 'MARK').every(e => ['ALPHA', 'src'].includes(e.textContent)));
  buttons(doc, 'file')[0].click(); assert.equal((await blobs[0].arrayBuffer()).byteLength, 0);
});
test('hostile names, binary bytes and directional controls remain inert escaped text', async () => {
  const path = Buffer.from('src/<img src=x>\u202e.txt'), bytes = Buffer.from('alpha beta <script>alert(1)</script>\u202e\0');
  const { get, ui } = await mounted(fixture('sha1', [{ path, bytes }])); await ui.search(); await ui.openIndexed(0);
  assert.match(get('results').textContent, /<img src=x>/); assert(!get('results').textContent.includes('\u202e'));
  assert(!get('file').textContent.includes('\0')); assert(!get('file').textContent.includes('\u202e'));
  assert(!all(get('file')).some(e => ['SCRIPT','IMG','IFRAME'].includes(e.tagName)));
});
test('stale or uninitialized index gives an operator action, never a successful empty result', async () => {
  const { ui, f, get } = await mounted(); f.config.fail = () => json({ type: 'source_error', code: 'source_index_uninitialized' }, 409);
  await ui.search(); assert.equal(f.calls.length, 1); assert.equal(get('results').textContent, '');
  assert.match(get('status').textContent, /operator must build or refresh/); assert.match(get('status').textContent, /No scan fallback/);
});
test('changing queries invalidates next-page closures and downloaded bytes', async () => {
  const { ui, f, get, doc, revoked } = await mounted(); await ui.search();
  const next = buttons(doc, 'results').find(b => b.textContent === 'Next indexed page'); await ui.openIndexed(0); buttons(doc, 'file')[0].click();
  const before = f.calls.length; get('query').value = 'different'; get('query').emit('input'); next.click(); await tick();
  assert.equal(f.calls.length, before); assert.equal(get('results').textContent, ''); assert.equal(get('file').textContent, ''); assert.equal(revoked.length, 1);
});
test('cancel and disconnect defeat late query/file responses and revoke downloads', async () => {
  const { ui, f, get, doc, revoked } = await mounted(); const d = deferred(); f.config.query = () => d.promise;
  const query = ui.search(); ui.cancel(); d.resolve(); await query; assert.equal(get('results').textContent, '');
  f.config.query = null; await ui.search(); await ui.openIndexed(0); buttons(doc, 'file')[0].click();
  const pending = deferred(); f.config.blob = () => pending.promise; const read = ui.openIndexed(0); doc.defaultView.emit('pagehide'); pending.resolve(); await read;
  assert.equal(get('file').textContent, ''); assert.equal(get('query').value, ''); assert.equal(get('prefixes').value, ''); assert.equal(get('snapshot').textContent, '');
  assert.equal(revoked.length, 1); assert(get('submit-search').disabled);
});
test('replaced file selection cannot be downloaded after a failed native check', async () => {
  const { ui, f, get, doc } = await mounted(); await ui.search(); await ui.openIndexed(0);
  const oldDownload = buttons(doc, 'file')[0]; f.config.blob = r => r.object_id = 'c'.repeat(40);
  await ui.openIndexed(0); oldDownload.click(); assert.equal(doc.downloads.length, 0); assert.equal(get('file').textContent, '');
});
test('release snapshot does not erase the retained generation checkpoint', async () => {
  const { ui, get, f } = await mounted(); await ui.search(); ui.refresh();
  assert.match(get('snapshot').textContent, /next successful search/); assert.match(get('snapshot').textContent, /checkpoint 7/);
  await ui.search(); assert.equal(f.calls.at(-1).params.has('expected_head'), false); assert.equal(f.calls.at(-1).params.get('minimum_index_number'), '7');
});
test('changed connection settings remove every selected index result and require a new token', async () => {
  const { ui, get } = await mounted(); await ui.search(); get('reference').value = 'refs/heads/other'; get('reference').emit('input');
  assert.equal(get('snapshot').textContent, ''); assert.equal(get('results').textContent, ''); assert(get('submit-search').disabled);
});
test('indexed preview remains bounded even when an 8-MiB file is fully verified', async () => {
  const bytes = Buffer.alloc(8 * 1024 * 1024, 0); bytes.write('alpha beta');
  const { ui, get } = await mounted(fixture('sha256', [{ path: Buffer.from('src/large.bin'), bytes }]));
  await ui.search(); await ui.openIndexed(0); assert.match(get('file').textContent, /8388608 complete file bytes/); assert(get('file').textContent.length < 10000);
});
for (const mode of ['literal','batch','regex']) test(`existing ${mode} mode keeps native form, completion and file verification`, async () => {
  const f = fixture('sha1', [{ path: Buffer.from('src/a'), bytes: Buffer.from('alpha beta\n') }]);
  const raw = { path_hex: hex(f.docs[0].path), blob: f.docs[0].blob, byte_offset: 0, match_length: 5, line: 1, byte_column: 1,
    excerpt_offset: 0, excerpt_hex: hex('alpha beta') };
  const group = { completion: 'complete', complete: true, returned_matches: 1, matches: [raw] };
  const stats = { ...f.common, case: 'exact', max_matches: 1, files_selected: 1, files_read: 1, bytes_read: 11, bytes_searched: 11, non_regular_entries: 0 };
  const baseFetch = f.fetchImpl;
  f.fetchImpl = async (u, o) => {
    if (String(u).endsWith('/blob')) return baseFetch(u, o);
    const params = new URLSearchParams(o.body); assert(!params.has('term_hex')); assert(!params.has('index_token'));
    if (mode === 'literal') { assert(String(u).endsWith('/search')); return json({ ...stats, ...group, type: 'source_search', profile: 'literal-bytes-v1' }); }
    if (mode === 'batch') { assert(String(u).endsWith('/search-batch')); return json({ ...stats, type: 'source_search_batch', profile: 'literal-bytes-batch-v1', shared_scan: true,
      query_count: 2, path_prefixes_hex: [], results: [0, 1].map(i => ({ ...group, query_index: i, needle_hex: hex('alpha') })) }); }
    assert(String(u).endsWith('/search-regex')); return json({ ...stats, ...group, type: 'source_search_regex', profile: 'byte-regex-lines-v1', match_policy: 'leftmost-longest-per-line',
      pattern_hex: hex('alpha'), max_steps: 67108864, path_prefix_hex: [], vm_steps: 10, program_states: 6, lines_searched: 1,
      matches: [{ ...raw, match_truncated_in_excerpt: false }] });
  };
  const { doc, ui, get } = await mounted(f); get('mode').value = mode; get('query').value = mode === 'batch' ? 'alpha\nalpha' : 'alpha'; get('mode').emit('change');
  const q = query(readQuery(doc)); assert.equal(q.mode, mode); if (mode === 'batch') assert.equal(q.needlesHex.length, 2);
  await ui.search(); assert.match(get('results').textContent, /returned matches/); await ui.openMatch(0, 0);
  assert.match(get('file').textContent, /Native blob verified/); assert.match(get('file').textContent, /Line 1, byte column 1/);
});
test('HTML controls and source-gated import graph match the mounted module without inline code', async () => {
  const base = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
  const html = await readFile(new URL('search.html', base), 'utf8'), routes = await readFile(new URL('search.rs', base), 'utf8');
  for (const id of controls) assert(html.includes(`id="${id}"`), id);
  assert(html.includes('value="indexed-content"')); assert(html.includes('value="indexed-path"'));
  assert(!html.includes('<script>'));
  const visited = new Set();
  async function walk(name) {
    if (visited.has(name)) return; visited.add(name); assert(routes.includes(`include_str!("${name}")`), name);
    const source = await readFile(new URL(name, base), 'utf8');
    for (const m of source.matchAll(/from '\.\/(.*?)'/g)) await walk(m[1]);
  }
  await walk('search-view.mjs'); assert.equal(visited.size, 5);
});
