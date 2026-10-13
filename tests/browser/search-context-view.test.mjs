// DOM/controller tests use explicit adapters, not a real browser or Rust node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { contextReply, contextReport, readContextQuery, mountContextControls, renderSourceContext,
  CONTEXT_DISPLAY_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/search-context.mjs';
import { fixture, copy, hex } from './search-context-fixtures.mjs';
import { setup } from './search-context-harness.mjs';
class Element {
  constructor(document, tag) { Object.assign(this, { ownerDocument: document, tagName: tag.toUpperCase(), children: [], parentNode: null,
    _text: '', id: '', value: '', checked: false, disabled: false, hidden: false, listeners: new Map(), attributes: {} }); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...nodes) { for (const node of nodes) { node.parentNode = this; this.children.push(node); } }
  prepend(...nodes) { for (const node of nodes) node.parentNode = this; this.children.unshift(...nodes); }
  replaceChildren(...nodes) { for (const child of this.children) child.parentNode = null; this._text = ''; this.children = []; this.append(...nodes); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, fn) { const list = this.listeners.get(name) ?? []; list.push(fn); this.listeners.set(name, list); }
  fire(name) { for (const fn of this.listeners.get(name) ?? []) fn({ preventDefault() {}, target: this }); }
  click() { if (!this.disabled) this.fire('click'); }
  focus() {}
  remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(child => child !== this); this.parentNode = null; }
}
const walk = node => [node, ...node.children.flatMap(walk)];
function documentFixture() {
  const doc = { createElement(tag) { return new Element(doc, tag); },
    getElementById(id) { return walk(doc.body).find(node => node.id === id) ?? null; },
    defaultView: { addEventListener() {} } };
  doc.body = new Element(doc, 'body'); return doc;
}
function uiFixture() {
  const f = fixture(), r = f.retrieval;
  r.scope = { tenant: '1'.repeat(32), repository: '2'.repeat(32), incarnation: '3'.repeat(32), format: 'sha1' };
  r.pin = { head: 'selected-head', sourceHead: 'source-head', rcr: 'source-rcr', commit: 'c'.repeat(40), tree: 'd'.repeat(40) };
  r.query = { mode: 'initial', termsHex: [hex('thing')], prefixesHex: [], symbol: { nameHex: hex('Thing'), match: 'exact', kinds: [], policy: 'optional' },
    maxMatches: 100, maxWork: 16777216, maxPayloadBytes: 33554432, maxResultBytes: 2097152, maxFileBytes: 8388608 };
  r.lexicalCheckpoint = { token: 'lexical-checkpoint', number: 3 }; r.totalHits = 3;
  r.stats = { retainedBytes: 400, payloadBytes: 120, work: 12 };
  for (const channel of ['content', 'path']) {
    Object.assign(r[channel], { index: { token: 'lexical-index', number: 2 }, selectedIndex: r.lexicalCheckpoint,
      complete: true, coverageComplete: true, omissions: [], seen: 1, nextAfter: null,
      stats: { documents: 1, sourceBytes: 18, nonRegular: 0, segments: 1, payloadBytes: 40, generationBytes: 16, work: 4 } });
    r[channel].hits[0].documentId = 1;
  }
  Object.assign(r.symbols.result, { index: { token: 'symbol-index', number: 7 }, complete: true, coverageComplete: true,
    omissions: [], query: { match: 'exact', nameHex: hex('Thing') },
    stats: { declarations: 1, files: 1, unsupported: 0, nonRegular: 0, tables: 1, payloadBytes: 40, work: 4 } });
  Object.assign(r.symbols.result.hits[0], { kind: 'struct', line: 1, column: 12, excerptHex: hex('pub struct Thing;') });
  f.reply.retrieval = { normalized: r };
  return { ...r, context: contextReply(f.reply, r, {}), wire: f.reply };
}
const plainDisplay = bytes => Buffer.from(bytes).toString('utf8');
function urls() { let next = 0; const created = new Map(), revoked = [];
  return { created, revoked, createObjectURL(blob) { const id = `blob:fixture/${++next}`; created.set(id, blob); return id; }, revokeObjectURL(id) { revoked.push(id); } };
}
function controlsDocument() {
  const doc = documentFixture(), parent = doc.createElement('div'); parent.id = 'initial-controls'; doc.body.append(parent); return { doc, parent };
}
test('source hydration is off by default; options are independent and bounded', () => {
  const { doc, parent } = controlsDocument(); let changes = 0;
  const controls = mountContextControls(doc, parent, () => { changes++; controls.sync(true); });
  controls.sync(true); assert.deepEqual(readContextQuery(doc), {});
  assert.equal(doc.getElementById('context-files').disabled, true);
  doc.getElementById('context-enabled').checked = true; doc.getElementById('context-enabled').fire('change');
  assert.equal(changes, 1); assert.equal(doc.getElementById('context-files').disabled, false);
  doc.getElementById('context-radius').value = '0';
  assert.equal(readContextQuery(doc).context.radiusBytes, 0);
  controls.sync(false); assert.equal(doc.getElementById('context-controls').hidden, true);
  assert.equal(doc.getElementById('context-enabled').disabled, true);
  controls.reset(); assert.deepEqual(readContextQuery(doc), {});
  assert.throws(() => mountContextControls(doc, parent, () => {}), /duplicate/);
});
for (const text of ['', '-1', '01', '1e2', '1.0', ' 2', 'NaN', '9999999999']) test(`context form rejects noncanonical ${JSON.stringify(text)}`, () => {
  const { doc, parent } = controlsDocument(); mountContextControls(doc, parent, () => {});
  doc.getElementById('context-enabled').checked = true; doc.getElementById('context-files').value = text;
  assert.throws(() => readContextQuery(doc));
});
test('report preserves scope, generation, omissions and bytes, but not ambient credentials', () => {
  const value = uiFixture(); value.token = 'SECRET-CREDENTIAL'; value.scope.token = 'SECRET-CREDENTIAL';
  value.context.files[0].token = 'SECRET-CREDENTIAL'; value.context.files[0].excerpts[0].token = 'SECRET-CREDENTIAL';
  value.query.token = 'SECRET-CREDENTIAL'; value.vector.lexical.tokenCredential = 'SECRET-CREDENTIAL';
  value.content.omissions = [{ pathHex: hex('omitted.rs'), blob: 'e'.repeat(40), sourceBytes: 999, reason: 'file_bytes', offset: null, limit: 256, token: 'SECRET-CREDENTIAL' }];
  value.content.coverageComplete = false; value.complete = false; value.context.complete = false;
  const text = contextReport(value), report = JSON.parse(text);
  assert.equal(text.includes('SECRET-CREDENTIAL'), false); assert.equal(report.independentBlobVerification, false);
  assert.equal(report.source.commit, 'c'.repeat(40)); assert.deepEqual(report.generationVector, { lexical: { token: 'lexical', number: 3 }, symbols: { token: 'symbols', number: 7 } });
  assert.equal(report.retrieval.content.omissions[0].pathHex, hex('omitted.rs'));
  assert.equal(report.context.files[0].excerpts[0].bytesHex, hex('pub struct Thing;\n'));
  assert.equal(report.retrieval.complete, false); assert.equal(report.sourceMaterialUntrusted, true);
});
test('rendered source is inert text, with path and file coordinates kept distinct', () => {
  const doc = documentFixture(), value = uiFixture(); value.context.files[0].excerpts[0].bytesHex = hex('<img src=x onerror=alert(1)>');
  const rendered = renderSourceContext(doc, value, { display: plainDisplay });
  doc.body.append(rendered.element);
  assert.match(doc.body.textContent, /UNTRUSTED SOURCE MATERIAL/); assert.match(doc.body.textContent, /PATH bytes \[4, 9\)/);
  assert.match(doc.body.textContent, /FILE bytes \[11, 16\)/);
  assert.match(doc.body.textContent, /<img src=x onerror=alert\(1\)>/);
  assert.equal(walk(doc.body).some(node => ['IMG', 'SCRIPT', 'IFRAME'].includes(node.tagName)), false);
});
test('display clipping leaves all paths and all export bytes intact', () => {
  const doc = documentFixture(), value = uiFixture(), file = value.context.files[0];
  file.excerpts[0].bytesHex = '41'.repeat(CONTEXT_DISPLAY_BYTES + 4);
  const other = copy(file); other.pathHex = hex('z/other.rs'); other.excerpts[0].bytesHex = hex('tail'); value.context.files.push(other);
  const rendered = renderSourceContext(doc, value, { display: plainDisplay }); doc.body.append(rendered.element);
  assert.equal(rendered.clipped, true); assert.match(doc.body.textContent, /DISPLAY CLIPPED/); assert.match(doc.body.textContent, /z\/other.rs/);
  const report = JSON.parse(contextReport(value)); assert.equal(report.context.files[0].excerpts[0].bytesHex.length / 2, CONTEXT_DISPLAY_BYTES + 4);
  assert.equal(report.context.files[1].excerpts[0].bytesHex, hex('tail'));
});
test('download is explicit, bounded to one live URL and disabled when disposed or stale', async () => {
  const doc = documentFixture(), urlApi = urls(), value = uiFixture(); let current = true;
  const rendered = renderSourceContext(doc, value, { display: plainDisplay, urlApi, current: () => current });
  doc.body.append(rendered.element); assert.equal(urlApi.created.size, 0);
  rendered.download.click(); assert.equal(urlApi.created.size, 1);
  assert.equal(JSON.parse(await urlApi.created.get('blob:fixture/1').text()).sourceMaterialUntrusted, true);
  rendered.download.click(); assert.equal(urlApi.created.size, 2); assert.deepEqual(urlApi.revoked, ['blob:fixture/1']);
  current = false; rendered.download.click(); assert.equal(urlApi.created.size, 2);
  rendered.dispose(); assert.deepEqual(urlApi.revoked, ['blob:fixture/1', 'blob:fixture/2']);
  current = true; rendered.download.click(); assert.equal(urlApi.created.size, 2);
  rendered.dispose(); assert.equal(urlApi.revoked.length, 2);
});
test('incomplete or empty context is never displayed as complete source coverage', () => {
  const doc = documentFixture(), value = uiFixture();
  value.context.complete = false; value.context.omittedFiles = 3; value.context.files = [];
  const rendered = renderSourceContext(doc, value, { display: plainDisplay });
  assert.match(rendered.element.textContent, /INCOMPLETE CONTEXT: 3/);
  assert.match(rendered.element.textContent, /does not establish absence/);
});
function pageFixture() {
  const doc = documentFixture();
  // Existing search-page shell IDs. This is a DOM contract fixture, not HTML parsing.
  const ids = ['connection', 'token', 'reference', 'format', 'search-form', 'mode', 'encoding', 'case', 'query', 'prefixes', 'prefix-encoding',
    'max-matches', 'max-file-bytes', 'max-bytes', 'max-steps', 'index-work', 'index-payload', 'symbol-match', 'symbol-kind', 'initial-symbol-name',
    'initial-symbol-policy', 'initial-result-bytes', 'index-source-mode', 'initial-controls', 'initial-help', 'index-help', 'index-source-help',
    'symbol-help', 'symbol-controls', 'regex-help', 'query-help', 'submit-search', 'refresh', 'cancel', 'disconnect', 'status', 'snapshot', 'results', 'file'];
  for (const id of ids) { const node = doc.createElement('div'); node.id = id; doc.body.append(node); }
  const values = { token: 'fixture-token', reference: 'refs/heads/main', format: 'sha1', mode: 'initial', encoding: 'utf8', case: 'exact', query: 'thing',
    prefixes: '', 'prefix-encoding': 'utf8', 'max-matches': '100', 'max-file-bytes': '8388608', 'max-bytes': '67108864', 'max-steps': '67108864',
    'index-work': '16777216', 'index-payload': '33554432', 'symbol-match': 'exact', 'symbol-kind': 'all', 'initial-symbol-name': 'Thing',
    'initial-symbol-policy': 'optional', 'initial-result-bytes': '2097152', 'index-source-mode': 'exact' };
  for (const [id, value] of Object.entries(values)) doc.getElementById(id).value = value;
  return doc;
}
test('actual search view wires opt-in hydration, export, then disconnect cleanup', async t => {
  const value = uiFixture(), urlApi = urls(), doc = pageFixture();
  const env = await setup(t, async path => ({ value: path === 'source/context-initial' ? value.wire : value.wire.retrieval }));
  const { mount, readQuery } = await env.loadView(); const view = mount(doc, { href: env.options.href }, { ...env.options, urlApi });
  await view.connect(); assert.equal(env.calls.length, 0);
  assert.equal('context' in readQuery(doc), false); await view.search();
  assert.equal(env.calls[0].path, 'source/search-initial');
  doc.getElementById('context-enabled').checked = true; doc.getElementById('context-enabled').fire('change');
  await view.search(); assert.equal(env.calls[1].path, 'source/context-initial');
  assert.match(doc.getElementById('results').textContent, /UNTRUSTED SOURCE MATERIAL/);
  assert.match(doc.getElementById('status').textContent, /Source context retrieved/);
  const download = walk(doc.body).find(node => node.tagName === 'BUTTON' && node.textContent === 'Download exact source-context report');
  download.click(); assert.equal(urlApi.created.size, 1);
  view.disconnect(); assert.equal(doc.getElementById('results').textContent, '');
  assert.equal(doc.getElementById('context-enabled').checked, false); assert.deepEqual(urlApi.revoked, ['blob:fixture/1']);
  download.click(); assert.equal(urlApi.created.size, 1);
});
test('query edits invalidate in-flight context before any late bytes reach the actual view', async t => {
  const value = uiFixture(), doc = pageFixture(); let resolve;
  const pending = new Promise(r => { resolve = r; }); const env = await setup(t, () => pending);
  const { mount } = await env.loadView(); const view = mount(doc, { href: env.options.href }, env.options);
  await view.connect(); doc.getElementById('context-enabled').checked = true; doc.getElementById('context-enabled').fire('change');
  const task = view.search(); assert.equal(env.calls.length, 1);
  doc.getElementById('context-radius').value = '0'; doc.getElementById('context-radius').fire('input');
  resolve({ value: value.wire }); await task;
  assert.equal(doc.getElementById('results').textContent, ''); assert.match(doc.getElementById('status').textContent, /Query changed/);
});
test('the actual view preserves ordinary search grammar when another mode is selected', async t => {
  const doc = pageFixture(), env = await setup(t, async () => { throw new Error('unexpected read'); });
  const { mount, readQuery } = await env.loadView(); mount(doc, { href: env.options.href }, env.options);
  doc.getElementById('context-enabled').checked = true; doc.getElementById('mode').value = 'indexed-content'; doc.getElementById('mode').fire('change');
  assert.equal('context' in readQuery(doc), false); assert.equal(doc.getElementById('context-enabled').disabled, true);
  assert.equal(env.calls.length, 0);
});

// Ranked browser integration adds a selector, explicit evidence and export.
// The native-schema test data below does not represent a live HTTP node.
import { rankedFixture, PROFILE as RANKED_PROFILE } from './search-context-ranked-fixtures.mjs';
function rankedUiFixture(maxFiles = 1) {
  const base = uiFixture(), f = rankedFixture('sha1', maxFiles), r = f.retrieval;
  Object.assign(r, { scope: base.scope, pin: base.pin, query: base.query, stats: base.stats,
    lexicalCheckpoint: base.lexicalCheckpoint, totalHits: 5 });
  for (const channel of ['content', 'path']) r[channel] = { ...base[channel], ...r[channel] };
  r.symbols.result = { ...base.symbols.result, ...r.symbols.result };
  f.reply.retrieval = { normalized: r };
  return { ...r, context: contextReply(f.reply, r, f.limits), wire: f.reply };
}
test('ranked hydration is explicitly selectable, disabled when off, and reset on disconnect', () => {
  const { doc, parent } = controlsDocument(); let changes = 0;
  const controls = mountContextControls(doc, parent, () => { changes++; controls.sync(true); });
  const select = doc.getElementById('context-selection');
  assert.equal(select.value, 'raw-path-prefix'); assert.equal(select.disabled, true);
  doc.getElementById('context-enabled').checked = true; controls.sync(true);
  assert.equal(select.disabled, false); select.value = RANKED_PROFILE; select.fire('change');
  assert.equal(changes, 1); assert.equal(readContextQuery(doc).context.selection, RANKED_PROFILE);
  controls.sync(false); assert.equal(select.disabled, true);
  controls.reset(); assert.equal(select.value, 'raw-path-prefix'); assert.deepEqual(readContextQuery(doc), {});
});
test('a forged ranked selector does not silently fall back to alphabetical', () => {
  const { doc, parent } = controlsDocument(); mountContextControls(doc, parent, () => {});
  doc.getElementById('context-enabled').checked = true;
  for (const value of ['', 'ranked', 'semantic', 'context-weighted-rrf-q16-v2']) {
    doc.getElementById('context-selection').value = value; assert.throws(() => readContextQuery(doc));
  }
});
test('priority evidence stays separate from path-sorted excerpt order', () => {
  const doc = documentFixture(), value = rankedUiFixture(2);
  const rendered = renderSourceContext(doc, value, { display: plainDisplay });
  doc.body.append(rendered.element);
  assert.match(doc.body.textContent, /not semantic relevance/);
  assert.match(doc.body.textContent, /Duplicate declarations do not amplify/);
  const rows = walk(doc.body).filter(node => node.tagName === 'TR').slice(1);
  assert.equal(rows[0].children[1].textContent, 'z/Thing.rs'); assert.equal(rows[0].children[2].textContent, '4279');
  assert.equal(rows[1].children[1].textContent, '00.txt');
  assert.match(rows[0].children[3].textContent, /content: document 2, weight 1, \+1057/);
  const files = walk(doc.body).filter(node => node.tagName === 'ARTICLE');
  assert.equal(files[0].children[0].textContent, 'Priority 2 · 00.txt');
  assert.equal(files[1].children[0].textContent, 'Priority 1 · z/Thing.rs');
});
test('export retains ranking plus all input identities including unselected and repeated documents', () => {
  const value = rankedUiFixture(), secret = 'NEVER_EXPORT_AMBIENT_CREDENTIAL';
  value.context.ranking.token = secret; value.context.ranking.selected[0].token = secret;
  value.context.ranking.selected[0].contributions[0].token = secret;
  value.content.hits[0].token = secret; value.symbols.result.hits[0].token = secret;
  const text = contextReport(value), report = JSON.parse(text);
  assert.equal(text.includes(secret), false);
  assert.equal(report.context.selection, RANKED_PROFILE); assert.equal(report.context.limits.selection, RANKED_PROFILE);
  assert.equal(report.context.ranking.selected[0].score_q16, 4279); assert.equal(report.context.ranking.semantic_relevance, false);
  assert.equal(report.context.rankingInputs.content.length, 2);
  assert.equal(report.context.rankingInputs.content[0].pathHex, hex('00.txt'));
  assert.equal(report.context.rankingInputs.symbols.hits.length, 2);
  assert.deepEqual(Object.keys(report.context.rankingInputs.content[0]), ['pathHex', 'blob']);
  assert.equal(report.independentBlobVerification, false); assert.equal(report.context.complete, false);
});
test('default reports do not gain an invented rank or new ranking inputs', () => {
  const value = uiFixture(), report = JSON.parse(contextReport(value));
  assert.equal(report.context.selection, 'raw-path-prefix');
  assert.equal('ranking' in report.context, false); assert.equal('rankingInputs' in report.context, false);
  const rendered = renderSourceContext(documentFixture(), value, { display: plainDisplay });
  assert.match(rendered.element.textContent, /Alphabetical truncation, not relevance ranking/);
});
test('ranked source display and export fail closed when the retained ranking is missing', () => {
  const value = rankedUiFixture(); delete value.context.ranking;
  assert.throws(() => contextReport(value), /receipt required/);
  assert.throws(() => renderSourceContext(documentFixture(), value, { display: plainDisplay }), /receipt required/);
});
test('ranking path and contribution text is inert DOM content, not HTML', () => {
  const value = rankedUiFixture(), pathHex = hex('<img onerror=bad>');
  value.context.ranking.selected[0].path_hex = pathHex;
  value.context.ranking.selected[0].contributions[0].channel = '<svg onload=bad>';
  value.context.files[0].pathHex = pathHex;
  const rendered = renderSourceContext(documentFixture(), value, { display: plainDisplay });
  assert.match(rendered.element.textContent, /<img onerror=bad>/);
  assert.match(rendered.element.textContent, /<svg onload=bad>/);
  assert.equal(walk(rendered.element).some(node => ['IMG', 'SVG', 'SCRIPT'].includes(node.tagName)), false);
});
test('actual view sends the selected profile and displays the checked priority receipt', async t => {
  const value = rankedUiFixture(), doc = pageFixture(), urlApi = urls();
  const env = await setup(t, async () => ({ value: value.wire }));
  const { mount } = await env.loadView(), view = mount(doc, { href: env.options.href }, { ...env.options, urlApi });
  await view.connect(); doc.getElementById('context-enabled').checked = true;
  doc.getElementById('context-files').value = '1';
  doc.getElementById('context-selection').value = RANKED_PROFILE; doc.getElementById('context-selection').fire('change');
  await view.search(); assert.equal(env.calls.length, 1);
  assert.equal(new URLSearchParams(env.calls[0].options.body).get('context_selection'), RANKED_PROFILE);
  assert.match(doc.getElementById('results').textContent, /4279/);
  const download = walk(doc.body).find(node => node.tagName === 'BUTTON' && node.textContent === 'Download exact source-context report');
  download.click(); assert.equal(urlApi.created.size, 1);
  const report = JSON.parse(await urlApi.created.get('blob:fixture/1').text());
  assert.equal(report.context.ranking.selected[0].path_hex, hex('z/Thing.rs'));
  view.disconnect(); assert.deepEqual(urlApi.revoked, ['blob:fixture/1']);
  assert.equal(doc.getElementById('context-selection').value, 'raw-path-prefix');
});
test('selection changes invalidate downloads while retaining the existing snapshot pin', async t => {
  const value = rankedUiFixture(), doc = pageFixture(), urlApi = urls();
  const env = await setup(t, async () => ({ value: value.wire }));
  const { mount } = await env.loadView(), view = mount(doc, { href: env.options.href }, { ...env.options, urlApi });
  await view.connect(); doc.getElementById('context-enabled').checked = true; doc.getElementById('context-files').value = '1';
  const selection = doc.getElementById('context-selection'); selection.value = RANKED_PROFILE; selection.fire('change');
  await view.search(); const oldPin = doc.getElementById('snapshot').textContent;
  const download = walk(doc.body).find(node => node.tagName === 'BUTTON' && node.textContent === 'Download exact source-context report');
  download.click(); selection.value = 'raw-path-prefix'; selection.fire('change');
  assert.equal(doc.getElementById('results').textContent, ''); assert.deepEqual(urlApi.revoked, ['blob:fixture/1']);
  assert.equal(doc.getElementById('snapshot').textContent, oldPin); assert.equal(env.calls.length, 1);
  download.click(); assert.equal(urlApi.created.size, 1);
});
test('selection changes during a read cannot install a stale priority receipt', async t => {
  const value = rankedUiFixture(), doc = pageFixture(); let resolve;
  const pending = new Promise(r => { resolve = r; }), env = await setup(t, () => pending);
  const { mount } = await env.loadView(), view = mount(doc, { href: env.options.href }, env.options);
  await view.connect(); doc.getElementById('context-enabled').checked = true; doc.getElementById('context-files').value = '1';
  const selection = doc.getElementById('context-selection'); selection.value = RANKED_PROFILE; selection.fire('change');
  const task = view.search(); selection.value = 'raw-path-prefix'; selection.fire('change');
  resolve({ value: value.wire }); await task;
  assert.equal(doc.getElementById('results').textContent, ''); assert.equal(env.calls.length, 1);
  assert.match(doc.getElementById('status').textContent, /Query changed/);
});
