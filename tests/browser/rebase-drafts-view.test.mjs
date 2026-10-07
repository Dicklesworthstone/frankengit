// HTML-derived DOM contracts with the real client and explicit HTTP/File doubles.
// Real Chromium coverage lives in rebase-drafts-browser.mjs; neither is a native-node test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { RebaseClient, DRAFT_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/rebase.mjs';
import { mountRebase } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-view.mjs';
import { FILE_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-data.mjs';
import { utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, token, href, crypto } from './rebase-session-fixtures.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/rebase.html', import.meta.url), 'utf8');
class Element {
  children = []; listeners = new Map(); value = ''; disabled = false; checked = false; files = []; ownText = ''; hidden = false;
  constructor(tag) { this.tagName = tag.toUpperCase(); }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(c => c.textContent ?? String(c)).join(''); }
  addEventListener(kind, fn) { this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), fn]); }
  replaceChildren(...children) { this.children = children; this.ownText = ''; }
  append(...children) { this.children.push(...children); }
  click() { return this.fire(); }
  async fire(kind = 'click') { if (kind === 'click' && this.disabled) return; for (const fn of this.listeners.get(kind) ?? []) await fn({ target: this, preventDefault() {} }); }
}
function documentFixture() {
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(m => {
    const e = new Element(m[1]); e.value = /\bvalue="([^"]*)"/.exec(m[0])?.[1] ?? ''; return [m[2], e];
  }));
  for (const match of html.matchAll(/<select\b[^>]*id="([^"]+)"[^>]*>([\s\S]*?)<\/select>/g)) nodes.get(match[1]).value = /value="([^"]*)"/.exec(match[2])?.[1] ?? '';
  return { nodes, getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
}
const file = bytes => ({ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer });
async function setup(options = {}) {
  const f = await fixture(options.algorithm ?? 'sha1'), doc = documentFixture(), events = new Map(), saved = [];
  const client = new RebaseClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl });
  const app = mountRebase(doc, { client, events: { addEventListener: (k, fn) => events.set(k, fn) }, saveDraft: value => saved.push(value), ...options.mount });
  const el = id => doc.nodes.get(id);
  el('format').value = f.algorithm; el('token').value = token; await el('connect').fire(); await el('select').fire();
  for (const key of ['upstream', 'committer', 'timestamp']) el(key).value = String(f.input[key]);
  return { f, client, doc, app, el, events, saved };
}
async function prepared(options) { const s = await setup(options); await s.el('prepare').fire(); assert(s.client.candidate); return s; }
async function stopped(options) { const s = await setup(options); s.f.config.sequence = [s.f.stopped(0)]; await s.el('prepare').fire(); return s; }
async function load(s, value) { s.el('draft-file').files = [file(utf8.encode(value))]; await s.el('draft-file').fire('change'); await s.el('load-draft').fire(); }
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: UI saves, loads without requests, resumes and still requires separate publication confirmation`, async () => {
    const a = await prepared({ algorithm }), count = a.f.calls.length;
    await a.el('save-draft').fire(); assert.equal(a.saved.length, 1); assert.equal(a.f.calls.length, count);
    const b = await setup({ algorithm }); b.f.calls.length = 0; await load(b, a.saved[0]);
    assert.equal(b.f.calls.length, 0); assert.equal(b.client.state.resumeRequired, true);
    assert.equal(b.el('upstream').value, a.f.input.upstream); assert.equal(b.el('max-commits').value, '32');
    assert(b.el('prepare').disabled && b.el('stage').disabled); assert(!b.el('resume-draft').disabled);
    assert.match(b.el('report').textContent, /native revalidation required/);
    await b.el('resume-draft').fire(); assert(b.client.candidate); assert(!b.el('stage').disabled);
    await b.el('stage').fire(); const before = b.f.calls.length; await b.el('send').fire();
    assert.equal(b.f.calls.length, before); assert.match(b.el('status').textContent, /Confirm/);
    assert(b.el('save-draft').disabled && b.el('load-draft').disabled && b.el('resume-draft').disabled);
    b.el('confirm-send').checked = true; await b.el('send').fire(); assert.equal(b.client.pending, null);
    a.app.disconnect(); b.app.disconnect();
  });
  test(`${algorithm}: all current hex choices can be saved without native submission`, async () => {
    const s = await stopped({ algorithm }), row = s.app.rows[0], count = s.f.calls.length;
    row.choice.value = 'hex'; row.content.value = '00 ff 0d 0a'; row.mode.value = '100755'; await row.choice.fire('change');
    s.el('include-choices').checked = true; await s.el('save-draft').fire(); assert.equal(s.f.calls.length, count);
    const data = JSON.parse(JSON.parse(s.saved[0]).payload), p = data.recipes[0].paths[0];
    assert.equal(p.bytes_hex, '00ff0d0a'); assert.equal(p.mode, 0o100755); assert.equal(s.client.state.resolutionPaths, 0);
    await load(s, s.saved[0]); await s.el('resume-draft').fire(); assert.equal(s.client.state.resolutionPaths, 1);
    assert(s.client.candidate); s.app.disconnect();
  });
}
test('excluding current choices is explicit and preserves the editable stop', async () => {
  const s = await stopped(); const row = s.app.rows[0]; row.choice.value = 'text'; row.content.value = 'unsent';
  await row.choice.fire('change'); await s.el('save-draft').fire();
  assert.equal(JSON.parse(JSON.parse(s.saved[0]).payload).recipes.length, 0);
  assert.match(s.el('status').textContent, /Current unsubmitted choices are not included/);
  assert.equal(s.app.rows[0], row); assert.equal(row.content.value, 'unsent'); s.app.disconnect();
});
test('incomplete current choices refuse instead of silently omitting work', async () => {
  const s = await stopped(), count = s.f.calls.length; s.el('include-choices').checked = true;
  await s.el('save-draft').fire(); assert.equal(s.saved.length, 0); assert.equal(s.f.calls.length, count);
  assert.match(s.el('status').textContent, /explicit resolution/); assert.equal(s.client.report.state, 'conflicted'); s.app.disconnect();
});
test('current upload size is checked before reading or saving', async () => {
  const s = await stopped(), row = s.app.rows[0]; let reads = 0;
  row.choice.value = 'file'; row.file.files = [{ size: FILE_BYTES + 1, arrayBuffer() { reads++; throw Error('unexpected'); } }];
  s.el('include-choices').checked = true; await s.el('save-draft').fire();
  assert.equal(reads, 0); assert.equal(s.saved.length, 0); assert.match(s.el('status').textContent, /256 KiB/); s.app.disconnect();
});
test('draft size is checked before reading and failed imports preserve existing branch pins', async () => {
  const s = await prepared(), before = s.client.selection, report = s.client.report; let reads = 0;
  s.el('draft-file').files = [{ size: DRAFT_BYTES + 1, arrayBuffer() { reads++; throw Error('unexpected'); } }];
  await s.el('draft-file').fire('change'); await s.el('load-draft').fire();
  assert.equal(reads, 0); assert.deepEqual(s.client.selection, before); assert.deepEqual(s.client.report, report);
  await load(s, '{broken'); assert.deepEqual(s.client.selection, before); assert.deepEqual(s.client.report, report);
  assert.equal(s.client.candidate, null); assert(s.el('stage').disabled); s.app.disconnect();
});
for (const action of ['change', 'disconnect']) test(`${action} during draft upload cannot restore stale state`, async () => {
  const a = await prepared(); const draft = await a.client.exportDraft(), s = await setup(); let release;
  const bytes = utf8.encode(draft), pending = { size: bytes.length, arrayBuffer: () => new Promise(r => { release = r; }) };
  s.el('draft-file').files = [pending]; const work = s.el('load-draft').fire(); assert.equal(typeof release, 'function');
  if (action === 'disconnect') s.app.disconnect();
  else { s.el('draft-file').files = [file(bytes)]; await s.el('draft-file').fire('change'); }
  release(bytes.buffer); await work; assert.equal(s.client.state.resumeRequired, false); assert.equal(s.client.candidate, null);
  a.app.disconnect(); s.app.disconnect();
});
test('changed current choice during a file read cannot save an older resolution', async () => {
  const s = await stopped(), row = s.app.rows[0]; let release;
  row.choice.value = 'file'; row.file.files = [{ size: 1, arrayBuffer: () => new Promise(r => { release = r; }) }];
  s.el('include-choices').checked = true; const work = s.el('save-draft').fire();
  row.mode.value = '100755'; await row.mode.fire('change'); release(new Uint8Array(1).buffer); await work;
  assert.equal(s.saved.length, 0); assert.equal(s.client.state.resolutionPaths, 0); s.app.disconnect();
});
test('stale resume keeps the loaded draft and cannot enable publication', async () => {
  const s = await prepared(), draft = await s.client.exportDraft(); await load(s, draft);
  s.f.config.root = r => { r.source_commit = s.f.id(99); }; await s.el('resume-draft').fire();
  assert.equal(s.client.state.resumeRequired, true); assert(s.el('stage').disabled); assert.match(s.el('status').textContent, /changed/);
  await s.el('save-draft').fire(); assert.equal(s.saved[0], draft); s.app.disconnect();
});
test('loaded draft warns before page exit and disconnect clears sensitive working data', async () => {
  const s = await prepared(); await load(s, await s.client.exportDraft()); let warned = false;
  s.events.get('beforeunload')({ preventDefault() { warned = true; } }); assert(warned);
  s.events.get('pagehide')(); assert.equal(s.client.selection, null); assert.equal(s.client.state.resumeRequired, false);
  assert.equal(s.el('token').value, ''); assert.equal(s.el('draft-file').value, ''); assert.equal(s.el('report').textContent, '');
});
test('download handles are revoked on disconnect and exported drafts contain no credential', async () => {
  const made = [], revoked = [], timers = new Map(); let n = 0;
  const s = await prepared({ mount: { saveDraft: undefined, urls: { createObjectURL: b => { made.push(b); return 'blob:one'; }, revokeObjectURL: u => revoked.push(u) },
    timers: { setTimeout: fn => { timers.set(++n, fn); return n; }, clearTimeout: i => timers.delete(i) } } });
  await s.el('save-draft').fire(); assert.equal(made.length, 1); assert.equal(made[0].type, 'application/json');
  assert(!(await made[0].text()).includes(token)); assert.equal(timers.size, 1); s.app.disconnect();
  assert.deepEqual(revoked, ['blob:one']); assert.equal(timers.size, 0);
});
test('download failure is not reported as a saved draft and cannot publish', async () => {
  const s = await prepared({ mount: { saveDraft() { throw Error('disk unavailable'); } } }), count = s.f.calls.length;
  await s.el('save-draft').fire(); assert.match(s.el('status').textContent, /disk unavailable/);
  assert.equal(s.f.calls.length, count); assert.equal(s.client.pending, null); s.app.disconnect();
});
test('pending publication keeps its original receipt route separate from draft imports', async () => {
  const saved = [], s = await prepared({ mount: { saveReceipt: value => saved.push(value) } });
  await s.el('stage').fire(); const original = s.client.pending; await s.el('save-draft').fire(); await s.el('load-draft').fire();
  assert.equal(s.saved.length, 0); assert.deepEqual(s.client.pending, original); await s.el('save-receipt').fire();
  assert.equal(JSON.parse(saved[0]).schema, 'frankengit-rebase-retry-v1'); assert.equal(JSON.parse(saved[0]).key, original.key); s.app.disconnect();
});
