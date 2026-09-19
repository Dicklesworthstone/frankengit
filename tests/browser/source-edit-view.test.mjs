import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { mountSourceEditor, editorBytes, chosenBytes } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-view.mjs';
import { FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { fixture, href, token, crypto, metadata } from './source-edit-fixtures.mjs';
import { utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/source-edit.html', import.meta.url), 'utf8');
class Element {
  children = []; listeners = new Map(); value = ''; disabled = false; checked = false; files = []; ownText = '';
  constructor(tag) { this.tagName = tag.toUpperCase(); }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent ?? String(child)).join(''); }
  addEventListener(kind, fn) { this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), fn]); }
  replaceChildren(...children) { this.children = children; this.ownText = ''; }
  append(...children) { this.children.push(...children); }
  async fire(kind = 'click') {
    if (kind === 'click' && this.disabled) return;
    for (const fn of this.listeners.get(kind) ?? []) await fn({ preventDefault() {}, target: this });
  }
}
function documentFixture() {
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => [match[2], new Element(match[1])]));
  Object.assign(nodes.get('branch'), { value: 'refs/heads/main' }); nodes.get('format').value = 'sha1';
  for (const [id, value] of Object.entries({ 'path-kind': 'utf8', 'change-kind': 'modify', 'file-mode': '100644', 'line-endings': 'lf' })) nodes.get(id).value = value;
  return { nodes, getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
}
async function setup() {
  const f = await fixture(), doc = documentFixture(), client = new SourceEditClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto });
  const events = { callbacks: new Map(), addEventListener(kind, fn) { this.callbacks.set(kind, fn); } };
  let saved;
  const app = mountSourceEditor(doc, { client, events, saveReceipt: value => { saved = value; } });
  const el = id => doc.getElementById(id);
  el('token').value = token; await el('connect').fire(); await el('select-base').fire();
  for (const [id, value] of Object.entries(metadata)) el(id).value = String(value);
  return { f, doc, app, el, client, events, saved: () => saved };
}
async function queueAndInspect(state) {
  const { el } = state; el('path').value = 'file.txt'; await el('path').fire('input'); await el('load-file').fire();
  el('file-text').value = 'after'; await el('file-text').fire('input'); el('file-mode').value = '100755';
  await el('queue-file').fire(); await el('prepare-edits').fire();
}
test('source UI completes native authoring but never publishes without a separate confirmation', async () => {
  const s = await setup(); assert.equal(s.el('token').value, ''); await queueAndInspect(s);
  assert.equal(s.app.queued.length, 1); assert.equal(s.client.candidate.fields.candidate_commit, s.f.candidate);
  assert(s.el('candidate').textContent.includes(s.f.candidate)); await s.el('stage').fire();
  assert(s.client.pending); assert(!s.f.calls.some(call => call.endpoint === 'source/apply'));
  await s.el('send').fire(); assert(!s.f.calls.some(call => call.endpoint === 'source/apply'));
  s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.equal(s.f.calls.at(-1).endpoint, 'source/apply'); assert.equal(s.client.pending, null);
  assert(s.el('status').textContent.includes('Canonical committed')); assert.equal(s.app.queued.length, 0);
});
test('changing branch selection clears old files, queue, and candidate before any new authoring', async () => {
  const s = await setup(); await queueAndInspect(s); s.el('branch').value = 'refs/heads/other'; await s.el('branch').fire('input');
  assert.equal(s.client.selection, null); assert.equal(s.client.candidate, null); assert.equal(s.app.queued.length, 0);
  assert.equal(s.el('file-text').value, ''); assert(s.el('prepare-edits').disabled);
});
test('commit metadata edits invalidate the inspected candidate', async () => {
  const s = await setup(); await queueAndInspect(s); s.el('message').value = 'another meaning'; await s.el('message').fire('input');
  assert.equal(s.client.candidate, null); assert(s.el('stage').disabled); assert.equal(s.el('candidate').textContent, '');
});
test('pending source writes disable editor replacement and retain original-key recovery after disconnect', async () => {
  const s = await setup(); await queueAndInspect(s); await s.el('stage').fire(); const key = s.client.pending.key;
  assert(s.el('branch').disabled); assert(s.el('prepare-edits').disabled); assert(s.el('file-text').disabled);
  await s.el('save-receipt').fire(); assert(s.saved()); assert(!s.saved().includes(token));
  await s.el('disconnect').fire(); assert.equal(s.client.pending.key, key); assert.equal(s.client.candidate, null);
  assert.equal(s.el('file-text').value, ''); assert.equal(s.el('candidate').textContent, ''); assert.equal(s.el('token').value, '');
});
test('oversized file uploads are refused before reading their bytes', async () => {
  const s = await setup(); let reads = 0;
  s.el('replacement').files = [{ size: FILE_LIMIT + 1, async arrayBuffer() { reads += 1; throw new Error('must not read'); } }];
  await s.el('replacement').fire('change'); assert.equal(reads, 0); assert(s.el('status').textContent.includes('byte limit'));
});
test('late file reads cannot restore bytes after disconnect', async () => {
  const s = await setup(); let release;
  s.el('replacement').files = [{ size: 3, arrayBuffer() { return new Promise(resolve => { release = resolve; }); } }];
  const loading = s.el('replacement').fire('change'); while (!release) await new Promise(resolve => setImmediate(resolve));
  await s.el('disconnect').fire(); release(utf8.encode('new').buffer); await loading;
  assert.equal(s.client.connected, false); assert.equal(s.el('file-text').value, ''); assert.equal(s.app.queued.length, 0);
});
test('source text and path labels are rendered as text, not markup', async () => {
  const s = await setup(); await queueAndInspect(s);
  assert(!html.includes('<script>')); assert(!html.includes('onclick='));
  const script = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/source-edit-view.mjs', import.meta.url), 'utf8');
  for (const forbidden of ['innerHTML', 'localStorage', 'sessionStorage', 'document.write']) assert(!script.includes(forbidden));
});
test('page exit clears credentials and source bytes while warning about unresolved responsibility', async () => {
  const s = await setup(); await queueAndInspect(s); await s.el('stage').fire();
  const event = { prevented: false, preventDefault() { this.prevented = true; }, returnValue: null };
  s.events.callbacks.get('beforeunload')(event); assert(event.prevented);
  s.events.callbacks.get('pagehide')(); assert.equal(s.client.connected, false); assert(s.client.pending); assert.equal(s.app.queued.length, 0);
});
test('text editor preserves unedited bytes but applies explicit edited newline policy', () => {
  const original = utf8.encode('\ufeffbefore\r\n');
  assert.deepEqual(editorBytes('browser normalized display\n', original, false, 'lf'), original);
  assert.deepEqual(editorBytes('a\nb', null, true, 'crlf'), utf8.encode('a\r\nb'));
  assert.deepEqual(editorBytes('a\r\nb\r', null, true, 'lf'), utf8.encode('a\nb\n'));
  assert.throws(() => editorBytes('x\ud800', null, true, 'lf'));
  assert.throws(() => editorBytes('x\0y', null, true, 'lf'));
  assert.throws(() => editorBytes('text', null, true, 'guess'));
});
test('file reader binds declared size and cancellation on both sides of an asynchronous read', async () => {
  let reads = 0;
  const file = { size: 3, async arrayBuffer() { reads += 1; return utf8.encode('ab').buffer; } };
  await assert.rejects(chosenBytes(file, FILE_LIMIT)); assert.equal(reads, 1);
  await assert.rejects(chosenBytes(file, FILE_LIMIT, () => false)); assert.equal(reads, 1);
});
