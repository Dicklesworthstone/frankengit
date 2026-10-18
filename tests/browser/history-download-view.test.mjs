// Production markup/controller with explicit DOM/native-response doubles, not a browser or fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountHistory } from '../../crates/fgit-node/src/smart_http/server/browser/history-view.mjs';
import { fixture, harness, hex, jsonResponse, token } from './history-compare-fixtures.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/history.html', import.meta.url), 'utf8');
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.handlers = new Map(); this.value = ''; this.disabled = false; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { assert.fail('Executable markup sink'); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; this.text = ''; }
  addEventListener(event, callback) { this.handlers.set(event, [...this.handlers.get(event) ?? [], callback]); }
  async fire(event) { await Promise.all((this.handlers.get(event) ?? []).map(fn => fn({ preventDefault() {} }))); }
}
function button(root, prefix) {
  if (root.tagName === 'button' && root.textContent.startsWith(prefix)) return root;
  for (const child of root.children) { const found = button(child, prefix); if (found) return found; }
  return null;
}
function view(f, respond = null) {
  const h = harness(f, respond), nodes = Object.fromEntries([...html.matchAll(/id="history-([^"]+)"/g)].map(m => [m[1], new Element()]));
  nodes.ref.value = f.afterRef; nodes.format.value = f.algorithm;
  const files = [], events = new Element(), doc = { createElement: tag => new Element(tag), body: new Element('body'), getElementById: id => nodes[id.slice(8)] };
  const app = mountHistory(doc, { client: h.client, events, downloadFile: (name, bytes) => files.push({ name, bytes }) });
  const open = async () => { nodes.token.value = token; await nodes.connect.fire('submit'); };
  const file = () => app.historical('blob', f.before, hex('src/old-file.bin'));
  const download = () => { const found = button(nodes.content, 'Download complete historical'); assert.ok(found); return found.fire('click'); };
  return { ...h, nodes, app, open, file, download, files, events };
}
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: the historical browser downloads an old multi-range file, not just its preview`, async () => {
  const f = fixture(algorithm, { after: Buffer.alloc(1024 * 1024 + 9, 211) }), v = view(f);
  await v.open(); await v.file(); assert.match(v.nodes.content.textContent, /Bytes \[0, 65536\)/);
  const selected = v.client.selection, old = button(v.nodes.content, 'Download complete historical');
  await v.download(); assert.equal(v.files.length, 1); assert.deepEqual(Buffer.from(v.files[0].bytes), f.afterBody);
  assert.equal(v.files[0].name, `frankengit-history-${f.afterBlob}.bin`);
  assert.match(v.nodes.content.textContent, /2 bounded range reads/); assert.match(v.nodes.status.textContent, /hash-checked/);
  assert.deepEqual(v.client.selection, selected);
  const requests = v.calls.slice(2); assert.equal(requests.length, 2);
  for (const call of requests) { assert.equal(call.form.get('at_commit'), f.before); assert.equal(call.form.get('expected_ref_tip'), f.after); }
  await old.fire('click'); assert.equal(v.calls.length, 4, 'detached download cannot launch more reads');
  await button(v.nodes.breadcrumbs, 'Back to historical file').fire('click'); assert.equal(v.calls.at(-1).form.get('at_commit'), f.before);
});

test('oversized historical files remain previewable but no synthetic click can bypass the complete-file budget', async () => {
  const f = fixture('sha1', { after: Buffer.alloc(8 * 1024 * 1024 + 1, 201) }), v = view(f);
  await v.open(); await v.file(); assert.equal(button(v.nodes.content, 'Download complete historical').disabled, true);
  const count = v.calls.length; await v.download(); assert.equal(v.calls.length, count); assert.equal(v.files.length, 0);
  assert.match(v.nodes.status.textContent, /complete historical file bytes/);
});

test('a corrupt last range clears the result and produces no file or success message', async () => {
  const f = fixture('sha256', { after: Buffer.alloc(1024 * 1024 + 5, 201) }), v = view(f, call => {
    if (!call.url.endsWith('/historical-blob') || Number(call.form.get('offset')) === 0) return null;
    const value = f.historical(call.form); value.source.content_hex = 'aa'.repeat(value.source.returned_bytes); return jsonResponse(value);
  }); await v.open(); await v.file(); await v.download(); assert.equal(v.files.length, 0);
  assert.equal(v.nodes.download.disabled, true); assert.match(v.nodes.status.textContent, /blob identity/);
});

test('pagehide during acquisition prevents a late range from causing a download', async () => {
  let finish, started; const gate = new Promise(resolve => { finish = resolve; }), entered = new Promise(resolve => { started = resolve; });
  const f = fixture('sha1', { after: Buffer.alloc(1024 * 1024 + 7, 213) }), v = view(f, call => {
    if (call.url.endsWith('/historical-blob') && Number(call.form.get('offset')) > 0) { started(call); return gate; } return null;
  }); await v.open(); await v.file(); const pending = v.download(), call = await entered;
  await v.events.fire('pagehide'); finish(jsonResponse(f.historical(call.form))); await pending;
  assert.equal(v.files.length, 0); assert.equal(v.client.connected, false); assert.equal(v.nodes.content.textContent, '');
  assert.equal(v.nodes.download.disabled, true);
});
