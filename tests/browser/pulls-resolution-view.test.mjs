// DOM/File/HTTP doubles. Live browser and native pack validation are separate lanes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ResolutionEditor } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution-view.mjs';
import { mountPulls, displayBytes } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { resolutionUpload } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution.mjs';
import { fixture } from './pulls-candidate-fixtures.mjs';
import { token, page, show, json, webcrypto, deferred } from './pulls-fixtures.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/pulls.html', import.meta.url), 'utf8');
const f = fixture(), meta = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 1, message: 'Exact candidate\n' };
const report = () => ({ ...structuredClone(f.metadata), state: 'conflicted', candidate: null, bundle: null, merge_base: f.fields.merge_base,
  conflicts: [{ path_hex: '61ff', kind: 'content', base: null, ours: { mode: 0o100644, oid: '1'.repeat(40) }, theirs: { mode: 0o100755, oid: '2'.repeat(40) } }] });
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.value = ''; this.text = ''; this.files = []; this.listeners = new Map(); this.disabled = false; this.checked = false; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('Unsafe sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  addEventListener(event, fn) { const all = this.listeners.get(event) ?? []; all.push(fn); this.listeners.set(event, all); }
  fire(event) { for (const fn of this.listeners.get(event) ?? []) fn({ preventDefault() {} }); }
}
const descendants = node => [node, ...node.children.flatMap(descendants)];
const widgets = parent => descendants(parent).filter(node => ['select', 'textarea', 'input'].includes(node.tagName));
function editor() {
  const parent = new Element(), doc = { createElement: tag => new Element(tag) };
  const editor = new ResolutionEditor(doc, parent, displayBytes); editor.show(report()); editor.setDisabled(false);
  const [choice, mode, source, content, upload] = widgets(parent); return { editor, parent, choice, mode, source, content, upload };
}
function select(node, value) { node.value = value; node.fire('change'); }
function blob(bytes, extra = {}) { return { size: bytes.length, arrayBuffer: async () => bytes.slice().buffer, ...extra }; }
const byteFile = (h, bytes) => { select(h.choice, 'file'); select(h.mode, '100755'); select(h.source, 'upload'); h.upload.files = [blob(bytes)]; };
const utfFile = (h, value) => { select(h.choice, 'file'); select(h.mode, '100644'); select(h.source, 'text'); h.content.value = value; };

test('conflict controls have no default, expose byte paths, and disable absent sides', async () => {
  const h = editor(); assert.equal(h.choice.value, ''); await assert.rejects(h.editor.collect(), /every conflicted path/);
  assert.equal(h.choice.children.find(option => option.value === 'base').disabled, true);
  assert.match(h.parent.textContent, /a\\xff/); assert.match(h.parent.textContent, /Ours \(target\)/);
  assert.match(h.parent.textContent, /Path bytes: 61ff/);
  select(h.choice, 'base'); await assert.rejects(h.editor.collect(), /absent/);
  select(h.choice, 'delete'); assert.deepEqual(await h.editor.collect(), [{ path_hex: '61ff', choice: 'delete' }]);
});
test('side and custom input widgets enforce deliberate mode and source selection', async () => {
  const h = editor(); assert.equal(h.mode.disabled, true); select(h.choice, 'file'); assert.equal(h.mode.disabled, false);
  await assert.rejects(h.editor.collect(), /mode/); select(h.mode, '100644'); await assert.rejects(h.editor.collect(), /input explicitly/);
  select(h.source, 'text'); assert.equal(h.content.disabled, false); assert.equal(h.upload.disabled, true);
  h.editor.setDisabled(true); assert.ok(widgets(h.parent).every(node => node.disabled));
  h.editor.setDisabled(false); select(h.choice, 'ours'); assert.equal(h.content.disabled, true);
});
test('explicit empty UTF-8 files and binary uploads preserve distinct exact payloads', async () => {
  const h = editor(); utfFile(h, ''); assert.equal((await h.editor.collect())[0].bytes.length, 0);
  utfFile(h, '<script>\n🦀'); assert.deepEqual((await h.editor.collect())[0].bytes, new TextEncoder().encode('<script>\n🦀'));
  const bytes = new Uint8Array([0, 255, 13, 10]); byteFile(h, bytes);
  assert.deepEqual((await h.editor.collect())[0], { path_hex: '61ff', choice: 'file', mode: '100755', bytes });
});
test('file limits, invalid files, and total limits precede any asynchronous file read', async () => {
  const h = editor(); let reads = 0;
  byteFile(h, new Uint8Array()); h.upload.files = [blob(new Uint8Array(), { size: 1048577, arrayBuffer() { reads += 1; } })];
  await assert.rejects(h.editor.collect()); assert.equal(reads, 0);
  h.upload.files = []; await assert.rejects(h.editor.collect(), /exactly one/);
  h.upload.files = [blob(new Uint8Array()), blob(new Uint8Array())]; await assert.rejects(h.editor.collect(), /exactly one/);
  utfFile(h, 'é'.repeat(524289)); await assert.rejects(h.editor.collect(), /oversized/);
  const huge = report(); huge.conflicts = Array.from({ length: 17 }, (_, i) => ({ ...huge.conflicts[0], path_hex: Buffer.from(`x${i}`).toString('hex') }));
  h.editor.show(huge); h.editor.setDisabled(false);
  const all = widgets(h.parent);
  for (let i = 0; i < all.length; i += 5) {
    select(all[i], 'file'); select(all[i + 1], '100644'); select(all[i + 2], 'upload');
    all[i + 4].files = [blob(new Uint8Array(), { size: 1048576, arrayBuffer() { reads += 1; } })];
  }
  await assert.rejects(h.editor.collect(), /16 MiB/); assert.equal(reads, 0);
});
test('changed selection, cleared view and changed declared file size reject pending reads', async () => {
  for (const change of ['selection', 'clear', 'size']) {
    const h = editor(), wait = deferred(); byteFile(h, new Uint8Array([0, 255]));
    h.upload.files[0].arrayBuffer = () => wait.promise;
    const collecting = h.editor.collect();
    if (change === 'clear') h.editor.clear();
    if (change === 'selection') select(h.choice, 'theirs');
    wait.resolve(new Uint8Array(change === 'size' ? [0] : [0, 255]).buffer);
    await assert.rejects(collecting, /changed/);
  }
});
test('caller cancellation during asynchronous file reads prevents a usable resolution set', async () => {
  const h = editor(), wait = deferred(); byteFile(h, new Uint8Array([1]));
  h.upload.files[0].arrayBuffer = () => wait.promise; let live = true;
  const collecting = h.editor.collect(() => { if (!live) throw new Error('superseded'); });
  live = false; wait.resolve(new Uint8Array([1]).buffer); await assert.rejects(collecting, /superseded/);
});
test('untrusted conflict labels remain text and clearing removes custom content', async () => {
  const h = editor(), hostile = report(); hostile.conflicts[0].path_hex = Buffer.from('<img src=x onerror=alert(1)>').toString('hex');
  h.editor.show(hostile); assert.match(h.parent.textContent, /<img src=x onerror=alert\(1\)>/);
  const controls = widgets(h.parent); controls[3].value = 'private resolved bytes'; h.editor.clear();
  assert.equal(controls[3].value, ''); assert.equal(h.parent.textContent, ''); await assert.rejects(h.editor.collect());
});

const jobs = new Set();
const crypto = { getRandomValues: value => webcrypto.getRandomValues(value), subtle: { digest(...args) {
  const p = webcrypto.subtle.digest(...args); jobs.add(p); p.then(() => jobs.delete(p), () => jobs.delete(p)); return p;
} } };
async function settle() { for (let i = 0; i < 30; i += 1) { await Promise.all([...jobs]); await new Promise(setImmediate); } }
async function mounted(respond = () => null) {
  const nodes = Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
  const lifecycle = new Element(), document = { createElement: tag => new Element(tag), getElementById: id => nodes[id], defaultView: lifecycle };
  const calls = [];
  const app = mountPulls(document, { href: 'https://forge.example/team/repo.git/ui/pulls/', cryptoImpl: crypto, downloadImpl() {},
    fetchImpl: async (url, init) => {
      const path = new URL(url).pathname; const call = { path, ...init }; calls.push(call);
      const override = await respond(call); if (override !== null && override !== undefined) return override;
      if (path.endsWith('/pulls')) return json(page()); if (path.endsWith('/pulls/1')) return json(show());
      if (path.endsWith('/prepare')) return json(report(), 409); if (path.endsWith('/inspect')) return json(f.inspection);
      throw new Error(`Unexpected request: ${path}`);
    } });
  nodes.token.value = token; nodes.connection.fire('submit'); await settle(); await app.loadPr(1); await settle();
  nodes['policy-epoch'].value = '1'; nodes.author.value = meta.author; nodes.committer.value = meta.committer; nodes.timestamp.value = '1'; nodes.message.value = meta.message;
  nodes.prepare.fire('submit'); await settle();
  return { app, nodes, calls, lifecycle, controls: () => widgets(nodes['resolution-paths']) };
}
async function resolved(choices) {
  const upload = await resolutionUpload(report(), f.selected, meta, choices, webcrypto);
  return { ...f.metadata, state: 'resolved', resolution_profile: 'exact-path-resolutions-v1', resolutions: upload.expected.rows };
}
test('mounted resolution is an explicit read-only operation and enables review only after inspection', async () => {
  const metadata = await resolved([{ path_hex: '61ff', choice: 'ours' }]), wait = deferred();
  const h = await mounted(call => call.path.endsWith('/resolve') ? new Response(f.mixed(metadata), { headers: { 'Content-Type': f.type } }) : call.path.endsWith('/inspect') ? wait.promise : null);
  assert.equal(h.nodes.resolution.hidden, false); assert.equal(h.nodes['review-stage'].disabled, true);
  h.nodes.resolution.fire('submit'); await settle(); assert.equal(h.calls.length, 3, 'empty choices do not call resolve');
  select(h.controls()[0], 'ours'); h.nodes.resolution.fire('submit'); await settle();
  assert.equal(h.app.client.candidate, null); assert.equal(h.nodes['review-stage'].disabled, true); assert.equal(h.nodes['resolve-candidate'].disabled, true);
  wait.resolve(json(f.inspection)); await settle();
  assert.ok(h.app.client.candidate); assert.equal(h.app.client.pending, null); assert.equal(h.nodes.resolution.hidden, true);
  assert.equal(h.nodes['resolution-paths'].textContent, ''); assert.equal(h.nodes['review-stage'].disabled, false);
  assert.ok(h.calls.every(call => !call.headers['Idempotency-Key']));
  assert.match(h.nodes.status.textContent, /No vote or publication exists/);
});
test('mounted custom text produces a native file descriptor and exact result verification', async () => {
  const bytes = new TextEncoder().encode('<b>resolved</b>\n');
  const metadata = await resolved([{ path_hex: '61ff', choice: 'file', mode: '100644', bytes }]);
  const h = await mounted(call => call.path.endsWith('/resolve') ? new Response(f.mixed(metadata), { headers: { 'Content-Type': f.type } }) : null);
  const [choice, mode, source, content] = h.controls(); select(choice, 'file'); select(mode, '100644'); select(source, 'text'); content.value = '<b>resolved</b>\n';
  h.nodes.resolution.fire('submit'); await settle(); assert.ok(h.app.client.candidate);
  const call = h.calls.find(call => call.path.endsWith('/resolve')), body = await call.body.text();
  assert.match(body, /61ff%3Afile%3A100644%3Afile_0/); assert.match(body, /<b>resolved<\/b>\n\r\n--/);
  assert.equal(call.headers['Idempotency-Key'], undefined);
});
test('editing original candidate inputs clears conflict choices and prevents stale file dispatch', async () => {
  const h = await mounted(), wait = deferred(), [choice, mode, source, , upload] = h.controls();
  select(choice, 'file'); select(mode, '100644'); select(source, 'upload'); upload.files = [blob(new Uint8Array([1]), { arrayBuffer: () => wait.promise })];
  h.nodes.resolution.fire('submit'); await settle(); h.nodes.timestamp.value = '2'; h.nodes.prepare.fire('input');
  wait.resolve(new Uint8Array([1]).buffer); await settle();
  assert.equal(h.app.client.conflict, null); assert.equal(h.app.client.candidate, null); assert.equal(h.nodes.resolution.hidden, true);
  assert.equal(h.calls.some(call => call.path.endsWith('/resolve')), false);
});
test('disconnect during native resolution cannot restore private candidate or conflict views', async () => {
  const metadata = await resolved([{ path_hex: '61ff', choice: 'delete' }]), wait = deferred();
  const h = await mounted(call => call.path.endsWith('/resolve') ? wait.promise : null);
  select(h.controls()[0], 'delete'); h.nodes.resolution.fire('submit'); await settle(); h.nodes.disconnect.fire('click');
  wait.resolve(new Response(f.mixed(metadata), { headers: { 'Content-Type': f.type } })); await settle();
  assert.equal(h.app.client.connected, false); assert.equal(h.app.client.conflict, null); assert.equal(h.app.client.candidate, null);
  assert.equal(h.nodes['resolution-paths'].textContent, ''); assert.equal(h.nodes.candidate.textContent, '');
  assert.equal(h.calls.some(call => call.path.endsWith('/inspect')), false);
});
test('native resolution failure preserves choices without a second preparation or implicit retry', async () => {
  const h = await mounted(call => call.path.endsWith('/resolve') ? json({ type: 'pull_request_error', code: 'preparation_subject_moved' }, 409) : null);
  select(h.controls()[0], 'ours'); h.nodes.resolution.fire('submit'); await settle();
  assert.ok(h.app.client.conflict); assert.equal(h.app.client.candidate, null); assert.equal(h.app.client.pending, null);
  assert.equal(h.controls()[0].value, 'ours'); assert.equal(h.nodes['resolve-candidate'].disabled, false);
  assert.equal(h.calls.filter(call => call.path.endsWith('/prepare')).length, 1);
  assert.equal(h.calls.filter(call => call.path.endsWith('/resolve')).length, 1);
});
