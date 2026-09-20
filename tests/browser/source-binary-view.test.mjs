// DOM and File doubles, not a live browser or a native node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { mountSourceEditor, hexEditorBytes, formatHexBytes, editableText, HEX_TEXT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-view.mjs';
import { FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { fixture, href, token, crypto, metadata, decodeUpload } from './source-edit-fixtures.mjs';
const base = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const html = readFileSync(new URL('source-edit.html', base), 'utf8');
const side = (bytes, mode = 0o100644) => ({ bytes: Uint8Array.from(bytes), mode });
const edit = (before = side([0, 255, 13, 10, 0]), after = side([0, 254, 0, 10], 0o100755), path = 'asset.bin') => ({
  path_hex: Buffer.from(path).toString('hex'), before, after });
const file = bytes => ({ size: bytes.length, async arrayBuffer() { return Uint8Array.from(bytes).buffer; } });
class Element {
  children = []; listeners = new Map(); disabled = false; checked = false; hidden = false; files = []; ownText = ''; current = '';
  constructor(tag, isFile = false) { this.tagName = tag.toUpperCase(); this.isFile = isFile; }
  set value(value) { this.current = this.tagName === 'TEXTAREA' ? String(value).replace(/\r\n?/g, '\n') : String(value); if (this.isFile && value === '') this.files = []; }
  get value() { return this.current; }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent ?? String(child)).join(''); }
  addEventListener(kind, fn) { this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), fn]); }
  replaceChildren(...children) { this.children = children; this.ownText = ''; }
  append(...children) { this.children.push(...children); }
  click() { this.clicked = true; if (this.failClick) throw new Error('download refused'); }
  async fire(kind = 'click') {
    if (kind === 'click' && this.disabled) return;
    for (const fn of this.listeners.get(kind) ?? []) await fn({ preventDefault() {}, target: this });
  }
}
function documentFixture() {
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => [match[2], new Element(match[1], match[0].includes('type="file"'))]));
  const created = [];
  for (const [id, value] of Object.entries({ branch: 'refs/heads/main', format: 'sha1', 'path-kind': 'utf8', 'change-kind': 'modify', 'file-mode': '100644', 'line-endings': 'lf' })) nodes.get(id).value = value;
  return { nodes, created, getElementById: id => nodes.get(id), createElement(tag) { const node = new Element(tag); created.push(node); return node; } };
}
async function setup(edits = [edit()], algorithm = 'sha1', extra = {}) {
  const f = await fixture(algorithm, edits, { allowBinary: true }), doc = documentFixture();
  const client = new SourceEditClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto });
  const events = { callbacks: new Map(), addEventListener(kind, fn) { this.callbacks.set(kind, fn); } };
  const saved = [], receipts = [];
  const app = mountSourceEditor(doc, { client, events, saveFile: bytes => saved.push(bytes), saveReceipt: r => receipts.push(r), ...extra });
  const el = id => doc.getElementById(id); el('token').value = token; await el('connect').fire();
  el('format').value = algorithm; await el('select-base').fire();
  for (const [id, value] of Object.entries(metadata)) el(id).value = String(value);
  return { f, doc, client, app, events, saved, receipts, el };
}
async function load(s, row = s.f.edits[0], kind = 'modify') {
  s.el('change-kind').value = kind; await s.el('change-kind').fire('input');
  s.el('path-kind').value = 'hex'; s.el('path').value = row.path_hex; await s.el('path').fire('input');
  if (row.before) await s.el('load-file').fire();
}
async function hexEdit(s, bytes) {
  s.el('content-mode').value = 'hex'; await s.el('content-mode').fire('change');
  s.el('file-hex').value = formatHexBytes(Uint8Array.from(bytes)); await s.el('file-hex').fire('input');
}
async function queue(s) { await hexEdit(s, s.f.edits[0].after.bytes); s.el('file-mode').value = s.f.edits[0].after.mode.toString(8); await s.el('queue-file').fire(); }
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: binary source editing reaches inspection and separately confirmed publication`, async () => {
  const s = await setup([edit()], algorithm); await load(s);
  assert.equal(s.el('content-mode').value, 'hex'); assert.equal(s.el('file-text').value, '');
  assert(s.el('file-text').disabled); assert(s.el('text-editor').hidden); assert(!s.el('hex-editor').hidden);
  assert.deepEqual(hexEditorBytes(s.el('file-hex').value), s.f.edits[0].before.bytes);
  await queue(s); assert.deepEqual(s.app.queued[0].after.bytes, s.f.edits[0].after.bytes);
  await s.el('prepare-edits').fire(); assert(s.client.candidate); await s.el('stage').fire();
  assert(s.el('file-hex').disabled); assert(s.el('content-mode').disabled);
  await s.el('send').fire(); assert(!s.f.calls.some(c => c.endpoint === 'source/apply'));
  s.el('confirm-send').checked = true; await s.el('send').fire(); assert.equal(s.client.pending, null);
  assert.equal(s.el('file-hex').value, ''); assert.equal(s.el('file-text').value, '');
});
test('binary replacement upload preserves bytes and does not enter them into the text editor', async () => {
  const s = await setup(); await load(s); const bytes = s.f.edits[0].after.bytes;
  s.el('replacement').files = [file(bytes)]; await s.el('replacement').fire('change');
  assert.equal(s.el('file-text').value, ''); assert.deepEqual(hexEditorBytes(s.el('file-hex').value), bytes);
  s.el('file-mode').value = '100755'; await s.el('queue-file').fire();
  assert.deepEqual(s.app.queued[0].after.bytes, bytes);
});
test('binary creation requires an explicit create action and can coexist with text edits', async () => {
  const rows = [edit(null, side([0, 255]), 'image.dat'), edit(null, side(Buffer.from('text\n')), 'note.txt')];
  const s = await setup(rows);
  for (const row of rows) { await load(s, row, 'create'); await hexEdit(s, row.after.bytes); await s.el('queue-file').fire(); }
  assert.equal(s.app.queued.length, 2); await s.el('prepare-edits').fire(); assert(s.client.candidate);
  assert(s.el('edits').textContent.includes('binary/raw'));
});
test('binary deletion uses only verified original bytes, not an unrelated invalid hex draft', async () => {
  const row = edit(side([0, 255, 0]), null), s = await setup([row]); await load(s, row, 'delete');
  s.el('file-hex').value = 'not hex'; await s.el('file-hex').fire('input'); await s.el('queue-file').fire();
  assert.equal(s.app.queued.length, 1); assert.equal(s.app.queued[0].after, null);
  await s.el('prepare-edits').fire(); assert(s.client.candidate);
});
test('mode-only binary changes never round-trip through a string', async () => {
  const bytes = [0, 13, 10, 255, 0], s = await setup([edit(side(bytes), side(bytes, 0o100755))]); await load(s);
  s.el('file-mode').value = '100755'; await s.el('file-mode').fire('input'); await s.el('queue-file').fire();
  assert.deepEqual(s.app.queued[0].before.bytes, s.app.queued[0].after.bytes);
  assert.equal(s.app.queued[0].after.mode, 0o100755);
});
test('clearing the hex editor creates an empty existing file, not a deletion', async () => {
  const s = await setup([edit(side([0, 1]), side([]))]); await load(s); await hexEdit(s, []); await s.el('queue-file').fire();
  assert(s.app.queued[0].after); assert.equal(s.app.queued[0].after.bytes.length, 0);
});
test('text/hex view changes preserve BOM, CRLF and bare CR despite textarea normalization', async () => {
  const bytes = Buffer.from('\ufefffirst\r\nsecond\rthird');
  const s = await setup([edit(side(bytes), side(bytes, 0o100755))]); await load(s);
  assert(!s.el('file-text').value.includes('\r'));
  for (const mode of ['hex', 'text', 'hex', 'text']) { s.el('content-mode').value = mode; await s.el('content-mode').fire('change'); }
  s.el('file-mode').value = '100755'; await s.el('queue-file').fire();
  assert.deepEqual(s.app.queued[0].after.bytes, new Uint8Array(bytes));
});
test('binary or invalid UTF-8 cannot be implicitly converted to text', async () => {
  const s = await setup(); await load(s); const original = s.el('file-hex').value;
  s.el('content-mode').value = 'text'; await s.el('content-mode').fire('change');
  assert.equal(s.el('content-mode').value, 'hex'); assert.equal(s.el('file-hex').value, original);
  assert.equal(s.el('file-text').value, ''); assert.match(s.el('status').textContent, /cannot be edited/);
});
test('explicit hex-to-text replacement followed by a text edit uses the chosen line endings', async () => {
  const s = await setup(); await load(s); await hexEdit(s, Buffer.from('safe\r\n'));
  s.el('content-mode').value = 'text'; await s.el('content-mode').fire('change');
  s.el('file-text').value = 'edited\n'; await s.el('file-text').fire('input'); s.el('line-endings').value = 'crlf'; await s.el('line-endings').fire('input');
  await s.el('queue-file').fire(); assert.deepEqual(s.app.queued[0].after.bytes, new Uint8Array(Buffer.from('edited\r\n')));
});
test('hex content is independent of disabled text newline controls', async () => {
  const s = await setup(); await load(s); await hexEdit(s, [0, 13, 10, 13]);
  s.el('line-endings').value = 'lf'; await s.el('line-endings').fire('input'); await s.el('queue-file').fire();
  assert.deepEqual(s.app.queued[0].after.bytes, Uint8Array.of(0, 13, 10, 13));
});
test('hex parsing is exact, bounded, and accepts only ASCII spacing around hex digits', () => {
  assert.deepEqual(hexEditorBytes('00 FF\t0a\r\n0D'), Uint8Array.of(0, 255, 10, 13));
  assert.deepEqual(hexEditorBytes(' \r\n'), new Uint8Array());
  for (const value of ['0', '0x00', '00 # comment', '00\u00a0ff', '00\0', 'gg', ' '.repeat(HEX_TEXT_LIMIT + 1), 'ff'.repeat(FILE_LIMIT + 1)]) assert.throws(() => hexEditorBytes(value));
  const bytes = new Uint8Array(FILE_LIMIT); for (let i = 0; i < bytes.length; i++) bytes[i] = i % 256;
  const text = formatHexBytes(Uint8Array.from(bytes)); assert(text.length <= HEX_TEXT_LIMIT); assert.deepEqual(hexEditorBytes(text), bytes);
});
for (const bytes of [[0], [255], [27, 91, 48, 109], [...Buffer.from('\u202eunsafe')]]) test(`non-text byte class ${bytes.join(',')} selects hex rather than a lossy preview`, async () => {
  assert.equal(editableText(Uint8Array.from(bytes)), null);
  const s = await setup([edit(side(bytes), side([0, 2]))]); await load(s);
  assert.equal(s.el('content-mode').value, 'hex'); assert.equal(s.el('file-text').value, '');
});
test('invalid hex cannot replace a queued file or yield a download', async () => {
  const s = await setup(); await load(s); await queue(s); const original = s.app.queued;
  s.el('file-hex').value = '0x00'; await s.el('file-hex').fire('input'); await s.el('queue-file').fire(); await s.el('save-file').fire();
  assert.deepEqual(s.app.queued, original); assert.equal(s.saved.length, 0); assert.equal(s.client.candidate, null);
});
test('a failed replacement selection cannot reuse the previous successful upload', async () => {
  const s = await setup(); await load(s);
  s.el('replacement').files = [file([0, 8])]; await s.el('replacement').fire('change');
  let reads = 0; s.el('replacement').files = [{ size: FILE_LIMIT + 1, async arrayBuffer() { reads++; return new ArrayBuffer(0); } }];
  await s.el('replacement').fire('change'); await s.el('queue-file').fire(); await s.el('save-file').fire();
  assert.equal(reads, 0); assert.equal(s.app.queued.length, 0); assert.equal(s.saved.length, 0);
  assert.match(s.el('status').textContent, /has not completed validation/);
});
test('aggregate queued bytes are reserved before reading another binary replacement', async () => {
  const s = await setup();
  for (let i = 0; i < 4; i++) {
    const row = edit(null, side([0]), `asset${i}`); await load(s, row, 'create');
    s.el('replacement').files = [file(new Uint8Array(200 * 1024))]; await s.el('replacement').fire('change'); await s.el('queue-file').fire();
  }
  assert.equal(s.app.queued.length, 4); await load(s, edit(null, side([0]), 'fifth'), 'create');
  let reads = 0; s.el('replacement').files = [{ size: FILE_LIMIT, async arrayBuffer() { reads++; return new ArrayBuffer(FILE_LIMIT); } }];
  await s.el('replacement').fire('change'); assert.equal(reads, 0); assert.match(s.el('status').textContent, /combined draft/);
});
test('superseding an in-flight file selection invalidates the old read before it can become draft bytes', async () => {
  const s = await setup(); await load(s); let release, newReads = 0;
  s.el('replacement').files = [{ size: 2, arrayBuffer: () => new Promise(resolve => { release = resolve; }) }];
  const reading = s.el('replacement').fire('change'); await new Promise(setImmediate); assert.equal(typeof release, 'function');
  s.el('replacement').files = [{ size: 2, async arrayBuffer() { newReads++; return Uint8Array.of(0, 9).buffer; } }];
  await s.el('replacement').fire('change'); release(Uint8Array.of(0, 8).buffer); await reading;
  await s.el('queue-file').fire(); assert.equal(s.app.queued.length, 0); assert.equal(newReads, 0);
  assert.match(s.el('status').textContent, /has not completed validation/);
});
test('a changed File object without a matching event cannot complete the old selection', async () => {
  const s = await setup(); await load(s); let release;
  s.el('replacement').files = [{ size: 2, arrayBuffer: () => new Promise(resolve => { release = resolve; }) }];
  const reading = s.el('replacement').fire('change'); await new Promise(setImmediate);
  s.el('replacement').files = [file([0, 9])]; release(Uint8Array.of(0, 8).buffer); await reading;
  await s.el('queue-file').fire(); assert.equal(s.app.queued.length, 0);
});
test('disconnect drains a pending binary File read without restoring either editor view', async () => {
  const s = await setup(); await load(s); let release;
  s.el('replacement').files = [{ size: 2, arrayBuffer: () => new Promise(resolve => { release = resolve; }) }];
  const reading = s.el('replacement').fire('change'); await new Promise(setImmediate);
  s.app.disconnect(); release(Uint8Array.of(0, 8).buffer); await reading;
  assert.equal(s.el('file-hex').value, ''); assert.equal(s.el('file-text').value, ''); assert.equal(s.app.queued.length, 0);
});
test('file byte-length mismatch leaves the replacement unvalidated, never empty or old content', async () => {
  const s = await setup(); await load(s);
  s.el('replacement').files = [{ size: 2, async arrayBuffer() { return new ArrayBuffer(1); } }];
  await s.el('replacement').fire('change'); await s.el('queue-file').fire(); assert.equal(s.app.queued.length, 0);
});
test('draft downloads are byte-exact, detached, and make no repository request', async () => {
  const s = await setup(); await load(s); const count = s.f.calls.length; await s.el('save-file').fire();
  assert.equal(s.f.calls.length, count); assert.deepEqual(s.saved[0], s.f.edits[0].before.bytes);
  s.saved[0].fill(9); await s.el('save-file').fire(); assert.deepEqual(s.saved[1], s.f.edits[0].before.bytes);
});
test('object-URL downloads have fixed inert filenames and are revoked on page exit', async () => {
  const blobs = new Map(), revoked = [], callbacks = new Map(); let id = 0;
  const urls = { createObjectURL(blob) { const name = `blob:test-${++id}`; blobs.set(name, blob); return name; }, revokeObjectURL(url) { revoked.push(url); } };
  const timers = { setTimeout(fn) { callbacks.set(id, fn); return id; }, clearTimeout(n) { callbacks.delete(n); } };
  const s = await setup(undefined, 'sha1', { saveFile: undefined, urls, timers }); await load(s); await s.el('save-file').fire();
  const link = s.doc.created.find(node => node.clicked); assert.equal(link.download, 'frankengit-file.bin'); assert.equal(blobs.get(link.href).type, 'application/octet-stream');
  assert.deepEqual(new Uint8Array(await blobs.get(link.href).arrayBuffer()), s.f.edits[0].before.bytes);
  s.events.callbacks.get('pagehide')(); assert.deepEqual(revoked, [link.href]); assert.equal(callbacks.size, 0);
});
test('download refusal retains exact draft bytes rather than treating them as saved', async () => {
  const s = await setup(undefined, 'sha1', { saveFile() { throw new Error('save denied'); } }); await load(s); await s.el('save-file').fire();
  assert.match(s.el('status').textContent, /save denied/); assert.deepEqual(hexEditorBytes(s.el('file-hex').value), s.f.edits[0].before.bytes);
});
test('unsubmitted binary drafts warn before leaving and clear on page exit', async () => {
  const s = await setup(); await load(s); await hexEdit(s, [0, 9]); let prevented = false;
  s.events.callbacks.get('beforeunload')({ preventDefault() { prevented = true; } }); assert(prevented);
  s.events.callbacks.get('pagehide')(); assert.equal(s.el('file-hex').value, ''); assert.equal(s.el('replacement').files.length, 0);
});
test('pending binary publication is immutable despite attempted draft edits and lost replies', async () => {
  const s = await setup(); await load(s); await queue(s); await s.el('prepare-edits').fire(); await s.el('stage').fire();
  const pending = s.client.pending; s.el('file-hex').value = '00'; await s.el('file-hex').fire('input');
  s.el('replacement').files = [file([0, 7])]; await s.el('replacement').fire('change'); assert.deepEqual(s.client.pending, pending);
  s.f.config.loseApply = true; s.el('confirm-send').checked = true; await s.el('send').fire();
  assert(s.client.pending); assert.equal(s.client.pending.key, pending.key); await s.el('save-receipt').fire();
  assert(s.receipts[0]); assert(!s.receipts[0].includes(token));
  const command = decodeUpload(s.f.calls.find(c => c.endpoint === 'source/apply').options).command;
  assert.equal(command.get('candidate_commit'), pending.fields.candidate_commit);
});
test('binary authoring stays on the existing exact static route and never executes file markup', () => {
  assert(html.includes('maxlength="786432"')); assert(html.includes('Create initial history')); assert(html.includes('compressed GIT binary patch'));
  const script = readFileSync(new URL('source-edit-view.mjs', base), 'utf8');
  for (const forbidden of ['innerHTML', 'localStorage', 'sessionStorage', 'document.write', 'eval(']) assert(!script.includes(forbidden));
  for (const match of script.matchAll(/from '\.\/([^']+)'/g)) assert(readFileSync(new URL(match[1], base)).length > 0);
});
