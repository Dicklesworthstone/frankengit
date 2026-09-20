// HTTP/DOM fixtures exercise the real source client/controller, not native Rust
// admission. The separate pinned Git lane applies actual emitted patch bytes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { mountSourceEditor } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-view.mjs';
import { renameEdits, fullFilePatch, FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, href, token, crypto, metadata, decodeUpload } from './source-edit-fixtures.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/source-edit.html', import.meta.url), 'utf8');
const h = value => hex(utf8.encode(value));
const standard = { bytes: utf8.encode('before\r\n'), mode: 0o100644 };
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
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(m => [m[2], new Element(m[1])]));
  for (const [key, value] of Object.entries({ branch: 'refs/heads/main', format: 'sha1', 'path-kind': 'hex',
    'rename-path-kind': 'hex', 'change-kind': 'rename', 'file-mode': '100644', 'line-endings': 'lf' })) nodes.get(key).value = value;
  return { nodes, getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
}
async function setup({ algorithm = 'sha1', source = h('file.txt'), destination = h('nested/moved.txt'), before = standard,
  after = before, load = true } = {}) {
  const pair = renameEdits(source, destination, before, after, { allowBinary: true });
  const f = await fixture(algorithm, pair, { allowBinary: true }), doc = documentFixture();
  const client = new SourceEditClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto });
  const events = { callbacks: new Map(), addEventListener(kind, fn) { this.callbacks.set(kind, fn); } };
  let saved;
  const app = mountSourceEditor(doc, { client, events, saveReceipt: value => { saved = value; } });
  const el = id => doc.getElementById(id);
  el('token').value = token; await el('connect').fire(); el('format').value = algorithm; await el('select-base').fire();
  for (const [key, value] of Object.entries(metadata)) el(key).value = String(value);
  el('path').value = source; await el('path').fire('input');
  el('rename-path').value = destination;
  if (load) {
    await el('load-file').fire();
    if (hex(before.bytes) !== hex(after.bytes)) {
      el('content-mode').value = 'hex'; await el('content-mode').fire('change');
      el('file-hex').value = hex(after.bytes); await el('file-hex').fire('input');
    }
    el('file-mode').value = after.mode.toString(8);
  }
  return { f, client, doc, app, el, events, source, destination, pair, before, after, saved: () => saved };
}
async function queued(s) { await s.el('queue-file').fire(); assert.deepEqual(s.app.queued, s.pair); }
async function prepared(s) { await queued(s); await s.el('prepare-edits').fire(); assert(s.client.candidate, s.el('status').textContent); }

for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: one queued rename produces two inspected effects and one confirmed publication`, async () => {
    const s = await setup({ algorithm, after: { bytes: utf8.encode('changed\n'), mode: 0o100755 } });
    await queued(s); assert.equal(s.el('edits').children.length, 1);
    assert.match(s.el('edits').textContent, /Rename .*two paths/);
    assert.equal(s.f.calls.length, 2, 'queueing has no network effect');
    await s.el('prepare-edits').fire(); assert(s.client.candidate, s.el('status').textContent);
    assert.equal(s.client.candidate.inspection.comparison.entries.length, 2);
    const upload = s.f.calls.find(call => call.endpoint === 'source/prepare');
    assert.deepEqual(decodeUpload(upload.options).payload, fullFilePatch(s.pair, { allowBinary: true }).bytes);
    assert.equal(upload.headers['idempotency-key'], undefined);
    assert(!s.f.calls.some(c => c.endpoint === 'source/apply'));
    await s.el('stage').fire(); assert(s.client.pending);
    for (const id of ['rename-path', 'rename-path-kind', 'change-kind']) assert(s.el(id).disabled);
    await s.el('send').fire(); assert(!s.f.calls.some(c => c.endpoint === 'source/apply'));
    s.el('confirm-send').checked = true; await s.el('send').fire();
    assert.equal(s.f.calls.filter(c => c.endpoint === 'source/apply').length, 1);
    assert.equal(s.client.pending, null); assert.equal(s.app.queued.length, 0);
  });
  test(`${algorithm}: raw paths and binary content survive rename plus executable-mode changes`, async () => {
    const before = { bytes: Uint8Array.from([0, 255, 13, 10, 1, 127]), mode: 0o100644 };
    const after = { bytes: Uint8Array.from({ length: 256 }, (_, i) => i), mode: 0o100755 };
    const s = await setup({ algorithm, source: h('old/') + 'ff', destination: h('new/') + 'fe', before, after });
    assert.equal(s.el('content-mode').value, 'hex'); await prepared(s);
    const rows = s.client.candidate.inspection.comparison.entries;
    assert.equal(rows.find(r => r.path_hex === s.source).after, null);
    assert.equal(rows.find(r => r.path_hex === s.destination).before, null);
    assert.equal(rows.find(r => r.path_hex === s.destination).after.mode, 0o100755);
    assert.deepEqual(s.app.queued.find(r => r.path_hex === s.destination).after.bytes, after.bytes);
    assert.match(s.el('edits').textContent, /bytes:/);
  });
  test(`${algorithm}: empty files are moved, not mistaken for absent sides`, async () => {
    const s = await setup({ algorithm, before: { bytes: new Uint8Array(), mode: 0o100755 } });
    await prepared(s); const rows = s.client.candidate.preparation.paths;
    const old = rows.find(r => r.path_hex === s.source), next = rows.find(r => r.path_hex === s.destination);
    assert.equal(next.old_blob, null); assert.equal(old.new_blob, null);
    assert.equal(next.new_blob, old.old_blob); assert(next.new_blob && !/^0+$/.test(next.new_blob));
    assert.equal(s.app.queued.find(r => r.path_hex === s.destination).after.bytes.length, 0);
  });
  test(`${algorithm}: lost rename publication retains exact bytes and key across restored source sessions`, async () => {
    const s = await setup({ algorithm }); await prepared(s); await s.el('stage').fire();
    s.f.config.loseApply = true; s.el('confirm-send').checked = true; await s.el('send').fire();
    assert(s.client.pending?.sent); assert.match(s.el('status').textContent, /Outcome unknown/);
    const original = s.f.calls.at(-1); await s.el('save-receipt').fire(); const receipt = s.saved();
    assert(receipt && !receipt.includes(token)); await s.el('disconnect').fire();
    const next = new SourceEditClient({ href, fetchImpl: s.f.fetchImpl, cryptoImpl: crypto });
    await next.connect(token); const count = s.f.calls.length; await next.restoreReceipt(receipt);
    assert.equal(s.f.calls.length, count, 'restoration never refreshes a moved source path');
    s.f.config.loseApply = false; assert.equal((await next.send()).outcome, 'committed');
    assert.equal(s.f.calls.length, count + 1);
    assert.deepEqual(s.f.calls.at(-1).body, original.body);
    assert.equal(s.f.calls.at(-1).headers['idempotency-key'], original.headers['idempotency-key']);
  });
  test(`${algorithm}: incomplete native rename path receipts cannot become a publishable candidate`, async () => {
    const s = await setup({ algorithm }); await queued(s);
    s.f.config.prepare = value => { value.paths = value.paths.filter(row => row.path_hex === s.destination); };
    await s.el('prepare-edits').fire(); assert.equal(s.client.candidate, null); assert(s.el('stage').disabled);
    assert.equal(s.app.queued.length, 2); assert(!s.f.calls.some(c => c.endpoint === 'source/apply'));
  });
  test(`${algorithm}: inspection cannot claim the source blob already existed at the destination`, async () => {
    const s = await setup({ algorithm }); await queued(s);
    s.f.config.inspect = value => {
      value.comparison.entries.find(row => row.path_hex === s.destination).before = { mode: 0o100644, oid: s.f.manifest.find(row => row.path_hex === s.source).old_blob };
    };
    await s.el('prepare-edits').fire(); assert.equal(s.client.candidate, null); assert(s.el('stage').disabled);
    assert.equal(s.app.queued.length, 2);
  });
}

test('removing a queued rename removes both effects and invalidates its inspected candidate', async () => {
  const s = await setup(); await prepared(s);
  const row = s.el('edits').children[0]; await row.children.find(child => child.tagName === 'BUTTON').fire();
  assert.equal(s.app.queued.length, 0); assert.equal(s.el('edits').children.length, 0);
  assert.equal(s.client.candidate, null); assert(s.el('stage').disabled);
});
test('an ordinary edit cannot overwrite the source half of a queued rename', async () => {
  const s = await setup(); await queued(s); const original = s.app.queued;
  s.el('change-kind').value = 'modify'; await s.el('change-kind').fire('input'); await s.el('load-file').fire();
  s.el('file-text').value = 'different'; await s.el('file-text').fire('input'); await s.el('queue-file').fire();
  assert.deepEqual(s.app.queued, original); assert.match(s.el('status').textContent, /Remove the queued rename/);
});
test('an ordinary create cannot overwrite the destination half of a queued rename', async () => {
  const s = await setup(); await queued(s); const original = s.app.queued;
  s.el('change-kind').value = 'create'; await s.el('change-kind').fire('input');
  s.el('path').value = s.destination; await s.el('path').fire('input'); s.el('file-text').value = 'unrelated';
  await s.el('file-text').fire('input'); await s.el('queue-file').fire();
  assert.deepEqual(s.app.queued, original); assert.match(s.el('status').textContent, /Remove the queued rename/);
});
test('a rename cannot silently replace an already queued destination edit', async () => {
  const s = await setup(); s.el('change-kind').value = 'create'; await s.el('change-kind').fire('input');
  s.el('path').value = s.destination; await s.el('path').fire('input'); s.el('file-text').value = 'already queued';
  await s.el('file-text').fire('input'); await s.el('queue-file').fire(); const original = s.app.queued; assert.equal(original.length, 1);
  s.el('change-kind').value = 'rename'; await s.el('change-kind').fire('input');
  s.el('path').value = s.source; await s.el('path').fire('input'); await s.el('load-file').fire();
  await s.el('queue-file').fire(); assert.deepEqual(s.app.queued, original);
  assert.match(s.el('status').textContent, /Remove queued edits/);
});
test('changing a destination preserves the loaded source, but never rewrites an existing queue', async () => {
  const s = await setup(); await prepared(s); const original = s.app.queued;
  s.el('rename-path').value = h('elsewhere'); await s.el('rename-path').fire('input');
  assert.equal(s.client.candidate, null); assert.deepEqual(s.app.queued, original);
  await s.el('clear-edits').fire(); await s.el('queue-file').fire();
  assert.equal(s.app.queued.length, 2); assert(s.app.queued.some(r => r.path_hex === h('elsewhere')));
  assert.deepEqual(s.app.queued.find(r => r.path_hex === s.source).before.bytes, standard.bytes);
});
for (const [name, value, encoding] of [['same path', h('file.txt'), 'hex'], ['ancestor overlap', h('file.txt/child'), 'hex'],
  ['empty destination', '', 'hex'], ['Git control directory', '.git/config', 'utf8'], ['invalid byte encoding', 'fff', 'hex'],
  ['parent traversal', '../secret', 'utf8'], ['unknown encoding', 'safe', 'automatic']]) {
  test(`refused ${name} leaves no half-queued move`, async () => {
    const s = await setup(); s.el('rename-path').value = value; s.el('rename-path-kind').value = encoding;
    await s.el('queue-file').fire(); assert.equal(s.app.queued.length, 0); assert.equal(s.f.calls.length, 2);
  });
}
test('a source must be completely loaded from the selected base before renaming', async () => {
  const s = await setup({ load: false }); await s.el('queue-file').fire();
  assert.equal(s.app.queued.length, 0); assert.match(s.el('status').textContent, /Load the complete existing file/);
});
test('pending publication cannot be rewritten by changed destination form values', async () => {
  const s = await setup(); await prepared(s); await s.el('stage').fire(); const original = s.client.pending;
  s.el('rename-path').value = h('unrelated'); await s.el('rename-path').fire('input'); await s.el('queue-file').fire();
  assert.deepEqual(s.client.pending, original); assert.equal(s.app.queued.length, 2);
});
test('disconnect and branch selection changes erase queued rename groups as well as their effects', async () => {
  const s = await setup(); await queued(s); await s.el('disconnect').fire();
  assert.equal(s.app.queued.length, 0); assert.equal(s.el('rename-path').value, '');
  assert.equal(s.el('edits').children.length, 0); assert.equal(s.el('file-text').value, '');
});
test('destination changes during a replacement read cannot restore stale uploaded bytes', async () => {
  const s = await setup(); let release;
  s.el('replacement').files = [{ size: 3, arrayBuffer: () => new Promise(resolve => { release = resolve; }) }];
  const loading = s.el('replacement').fire('change'); while (!release) await new Promise(setImmediate);
  s.el('rename-path').value = h('other'); await s.el('rename-path').fire('input'); release(utf8.encode('new').buffer); await loading;
  await s.el('queue-file').fire(); assert.equal(s.app.queued.length, 0);
  assert.match(s.el('status').textContent, /replacement has not completed validation/);
});
test('a queued endpoint collision prevents replacement-file reads', async () => {
  const s = await setup(); await queued(s); let reads = 0;
  s.el('replacement').files = [{ size: 1, async arrayBuffer() { reads++; return Uint8Array.of(1).buffer; } }];
  await s.el('replacement').fire('change'); assert.equal(reads, 0); assert.equal(s.app.queued.length, 2);
});
test('a rename reserves two of the 64 path slots before reading a replacement', async () => {
  const s = await setup(); s.el('change-kind').value = 'create'; await s.el('change-kind').fire('input');
  for (let i = 0; i < 63; i++) {
    s.el('path').value = h(`new-${i}`); await s.el('path').fire('input'); await s.el('queue-file').fire();
  }
  assert.equal(s.app.queued.length, 63);
  s.el('change-kind').value = 'rename'; await s.el('change-kind').fire('input');
  s.el('path').value = s.source; await s.el('path').fire('input'); await s.el('load-file').fire();
  let reads = 0; s.el('replacement').files = [{ size: 1, async arrayBuffer() { reads++; return Uint8Array.of(1).buffer; } }];
  await s.el('replacement').fire('change'); assert.equal(reads, 0); assert.equal(s.app.queued.length, 63);
  assert.match(s.el('status').textContent, /path budget/);
});
test('rename normalization captures both byte buffers and respects the explicit binary profile', () => {
  const before = { bytes: Uint8Array.of(0, 255), mode: 0o100644 }, after = { bytes: Uint8Array.of(4, 0), mode: 0o100755 };
  assert.throws(() => renameEdits(h('old'), h('new'), before, after));
  const pair = renameEdits(h('old'), h('new'), before, after, { allowBinary: true }); before.bytes.fill(9); after.bytes.fill(8);
  assert.deepEqual(pair.find(r => r.before).before.bytes, Uint8Array.of(0, 255));
  assert.deepEqual(pair.find(r => r.after).after.bytes, Uint8Array.of(4, 0));
  for (const [old, next] of [[null, standard], [standard, null], [undefined, standard]]) assert.throws(() => renameEdits(h('a'), h('b'), old, next));
  assert.throws(() => renameEdits(h('a'), h('b'), standard, { bytes: new Uint8Array(FILE_LIMIT + 1), mode: 0o100644 }));
  assert.throws(() => renameEdits(h('a'), h('b'), standard, { bytes: new Uint8Array(), mode: 0o120000 }));
});
