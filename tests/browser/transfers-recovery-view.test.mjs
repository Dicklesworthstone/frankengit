// Actual transfer client/controller with inert DOM, File and HTTP doubles.
// These are not browser rendering or native server integration claims.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { mountTransfers } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-view.mjs';
import { fixture, crypto, href, token, actor, hex, deferred } from './transfers-fixtures.mjs';
import { completeBundle } from './transfer-closure-fixtures.mjs';

const ROTATED = '8'.repeat(64), OTHER = 'a'.repeat(32);
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/transfers.html', import.meta.url), 'utf8');
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.checked = false; this.files = []; this.disabled = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(n => n.textContent).join(''); }
  set innerHTML(_) { assert.fail('Repository data reached executable markup'); }
  append(...nodes) { for (const node of nodes) { node.parent = this; this.children.push(node); } }
  replaceChildren(...nodes) { this._text = ''; this.children = []; this.append(...nodes); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(node => node !== this); }
  addEventListener(name, fn) { if (!this.listeners.has(name)) this.listeners.set(name, []); this.listeners.get(name).push(fn); }
  // Deliberately dispatches disabled controls too: handlers must enforce the
  // active client mode without relying on the browser's default event filter.
  async fire(name, event = { preventDefault() {} }) { for (const fn of this.listeners.get(name) ?? []) await fn(event); }
}
function dom() {
  const map = new Map([...html.matchAll(/<([a-z]+)\b[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => [match[2], new Element(match[1])]));
  map.get('transfer-format').value = 'sha1';
  return { body: new Element('body'), events: new Element('window'), createElement: tag => new Element(tag),
    getElementById(id) { assert.ok(map.has(id), `Missing declared control ${id}`); return map.get(id); } };
}
const file = bytes => ({ size: bytes.length, async arrayBuffer() { return bytes.slice().buffer; } });
const encoded = value => new TextEncoder().encode(value);
function mount(f, retained = null) {
  const doc = dom(), downloads = [], get = id => doc.getElementById(id);
  const client = retained ?? new TransferClient({ href, cryptoImpl: crypto, fetchImpl: (...args) => f.fetchImpl(...args) });
  const view = mountTransfers(doc, { client, events: doc.events, download: (bytes, name, media) => downloads.push({ bytes, name, media }) });
  return { f, client, doc, downloads, get, view,
    async connect(credential = ROTATED, recoveryOnly = true, originalPrincipal = actor) {
      get('transfer-recovery-only').checked = recoveryOnly; get('transfer-original-principal').value = originalPrincipal;
      await get('transfer-recovery-only').fire('change');
      get('transfer-token').value = credential; await get('transfer-connect').fire('click');
    },
    async restore(receipt) {
      get('receipt-file').files = [file(encoded(receipt))]; await get('receipt-file').fire('change');
      await get('restore-transfer').fire('click');
    },
  };
}
async function prepared(algorithm = 'sha1', operation = 'fetch') {
  const f = fixture(algorithm, completeBundle(algorithm, { refCount: 2 }).bytes);
  const c = new TransferClient({ href, cryptoImpl: crypto, fetchImpl: (...args) => f.fetchImpl(...args) });
  await c.connect(token); await c.select(algorithm); await c.load(f.input, { verifyClosure: true });
  await c.stage(operation, operation === 'import' ? [] : [{ source_hex: hex('refs/heads/main'),
    destination_hex: hex('refs/remotes/retained/') + 'ff', expected_old: 'b'.repeat(algorithm === 'sha1' ? 40 : 64) }], { requireVerified: true });
  return { f, c };
}
const ordinaryControls = ['transfer-format', 'select-target', 'export-bundle', 'download-bundle', 'bundle-file',
  'bundle-sha256', 'bundle-pins', 'bundle-pin-encoding', 'bundle-exact-refs', 'load-bundle', 'stage-import', 'stage-fetch', 'confirm-transfer', 'send-transfer', 'discard-transfer'];
function restricted(h) {
  assert.equal(h.client.recoveryOnly, true); assert.match(h.get('transfer-connection-mode').textContent, /RECOVERY ONLY/);
  for (const id of ordinaryControls) assert.equal(h.get(id).disabled, true, id);
}

for (const algorithm of ['sha1', 'sha256']) for (const operation of ['import', 'fetch']) {
  test(`${algorithm} ${operation}: the page restores with a replacement bearer, retains the original receipt, and only checks its outcome`, async () => {
    const { f, c } = await prepared(algorithm, operation), receipt = c.exportReceipt(), saved = JSON.parse(receipt);
    const h = mount(f), before = f.calls.length;
    await h.connect(); assert.equal(h.get('transfer-token').value, ''); assert.equal(f.calls.length, before);
    restricted(h); assert.equal(h.get('receipt-file').disabled, false); assert.equal(h.get('restore-transfer').disabled, false);
    await h.restore(receipt); assert.equal(f.calls.length, before); assert.equal(h.client.pending.key, saved.key);
    assert.equal(h.client.pending.observedPrincipal, null); assert.equal(h.client.recoveryPrincipal, actor);
    restricted(h); assert.equal(h.get('recover-transfer').disabled, false); assert.equal(h.get('save-transfer').disabled, false);
    h.get('confirm-transfer').checked = true; await h.get('send-transfer').fire('click');
    assert.equal(f.calls.length, before); assert.equal(h.downloads.length, 0); assert.equal(h.client.pending.key, saved.key);
    await h.get('save-transfer').fire('click'); assert.equal(h.downloads.length, 1);
    assert.equal(h.downloads[0].bytes, receipt); assert.equal(h.downloads[0].name, 'frankengit-transfer-retry.json');
    assert(!h.downloads[0].bytes.includes(token)); assert(!h.downloads[0].bytes.includes(ROTATED));
    f.config.outcome = operation === 'import' ? 'committed' : 'refused'; await h.get('recover-transfer').fire('click');
    assert.equal(h.client.pending, null); restricted(h); assert.match(h.get('transfer-status').textContent, /Recovery-only mode remains active/);
    const call = f.calls.at(-1); assert.equal(call.path, 'outcomes'); assert.equal(call.method, 'POST'); assert.equal(call.body, undefined);
    assert.equal(call.headers.authorization, `Bearer ${ROTATED}`); assert.equal(call.headers['idempotency-key'], saved.key);
    assert.deepEqual(f.calls.slice(before).map(call => call.path), ['outcomes']);
    await h.get('select-target').fire('click'); assert.equal(f.calls.length, before + 1);
    await h.connect(ROTATED, false); assert.equal(h.client.recoveryOnly, false); assert.equal(f.calls.length, before + 1);
    h.get('transfer-format').value = algorithm; await h.get('select-target').fire('click'); assert.equal(f.calls.at(-1).path, 'source/refs');
  });
}

test('forced ordinary controls cannot read a file, export data, prepare, discard or send in recovery-only mode', async () => {
  const { f, c } = await prepared(), receipt = c.exportReceipt(), h = mount(f);
  await h.connect(); const before = f.calls.length; let fileReads = 0;
  const blockedFile = { size: f.input.length, async arrayBuffer() { fileReads++; return f.input.slice().buffer; } };
  for (const withReceipt of [false, true]) {
    if (withReceipt) await h.restore(receipt);
    const pending = h.client.pending;
    h.get('bundle-file').files = [blockedFile]; h.get('confirm-transfer').checked = true;
    // Editing the connection form only selects the next explicit connection.
    h.get('transfer-recovery-only').checked = false; h.get('transfer-original-principal').value = OTHER;
    await h.get('transfer-recovery-only').fire('change'); restricted(h);
    for (const id of ['select-target', 'export-bundle', 'download-bundle', 'load-bundle', 'stage-import', 'stage-fetch', 'send-transfer', 'discard-transfer']) {
      h.get(id).disabled = false; await h.get(id).fire('click');
      assert.equal(fileReads, 0, id); assert.equal(f.calls.length, before, id); assert.equal(h.downloads.length, 0, id);
      assert.deepEqual(h.client.pending, pending, id); assert.equal(h.client.recoveryOnly, true);
    }
  }
});

test('a retained verified bundle download cannot survive switching into recovery-only access', async () => {
  const f = fixture('sha1', completeBundle('sha1', { refCount: 2 }).bytes), h = mount(f);
  await h.connect(token, false); await h.get('select-target').fire('click'); await h.get('export-bundle').fire('click');
  assert.equal(h.get('download-bundle').disabled, false); assert.equal(h.client.exportVerification.object_closure_verified, true);
  await h.connect(); restricted(h); assert.equal(h.client.exported, null); assert.equal(h.get('export-info').textContent, '');
  const before = f.calls.length; h.get('download-bundle').disabled = false; await h.get('download-bundle').fire('click');
  assert.equal(h.downloads.length, 0); assert.equal(f.calls.length, before);
});

for (const state of ['key_not_observed', 'committed']) {
  test(`wrong-principal ${state} remains unresolved on the page and the original receipt stays downloadable`, async () => {
    const { f, c } = await prepared(), receipt = c.exportReceipt(), h = mount(f);
    await h.connect(); await h.restore(receipt); const pending = h.client.pending;
    f.config.outcome = state; f.config.recover = reply => { reply.principal_id = OTHER; };
    await h.get('recover-transfer').fire('click'); assert.deepEqual(h.client.pending, pending); restricted(h);
    assert.match(h.get('transfer-status').textContent, /selected original principal/);
    await h.get('save-transfer').fire('click'); assert.equal(h.downloads[0].bytes, receipt);
    assert.equal(h.get('send-transfer').disabled, true); assert.equal(h.get('discard-transfer').disabled, true);
  });
}

test('the receipt never fills or overrides the independently entered original principal', async () => {
  const { f, c } = await prepared(); await c.recover(); const receipt = c.exportReceipt(), h = mount(f), before = f.calls.length;
  await h.connect(ROTATED, true, ''); assert.equal(h.client.connected, false);
  assert.equal(h.get('transfer-original-principal').value, ''); assert.equal(h.get('transfer-token').value, '');
  await h.connect(ROTATED, true, OTHER); await h.restore(receipt);
  assert.equal(h.client.pending, null); assert.equal(h.client.recoveryPrincipal, OTHER);
  assert.equal(h.get('transfer-original-principal').value, OTHER); assert.match(h.get('transfer-status').textContent, /Receipt principal conflicts/);
  assert.equal(f.calls.length, before);
  await h.connect(ROTATED, true, actor); await h.restore(receipt); assert.equal(h.client.pending.observedPrincipal, actor);
});

test('a retained unsent preparation cannot use forced send or receipt saving to publish with the rotated bearer', async () => {
  const { f, c } = await prepared(), h = mount(f, c), before = f.calls.length, originalKey = c.pending.key;
  assert.equal(c.pending.sent, false); assert.equal(c.pending.exported, false);
  await h.connect(); restricted(h);
  h.get('confirm-transfer').checked = true; h.get('send-transfer').disabled = false; await h.get('send-transfer').fire('click');
  assert.equal(f.calls.length, before); assert.equal(h.downloads.length, 0); assert.equal(c.pending.sent, false); assert.equal(c.pending.exported, false);
  await h.get('save-transfer').fire('click'); assert.equal(c.pending.exported, true); assert.equal(c.pending.sent, false);
  assert.equal(JSON.parse(h.downloads[0].bytes).key, originalKey); assert.equal(f.calls.length, before);
  h.get('send-transfer').disabled = false; await h.get('send-transfer').fire('click'); assert.equal(f.calls.length, before);
  assert.equal(c.pending.key, originalKey); assert.equal(c.recoveryOnly, true);
});

test('saving or replacing credentials while an outcome is settling cannot bypass the busy boundary', async () => {
  const { f, c } = await prepared(), h = mount(f, c); await h.connect();
  const entered = deferred(), gate = deferred(), before = f.calls.length;
  f.config.recover = async () => { entered.resolve(); await gate.promise; };
  const settling = h.get('recover-transfer').fire('click'); await entered.promise;
  h.get('save-transfer').disabled = false; await h.get('save-transfer').fire('click'); assert.equal(h.downloads.length, 0); assert.equal(c.pending.exported, false);
  h.get('transfer-token').value = token; h.get('transfer-recovery-only').checked = false; await h.get('transfer-connect').fire('click');
  assert.equal(h.get('transfer-token').value, ''); assert.equal(c.recoveryOnly, true);
  gate.resolve(); await settling; assert.equal(f.calls.length, before + 1); assert.equal(c.pending.observedPrincipal, actor);
  await h.get('save-transfer').fire('click'); assert.equal(h.downloads.length, 1); restricted(h);
});

test('disconnect during outcome lookup keeps the receipt and rejects a late terminal response', async () => {
  const { f, c } = await prepared(), receipt = c.exportReceipt(), h = mount(f);
  await h.connect(); await h.restore(receipt); const before = h.client.pending, entered = deferred(), gate = deferred();
  f.config.outcome = 'committed'; f.config.recover = async () => { entered.resolve(); await gate.promise; };
  const settling = h.get('recover-transfer').fire('click'); await entered.promise; h.view.disconnect(); gate.resolve(); await settling;
  assert.equal(h.client.connected, false); assert.deepEqual(h.client.pending, before);
  assert.equal(h.get('transfer-token').value, ''); assert.equal(h.get('send-transfer').disabled, true);
  await h.get('save-transfer').fire('click'); assert.equal(h.downloads[0].bytes, receipt);
  f.config.recover = null; await h.connect(); await h.get('recover-transfer').fire('click'); assert.equal(h.client.pending, null); restricted(h);
});

test('a changed or disconnected receipt file never becomes a newly selected request', async () => {
  const { f, c } = await prepared(), receipt = c.exportReceipt(), h = mount(f);
  await h.connect(); const before = f.calls.length, started = deferred(), gate = deferred(), bytes = encoded(receipt);
  const original = { size: bytes.length, async arrayBuffer() { started.resolve(); await gate.promise; return bytes.slice().buffer; } };
  h.get('receipt-file').files = [original]; const restoring = h.get('restore-transfer').fire('click'); await started.promise;
  h.get('receipt-file').files = [file(bytes)]; await h.get('receipt-file').fire('change'); gate.resolve(); await restoring;
  assert.equal(h.client.pending, null); assert.equal(f.calls.length, before); restricted(h);
  await h.restore(receipt); assert.equal(h.client.pending.key, JSON.parse(receipt).key);
});

test('the page explains principal selection, lookup-only behavior and retained terminal restrictions', () => {
  assert.match(html, /independently retained record/); assert.match(html, /including absence/);
  assert.match(html, /receipt does not select or authenticate the principal/);
  assert.match(html, /restriction remains after a terminal result/);
  assert.match(html, /cannot read source, export bundles, prepare, discard or resend/);
});
