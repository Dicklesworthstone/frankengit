import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { mountExportVerifier, transferPage, displayRef } from '../../crates/fgit-node/src/smart_http/server/browser/export-verify.mjs';
import { BUNDLE_LIMIT, EXPORT_MANIFEST_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import { crypto, token, row, page, bundle, binary, json, deferred, hex, encode } from './export-integrity-fixtures.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/export-verify.html', import.meta.url), 'utf8');
class Element {
  children = []; listeners = new Map(); disabled = false; files = []; ownText = ''; _value = '';
  constructor(tag, id) { this.tagName = tag.toUpperCase(); this.id = id; }
  set value(v) { this._value = v; if (this.id?.startsWith('verify-') && v === '') this.files = []; }
  get value() { return this._value; }
  set textContent(v) { this.ownText = String(v); this.children = []; }
  get textContent() { return this.ownText + this.children.map(c => c.textContent ?? String(c)).join(''); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.ownText = ''; this.children = items; }
  addEventListener(event, fn) { this.listeners.set(event, [...(this.listeners.get(event) ?? []), fn]); }
  remove() { this.removed = true; }
  click() { this.clicked = true; }
  async fire(event = 'click') {
    if (event === 'click' && this.disabled) return;
    for (const fn of this.listeners.get(event) ?? []) await fn({ preventDefault() {}, target: this });
  }
}
export function documentFixture() {
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(m => [m[2], new Element(m[1], m[2])]));
  const body = new Element('body'); nodes.get('export-format').value = 'sha1';
  return { nodes, body, getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
}
const file = (bytes, name = '../../ignored') => ({ name, size: bytes.length, async arrayBuffer() { return Uint8Array.from(bytes).buffer; } });
async function setup({ algorithm = 'sha1', customize = null, saver = true, cryptoImpl = crypto } = {}) {
  const doc = documentFixture(), calls = [], input = bundle(algorithm), saved = [], callbacks = new Map();
  const client = new TransferClient({ href: 'https://forge.invalid/r.git/ui/transfers/', cryptoImpl, fetchImpl: async (url, init) => {
    const path = new URL(url).pathname.split('/api/v1/')[1]; calls.push({ path, ...init });
    const fields = new URLSearchParams(init.body);
    const override = await customize?.(path, fields, input, init); if (override) return override;
    if (path === 'source/refs') return json(page(algorithm, [row('refs/heads/main', algorithm)], { limit: Number(fields.get('limit')) }));
    if (path === 'source/bundle/export') return binary(input, algorithm);
    throw new Error(`UI must not write: ${path}`);
  } });
  const handles = [], revoked = [], timers = new Map(); let nextTimer = 0;
  const app = mountExportVerifier(doc, { client, cryptoImpl,
    events: { addEventListener: (name, fn) => callbacks.set(name, fn) },
    save: saver ? (bytes, name, media) => saved.push({ bytes, name, media }) : null,
    urlApi: { createObjectURL(blob) { const url = `blob:local-${handles.length}`; handles.push({ url, blob }); return url; }, revokeObjectURL(url) { revoked.push(url); } },
    schedule(fn) { const id = ++nextTimer; timers.set(id, fn); return id; }, unschedule(id) { timers.delete(id); }
  });
  const el = id => doc.getElementById(id); el('export-format').value = algorithm;
  return { app, client, doc, el, calls, input, saved, callbacks, handles, revoked, timers };
}
async function exportPair(s) {
  s.el('export-token').value = token; await s.el('export-connect').fire(); await s.el('export-build').fire();
  assert(s.client.exported?.snapshot_refs_checked); return s.client.exportManifest();
}
async function localPair(s) {
  const encoded = await exportPair(s); await s.el('export-disconnect').fire();
  s.el('verify-bundle').files = [file(s.input)]; s.el('verify-manifest').files = [file(encode(encoded))]; return encoded;
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: UI audits the snapshot, downloads exact bytes and never invokes a mutation`, async () => {
    const s = await setup({ algorithm }); assert(s.el('export-build').disabled); await exportPair(s);
    assert.equal(s.el('export-token').value, ''); assert(!s.el('export-save-bundle').disabled);
    await s.el('export-save-bundle').fire(); await s.el('export-save-manifest').fire();
    assert.deepEqual(s.saved[0].bytes, s.input); assert.equal(s.saved[0].name, 'repository.bundle');
    assert.equal(s.saved[1].name, 'repository.export.json'); assert(!new TextDecoder().decode(s.saved[1].bytes).includes(token));
    assert(s.el('export-report').textContent.includes('refs/heads/main'));
    assert.deepEqual(s.calls.map(c => c.path), ['source/refs', 'source/refs', 'source/bundle/export']);
    assert(s.calls.every(c => c.method === 'POST' && !c.headers['Idempotency-Key']));
  });
  test(`${algorithm}: saved files are verified without connection or upload`, async () => {
    const s = await setup({ algorithm }); await localPair(s); const n = s.calls.length;
    await s.el('verify-files').fire(); assert(s.app.offline); assert.equal(s.calls.length, n);
    assert.equal(s.client.connected, false); assert.equal(s.app.offline.independently_authenticated, false);
    assert(s.el('offline-status').textContent.includes('unsigned')); assert(s.el('offline-report').textContent.includes('live_snapshot_rechecked'));
  });
}
for (const which of ['verify-bundle', 'verify-manifest']) test(`both file sizes are checked before reading an oversized ${which}`, async () => {
  const s = await setup(); let reads = 0;
  const read = async () => { reads++; throw new Error('must not read'); };
  s.el('verify-bundle').files = [{ size: 20, arrayBuffer: read }];
  s.el('verify-manifest').files = [{ size: 20, arrayBuffer: read }];
  s.el(which).files[0].size = (which === 'verify-bundle' ? BUNDLE_LIMIT : EXPORT_MANIFEST_LIMIT) + 1;
  await s.el('verify-files').fire(); assert.equal(reads, 0); assert.equal(s.app.offline, null);
});
test('changed file length and malformed UTF-8 fail before an offline success', async () => {
  const s = await setup(); await localPair(s);
  s.el('verify-manifest').files = [{ size: 3, arrayBuffer: async () => new ArrayBuffer(4) }];
  await s.el('verify-files').fire(); assert.equal(s.app.offline, null); assert(s.el('offline-status').textContent.includes('length changed'));
  s.el('verify-manifest').files = [file(Uint8Array.of(255))];
  await s.el('verify-files').fire(); assert.equal(s.app.offline, null);
});
for (const action of ['export-disconnect', 'export-cancel', 'file-change', 'pagehide']) test(`${action} suppresses late file results`, async () => {
  const s = await setup(); const encoded = await localPair(s); const gate = deferred(), entered = deferred();
  s.el('verify-manifest').files = [{ size: encode(encoded).length, arrayBuffer() { entered.resolve(); return gate.promise; } }];
  const pending = s.el('verify-files').fire(); await entered.promise;
  if (action === 'file-change') await s.el('verify-bundle').fire('change');
  else if (action === 'pagehide') s.callbacks.get('pagehide')(); else await s.el(action).fire();
  gate.resolve(Uint8Array.from(encode(encoded)).buffer); await pending;
  assert.equal(s.app.offline, null); assert.equal(s.el('offline-report').textContent, '');
});
test('offline file selections can change during hashing without resurrecting success', async () => {
  let gate = null, entered = null;
  const controlled = { getRandomValues: a => crypto.getRandomValues(a), subtle: { async digest(...args) { if (gate) { entered.resolve(); await gate.promise; } return crypto.subtle.digest(...args); } } };
  const s = await setup({ cryptoImpl: controlled }); await localPair(s); gate = deferred(); entered = deferred();
  const pending = s.el('verify-files').fire(); await entered.promise; await s.el('verify-manifest').fire('change'); gate.resolve(); await pending;
  assert.equal(s.app.offline, null); assert.equal(s.el('offline-report').textContent, '');
});
test('new local files immediately invalidate an earlier successful check', async () => {
  const s = await setup(); await localPair(s); await s.el('verify-files').fire(); assert(s.app.offline);
  s.el('verify-bundle').files = [file(Uint8Array.of(1, 2, 3))]; await s.el('verify-bundle').fire('change'); assert.equal(s.app.offline, null);
  await s.el('verify-files').fire(); assert.equal(s.app.offline, null); assert.equal(s.el('offline-report').textContent, '');
});
for (const action of ['export-cancel', 'export-disconnect', 'pagehide']) test(`${action} prevents late network downloads`, async () => {
  const gate = deferred(), entered = deferred();
  const s = await setup({ customize: async path => { if (path === 'source/bundle/export') { entered.resolve(); await gate.promise; } } });
  s.el('export-token').value = token; await s.el('export-connect').fire(); const pending = s.el('export-build').fire(); await entered.promise;
  if (action === 'pagehide') s.callbacks.get('pagehide')(); else await s.el(action).fire(); gate.resolve(); await pending;
  assert.equal(s.client.exported, null); assert(s.el('export-save-bundle').disabled); assert.equal(s.el('export-report').textContent, '');
});
test('format changes invalidate the previous artifact and manifest', async () => {
  const s = await setup(); await exportPair(s); s.el('export-format').value = 'sha256'; await s.el('export-format').fire('change');
  assert.equal(s.client.exported, null); assert(s.el('export-save-bundle').disabled); assert.throws(() => s.client.exportManifest());
});
test('native snapshot refusal cannot leave the earlier export downloadable', async () => {
  let refuse = false;
  const s = await setup({ customize: path => refuse && path === 'source/refs' ? new Response('{}', { status: 409 }) : null });
  await exportPair(s); refuse = true; await s.el('export-build').fire(); assert.equal(s.client.exported, null); assert(s.el('export-save-bundle').disabled);
});
test('download object URLs use fixed filenames and are revoked on exit', async () => {
  const s = await setup({ saver: false }); await exportPair(s); await s.el('export-save-bundle').fire(); await s.el('export-save-manifest').fire();
  assert.equal(s.handles.length, 2); assert.equal(s.timers.size, 2);
  assert.deepEqual(s.doc.body.children.map(c => c.download), ['repository.bundle', 'repository.export.json']);
  assert(s.doc.body.children.every(c => c.clicked && c.removed));
  s.callbacks.get('pagehide')(); assert.deepEqual(s.revoked, s.handles.map(h => h.url)); assert.equal(s.timers.size, 0);
});
test('scheduled URL cleanup releases download handles without another user action', async () => {
  const s = await setup({ saver: false }); await exportPair(s); await s.el('export-save-bundle').fire();
  [...s.timers.values()][0](); assert.equal(s.revoked.length, 1); assert.equal(s.timers.size, 0);
});
test('page routing never turns a query, external endpoint, or URL credential into an API request', () => {
  assert.equal(transferPage('https://forge.invalid/r.git/ui/transfers/verify/'), 'https://forge.invalid/r.git/ui/transfers/');
  for (const href of ['http://forge.invalid/r.git/ui/transfers/verify/', 'https://forge.invalid/r.git/ui/export/',
    'https://secret@forge.invalid/r.git/ui/transfers/verify/', 'https://forge.invalid/r.git/ui/transfers/verify/?token=x',
    'https://forge.invalid/r.git/ui/transfers/verify/#a', 'file:///r.git/ui/transfers/verify/']) assert.throws(() => transferPage(href));
});
test('untrusted text is inert and misleading directional controls remain visible', () => {
  assert.equal(displayRef(hex(encode('refs/tags/<script>'))), 'refs/tags/<script>');
  assert(displayRef(hex(encode('refs/tags/\u202e'))).includes('\\u202e'));
  assert(displayRef(hex(encode('refs/tags/')) + 'ff').includes('raw bytes'));
  const script = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/export-verify.mjs', import.meta.url), 'utf8');
  for (const forbidden of ['innerHTML', 'localStorage', 'sessionStorage', 'document.write', '.send(', '.stage(', '.recover(']) assert(!script.includes(forbidden));
  assert(!html.includes('<script>')); assert(!html.includes('onclick='));
});
test('every transitive browser import is served by an exact source-gated route', () => {
  const assets = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
  const route = readFileSync(new URL('export_verify.rs', assets), 'utf8');
  const pending = ['export-verify.mjs'], seen = new Set();
  while (pending.length) {
    const name = pending.pop(); if (seen.has(name)) continue; seen.add(name);
    assert(route.includes(`b"/ui/transfers/verify/${name}"`)); assert(route.includes(`include_str!("${name}")`));
    const content = readFileSync(new URL(name, assets), 'utf8');
    for (const match of content.matchAll(/from\s+['"]\.\/([^'"]+)['"]/g)) pending.push(match[1]);
  }
  assert.equal(seen.size, 6); assert(route.includes('profile.allow_source'));
  const parent = readFileSync(new URL('../browser.rs', assets), 'utf8');
  assert(parent.includes('mod export_verify;')); assert(parent.includes('export_verify::serve(profile, request, trailing, writer)?'));
  assert(html.includes('src="export-verify.mjs"'));
});
