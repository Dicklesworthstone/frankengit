// The actual controller and client with DOM/URL/HTTP doubles. These tests cover
// user flows and byte downloads, not browser rendering or native-node execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ArtifactClient } from '../../crates/fgit-node/src/smart_http/server/browser/artifacts.mjs';
import { inputPins, mountArtifacts } from '../../crates/fgit-node/src/smart_http/server/browser/artifacts-view.mjs';
import { ARTIFACT_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/artifacts-protocol.mjs';
import { bindMetadata, crypto, deferred, digest, fixture, href, incarnation, token } from './artifacts-fixtures.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/artifacts.html', import.meta.url), 'utf8');
class Element {
  constructor(tag = 'div', doc = null) { this.tagName = tag; this.doc = doc; this.children = []; this.listeners = new Map(); this.value = ''; this.disabled = false; this.hidden = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { assert.fail('Repository data became executable markup'); }
  append(...elements) { for (const element of elements) { element.parent = this; this.children.push(element); } }
  replaceChildren(...elements) { this._text = ''; this.children = []; this.append(...elements); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(element => element !== this); }
  removeAttribute(name) { delete this[name]; }
  addEventListener(name, listener) { this.listeners.set(name, [...this.listeners.get(name) ?? [], listener]); }
  removeEventListener(name, listener) { this.listeners.set(name, (this.listeners.get(name) ?? []).filter(value => value !== listener)); }
  async fire(name, event = { preventDefault() {} }) { for (const listener of this.listeners.get(name) ?? []) await listener(event); }
  click() { this.doc.downloads.push({ url: this.href, filename: this.download, blob: this.doc.urls.get(this.href) }); }
}
function dom() {
  const doc = { downloads: [], urls: new Map(), revoked: [], events: new Element('window') };
  const map = new Map([...html.matchAll(/<([a-z]+)\b[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => [match[2], new Element(match[1], doc)]));
  let serial = 0;
  Object.assign(doc, { body: new Element('body', doc), getElementById(id) { assert.ok(map.has(id), `missing control ${id}`); return map.get(id); },
    createElement: tag => new Element(tag, doc), urlApi: { createObjectURL(blob) { const url = `blob:test/${++serial}`; doc.urls.set(url, blob); return url; },
      revokeObjectURL(url) { assert.ok(doc.urls.has(url), 'revoke an active URL exactly once'); doc.revoked.push(url); doc.urls.delete(url); } } });
  return doc;
}
function harness(t, index = 1, options = {}) {
  const f = fixture(index), doc = dom();
  const client = new ArtifactClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl, ...options });
  const view = mountArtifacts(doc, { client, events: doc.events, urlApi: doc.urlApi });
  t.after(() => view.destroy());
  const get = id => doc.getElementById('artifact-' + id);
  return { f, doc, client, view, get,
    async connect() { get('token').value = token; get('incarnation').value = incarnation; await get('connect').fire('click'); },
    async inspect() { get('id').value = f.config.metadata.artifact_id; await get('inspect').fire('click'); },
    async verify() { await this.connect(); await this.inspect(); await get('verify').fire('click'); },
    async download() { await this.verify(); await get('download').fire('click'); } };
}
test('usable connect, metadata inspection, verified preview and explicit binary download preserve exact bytes', async t => {
  const h = harness(t); assert.equal(h.get('inspect').disabled, true); assert.equal(h.get('download').disabled, true);
  await h.connect(); assert.equal(h.get('token').value, ''); assert.equal(h.f.calls.length, 0);
  h.get('payload-sha256').value = h.f.config.metadata.payload_sha256; h.get('payload-bytes').value = String(h.f.original.length);
  await h.inspect(); assert.match(h.get('summary').textContent, /Build log/); assert.match(h.get('summary').textContent, /30 days/);
  assert.match(h.get('summary').textContent, /match the supplied pins/); assert.equal(h.get('download').disabled, true);
  assert.equal(h.doc.downloads.length, 0); assert.equal(h.get('preview').hidden, true);
  assert.equal(h.get('link').href, `${href}#artifact=${h.f.config.metadata.artifact_id}&incarnation=${incarnation}`);
  await h.get('verify').fire('click'); assert.equal(h.doc.downloads.length, 0); assert.equal(h.get('download').disabled, false);
  assert.equal(h.get('preview').textContent, new TextDecoder().decode(h.f.original)); assert.match(h.get('status').textContent, /bytes verified/);
  await h.get('download').fire('click'); assert.equal(h.doc.downloads.length, 1);
  const download = h.doc.downloads[0]; assert.equal(download.filename, `artifact-${h.f.config.metadata.artifact_id}`);
  assert.equal(download.blob.type, 'application/octet-stream'); assert.deepEqual(new Uint8Array(await download.blob.arrayBuffer()), h.f.original);
  assert.equal(h.doc.body.children.length, 0); assert.equal(h.doc.urls.size, 1);
});
test('HTML payloads, media declarations, legal hold reasons and bidi text never become active markup', async t => {
  const h = harness(t, 3); await h.verify();
  assert.match(h.get('summary').textContent, /<script>never execute<\/script>/);
  assert.match(h.get('summary').textContent, /\\u\{202e\}/); assert.match(h.get('summary').textContent, /18446744073709551614/);
  assert.equal(h.get('preview').textContent, '<script>alert("inert")</script>\n'); assert.equal(h.get('preview').children.length, 0);
  assert.match(h.get('identities').textContent, /not authenticated proof/);
  await h.get('download').fire('click'); assert.equal(h.doc.downloads[0].blob.type, 'application/octet-stream');
});
test('empty verified artifacts can be previewed and downloaded without pretending no payload was loaded', async t => {
  const h = harness(t, 2); await h.download(); assert.equal(h.get('preview').hidden, false);
  assert.match(h.get('preview-label').textContent, /0 of 0 bytes/); assert.equal(h.doc.downloads[0].blob.size, 0);
});
test('preview clipping never turns a partial payload into a verified download', async t => {
  const h = harness(t), bytes = new Uint8Array(5000).fill(65);
  h.f.config.content = bytes; h.f.config.metadata = bindMetadata({ ...h.f.config.metadata, payload_bytes: bytes.length, payload_sha256: digest(bytes) });
  await h.download(); assert.equal(h.get('preview').textContent.length, 4096); assert.match(h.get('preview-label').textContent, /preview clipped/);
  assert.deepEqual(new Uint8Array(await h.doc.downloads[0].blob.arrayBuffer()), bytes);
});
test('corrupt content cannot produce a preview, a link, a download or a stale metadata result', async t => {
  const h = harness(t); await h.connect(); await h.inspect(); h.f.config.content[0] ^= 1;
  await h.get('verify').fire('click'); assert.match(h.get('status').textContent, /SHA-256/);
  assert.equal(h.get('preview').textContent, ''); assert.equal(h.get('summary').textContent, '');
  assert.equal(h.get('link').hidden, true); assert.equal(h.get('link').href, undefined); assert.equal(h.get('download').disabled, true);
  await h.get('download').fire('click'); assert.equal(h.doc.downloads.length, 0); assert.equal(h.doc.urls.size, 0);
});
for (const status of [401,403]) test(`HTTP ${status} purges credentials, visible state, inputs and existing object URLs`, async t => {
  const h = harness(t); await h.download(); h.f.config.metadataStatus = status; await h.inspect();
  assert.equal(h.client.connected, false); assert.equal(h.doc.revoked.length, 1); assert.equal(h.doc.urls.size, 0);
  for (const id of ['token','incarnation','id','payload-sha256','payload-bytes']) assert.equal(h.get(id).value, '');
  for (const id of ['summary','identities','preview']) assert.equal(h.get(id).textContent, '');
  assert.equal(h.get('download').disabled, true); assert.equal(h.get('link').href, undefined);
  assert.ok(!h.get('status').textContent.includes('private server error'));
});
test('replacement incarnation before or during byte transfer refuses the workflow without a fallback', async t => {
  for (const during of [false,true]) {
    const h = harness(t); await h.connect(); await h.inspect();
    const replace = () => { h.f.config.metadata = bindMetadata({ ...h.f.config.metadata, repository_incarnation_id: 'ff'.repeat(16) }); };
    if (during) h.f.config.before = call => { if (call.path.endsWith('/content')) replace(); }; else replace();
    await h.get('verify').fire('click'); assert.match(h.get('status').textContent, /incarnation changed/);
    assert.equal(h.get('download').disabled, true); assert.equal(h.get('preview').textContent, ''); assert.equal(h.doc.urls.size, 0);
  }
});
test('over-limit artifacts retain useful inspection metadata and cannot be loaded through the normal controls', async t => {
  const h = harness(t); h.f.config.metadata = bindMetadata({ ...h.f.config.metadata, payload_bytes: ARTIFACT_BYTES + 1 });
  await h.connect(); await h.inspect(); assert.match(h.get('summary').textContent, /16,777,217 bytes/);
  assert.match(h.get('summary').textContent, /exceeds the browser download limit/); assert.equal(h.get('verify').disabled, true);
  assert.equal(h.f.calls.length, 1); assert.equal(h.get('link').hidden, false);
});
for (const field of ['id','payload-sha256','payload-bytes']) test(`editing ${field} releases the existing download and requires explicit reinspection`, async t => {
  const h = harness(t); await h.download(); h.get(field).value = 'new'; await h.get(field).fire('input');
  assert.equal(h.doc.urls.size, 0); assert.equal(h.doc.revoked.length, 1); assert.equal(h.client.state.artifact, null);
  assert.equal(h.get('preview').textContent, ''); assert.equal(h.get('download').disabled, true); assert.equal(h.client.connected, true);
});
test('malformed edited receipt pins clear earlier verified bytes even when validation fails before HTTP', async t => {
  const h = harness(t); await h.verify(); const calls = h.f.calls.length;
  h.get('payload-sha256').value = 'f'.repeat(64); h.get('payload-bytes').value = '00'; await h.get('inspect').fire('click');
  assert.match(h.get('status').textContent, /canonical byte count/); assert.equal(h.f.calls.length, calls);
  assert.equal(h.get('preview').textContent, ''); assert.equal(h.get('download').disabled, true);
});
for (const action of ['disconnect','pagehide','hashchange','token','incarnation']) test(`${action} purges loaded bytes and revokes the single active download URL`, async t => {
  const h = harness(t); await h.download();
  if (['pagehide','hashchange'].includes(action)) await h.doc.events.fire(action);
  else if (action === 'disconnect') await h.get(action).fire('click');
  else { h.get(action).value = 'edited'; await h.get(action).fire('input'); }
  assert.equal(h.client.connected, false); assert.equal(h.client.preview, null); assert.equal(h.doc.revoked.length, 1);
  assert.equal(h.doc.urls.size, 0); assert.equal(h.get('summary').textContent, ''); assert.equal(h.get('preview').textContent, '');
});
test('another explicit download revokes the previous URL, and disposal removes all event listeners', async t => {
  const h = harness(t); await h.download(); await h.get('download').fire('click');
  assert.equal(h.doc.downloads.length, 2); assert.equal(h.doc.revoked.length, 1); assert.equal(h.doc.urls.size, 1);
  h.view.destroy(); assert.equal(h.doc.revoked.length, 2); assert.equal(h.doc.urls.size, 0);
  assert.equal(h.doc.events.listeners.get('pagehide').length, 0); await h.get('connect').fire('click'); assert.equal(h.client.connected, false);
});
test('pinned links prefill identity without credential lookup, automatic fetch or automatic download', async t => {
  const f = fixture(), link = `${href}#artifact=${f.config.metadata.artifact_id}&incarnation=${incarnation}`;
  const h = harness(t, 1, { href: link });
  assert.equal(h.get('id').value, f.config.metadata.artifact_id); assert.equal(h.get('incarnation').value, incarnation);
  assert.equal(h.get('token').value, ''); assert.equal(h.f.calls.length, 0); assert.equal(h.doc.downloads.length, 0);
  h.get('token').value = token; h.get('incarnation').value = 'ff'.repeat(16); await h.get('connect').fire('click');
  assert.match(h.get('status').textContent, /pinned link/); assert.equal(h.f.calls.length, 0);
});
test('cancel rejects a pending read immediately and a late completion cannot repopulate its view', async t => {
  const h = harness(t), gate = deferred(), started = deferred(); await h.connect();
  h.f.config.before = async () => { started.resolve(); await gate.promise; };
  const work = h.inspect(); await started.promise; assert.equal(h.get('cancel').disabled, false);
  await h.get('cancel').fire('click'); await work; assert.equal(h.get('inspect').disabled, false);
  gate.resolve(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.get('summary').textContent, ''); assert.match(h.get('status').textContent, /Read cancelled/);
});
test('changing connections during a pending read cannot let its old finally block alter the new busy state', async t => {
  const h = harness(t), first = deferred(), firstStarted = deferred(); await h.connect();
  h.f.config.before = async () => { firstStarted.resolve(); await first.promise; };
  const old = h.inspect(); await firstStarted.promise; await h.get('incarnation').fire('input');
  await h.connect(); h.f.config.before = null; await h.inspect(); await old;
  first.resolve(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.client.connected, true); assert.equal(h.get('verify').disabled, false);
  assert.match(h.get('status').textContent, /namespace commitments verified/);
});
test('input pair parsing rejects floats, exponent forms, leading zeros, partial and oversized pins', () => {
  for (const bytes of ['', '-1','1.0','1e2','00','67108865','9'.repeat(100000)]) assert.throws(() => inputPins('a'.repeat(64), bytes));
  assert.throws(() => inputPins('', '0')); assert.deepEqual(inputPins('', ''), { payloadSha256: null, payloadBytes: null });
  assert.deepEqual(inputPins('a'.repeat(64), '0'), { payloadSha256: 'a'.repeat(64), payloadBytes: 0 });
});
