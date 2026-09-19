// DOM/File/HTTP doubles exercising the actual client and controller together.
// These are not browser rendering or native Rust-node integration evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { mountTransfers, selectedBytes, referenceLabel } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-view.mjs';
import { BUNDLE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import { fixture, bundleBytes, crypto, href, token, hex, head, deferred, decodeUpload, json } from './transfers-fixtures.mjs';
const root = '../../crates/fgit-node/src/smart_http/server/browser/';
const html = readFileSync(new URL(root + 'transfers.html', import.meta.url), 'utf8');
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.checked = false; this.files = []; this.disabled = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(n => n.textContent).join(''); }
  set innerHTML(_) { assert.fail('Executable repository text'); }
  append(...nodes) { for (const n of nodes) { n.parent = this; this.children.push(n); } }
  replaceChildren(...nodes) { this._text = ''; this.children = []; this.append(...nodes); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(n => n !== this); }
  addEventListener(name, fn) { if (!this.listeners.has(name)) this.listeners.set(name, []); this.listeners.get(name).push(fn); }
  async fire(name, event = { preventDefault() {} }) { for (const fn of this.listeners.get(name) ?? []) await fn(event); }
}
function dom() {
  const map = new Map([...html.matchAll(/<([a-z]+)\b[^>]*\bid="([^"]+)"[^>]*>/g)].map(m => [m[2], new Element(m[1])]));
  map.get('transfer-format').value = 'sha1';
  return { body: new Element('body'), getElementById(id) { assert.ok(map.has(id), `missing declared control ${id}`); return map.get(id); }, createElement: tag => new Element(tag), events: new Element('window') };
}
const file = (bytes, name = '../../ignored.bundle') => ({ name, size: bytes.length, async arrayBuffer() { return bytes.slice().buffer; } });
const all = element => [element, ...element.children.flatMap(all)];
const find = (element, tag, caption = '') => { const found = all(element).find(n => n.tagName === tag && n.textContent.includes(caption)); assert.ok(found, `${tag} ${caption}`); return found; };
async function harness(algorithm = 'sha1', input = bundleBytes(algorithm)) {
  const f = fixture(algorithm, input), doc = dom(), downloads = [];
  const client = new TransferClient({ href, cryptoImpl: crypto, fetchImpl: (...args) => f.fetchImpl(...args) });
  const view = mountTransfers(doc, { client, events: doc.events, download: (bytes, name, media) => downloads.push({ bytes, name, media }) });
  const get = id => doc.getElementById(id);
  get('transfer-token').value = token; await get('transfer-connect').fire('click');
  get('transfer-format').value = algorithm;
  return { f, doc, client, view, get, downloads,
    async select() { await get('select-target').fire('click'); },
    async load(bytes = input) { get('bundle-file').files = [file(bytes)]; await get('bundle-file').fire('change'); await get('load-bundle').fire('click'); },
    async map(destination = 'refs/remotes/portable/main', old = 'absent', encoding = 'text') {
      await find(get('bundle-refs'), 'button', 'Map this reference').fire('click');
      const row = get('mapping-rows').children.at(-1), inputs = all(row).filter(n => n.tagName === 'input');
      inputs[0].value = destination; inputs[1].value = old; find(row, 'select').value = encoding; return row;
    },
    async prepare(operation = 'fetch') { await this.select(); await this.load(); if (operation === 'fetch') await this.map(); await get(`stage-${operation}`).fire('click'); },
  };
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: export selects a pinned target and offers only complete identical bytes`, async () => {
    const h = await harness(algorithm); assert.equal(h.get('transfer-token').value, '');
    assert.equal(h.get('export-bundle').disabled, true); await h.select();
    await h.get('export-bundle').fire('click'); assert.equal(h.downloads.length, 0);
    assert.equal(h.get('download-bundle').disabled, false); await h.get('download-bundle').fire('click');
    assert.deepEqual(h.downloads[0].bytes, h.f.input); assert.equal(h.downloads[0].name, 'repository.bundle');
    assert.equal(new URLSearchParams(h.f.calls.at(-1).body).get('expected_head'), head);
    assert.equal(h.f.calls.at(-1).headers['idempotency-key'], undefined); assert.match(h.get('export-info').textContent, /objects_verified/);
  });
  test(`${algorithm}: preparation and explicit confirmation precede one atomic mapped fetch`, async () => {
    const h = await harness(algorithm); await h.prepare();
    assert.equal(h.f.calls.length, 1); assert.equal(h.client.pending.operation, 'fetch');
    const original = h.client.pending; await h.get('send-transfer').fire('click');
    assert.equal(h.f.calls.length, 1); assert.match(h.get('transfer-status').textContent, /Confirm the exact/);
    h.get('confirm-transfer').checked = true; await h.get('send-transfer').fire('click');
    assert.equal(h.get('confirm-transfer').checked, false); assert.equal(h.client.pending, null);
    const call = h.f.calls.at(-1); assert.equal(call.path, 'source/bundle/fetch'); assert.deepEqual(decodeUpload(call).payload, h.f.input);
    assert.equal(call.headers['idempotency-key'], original.key); assert.match(h.get('transfer-status').textContent, /Canonical committed/);
  });
  test(`${algorithm}: absent-ref import never manufactures a mapping or default HEAD change`, async () => {
    const h = await harness(algorithm); await h.prepare('import');
    assert.equal(h.client.pending.count, 2); assert.ok(h.client.pending.updates.every(r => r.expected_old === null));
    h.get('confirm-transfer').checked = true; await h.get('send-transfer').fire('click');
    assert.equal(h.f.calls.at(-1).path, 'source/bundle/import'); assert.equal(decodeUpload(h.f.calls.at(-1)).fields.has('mapping'), false);
  });
}
test('mapping controls never guess destination or absent lease from an advertised source', async () => {
  const h = await harness(); await h.select(); await h.load();
  await find(h.get('bundle-refs'), 'button', 'Map this reference').fire('click');
  const inputs = all(h.get('mapping-rows')).filter(n => n.tagName === 'input');
  assert.deepEqual(inputs.map(i => i.value), ['', '']);
  await h.get('stage-fetch').fire('click'); assert.equal(h.client.pending, null);
  inputs[0].value = 'refs/remotes/import/main'; await h.get('stage-fetch').fire('click');
  assert.equal(h.client.pending, null); assert.match(h.get('transfer-status').textContent, /requires absent/);
  inputs[1].value = 'absent'; await h.get('stage-fetch').fire('click'); assert.ok(h.client.pending);
});
test('fetch supports raw-byte destination names and exact old tips without filename substitution', async () => {
  const h = await harness(); await h.select(); await h.load(); const dest = hex('refs/remotes/input/') + 'ff', old = 'b'.repeat(40);
  await h.map(dest, old, 'hex'); await h.get('stage-fetch').fire('click');
  assert.equal(h.client.pending.updates[0].destination_hex, dest); assert.equal(h.client.pending.updates[0].expected_old, old);
  assert.equal(h.client.pending.fields.mapping[0].includes('ignored.bundle'), false);
});
test('duplicate destinations refuse and removing the conflicting mapping permits the real subset', async () => {
  const h = await harness(); await h.select(); await h.load(); await h.map(); const second = await h.map();
  await h.get('stage-fetch').fire('click'); assert.equal(h.client.pending, null); assert.match(h.get('transfer-status').textContent, /Duplicate/);
  await find(second, 'button', 'Remove').fire('click'); await h.get('stage-fetch').fire('click'); assert.equal(h.client.pending.count, 1);
});
test('large advertised sets can use mapped subsets but cannot import more than 64 refs', async () => {
  const id = 'a'.repeat(40), input = bundleBytes('sha1', '# v2 git bundle\n' + Array.from({ length: 65 }, (_, i) => `${id} refs/heads/r${i}\n`).join('') + '\n');
  const h = await harness('sha1', input); await h.select(); await h.load();
  assert.equal(h.get('stage-import').disabled, true); await h.map(); await h.get('stage-fetch').fire('click'); assert.equal(h.client.pending.count, 1);
});
test('mapping count is bounded before creating another editor', async () => {
  const h = await harness(); await h.select(); await h.load();
  for (let i = 0; i < 65; i++) await find(h.get('bundle-refs'), 'button', 'Map this reference').fire('click');
  assert.equal(h.get('mapping-rows').children.length, 64); assert.match(h.get('transfer-status').textContent, /At most 64/);
});
test('source refs, malicious-looking text and direction controls remain inert labels', async () => {
  const raw = 'refs/heads/<script>\u202e', header = `# v2 git bundle\n${'a'.repeat(40)} ${raw}\n${'a'.repeat(40)} refs/heads/`;
  const input = bundleBytes('sha1', Buffer.concat([Buffer.from(header), Buffer.from([255]), Buffer.from('\n\n')]));
  const h = await harness('sha1', input); await h.select(); await h.load();
  assert.match(h.get('bundle-refs').textContent, /<script>/); assert.match(h.get('bundle-refs').textContent, /\\u\{202e\}/);
  assert.match(h.get('bundle-refs').textContent, /Byte-valued reference/); assert.ok(!all(h.get('bundle-refs')).some(n => n.tagName === 'script'));
  assert.match(referenceLabel(hex(raw)), /\\u\{202e\}/);
});
test('new and invalid file selections clear old bytes and all destination assumptions', async () => {
  const h = await harness(); await h.select(); await h.load(); await h.map();
  h.get('bundle-file').files = [file(Uint8Array.of(255))]; await h.get('bundle-file').fire('change');
  assert.equal(h.client.bundle, null); assert.equal(h.get('mapping-rows').children.length, 0);
  await h.get('load-bundle').fire('click'); assert.equal(h.client.bundle, null); assert.equal(h.get('stage-import').disabled, true);
});
test('oversized bundle and receipt files are refused before any file read', async () => {
  const h = await harness(); await h.select();
  for (const [id, button, maximum] of [['bundle-file','load-bundle',BUNDLE_LIMIT], ['receipt-file','restore-transfer',24 * 1024 * 1024]]) {
    h.get(id).files = [{ size: maximum + 1, arrayBuffer() { assert.fail('Oversized file read'); } }];
    await h.get(button).fire('click'); assert.equal(h.client.pending, null); assert.match(h.get('transfer-status').textContent, /byte limit/);
  }
});
test('a changing file length cannot be accepted as the previously selected bundle', async () => {
  const h = await harness(); await h.select();
  h.get('bundle-file').files = [{ size: h.f.input.length + 1, async arrayBuffer() { return h.f.input.slice().buffer; } }];
  await h.get('load-bundle').fire('click'); assert.equal(h.client.bundle, null); assert.match(h.get('transfer-status').textContent, /File size changed/);
});
test('cancel and replacement while a File read is outstanding cannot resurrect its bundle', async () => {
  for (const action of ['cancel','replace','disconnect']) {
    const h = await harness(); await h.select(); const d = deferred();
    h.get('bundle-file').files = [{ size: h.f.input.length, arrayBuffer() { return d.promise; } }];
    const loading = h.get('load-bundle').fire('click');
    if (action === 'cancel') await h.get('cancel-transfer-read').fire('click');
    else if (action === 'replace') { h.get('bundle-file').files = [file(h.f.input)]; await h.get('bundle-file').fire('change'); }
    else h.view.disconnect();
    d.resolve(h.f.input.slice().buffer); await loading; assert.equal(h.client.bundle, null); assert.equal(h.get('bundle-refs').textContent, '');
  }
});
test('corrupt or interrupted re-export cannot leave the prior download presented as new success', async () => {
  const h = await harness(); await h.select(); await h.get('export-bundle').fire('click');
  h.f.config.export = r => { r.headers['X-Fgit-Artifact-Sha256'] = '0'.repeat(64); };
  await h.get('export-bundle').fire('click'); assert.equal(h.get('download-bundle').disabled, true); assert.equal(h.get('export-info').textContent, '');
  await h.get('download-bundle').fire('click'); assert.equal(h.downloads.length, 0);
});
test('disconnect during export prevents late download activation and clears private file inputs', async () => {
  const h = await harness(); await h.select(); const d = deferred(); h.f.config.export = () => d.promise;
  const exporting = h.get('export-bundle').fire('click'); h.get('bundle-file').value = 'private.bundle'; h.get('receipt-file').value = 'private.json';
  h.view.disconnect(); d.resolve(); await exporting;
  assert.equal(h.get('download-bundle').disabled, true); assert.equal(h.get('bundle-file').value, ''); assert.equal(h.get('receipt-file').value, '');
  assert.match(h.get('transfer-status').textContent, /Disconnected/);
});
test('lost send retains original request and requires fresh confirmation for an identical retry', async () => {
  const h = await harness(); await h.prepare(); h.f.config.lose = true; h.get('confirm-transfer').checked = true;
  await h.get('send-transfer').fire('click'); const original = h.f.calls.at(-1), key = h.client.pending.key;
  assert.equal(h.get('confirm-transfer').checked, false); assert.equal(h.get('discard-transfer').disabled, true);
  assert.match(h.get('transfer-status').textContent, /Outcome unknown/); await h.get('send-transfer').fire('click'); assert.equal(h.f.calls.length, 2);
  h.f.config.lose = false; h.get('confirm-transfer').checked = true; await h.get('send-transfer').fire('click');
  assert.equal(h.f.calls.at(-1).headers['idempotency-key'], key); assert.deepEqual(h.f.calls.at(-1).body, original.body);
});
test('cancel-read during a submitted publication does not cancel or conceal its canonical settlement', async () => {
  const h = await harness(); await h.prepare(); const d = deferred(); h.f.config.terminal = () => d.promise;
  h.get('confirm-transfer').checked = true; const sending = h.get('send-transfer').fire('click');
  await h.get('cancel-transfer-read').fire('click'); assert.equal(h.f.calls.at(-1).signal.aborted, false); d.resolve(); await sending;
  assert.equal(h.client.pending, null); assert.match(h.get('transfer-status').textContent, /Canonical committed/);
});
test('canonical refusal is distinguished from uncertain or malformed transport replies', async () => {
  const h = await harness(); await h.prepare(); h.f.config.refuse = true; h.get('confirm-transfer').checked = true;
  await h.get('send-transfer').fire('click'); assert.equal(h.client.pending, null); assert.match(h.get('transfer-status').textContent, /Canonical refused/);
  await h.prepare(); h.f.config.refuse = false; h.f.config.terminal = r => { r.command_count++; }; h.get('confirm-transfer').checked = true;
  await h.get('send-transfer').fire('click'); assert.ok(h.client.pending); assert.match(h.get('transfer-status').textContent, /Outcome unknown/);
});
test('saved receipt survives page exit and restore never requires listing or resubmits automatically', async () => {
  const h = await harness(); await h.prepare(); const key = h.client.pending.key;
  await h.get('save-transfer').fire('click'); const receipt = h.downloads[0].bytes;
  assert.equal(receipt.includes(token), false); assert.equal(h.get('discard-transfer').disabled, true);
  await h.doc.events.fire('pagehide'); assert.equal(h.client.pending.key, key);
  const next = await harness(); next.get('receipt-file').files = [file(new TextEncoder().encode(receipt))];
  await next.get('restore-transfer').fire('click'); assert.equal(next.f.calls.length, 0); assert.equal(next.client.pending.key, key);
  assert.match(next.get('transfer-status').textContent, /No publication was dispatched/); assert.equal(next.get('confirm-transfer').checked, false);
});
test('outcome absence remains unresolved and terminal recovery clears the exact request', async () => {
  const h = await harness(); await h.prepare(); const key = h.client.pending.key;
  await h.get('recover-transfer').fire('click'); assert.equal(h.client.pending.key, key);
  assert.match(h.get('transfer-status').textContent, /Absence is not proof/); assert.equal(h.f.calls.at(-1).body, undefined);
  h.f.config.outcome = 'committed'; await h.get('recover-transfer').fire('click'); assert.equal(h.client.pending, null);
  assert.match(h.get('transfer-status').textContent, /Recovered canonical committed/);
});
test('invalid UTF-8 receipt cannot become an imported request', async () => {
  const h = await harness(); h.get('receipt-file').files = [file(Uint8Array.of(255))];
  await h.get('restore-transfer').fire('click'); assert.equal(h.client.pending, null); assert.equal(h.f.calls.length, 0);
});
test('pending scope and effects remain fixed when controls are edited after staging', async () => {
  const h = await harness(); await h.prepare(); const before = h.client.pending;
  for (const input of all(h.get('mapping-rows')).filter(n => n.tagName === 'input')) { input.value = 'changed'; await input.fire('input'); }
  assert.deepEqual(h.client.pending, before); assert.equal(h.get('stage-import').disabled, true);
});
test('beforeunload warns about loaded or pending responsibility, but not an empty session', async () => {
  const h = await harness(); let warnings = 0; const event = { preventDefault() { warnings++; } };
  await h.doc.events.fire('beforeunload', event); assert.equal(warnings, 0); await h.select(); await h.load();
  await h.doc.events.fire('beforeunload', event); assert.equal(warnings, 1);
  await h.get('stage-import').fire('click'); h.view.disconnect(); await h.doc.events.fire('beforeunload', event); assert.equal(warnings, 2);
});
test('current credential rejection clears target/bundle data and cannot fake an empty successful operation', async () => {
  const h = await harness(); await h.select(); await h.load(); h.f.fetchImpl = async () => json({}, 401);
  await h.get('export-bundle').fire('click'); assert.equal(h.client.connected, false); assert.equal(h.get('bundle-refs').textContent, '');
  assert.equal(h.get('download-bundle').disabled, true); assert.match(h.get('transfer-status').textContent, /Credential rejected/);
});
test('selected byte helper refuses cancellation before reading and checks complete returned bytes', async () => {
  await assert.rejects(selectedBytes({ size: 1, arrayBuffer() { assert.fail('Cancelled read'); } }, 10, () => false));
  await assert.rejects(selectedBytes({ size: 2, async arrayBuffer() { return new ArrayBuffer(1); } }, 10, () => true));
  assert.deepEqual(await selectedBytes(file(Uint8Array.of(0,255)), 2, () => true), Uint8Array.of(0,255));
});
test('HTML uses exact local modules and has every statically required control', () => {
  assert.ok(html.includes('src="./transfers-view.mjs"')); assert.ok(html.includes('href="../browser.css"'));
  assert.ok(!html.includes('<script>')); const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
  assert.equal(new Set(ids).size, ids.length); assert.ok(!html.includes('https://'));
  const h = dom(); mountTransfers(h, { client: new TransferClient({ href, cryptoImpl: crypto, fetchImpl: () => assert.fail('initial dispatch') }), events: h.events });
});
test('disconnect hides pending effect data without preventing receipt preservation', async () => {
  const h = await harness(); await h.prepare(); const before = h.client.pending;
  h.view.disconnect(); assert.deepEqual(h.client.pending, before);
  assert.ok(!h.get('pending-transfer').textContent.includes(before.fields.artifact_sha256));
  assert.ok(!h.get('pending-transfer').textContent.includes(before.updates[0].destination_hex));
  await h.get('save-transfer').fire('click'); assert.equal(JSON.parse(h.downloads[0].bytes).key, before.key);
});
test('static route asset closure contains every imported transfer module and retains parent guards', () => {
  const router = readFileSync(new URL(root + 'transfers.rs', import.meta.url), 'utf8');
  const assets = new Set([...router.matchAll(/include_str!\("([^"]+)"\)/g)].map(m => m[1]));
  for (const name of assets) {
    const source = readFileSync(new URL(root + name, import.meta.url), 'utf8');
    if (name.endsWith('.mjs')) for (const m of source.matchAll(/from '\.\/([^']+)'/g)) assert.ok(assets.has(m[1]), `${name} dependency ${m[1]}`);
  }
  const parent = readFileSync(new URL(root + '../browser.rs', import.meta.url), 'utf8');
  for (const previous of ['pulls','source_edit','initial','history','branches','search','transfers']) assert.ok(parent.includes(`if ${previous}::serve(`));
  assert.ok(router.includes('profile.allow_source')); assert.ok(router.includes('request.target.contains')); assert.ok(router.includes('request.expect_continue'));
});
