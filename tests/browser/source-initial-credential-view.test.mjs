// Production DOM handlers and controllers against synthetic HTTP peers. This
// exercises user-visible recovery, not browser rendering or native admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { InitialSourceClient } from '../../crates/fgit-node/src/smart_http/server/browser/initial.mjs';
import { mountSourceEditor } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-view.mjs';
import { mountInitialEditor } from '../../crates/fgit-node/src/smart_http/server/browser/initial-view.mjs';
import * as source from './source-edit-fixtures.mjs';
import * as initial from './initial-fixtures.mjs';

const ROTATED = '8'.repeat(64), OTHER = '6'.repeat(32);
const assets = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
class Element {
  children = []; listeners = new Map(); value = ''; disabled = false; checked = false; files = []; ownText = '';
  constructor(tag) { this.tagName = tag.toUpperCase(); }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent ?? String(child)).join(''); }
  addEventListener(kind, fn) { this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), fn]); }
  replaceChildren(...children) { this.children = children; this.ownText = ''; }
  append(...children) { this.children.push(...children); }
  // Synthetic dispatch deliberately bypasses disabled controls, just as script
  // can. Controller and handler checks must enforce the selected mode as well.
  async fire(kind = 'click', synthetic = false) {
    if (!synthetic && kind === 'click' && this.disabled) return;
    for (const listener of this.listeners.get(kind) ?? []) await listener({ preventDefault() {}, target: this });
  }
}
function documentFixture(kind, algorithm) {
  const html = readFileSync(new URL(kind === 'source' ? 'source-edit.html' : 'initial.html', assets), 'utf8');
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => [match[2], new Element(match[1])]));
  const defaults = { branch: 'refs/heads/main', format: algorithm, 'path-kind': 'utf8', 'file-mode': '100644', 'line-endings': 'lf',
    ...(kind === 'source' ? { 'change-kind': 'modify', 'content-mode': 'text' } : { 'input-kind': 'text' }) };
  for (const [id, value] of Object.entries(defaults)) nodes.get(id).value = value;
  return { html, nodes, getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
}
function uploaded(text) { const bytes = new TextEncoder().encode(text); return { size: bytes.length, async arrayBuffer() { return bytes.slice().buffer; } }; }
async function setup(kind, algorithm = 'sha1', retained = false) {
  const lib = kind === 'source' ? source : initial, f = await lib.fixture(algorithm);
  const Client = kind === 'source' ? SourceEditClient : InitialSourceClient;
  const make = () => new Client({ href: lib.href, cryptoImpl: lib.crypto, fetchImpl: f.fetchImpl });
  const original = make(); await original.connect(lib.token);
  if (kind === 'source') { await original.select(f.fields.ref, algorithm); await original.prepareEdits(f.edits, lib.metadata); }
  else await original.prepare(f.fields, f.files, lib.metadata);
  await original.stageApply(); const receipt = original.exportReceipt(); f.calls.length = 0;
  const client = retained ? original : make(), doc = documentFixture(kind, algorithm), el = id => doc.getElementById(id);
  const events = { callbacks: new Map(), addEventListener(name, fn) { this.callbacks.set(name, fn); } };
  let saved;
  const mount = kind === 'source' ? mountSourceEditor : mountInitialEditor;
  const app = mount(doc, { client, events, saveReceipt: value => { saved = value; } });
  return { kind, f, client, doc, el, app, receipt, events, saved: () => saved,
    receiptInput: kind === 'source' ? 'restore-file' : 'receipt',
    restore: kind === 'source' ? 'restore-receipt' : 'restore',
    save: kind === 'source' ? 'save-receipt' : 'save' };
}
async function connectRecovery(s, principal = source.actor) {
  s.el('recovery-only').checked = true; await s.el('recovery-only').fire('change');
  s.el('original-principal').value = principal; s.el('token').value = ROTATED;
  await s.el('connect').fire();
  assert.equal(s.client.recoveryOnly, true); assert.equal(s.client.connected, true);
  assert.equal(s.el('token').value, ''); assert.equal(s.el('original-principal').required, true);
  assert.match(s.el('connection-mode').textContent, /RECOVERY ONLY/);
}
async function restore(s) { s.el(s.receiptInput).files = [uploaded(s.receipt)]; await s.el(s.restore).fire(); assert(s.client.pending); }
function ordinaryButtons(kind) {
  return kind === 'source' ? ['select-base', 'load-file', 'queue-file', 'prepare-edits', 'prepare-patch', 'stage', 'send', 'discard', 'save-file']
    : ['queue', 'import-files', 'import-directory', 'prepare', 'stage', 'send', 'discard'];
}

for (const kind of ['source', 'initial']) {
  for (const algorithm of ['sha1', 'sha256']) test(`${kind} ${algorithm}: recovery form restores and settles without reopening ordinary work`, async () => {
    const s = await setup(kind, algorithm); await connectRecovery(s);
    assert.equal(s.f.calls.length, 0); assert.equal(s.el(s.restore).disabled, false);
    assert.equal(s.el(s.receiptInput).disabled, false);
    await restore(s); assert.equal(s.f.calls.length, 0);
    for (const name of ordinaryButtons(kind)) assert.equal(s.el(name).disabled, true, name);
    assert.equal(s.el('recover').disabled, false); assert.equal(s.el(s.save).disabled, false);
    await s.el(s.save).fire(); assert.deepEqual(JSON.parse(s.saved()), JSON.parse(s.receipt));
    assert(!s.saved().includes(ROTATED)); assert(!s.saved().includes(source.token));
    s.el('confirm-send').checked = true;
    for (const name of ordinaryButtons(kind)) await s.el(name).fire('click', true);
    assert.equal(s.f.calls.length, 0); assert.equal(s.el('confirm-send').checked, false);
    // Changing form selection is not an implicit connection-mode transition.
    s.el('recovery-only').checked = false; await s.el('recovery-only').fire('change');
    assert.equal(s.client.recoveryOnly, true); assert.equal(s.el('send').disabled, true);
    await s.el('recover').fire(); assert.equal(s.f.calls.length, 1);
    assert(s.client.pending); assert.match(s.el('status').textContent, /Absence does not prove non-commit/);
    s.f.config.outcome = 'committed'; await s.el('recover').fire();
    assert.equal(s.client.pending, null); assert.equal(s.client.recoveryOnly, true);
    assert.match(s.el('status').textContent, /Recovered canonical committed.*Recovery-only mode remains active/);
    assert.equal(s.el('branch').disabled, true); assert.equal(s.app.queued.length, 0);
    for (const name of ordinaryButtons(kind)) await s.el(name).fire('click', true);
    assert.equal(s.f.calls.length, 2);
    for (const call of s.f.calls) {
      assert.equal(call.endpoint, 'outcomes'); assert.equal(call.body, undefined);
      assert.equal(call.headers.authorization, `Bearer ${ROTATED}`);
      assert.equal(call.headers['idempotency-key'], JSON.parse(s.receipt).key);
    }
    s.el('token').value = ROTATED; await s.el('connect').fire();
    assert.equal(s.client.recoveryOnly, false); assert.equal(s.el('branch').disabled, false);
    assert.match(s.el('connection-mode').textContent, /Ordinary connection/);
    assert.equal(s.f.calls.length, 2);
  });

  test(`${kind}: retained requests use the selected principal and preserve their original receipt`, async () => {
    const s = await setup(kind, 'sha1', true), key = s.client.pending.key;
    await connectRecovery(s); assert.equal(s.client.pending.key, key);
    assert.equal(s.el(s.restore).disabled, true);
    await s.el(s.save).fire(); assert.equal(s.saved(), s.receipt);
    s.f.config.outcome = 'refused'; await s.el('recover').fire();
    assert.match(s.el('status').textContent, /Recovered canonical refused/);
    assert.equal(s.client.pending, null); assert.equal(s.client.recoveryOnly, true);
    assert.equal(s.f.calls.length, 1); assert.equal(s.f.calls[0].endpoint, 'outcomes');
  });

  test(`${kind}: wrong-principal response stays unresolved and cannot enable send`, async () => {
    const s = await setup(kind); await connectRecovery(s, OTHER); await restore(s);
    s.f.config.outcome = 'committed'; await s.el('recover').fire();
    assert(s.client.pending); assert.equal(s.client.pending.observedPrincipal, null);
    assert.match(s.el('status').textContent, /principal/);
    assert.equal(s.el('send').disabled, true); assert.equal(s.client.exportReceipt(), s.receipt);
    assert.equal(s.f.calls.length, 1);
  });

  test(`${kind}: synthetic authoring events cannot read uploaded files in recovery-only mode`, async () => {
    const s = await setup(kind); await connectRecovery(s); let reads = 0;
    const file = { name: 'safe.txt', webkitRelativePath: 'project/safe.txt', size: 1,
      async arrayBuffer() { reads++; return new Uint8Array([65]).buffer; } };
    const files = kind === 'source' ? ['replacement', 'patch'] : ['file', 'batch-files', 'directory-files'];
    for (const id of files) { s.el(id).files = [file]; await s.el(id).fire('change', true); }
    for (const name of ordinaryButtons(kind)) await s.el(name).fire('click', true);
    assert.equal(reads, 0); assert.equal(s.f.calls.length, 0); assert.equal(s.app.queued.length, 0);
    assert.equal(s.client.pending, null); assert.equal(s.client.recoveryOnly, true);
  });

  test(`${kind}: disconnect during receipt reading cannot populate a later connection`, async () => {
    const s = await setup(kind); await connectRecovery(s); let release;
    const bytes = new TextEncoder().encode(s.receipt);
    s.el(s.receiptInput).files = [{ size: bytes.length, arrayBuffer() { return new Promise(resolve => { release = resolve; }); } }];
    const reading = s.el(s.restore).fire();
    while (!release) await new Promise(resolve => setImmediate(resolve));
    await s.el('disconnect').fire(); release(bytes.buffer); await reading;
    assert.equal(s.client.connected, false); assert.equal(s.client.pending, null);
    assert.equal(s.el('token').value, ''); assert.equal(s.f.calls.length, 0);
    assert.match(s.el('status').textContent, /changed|cancelled/i);
  });

  test(`${kind}: invalid recovery selection cannot silently choose an ordinary connection`, async () => {
    const s = await setup(kind, 'sha1', true), key = s.client.pending.key;
    s.el('recovery-only').checked = true; s.el('original-principal').value = '';
    s.el('token').value = ROTATED; await s.el('connect').fire();
    assert.equal(s.client.connected, false); assert.equal(s.client.pending.key, key);
    assert.match(s.el('status').textContent, /principal/); assert.equal(s.f.calls.length, 0);
    assert.equal(s.el('send').disabled, true); assert.equal(s.el(s.save).disabled, false);
  });
}
