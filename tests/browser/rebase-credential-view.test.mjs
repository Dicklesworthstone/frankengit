// HTML-derived DOM contract tests of the actual client, not a real browser or node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { RebaseClient, RECEIPT_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/rebase.mjs';
import { mountRebase } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-view.mjs';
import { utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, token, actor, href, crypto } from './rebase-session-fixtures.mjs';
const base = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const html = readFileSync(new URL('rebase.html', base), 'utf8'), replacement = '8'.repeat(64);
class Element {
  children = []; listeners = new Map(); ownText = ''; disabled = false; checked = false; files = []; hidden = false; type = ''; _value = '';
  constructor(tag) { this.tagName = tag.toUpperCase(); }
  set value(value) { this._value = String(value); if (this.type === 'file' && value === '') this.files = []; }
  get value() { return this._value; }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(c => c.textContent ?? String(c)).join(''); }
  set innerHTML(_) { throw new Error('Repository data must not become markup'); }
  addEventListener(kind, fn) { this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), fn]); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this.ownText = ''; }
  async fire(kind = 'click') {
    if (kind === 'click' && this.disabled) return;
    for (const fn of this.listeners.get(kind) ?? []) await fn({ target: this, preventDefault() {} });
  }
  click() { return this.fire(); }
}
function documentFixture() {
  const nodes = new Map();
  for (const m of html.matchAll(/<(\w+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
    assert(!nodes.has(m[3]), `Duplicate HTML control ${m[3]}`);
    const el = new Element(m[1]), attr = m[2];
    el.type = /\btype="([^"]*)"/.exec(attr)?.[1] ?? '';
    el.value = /\bvalue="([^"]*)"/.exec(attr)?.[1] ?? '';
    el.disabled = /\bdisabled\b/.test(attr); el.checked = /\bchecked\b/.test(attr);
    if (m[1] === 'select') {
      const inner = html.slice(m.index + m[0].length).split('</select>')[0];
      el.value = /<option[^>]*value="([^"]*)"/.exec(inner)?.[1] ?? '';
    }
    nodes.set(m[3], el);
  }
  return { nodes, getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
}
const upload = value => { const bytes = utf8.encode(value); return { size: bytes.length, arrayBuffer: async () => bytes.slice().buffer }; };
async function setup(algorithm = 'sha1') {
  const f = await fixture(algorithm), doc = documentFixture(), control = { change: null };
  const fetchImpl = async (url, options) => {
    const response = await f.fetchImpl(url, options);
    if (!String(url).endsWith('/outcomes') || !control.change) return response;
    const value = await response.json(); control.change(value);
    return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
  };
  const client = new RebaseClient({ href, cryptoImpl: crypto, fetchImpl });
  const events = { callbacks: new Map(), addEventListener(k, fn) { this.callbacks.set(k, fn); } };
  const receipts = [], drafts = [], el = id => doc.nodes.get(id);
  const app = mountRebase(doc, { client, events, saveReceipt: value => receipts.push(value), saveDraft: value => drafts.push(value) });
  el('format').value = algorithm;
  for (const key of ['upstream', 'committer', 'timestamp']) el(key).value = String(f.input[key]);
  return { f, doc, el, app, client, events, receipts, drafts, control };
}
async function ordinary(s, credential = token) {
  if (s.el('recovery-only').checked) { s.el('recovery-only').checked = false; await s.el('recovery-only').fire('change'); }
  s.el('token').value = credential; await s.el('connect').fire();
}
async function stage(s) {
  await ordinary(s); await s.el('select').fire(); await s.el('prepare').fire(); await s.el('stage').fire();
  assert(s.client.pending);
}
async function recoverOnly(s, expected = actor) {
  s.el('recovery-only').checked = true; await s.el('recovery-only').fire('change');
  s.el('recovery-principal').value = expected; await s.el('recovery-principal').fire('input');
  s.el('token').value = replacement; await s.el('connect').fire();
}
const forbidden = ['source', 'onto', 'format', 'select', 'prepare', 'stage', 'resolve', 'continue-empty', 'send',
  'confirm-send', 'discard', 'save-draft', 'include-choices', 'draft-file', 'load-draft', 'resume-draft'];
function assertReadOnly(s) {
  assert(s.client.recoveryOnly);
  for (const id of forbidden) assert(s.el(id).disabled, `${id} must remain disabled`);
  assert.equal(s.el('confirm-send').checked, false);
  assert.match(s.el('connection-status').textContent, /Recovery only/);
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: ordinary controls still prepare, inspect and separately confirm the original write`, async () => {
    const s = await setup(algorithm); assert.equal(s.el('recovery-only').checked, false);
    assert(s.el('recovery-principal').disabled); await stage(s); const n = s.f.calls.length;
    assert.equal(s.el('token').value, ''); assert(s.client.candidate); assert(!s.client.recoveryOnly);
    assert.match(s.el('connection-status').textContent, /Ordinary/);
    await s.el('send').fire(); assert.equal(s.f.calls.length, n); assert.match(s.el('status').textContent, /Confirm/);
    s.el('confirm-send').checked = true; await s.el('send').fire(); assert.equal(s.client.pending, null);
    assert.equal(s.f.calls.at(-1).endpoint, 'source/rebase/apply');
  });
  test(`${algorithm}: a lost reply can be recovered after explicit replacement without another send`, async () => {
    const s = await setup(algorithm); await stage(s); s.f.config.lose = true;
    s.el('confirm-send').checked = true; await s.el('send').fire(); const pending = s.client.pending, n = s.f.calls.length;
    assert.match(s.el('status').textContent, /Outcome unknown/);
    await recoverOnly(s); assertReadOnly(s); assert.equal(s.f.calls.length, n);
    assert.equal(s.client.pending.key, pending.key); assert.equal(s.client.pending.requestSha256, pending.requestSha256);
    assert.equal(s.el('inspection').textContent, ''); assert.equal(s.el('token').value, '');
    assert(!s.el('recover').disabled); assert(!s.el('save-receipt').disabled);
    s.f.config.outcome = 'committed'; await s.el('recover').fire();
    assert.equal(s.client.pending, null); assertReadOnly(s); assert.match(s.el('status').textContent, /Recovered canonical committed/);
    assert.equal(s.f.calls.length, n + 1); assert.equal(s.f.calls.at(-1).options.body, undefined);
    assert.equal(s.f.calls.at(-1).options.headers['Idempotency-Key'], pending.key);
    await ordinary(s, replacement); assert(!s.client.recoveryOnly); assert(!s.el('select').disabled);
  });
  test(`${algorithm}: loading the original receipt locally does not load a draft or send any request`, async () => {
    const original = await setup(algorithm); await stage(original); const receipt = original.client.exportReceipt();
    const s = await setup(algorithm); await recoverOnly(s); assertReadOnly(s);
    s.el('restore-file').files = [upload(receipt)]; await s.el('restore').fire();
    assert.equal(s.f.calls.length, 0); assert.equal(s.client.pending.key, original.client.pending.key);
    assert.match(s.el('status').textContent, /read-only recovery/); assertReadOnly(s);
    await s.el('save-receipt').fire(); assert.equal(s.receipts.at(-1), receipt);
    assert(!s.receipts.at(-1).includes(token)); assert(!s.receipts.at(-1).includes(replacement));
  });
}
for (const state of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) {
  test(`recovery ${state} never interprets absence as permission to retry`, async () => {
    const s = await setup(); await stage(s); await recoverOnly(s); const key = s.client.pending.key;
    s.f.config.outcome = state; await s.el('recover').fire();
    assertReadOnly(s); assert.equal(s.client.pending === null, ['committed', 'refused'].includes(state));
    assert.equal(s.f.calls.at(-1).options.body, undefined);
    assert.equal(s.f.calls.at(-1).options.headers['Idempotency-Key'], key);
    if (s.client.pending) assert.match(s.el('status').textContent, /Absence does not prove non-commit/);
  });
}
for (const expected of ['', 'a', 'A'.repeat(32), '9'.repeat(33), '<script>']) test(`invalid original principal refuses without a request (${expected})`, async () => {
  const s = await setup(); await stage(s); const p = s.client.pending, n = s.f.calls.length;
  await recoverOnly(s, expected); assert(!s.client.connected); assert.match(s.el('status').textContent, /principal/);
  assert.deepEqual(s.client.pending, p); assert.equal(s.f.calls.length, n); assert.equal(s.el('token').value, '');
});
for (const state of ['key_not_observed', 'committed']) test(`wrong authenticated principal cannot settle ${state} through the controls`, async () => {
  const s = await setup(); await stage(s); await recoverOnly(s); const p = s.client.pending;
  s.f.config.outcome = state; s.control.change = r => { r.principal_id = 'a'.repeat(32); };
  await s.el('recover').fire(); assert.deepEqual(s.client.pending, p);
  assert.match(s.el('status').textContent, /original principal/); assertReadOnly(s);
  s.control.change = null; await s.el('recover').fire(); assert.equal(s.client.pending === null, state === 'committed');
});
test('changing intent disconnects instead of promoting the replacement token into a writer', async () => {
  const s = await setup(); await stage(s); await recoverOnly(s); const p = s.client.pending, n = s.f.calls.length;
  s.el('confirm-send').checked = true; s.el('recovery-only').checked = false; await s.el('recovery-only').fire('change');
  assert(!s.client.connected); assert(s.el('send').disabled); assert.equal(s.el('confirm-send').checked, false);
  assert.deepEqual(s.client.pending, p); assert.equal(s.f.calls.length, n);
  await ordinary(s, replacement); assert(!s.client.connected); assert.match(s.el('status').textContent, /credential/);
  await ordinary(s); assert(s.client.connected); assert(!s.client.recoveryOnly); assert(!s.el('send').disabled);
  await s.el('send').fire(); assert.equal(s.f.calls.length, n); // renewed confirmation mandatory
});
test('changing the recovery target during a lookup cannot authenticate a late terminal reply', async () => {
  const s = await setup(); await stage(s); await recoverOnly(s); const p = s.client.pending;
  let release, entered; const reached = new Promise(r => { entered = r; });
  s.f.config.outcome = 'committed'; s.f.config.wait = endpoint => endpoint === 'outcomes' ? new Promise(r => { release = r; entered(); }) : undefined;
  const work = s.el('recover').fire(); await reached;
  s.el('recovery-principal').value = 'a'.repeat(32); await s.el('recovery-principal').fire('input');
  release(); await work;
  assert(!s.client.connected); assert.deepEqual(s.client.pending, p);
  assert.match(s.el('status').textContent, /Disconnected/); assert(s.el('send').disabled);
});
test('page exit clears recovery controls but leaves the exact original request exportable', async () => {
  const s = await setup(); await stage(s); await recoverOnly(s); const key = s.client.pending.key;
  s.el('restore-file').files = [upload('{}')]; s.el('draft-file').files = [upload('{}')];
  s.events.callbacks.get('pagehide')(); assert(!s.client.connected); assert.equal(s.client.recoveryPrincipal, null);
  assert.equal(s.el('recovery-principal').value, ''); assert.equal(s.el('token').value, '');
  assert.equal(s.el('restore-file').files.length, 0); assert.equal(s.el('draft-file').files.length, 0);
  const event = { warned: false, preventDefault() { this.warned = true; } }; s.events.callbacks.get('beforeunload')(event); assert(event.warned);
  assert(!s.el('save-receipt').disabled); await s.el('save-receipt').fire(); assert.equal(JSON.parse(s.receipts.at(-1)).key, key);
});
test('altering disabled send controls cannot bypass the client recovery-only guard', async () => {
  const s = await setup(); await stage(s); await recoverOnly(s); const p = s.client.pending, n = s.f.calls.length;
  s.el('confirm-send').checked = true; s.el('send').disabled = false; await s.el('send').fire();
  assert.deepEqual(s.client.pending, p); assert.equal(s.f.calls.length, n); assertReadOnly(s);
});
test('known original principal cannot be rebound when reconnecting through the interface', async () => {
  const s = await setup(); await stage(s); s.f.config.outcome = 'undecided'; await s.el('recover').fire();
  const p = s.client.pending; await recoverOnly(s, 'a'.repeat(32)); assert(!s.client.connected);
  assert.match(s.el('status').textContent, /original authenticated observation/); assert.deepEqual(s.client.pending, p);
});
for (const cause of ['disconnect', 'file replacement']) test(`receipt read cancelled by ${cause} cannot install an old request`, async () => {
  const original = await setup(); await stage(original); const receipt = original.client.exportReceipt(), bytes = utf8.encode(receipt);
  const s = await setup(); await recoverOnly(s); let release;
  s.el('restore-file').files = [{ size: bytes.length, arrayBuffer: () => new Promise(r => { release = r; }) }];
  const work = s.el('restore').fire(); assert(release);
  if (cause === 'disconnect') await s.el('disconnect').fire();
  else { s.el('restore-file').files = [upload('{}')]; await s.el('restore-file').fire('change'); }
  release(bytes.buffer); await work; assert.equal(s.client.pending, null); assert.equal(s.f.calls.length, 0);
});
test('oversized receipt is refused before File.arrayBuffer and cannot replace the connection mode', async () => {
  const s = await setup(); await recoverOnly(s); let reads = 0;
  s.el('restore-file').files = [{ size: RECEIPT_BYTES + 1, arrayBuffer() { reads++; throw new Error('must not read'); } }];
  await s.el('restore').fire(); assert.equal(reads, 0); assert.equal(s.client.pending, null); assert.equal(s.f.calls.length, 0);
  assertReadOnly(s); assert.match(s.el('status').textContent, /byte limit/);
});
test('corrupted receipt retains its integrity checks with a replacement credential', async () => {
  const original = await setup(); await stage(original); const r = JSON.parse(original.client.exportReceipt()); r.fields.ref = 'refs/heads/substitute';
  const s = await setup(); await recoverOnly(s); s.el('restore-file').files = [upload(JSON.stringify(r))]; await s.el('restore').fire();
  assert.equal(s.client.pending, null); assert.equal(s.f.calls.length, 0); assertReadOnly(s); assert.match(s.el('status').textContent, /original request key/);
});
test('ordinary unsent draft controls still save, load and revalidate without a publication', async () => {
  const s = await setup(); await ordinary(s); await s.el('select').fire(); await s.el('prepare').fire(); await s.el('save-draft').fire();
  assert(s.drafts.length); const n = s.f.calls.length;
  s.el('draft-file').files = [upload(s.drafts[0])]; await s.el('load-draft').fire();
  assert.equal(s.f.calls.length, n); assert(s.client.state.resumeRequired); assert.equal(s.client.candidate, null);
  await s.el('resume-draft').fire(); assert(s.client.candidate); assert(!s.client.state.resumeRequired);
  assert.equal(s.client.pending, null); assert(!s.f.calls.some(c => c.endpoint.endsWith('/apply')));
});
test('recovery inputs are explicit inert controls with no persistence, inline execution or default identity', () => {
  const s = documentFixture(); assert.equal(s.nodes.get('recovery-only').checked, false); assert.equal(s.nodes.get('recovery-principal').value, '');
  assert(html.includes('outcomes-read')); assert(!html.includes('<script>')); assert(!html.includes('onclick='));
  for (const name of ['rebase-view.mjs', 'rebase.mjs']) {
    const source = readFileSync(new URL(name, base), 'utf8');
    for (const forbidden of ['innerHTML', 'localStorage', 'sessionStorage', 'document.write']) assert(!source.includes(forbidden));
  }
});
