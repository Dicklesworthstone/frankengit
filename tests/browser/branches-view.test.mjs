import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { BranchClient, expectedUpdates, RECEIPT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/branches.mjs';
import { mountBranches, readReceipt } from '../../crates/fgit-node/src/smart_http/server/browser/branches-view.mjs';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/branches.html', import.meta.url), 'utf8');
const token = 'a'.repeat(64), href = 'https://example.invalid/repo.git/ui/branches/';
const row = (name, b = 'a') => ({ ref: name, ref_hex: hex(utf8.encode(name)), object_id: `sha1:${b.repeat(40)}` });
const scope = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: 'sha1' };
const page = () => ({ ...scope, type: 'source_refs', namespace: 'branches', cursor_encoding: 'hex', source_head: 'head-id', snapshot_token: `alg:1:${'a'.repeat(64)}`,
  after: null, limit: 50, next_after: null, read_only: true, transaction_created: false, published: false, direct_refs_only: true,
  refs: [row('refs/heads/main'), row('refs/heads/topic', 'b')] });
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
function publication(p) { return { ...scope, type: 'branch_publication', principal_id: '4'.repeat(32), operation: p.operation, atomic: true, terminal: true,
  forge_transition: false, tx_id: 'tx-id', decision_sequence: 1, outcome: 'committed', repository_commit_id: 'rcr-id', updates: expectedUpdates(p.operation, p.fields) }; }
class Element {
  children = []; listeners = new Map(); value = ''; checked = false; files = []; disabled = false; ownText = '';
  constructor(tag) { this.tagName = tag.toUpperCase(); }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent ?? String(child)).join(''); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; this.ownText = ''; }
  addEventListener(kind, fn) { this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), fn]); }
  async fire(kind = 'click') {
    if (kind === 'click' && this.disabled) return;
    for (const fn of this.listeners.get(kind) ?? []) await fn({ preventDefault() {}, target: this });
  }
}
function fixture() {
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(m => [m[2], new Element(m[1])]));
  for (const [id, value] of Object.entries({ format: 'sha1', namespace: 'branches', 'page-size': '50', operation: 'create' })) nodes.get(id).value = value;
  const doc = { getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
  const calls = [], responses = []; let saved;
  const client = new BranchClient({ href, cryptoImpl: webcrypto, fetchImpl: async (url, options) => {
    calls.push({ url: url.href, ...options }); const reply = responses.shift();
    if (reply instanceof Error) throw reply; if (typeof reply === 'function') return reply();
    return reply ?? json(page());
  } });
  const events = { callbacks: new Map(), addEventListener(name, fn) { this.callbacks.set(name, fn); } };
  const app = mountBranches(doc, { client, events, saveReceipt: receipt => { saved = receipt; } });
  return { app, client, calls, responses, events, doc, el: id => nodes.get(id), saved: () => saved };
}
async function ready() {
  const s = fixture(); s.el('token').value = token; await s.el('connect').fire(); await s.el('load').fire();
  s.el('selected').value = 'refs/heads/topic'; s.el('target').value = 'refs/heads/main'; s.el('destination').value = 'refs/heads/new'; s.app.render(); return s;
}
for (const operation of ['create', 'update', 'delete', 'rename']) test(`UI ${operation} shows exact effects and requires separate confirmation`, async () => {
  const s = await ready(); s.el('operation').value = operation; await s.el('prepare').fire();
  assert.ok(s.client.pending); assert.equal(s.calls.length, 1); assert.equal(s.el('token').value, '');
  assert.ok(s.el('pending').textContent.includes(s.client.pending.key));
  if (operation === 'rename') { assert.ok(s.el('pending').textContent.includes('"expected_commit": null')); assert.equal(expectedUpdates(operation, s.client.pending.fields).length, 2); }
  await s.el('send').fire(); assert.equal(s.calls.length, 1); assert.match(s.el('status').textContent, /Confirm/);
  s.responses.push(json(publication(s.client.pending))); s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.equal(s.calls.length, 2); assert.equal(s.client.pending, null); assert.equal(s.client.page, null);
  assert.match(s.el('status').textContent, /Canonical committed/); assert.equal(s.el('confirm-send').checked, false);
});
test('pending requests lock selection/replacement but permit original-key recovery and export', async () => {
  const s = await ready(); await s.el('prepare').fire(); const key = s.client.pending.key;
  for (const id of ['selected','target','destination','operation','format','load','more','prepare','restore']) assert.equal(s.el(id).disabled, true);
  await s.el('save').fire(); assert.ok(s.saved()); assert.ok(!s.saved().includes(token)); assert.equal(s.el('discard').disabled, true);
  await s.el('disconnect').fire(); assert.equal(s.client.pending.key, key); assert.equal(s.el('refs').textContent, ''); assert.equal(s.el('destination').value, '');
  assert.equal(s.el('send').disabled, true); s.el('token').value = token; await s.el('connect').fire(); assert.equal(s.client.pending.key, key);
});
test('unknown send retains exact original key and requires confirmation again to retry', async () => {
  const s = await ready(); await s.el('prepare').fire(); const p = s.client.pending;
  s.responses.push(new Error('lost response')); s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.match(s.el('status').textContent, /Outcome unknown/); assert.equal(s.client.pending.key, p.key);
  await s.el('send').fire(); assert.equal(s.calls.length, 2);
  s.responses.push(json(publication(p))); s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.equal(s.calls[1].body, s.calls[2].body); assert.equal(s.calls[1].headers['Idempotency-Key'], s.calls[2].headers['Idempotency-Key']);
});
test('next page retains applied namespace and cursor even when controls change', async () => {
  const s = fixture(); s.el('token').value = token; await s.el('connect').fire(); s.el('page-size').value = '1';
  s.responses.push(json({ ...page(), limit: 1, refs: [row('refs/heads/main')], next_after: hex(utf8.encode('refs/heads/main')) })); await s.el('load').fire();
  s.el('namespace').value = 'tags'; s.el('page-size').value = '100';
  s.responses.push(json({ ...page(), limit: 1, after: hex(utf8.encode('refs/heads/main')), refs: [row('refs/heads/topic')] })); await s.el('more').fire();
  const body = new URLSearchParams(s.calls.at(-1).body); assert.equal(body.get('namespace'), 'branches'); assert.equal(body.get('limit'), '1'); assert.ok(body.get('expected_head'));
  assert.match(s.el('page-state').textContent, /2 retained/); assert.equal(s.el('more').disabled, true);
});
test('failed pagination keeps old snapshot without silently falling back to current state', async () => {
  const s = await ready(); s.el('page-size').value = '1';
  s.responses.push(json({ ...page(), limit: 1, refs: [row('refs/heads/main')], next_after: hex(utf8.encode('refs/heads/main')) })); await s.el('load').fire();
  s.responses.push(json({ code: 'snapshot_moved' }, 409)); await s.el('more').fire();
  assert.equal(s.client.page.next_after, hex(utf8.encode('refs/heads/main'))); assert.match(s.el('status').textContent, /snapshot changed/); assert.equal(s.calls.length, 3);
});
test('hostile ref text, directional controls and byte-only names are inert and visibly byte-bound', async () => {
  const s = await ready();
  const hostile = row('refs/heads/<script>'), bidi = row('refs/heads/a\u202eb');
  const raw = { ref: null, ref_hex: hex(utf8.encode('refs/heads/z')) + 'ff', object_id: 'a'.repeat(40) };
  s.responses.push(json({ ...page(), refs: [hostile, bidi, raw] })); await s.el('load').fire();
  const shown = s.el('refs').textContent;
  assert.ok(shown.includes('<script>')); assert.ok(shown.includes('\\u202e')); assert.ok(shown.includes(raw.ref_hex));
  assert.ok(!s.el('selected').children.some(n => n.value === null)); assert.equal(s.el('refs').children.every(n => n.tagName === 'LI'), true);
});
test('successful empty namespace is explicit, not a fake branch or default selection', async () => {
  const s = await ready(); s.responses.push(json({ ...page(), refs: [] })); await s.el('load').fire();
  assert.equal(s.el('selected').value, ''); assert.equal(s.el('prepare').disabled, true); assert.match(s.el('page-state').textContent, /0 refs/);
});
test('disconnect during a late listing cannot restore repository data or stale status', async () => {
  const s = await ready(); let release; s.responses.push(() => new Promise(resolve => { release = resolve; }));
  const running = s.el('load').fire(); await Promise.resolve(); await s.el('disconnect').fire(); release(json(page())); await running;
  assert.equal(s.client.page, null); assert.equal(s.el('refs').textContent, ''); assert.match(s.el('status').textContent, /Disconnected/);
});
test('restore reads a bounded receipt without listing or automatically sending', async () => {
  const a = await ready(); await a.el('prepare').fire(); await a.el('save').fire(); const receipt = a.saved();
  const s = fixture(); s.el('token').value = token; await s.el('connect').fire();
  s.el('receipt-file').files = [new Blob([receipt])]; await s.el('restore').fire();
  assert.equal(s.calls.length, 0); assert.equal(s.client.pending.key, a.client.pending.key); assert.equal(s.el('confirm-send').checked, false);
  assert.equal(s.el('discard').disabled, true); assert.match(s.el('status').textContent, /without sending/);
});
test('oversized receipt is refused before file I/O', async () => {
  let reads = 0;
  await assert.rejects(readReceipt({ size: RECEIPT_LIMIT + 1, arrayBuffer() { reads += 1; } })); assert.equal(reads, 0);
  for (const size of [0, -1, NaN, 1.5]) await assert.rejects(readReceipt({ size, arrayBuffer() { reads += 1; } })); assert.equal(reads, 0);
});
test('changed selection, truncated bytes and invalid UTF-8 cannot become a restored request', async () => {
  let current = true;
  await assert.rejects(readReceipt({ size: 1, async arrayBuffer() { current = false; return new ArrayBuffer(1); } }, () => current));
  await assert.rejects(readReceipt({ size: 2, async arrayBuffer() { return new ArrayBuffer(1); } }));
  await assert.rejects(readReceipt(new Blob([new Uint8Array([255])])));
});
test('receipt selected before disconnect never returns as a new pending request', async () => {
  const a = await ready(); await a.el('prepare').fire(); const receipt = utf8.encode(a.client.exportReceipt());
  const s = await ready(); let release;
  s.el('receipt-file').files = [{ size: receipt.length, arrayBuffer: () => new Promise(resolve => { release = resolve; }) }];
  const restoring = s.el('restore').fire(); await Promise.resolve(); await s.el('disconnect').fire(); release(receipt.buffer); await restoring;
  assert.equal(s.client.pending, null); assert.match(s.el('status').textContent, /Disconnected/);
});
test('leaving warns about original responsibility and clears token/views on page exit', async () => {
  const s = await ready(); let warned = false;
  s.events.callbacks.get('beforeunload')({ preventDefault() { warned = true; } }); assert.equal(warned, false);
  await s.el('prepare').fire(); const key = s.client.pending.key;
  s.events.callbacks.get('beforeunload')({ preventDefault() { warned = true; } }); assert.equal(warned, true);
  s.events.callbacks.get('pagehide')(); assert.equal(s.client.connected, false); assert.equal(s.client.pending.key, key); assert.equal(s.el('refs').textContent, '');
});
test('script and shell do not inject executable repository content or persist tokens', () => {
  assert.ok(!html.includes('<script>'));
  const script = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/branches-view.mjs', import.meta.url), 'utf8');
  for (const forbidden of ['innerHTML', 'localStorage', 'sessionStorage', 'document.write']) assert.ok(!script.includes(forbidden));
});

async function stage(s, operation, selected = 'refs/heads/topic', target = 'refs/heads/main', destination = 'refs/heads/new') {
  s.el('operation').value = operation; s.el('selected').value = selected; s.el('target').value = target; s.el('destination').value = destination;
  await s.el('operation').fire('change'); await s.el('batch-add').fire();
}
test('UI stages a mixed batch, reviews every exact effect and sends one confirmed atomic request', async () => {
  const s = await ready(); await stage(s, 'create'); await stage(s, 'update'); await stage(s, 'delete', 'refs/heads/main');
  assert.equal(s.calls.length, 1); assert.equal(s.client.stagedChanges.length, 3); assert.equal(s.client.pending, null);
  assert.match(s.el('batch-state').textContent, /3 of 32/); assert.equal(s.el('batch-changes').children.length, 3);
  assert.equal(s.el('prepare').disabled, true); assert.equal(s.el('batch-prepare').disabled, false);
  assert.ok(s.el('batch-changes').textContent.includes('"expected_commit": null')); assert.ok(s.el('batch-changes').textContent.includes('"new_commit": null'));
  const frozen = structuredClone(s.client.stagedChanges); s.el('selected').value = 'refs/heads/topic'; s.el('destination').value = 'refs/heads/changed-after-staging';
  await s.el('batch-prepare').fire(); const pending = s.client.pending;
  assert.equal(pending.operation, 'transaction'); assert.deepEqual(pending.fields.changes, frozen); assert.deepEqual(s.client.stagedChanges, []);
  assert.equal(s.el('batch-add').disabled, true); assert.equal(s.el('batch-clear').disabled, true); assert.equal(s.el('batch-prepare').disabled, true);
  assert.equal(s.el('confirm-send').checked, false); await s.el('send').fire(); assert.equal(s.calls.length, 1);
  s.responses.push(json(publication(pending))); s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.equal(s.calls.length, 2); assert.match(s.calls[1].url, /\/source\/branches\/transaction$/);
  assert.equal(new URLSearchParams(s.calls[1].body).getAll('create').length, 1); assert.equal(s.client.pending, null);
  assert.match(s.el('status').textContent, /Canonical committed/); assert.equal(s.el('refs').textContent, '');
});

test('UI duplicate staging is refused without losing prior effects and supports individual removal', async () => {
  const s = await ready(); await stage(s, 'create'); await stage(s, 'delete'); await stage(s, 'update');
  assert.match(s.el('status').textContent, /only once/); assert.equal(s.client.stagedChanges.length, 2);
  const first = s.el('batch-changes').children[0]; await first.children.at(-1).fire();
  assert.equal(s.client.stagedChanges.length, 1); assert.equal(s.client.stagedChanges[0].operation, 'delete');
  assert.match(s.el('batch-state').textContent, /1 of 32/); assert.equal(s.calls.length, 1);
  await s.el('batch-clear').fire(); assert.deepEqual(s.client.stagedChanges, []); assert.equal(s.el('batch-prepare').disabled, true);
  assert.equal(s.el('prepare').disabled, false); assert.match(s.el('status').textContent, /No request was sent/);
});

test('rename remains a single native action and cannot enter a staged batch', async () => {
  const s = await ready(); s.el('operation').value = 'rename'; await s.el('operation').fire('change');
  assert.equal(s.el('batch-add').disabled, true); assert.equal(s.el('prepare').disabled, false);
  await s.el('batch-add').fire(); assert.deepEqual(s.client.stagedChanges, []);
  await s.el('prepare').fire(); assert.equal(s.client.pending.operation, 'rename'); assert.equal(s.calls.length, 1);
});

test('byte-only branch selections use exact hex in batches and cannot enter text-only actions', async () => {
  const s = await ready(), raw = { ref: null, ref_hex: hex(utf8.encode('refs/heads/x')) + 'ff', object_id: `sha1:${'c'.repeat(40)}` };
  s.responses.push(json({ ...page(), refs: [...page().refs, raw] })); await s.el('load').fire();
  s.el('selected').value = `hex:${raw.ref_hex}`; s.el('operation').value = 'delete'; await s.el('operation').fire('change');
  assert.match(s.el('selection').textContent, /byte-only name/); assert.ok(s.el('selection').textContent.includes(raw.ref_hex));
  assert.equal(s.el('prepare').disabled, true); assert.equal(s.el('batch-add').disabled, false);
  await s.el('batch-add').fire(); assert.equal(s.client.stagedChanges[0].ref_hex, raw.ref_hex);
  assert.match(s.el('batch-changes').textContent, /"ref": null/); await s.el('batch-prepare').fire();
  s.responses.push(json(publication(s.client.pending))); s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.equal(new URLSearchParams(s.calls.at(-1).body).get('delete'), `${raw.ref_hex}:${'c'.repeat(40)}`);
});

test('staged hostile names remain inert and directional controls stay escaped in both previews', async () => {
  const s = await ready(); await stage(s, 'create', 'refs/heads/main', 'refs/heads/main', 'refs/heads/<img>\u202ex');
  assert.equal(s.el('batch-changes').children[0].children[0].tagName, 'PRE');
  assert.ok(s.el('batch-changes').textContent.includes('<img>')); assert.ok(s.el('batch-changes').textContent.includes('\\u202e'));
  await s.el('batch-prepare').fire(); assert.ok(s.el('pending').textContent.includes('\\u202e'));
  assert.ok(!s.el('pending').textContent.includes('\u202e')); assert.equal(s.calls.length, 1);
});

for (const action of ['load', 'cancel', 'disconnect']) test(`UI ${action} clears unprepared batch without fabricating a request`, async () => {
  const s = await ready(); await stage(s, 'delete'); s.el('confirm-send').checked = true;
  await s.el(action).fire(); assert.deepEqual(s.client.stagedChanges, []); assert.equal(s.client.pending, null);
  assert.equal(s.el('batch-changes').textContent, ''); assert.equal(s.el('batch-prepare').disabled, true); assert.equal(s.el('confirm-send').checked, false);
  assert.equal(s.calls.length, action === 'load' ? 2 : 1);
});

test('next pinned page preserves a staged source tip and never follows edited pagination controls', async () => {
  const s = fixture(); s.el('token').value = token; await s.el('connect').fire(); s.el('page-size').value = '1';
  s.responses.push(json({ ...page(), limit: 1, refs: [row('refs/heads/main')], next_after: hex(utf8.encode('refs/heads/main')) })); await s.el('load').fire();
  await stage(s, 'create', 'refs/heads/main'); const staged = s.client.stagedChanges;
  s.el('page-size').value = '100'; s.el('namespace').value = 'tags';
  s.responses.push(json({ ...page(), limit: 1, after: hex(utf8.encode('refs/heads/main')), refs: [row('refs/heads/topic', 'b')] })); await s.el('more').fire();
  assert.deepEqual(s.client.stagedChanges, staged); assert.equal(new URLSearchParams(s.calls[1].body).get('limit'), '1');
  assert.equal(new URLSearchParams(s.calls[1].body).get('namespace'), 'branches'); assert.match(s.el('batch-state').textContent, /1 of 32/);
});

test('batch recovery download restores every original effect without reads or automatic send', async () => {
  const a = await ready(); await stage(a, 'create'); await stage(a, 'delete'); await a.el('batch-prepare').fire(); await a.el('save').fire();
  assert.match(a.el('status').textContent, /offered for download/); assert.equal(a.el('discard').disabled, true);
  const s = fixture(); s.el('token').value = token; await s.el('connect').fire(); s.el('receipt-file').files = [new Blob([a.saved()])];
  await s.el('restore').fire(); assert.equal(s.calls.length, 0); assert.equal(s.client.pending.key, a.client.pending.key);
  assert.deepEqual(s.client.pending.fields, a.client.pending.fields); assert.equal(s.el('confirm-send').checked, false);
  assert.equal(s.el('batch-add').disabled, true); assert.equal(s.el('discard').disabled, true); assert.match(s.el('pending').textContent, /transaction/);
});

test('unknown atomic send keeps the complete batch unchanged and requires a new confirmation to retry', async () => {
  const s = await ready(); await stage(s, 'create'); await stage(s, 'delete'); await s.el('batch-prepare').fire(); const pending = s.client.pending;
  s.responses.push(new Error('lost reply')); s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.equal(s.client.pending.key, pending.key); assert.equal(s.el('confirm-send').checked, false); assert.match(s.el('status').textContent, /Outcome unknown/);
  await s.el('send').fire(); assert.equal(s.calls.length, 2);
  s.responses.push(json(publication(pending))); s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.equal(s.calls[1].body, s.calls[2].body); assert.equal(s.calls[1].headers['Idempotency-Key'], s.calls[2].headers['Idempotency-Key']);
  assert.equal(s.client.pending, null); assert.deepEqual(s.client.stagedChanges, []);
});
