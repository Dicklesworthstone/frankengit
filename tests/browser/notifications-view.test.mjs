// DOM/Response doubles and real WebCrypto test view lifecycle, not native authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Element } from './search-dom-fixture.mjs';
import { NotificationClient } from '../../crates/fgit-node/src/smart_http/server/browser/notifications.mjs';
import { mountNotificationInbox } from '../../crates/fgit-node/src/smart_http/server/browser/notifications-view.mjs';

const href = 'https://forge.example/repo.git/ui/notifications/';
const token = 'c'.repeat(64), head = `alg:2:${'b'.repeat(64)}`;
const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
  principal_id: '3'.repeat(32), repository_incarnation: '4'.repeat(32) };
const row = { number: 7, issue_version: 4, title: 'Private issue 雪 <script>inert</script>', state: 'open',
  preference_version: 2, mode: 'automatic', read_through: 1, latest_other_version: 3,
  unread: true, reasons: ['author', 'participant'] };
const page = { ...ids, type: 'notification_page', snapshot_token: head,
  source_positions: { authority_head_generation: 9, forge_position_root: `alg:2:${'5'.repeat(64)}`,
    outbox_root: `alg:2:${'6'.repeat(64)}`, complete: true },
  after: 0, limit: 20, unread_only: false, include_muted: false, next_after: null, threads: [row] };
const terminal = { ...ids, type: 'notification_publication', number: 7, expected_version: 2,
  action: 'read', tx_id: 'notification-tx', outcome: 'committed', decision_sequence: 10,
  repository_commit_id: 'notification-rcr', refusal_record_id: null, refusal_code: null, delivery_acknowledged: null };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status,
  headers: { 'Content-Type': 'application/json' } });
const settle = async () => { for (let i = 0; i < 4; i += 1) await new Promise(setImmediate); };
class ViewElement extends Element {
  querySelectorAll(selector) { assert.equal(selector, 'button'); return this.descendants().filter(child => child.tagName === 'BUTTON'); }
  fire(name, event = { preventDefault() {} }) { return Promise.all((this.listeners.get(name) ?? []).map(fn => fn(event))); }
}
function harness(respond = () => json(page), cryptoImpl = webcrypto) {
  const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/notifications.html', import.meta.url), 'utf8');
  const elements = new Map();
  const document = { getElementById: id => elements.get(id), createElement: tag => new ViewElement(tag, document) };
  document.defaultView = new ViewElement('window', document);
  for (const match of html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)) {
    const element = document.createElement(match[1]); element.id = match[2]; element.checked = false;
    element.files = []; element.hidden = /\bhidden\b/.test(match[0]); elements.set(element.id, element);
  }
  const calls = [], client = new NotificationClient({ href, cryptoImpl, fetchImpl: (url, init) => {
    const call = { url: String(url), ...init }; calls.push(call); return respond(call, calls.length);
  } });
  // Observe real operations because the existing submit listeners return void.
  // No client result, hash, binding, permission or terminal is fabricated here.
  const observe = name => {
    const original = client[name].bind(client);
    client[name] = (...args) => { observed[name] = original(...args); return observed[name]; };
  };
  const observed = {};
  observe('connect'); observe('read');
  const mounted = mountNotificationInbox({ document, href, client });
  const get = id => document.getElementById(id);
  return { ...mounted, calls, get, lifecycle: document.defaultView, observed,
    async connect() {
      get('inbox-token').value = token; const submitted = get('inbox-connect').fire('submit');
      await observed.connect; await observed.read.catch(() => {}); await submitted; await settle();
    },
    async refresh() {
      const submitted = get('inbox-filters').fire('submit');
      await observed.read.catch(() => {}); await submitted; await settle();
    },
  };
}
async function prepare(client) { await client.stage(7, 2, 'read', { read_through: 4 }); }
async function savedReceipt() {
  const client = new NotificationClient({ href, cryptoImpl: webcrypto, fetchImpl: async () => json(page) });
  await client.connect(token); await client.read(); await prepare(client);
  const receipt = client.exportReceipt(); client.disconnect(); return receipt;
}
const file = bytes => ({ size: bytes.byteLength,
  async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); },
  async text() { return new TextDecoder().decode(bytes); } });

test('inbox renders literal private titles and an observed recipient without executing markup', async () => {
  const h = harness(); await h.connect();
  assert.equal(h.get('inbox-token').value, '');
  assert.ok(h.get('inbox-content').textContent.includes(row.title));
  assert.ok(h.get('inbox-snapshot').textContent.includes(ids.principal_id));
  h.client.disconnect();
});

for (const boundary of ['disconnect', 'pagehide']) test(`${boundary} clears recipient presentation and preserves exact unresolved custody`, async () => {
  const h = harness(); await h.connect(); await prepare(h.client);
  const original = h.client.pending; h.get('inbox-number').value = 'Private lookup';
  if (boundary === 'disconnect') await h.get('inbox-disconnect').fire('click');
  else h.lifecycle.emit('pagehide');
  assert.equal(h.client.connected, false);
  assert.equal(h.controller.page, null);
  assert.equal(h.get('inbox-content').textContent, '');
  assert.equal(h.get('inbox-snapshot').textContent, '');
  assert.equal(h.get('inbox-number').value, '');
  assert.deepEqual(h.client.pending, original);
  assert.equal(h.get('inbox-retry').disabled, true);
  assert.equal(h.get('inbox-save').disabled, false, 'token-free custody remains exportable');
});

test('read authentication expiry removes the cached recipient page and visible issue data', async () => {
  const h = harness((_call, count) => count === 1 ? json(page) : json({}, 401)); await h.connect();
  await h.refresh();
  assert.equal(h.client.connected, false);
  assert.equal(h.controller.page, null);
  assert.equal(h.get('inbox-content').textContent, '');
  assert.equal(h.get('inbox-snapshot').textContent, '');
});

test('authentication expiry during mutation keeps exact possibly-sent recovery while clearing the inbox', async () => {
  const h = harness(call => call.method === 'POST' ? json({}, 401) : json(page)); await h.connect();
  const read = h.get('inbox-content').querySelectorAll('button').find(button => button.textContent === 'Mark read');
  await read.fire('click');
  assert.equal(h.client.connected, false);
  assert.equal(h.client.pending.sent, true);
  assert.equal(h.client.pending.action, 'read');
  assert.equal(h.controller.page, null);
  assert.equal(h.get('inbox-content').textContent, '');
  assert.equal(h.get('inbox-discard').disabled, true);
  assert.equal(h.client.exportReceipt().includes(token), false);
});

test('known preference commitment survives an authentication failure in the automatic refresh', async () => {
  let reads = 0;
  const h = harness(call => call.method === 'POST' ? json(terminal) : ++reads === 1 ? json(page) : json({}, 401));
  await h.connect();
  await h.get('inbox-content').querySelectorAll('button').find(button => button.textContent === 'Mark read').fire('click');
  assert.equal(h.client.pending, null);
  assert.equal(h.client.connected, false);
  assert.equal(h.controller.page, null);
  assert.equal(h.get('inbox-content').textContent, '');
  assert.match(h.get('inbox-status').textContent, /^Preference saved\. Inbox refresh failed:/);
});

test('navigation warns only while the original preference request remains unresolved', async () => {
  const h = harness(); await h.connect();
  assert.equal(h.lifecycle.emit('beforeunload').defaultPrevented, false);
  await prepare(h.client); const original = h.client.pending, count = h.calls.length;
  const event = h.lifecycle.emit('beforeunload');
  assert.equal(event.defaultPrevented, true); assert.equal(event.returnValue, '');
  assert.deepEqual(h.client.pending, original); assert.equal(h.calls.length, count);
  h.client.discardUnsent(); assert.equal(h.lifecycle.emit('beforeunload').defaultPrevented, false);
  h.client.disconnect();
});

test('a receipt file selected in the previous session cannot restore into a reconnected inbox', async () => {
  const receipt = await savedReceipt(), gate = Promise.withResolvers();
  const h = harness(); await h.connect();
  const bytes = new TextEncoder().encode(receipt);
  h.get('inbox-restore').files = [{ size: bytes.length, text: () => gate.promise,
    arrayBuffer: () => gate.promise.then(() => bytes.buffer) }];
  const old = h.get('inbox-restore').fire('change');
  await h.get('inbox-disconnect').fire('click'); await h.connect(); gate.resolve(receipt); await old;
  assert.equal(h.client.connected, true); assert.equal(h.client.pending, null);
  assert.equal(h.calls.length, 2, 'import never submits a mutation'); h.client.disconnect();
});

test('valid UTF-8 receipt import preserves its exact key/body and never sends', async () => {
  const receipt = await savedReceipt(), expected = JSON.parse(receipt).request, h = harness(); await h.connect();
  h.get('inbox-restore').files = [file(new TextEncoder().encode(receipt))];
  await h.get('inbox-restore').fire('change');
  assert.equal(h.client.pending.key, expected.key); assert.equal(h.client.pending.body, expected.body);
  assert.equal(h.client.pending.sent, true); assert.equal(h.client.pending.exported, true);
  assert.equal(h.calls.length, 1); assert.equal(h.get('inbox-discard').disabled, true); h.client.disconnect();
});

test('malformed or oversized file imports leave the connected inbox without a new request', async () => {
  const h = harness(); await h.connect();
  for (const bytes of [new Uint8Array([0xff]), new Uint8Array(1024 * 1024)]) {
    h.get('inbox-restore').files = [file(bytes)]; await h.get('inbox-restore').fire('change');
    assert.equal(h.client.pending, null); assert.equal(h.client.connected, true);
  }
  assert.equal(h.calls.length, 1); h.client.disconnect();
});

test('a read permission refusal retains the connected credential for independent outcome recovery', async () => {
  const h = harness((_call, count) => count === 1 ? json(page) : json({}, 403)); await h.connect();
  await prepare(h.client); const original = h.client.pending; await h.refresh();
  assert.equal(h.client.connected, true); assert.deepEqual(h.client.pending, original);
  h.client.disconnect();
});

test('a stale read error cannot disconnect a new credential digest while reconnect is pending', async () => {
  const old = Promise.withResolvers(), digestReady = Promise.withResolvers(), releaseDigest = Promise.withResolvers();
  let pause = false;
  const cryptoImpl = { getRandomValues: bytes => webcrypto.getRandomValues(bytes), subtle: { digest: async (...args) => {
    const result = await webcrypto.subtle.digest(...args);
    if (pause) { digestReady.resolve(); await releaseDigest.promise; }
    return result;
  } } };
  const h = harness((_call, count) => count === 2 ? old.promise : json(page), cryptoImpl); await h.connect();
  const stale = h.refresh(); pause = true; h.get('inbox-token').value = token;
  const submit = h.get('inbox-connect').fire('submit'); await digestReady.promise;
  old.reject(new Error('old read failed')); await stale; releaseDigest.resolve();
  await h.observed.connect; await h.observed.read; await submit; await settle();
  assert.equal(h.client.connected, true); assert.ok(h.get('inbox-content').textContent.includes(row.title));
  h.client.disconnect();
});
