// DOM/fetch doubles exercise the served UI; native authority is tested separately.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mountDiscussions } from '../../crates/fgit-node/src/smart_http/server/browser/discussions-view.mjs';

class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.checked = true; this.files = []; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { assert.fail('Executable HTML sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  addEventListener(name, handler) { this.listeners.set(name, handler); }
  fire(name, event = { preventDefault() {} }) { return this.listeners.get(name)?.(event); }
}
const token = 'c'.repeat(64), actor = '3'.repeat(32), head = `alg:1:${'b'.repeat(64)}`;
const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), scope: 'repository_discussions', snapshot_token: head };
const row = { number: 7, version: 1, title: '<img onerror=alert(1)>', body: 'body\u202e<script>', state: 'open', opened_by: actor, last_actor: actor, comments: 0, locked: false };
const page = extra => ({ ...ids, type: 'discussion_page', after: 0, limit: 20, next_after: null, discussions: [row], ...extra });
const history = extra => ({ ...ids, type: 'discussion_history', found: true, discussion: row, after_version: 0, limit: 20, next_after_version: null,
  events: [{ version: 1, actor, action: { name: 'open', title: row.title, body: row.body } }], ...extra });
const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const terminal = { ...ids, type: 'discussion_publication', principal_id: actor, number: 7, expected_version: 1, action: 'comment',
  tx_id: 'tx-1', outcome: 'committed', decision_sequence: 2, repository_commit_id: 'rcr-1', refusal_code: null, refusal_record_id: null, delivery_acknowledged: null };
async function settled() { for (let i = 0; i < 10; i += 1) await new Promise(setImmediate); }
function buttons(root) { return root.children.flatMap(child => [...(child.tagName === 'button' ? [child] : []), ...buttons(child)]); }
function click(root, name) { const found = buttons(root).find(child => child.textContent === name); assert.ok(found, `button ${name}`); return found.fire('click'); }
function harness(respond = call => json(call.url.includes('/discussions?') ? page() : history()), cryptoImpl = webcrypto) {
  const names = [...readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/discussions.html', import.meta.url), 'utf8').matchAll(/id="([^"]+)"/g)].map(match => match[1]);
  const elements = Object.fromEntries(names.map(name => [name, new Element()])); elements['change-action'].value = 'open';
  const lifecycle = new Element(), document = { getElementById: id => elements[id], createElement: tag => new Element(tag), defaultView: lifecycle };
  const calls = [], receipts = [];
  const mounted = mountDiscussions(document, new URL('https://forge.example/repo.git/ui/discussions/'), {
    fetchImpl: (url, options) => { const call = { url: String(url), ...options }; calls.push(call); return respond(call, calls.length); },
    cryptoImpl, saveReceipt: value => receipts.push(value),
  });
  return { elements, lifecycle, calls, receipts, ...mounted,
    async connect() { elements['discussion-token'].value = token; await elements['discussion-connect'].fire('submit'); },
  };
}
test('discussion navigation shows inert titles and authored text and follows the observed snapshot', async () => {
  const h = harness(); await h.connect();
  assert.equal(h.elements['discussion-token'].value, '');
  assert.ok(h.elements['discussion-content'].textContent.includes(row.title));
  await click(h.elements['discussion-content'], '#7 ' + row.title);
  assert.equal(new URL(h.calls[1].url).searchParams.get('expected_head'), head);
  assert.match(h.elements['discussion-content'].textContent, /body\\u\{202e\}<script>/);
  assert.ok(h.elements['discussion-content'].textContent.includes(actor));
  assert.equal(h.elements['show-number'].value, '7');
});
test('comment preparation captures the selected version and sends the immutable draft', async () => {
  const h = harness(call => json(call.method === 'POST' ? terminal : call.url.includes('/discussions?') ? page() : history()));
  await h.connect(); await h.read(7); await click(h.elements['discussion-content'], 'Comment');
  assert.equal(h.elements['change-version'].value, '1'); assert.equal(h.elements['change-body'].value, '');
  h.elements['change-body'].value = '<svg onload=alert(1)> & 雪';
  await h.elements['discussion-change'].fire('submit');
  assert.equal(h.calls.length, 2); assert.equal(h.client.pending.sent, false);
  assert.equal(h.client.pending.expected_version, 1);
  const body = h.client.pending.body; h.elements['change-body'].value = 'later edits';
  await h.elements['send-change'].fire('click');
  assert.equal(h.calls[2].body, body); assert.equal(h.client.pending, null);
  assert.match(h.elements['discussion-status'].textContent, /^Committed/);
});
test('append is an explicit choice without a version and survives changes to the editor', async () => {
  const reply = { ...terminal, expected_version: null, action: 'append-comment' };
  const h = harness(call => json(call.method === 'POST' ? reply : call.url.includes('/discussions?') ? page() : history()));
  await h.connect(); await h.read(7);
  await click(h.elements['discussion-content'], 'Comment');
  assert.equal(h.elements['change-action'].value, 'comment');
  assert.equal(h.elements['version-field'].hidden, false);
  assert.equal(h.elements['change-version'].required, true);
  await click(h.elements['discussion-content'], 'Append comment');
  assert.equal(h.elements['change-action'].value, 'append-comment');
  assert.equal(h.elements['change-version'].value, '');
  assert.equal(h.elements['version-field'].hidden, true);
  assert.equal(h.elements['change-version'].disabled, true);
  assert.equal(h.elements['change-version'].required, false);
  assert.equal(h.elements['append-comment-hint'].hidden, false);
  assert.equal(h.elements['change-body'].value, '');
  h.elements['change-body'].value = 'Keep my reply & 雪';
  h.elements['change-version'].value = 'stale input is not a precondition';
  await h.elements['discussion-change'].fire('submit');
  const original = h.client.pending;
  assert.equal(original.action, 'append-comment'); assert.equal(original.expected_version, null);
  assert.deepEqual([...new URLSearchParams(original.body)], [['body', 'Keep my reply & 雪']]);
  assert.match(h.elements['prepared-summary'].textContent, /accept concurrent replies/);
  h.elements['change-body'].value = 'later edit'; h.choose(row, 'comment');
  await h.elements['send-change'].fire('click');
  assert.ok(h.calls[2].url.endsWith('/discussions/7/append-comment'));
  assert.equal(h.calls[2].body, original.body);
  assert.equal(h.calls[2].headers['Idempotency-Key'], original.key);
  assert.equal(h.client.pending, null);
  assert.equal(h.elements['version-field'].hidden, false);
  assert.equal(h.elements['change-version'].required, true);
});
for (const state of ['open', 'closed']) test(`locked ${state} discussion disables comments and preserves exact unlock version`, async () => {
  const events = [...history().events, { version: 2, actor, action: { name: 'lock' } }];
  if (state === 'closed') events.push({ version: 3, actor, action: { name: 'close' } });
  const current = { ...row, version: events.length, locked: true, state };
  const h = harness(call => json(call.url.includes('/discussions?') ? page({ discussions: [current] }) : history({ discussion: current, events })));
  await h.connect(); await h.read(7);
  assert.equal(buttons(h.elements['discussion-content']).find(b => b.textContent === 'Comment').disabled, true);
  assert.equal(buttons(h.elements['discussion-content']).find(b => b.textContent === 'Append comment').disabled, true);
  h.choose(current, 'comment'); assert.equal(h.elements['prepare-change'].disabled, true);
  await h.elements['discussion-change'].fire('submit'); assert.equal(h.client.pending, null);
  h.choose(current, 'append-comment'); assert.equal(h.elements['prepare-change'].disabled, true);
  await h.elements['discussion-change'].fire('submit'); assert.equal(h.client.pending, null);
  await click(h.elements['discussion-content'], 'Unlock comments');
  assert.equal(h.elements['change-version'].value, String(events.length));
  assert.equal(h.elements['prepare-change'].disabled, false);
  await h.elements['discussion-change'].fire('submit');
  assert.equal(h.client.pending.action, 'unlock'); assert.equal(h.client.pending.expected_version, events.length);
});
test('write-only browser append needs no read or guessed predecessor', async () => {
  const reply = { ...terminal, expected_version: null, action: 'append-comment' };
  const h = harness(call => call.method === 'GET' ? new Response('', { status: 403 }) : json(reply));
  await h.connect(); assert.equal(h.client.connected, true);
  h.elements['change-number'].value = '7'; h.elements['change-action'].value = 'append-comment';
  h.elements['change-action'].fire('change'); h.elements['change-body'].value = 'Write-only reply';
  await h.elements['discussion-change'].fire('submit');
  assert.equal(h.client.pending.expected_version, null);
  await h.elements['send-change'].fire('click');
  assert.equal(h.client.pending, null);
  assert.match(h.elements['discussion-status'].textContent, /^Committed/);
  assert.deepEqual([...new URLSearchParams(h.calls[1].body)], [['body', 'Write-only reply']]);
});
test('lost mutation and disconnect preserve recoverable custody without exposing the token', async () => {
  const h = harness(call => { if (call.method === 'POST') throw new Error('lost'); return json(page()); });
  await h.connect(); h.choose(row, 'comment'); h.elements['change-body'].value = 'Private draft';
  await h.elements['discussion-change'].fire('submit'); await h.elements['send-change'].fire('click');
  assert.match(h.elements['discussion-status'].textContent, /Outcome unknown/);
  await h.elements['save-receipt'].fire('click'); assert.equal(h.receipts.length, 1);
  assert.equal(h.receipts[0].includes(token), false); const key = h.client.pending.key;
  h.elements['discussion-disconnect'].fire('click');
  assert.equal(h.client.pending.key, key); assert.equal(h.elements['discard-change'].disabled, true);
  assert.equal(h.elements['discussion-content'].textContent, '');
  assert.equal(h.elements['prepared-summary'].textContent.includes('Private draft'), false);
});
test('a late read cannot restore private content after disconnection', async () => {
  let resolve;
  const h = harness((_call, n) => n === 1 ? json(page()) : new Promise(done => { resolve = done; }));
  await h.connect(); const pending = h.read(7).catch(() => {}); await settled();
  h.elements['discussion-disconnect'].fire('click'); resolve(json(history())); await pending;
  assert.equal(h.elements['discussion-content'].textContent, '');
  assert.equal(h.elements['discussion-snapshot'].textContent, '');
});

for (const boundary of ['disconnect', 'pagehide', 'reconnect']) test(`${boundary} clears private discussion editors and retains the original unresolved request`, async () => {
  const h = harness(call => { if (call.method === 'POST') throw new Error('lost'); return json(page()); });
  await h.connect(); h.choose(row, 'comment');
  h.elements['change-body'].value = 'Private unresolved reply';
  await h.elements['discussion-change'].fire('submit');
  await h.elements['send-change'].fire('click');
  const original = h.client.pending;
  assert.equal(original.sent, true);
  h.elements['change-title-text'].value = 'Private title';
  h.elements['show-number'].value = '7';
  h.elements['restore-receipt'].value = 'private-retry.json';
  if (boundary === 'reconnect') await h.connect();
  else if (boundary === 'pagehide') h.lifecycle.fire('pagehide');
  else h.elements['discussion-disconnect'].fire('click');
  for (const id of ['discussion-token', 'change-title-text', 'change-body', 'change-number',
    'change-version', 'show-number', 'restore-receipt']) assert.equal(h.elements[id].value, '', id);
  assert.equal(h.client.pending.key, original.key);
  assert.equal(h.client.pending.body, original.body);
  assert.equal(h.client.pending.sent, true);
  if (!h.client.connected) {
    assert.equal(h.elements['discussion-content'].textContent, '');
    assert.equal(h.elements['prepared-summary'].textContent.includes('Private unresolved reply'), false);
  }
  await h.elements['save-receipt'].fire('click');
  const saved = JSON.parse(h.receipts[0]);
  assert.equal(saved.request.key, original.key);
  assert.equal(saved.request.body, original.body);
  assert.equal(h.receipts[0].includes(token), false);
});

test('expired credentials clear displayed discussion text without discarding an uncertain mutation', async () => {
  const h = harness(call => call.method === 'POST' ? new Response('', { status: 401 }) : json(page()));
  await h.connect(); h.choose(row, 'comment');
  h.elements['change-body'].value = 'Private reply after credential expiry';
  await h.elements['discussion-change'].fire('submit');
  const original = h.client.pending;
  await h.elements['send-change'].fire('click');
  assert.equal(h.client.connected, false);
  assert.equal(h.elements['discussion-content'].textContent, '');
  for (const id of ['change-title-text', 'change-body', 'change-number', 'change-version']) assert.equal(h.elements[id].value, '', id);
  assert.equal(h.client.pending.key, original.key);
  assert.equal(h.client.pending.body, original.body);
  assert.equal(h.client.pending.sent, true);
  assert.equal(h.elements['discard-change'].disabled, true);
});

test('leaving warns only while a discussion request remains unresolved', async () => {
  const h = harness(); await h.connect();
  const unload = () => {
    let warned = false;
    const event = { preventDefault() { warned = true; } };
    h.lifecycle.fire('beforeunload', event);
    return { warned, returnValue: event.returnValue };
  };
  assert.equal(unload().warned, false);
  h.choose(row, 'comment'); h.elements['change-body'].value = 'Keep this retry identity';
  await h.elements['discussion-change'].fire('submit');
  const original = h.client.pending, calls = h.calls.length;
  assert.deepEqual(unload(), { warned: true, returnValue: '' });
  assert.equal(h.client.pending.key, original.key);
  assert.equal(h.calls.length, calls, 'unload protection must not send the prepared request');
  h.client.discardUnsent();
  assert.equal(unload().warned, false);
});

test('read permission refusal retains the connected write-only discussion editor', async () => {
  const h = harness(call => call.method === 'GET' ? new Response('', { status: 403 }) : json(terminal));
  await h.connect();
  assert.equal(h.client.connected, true);
  assert.equal(h.elements['prepare-change'].disabled, false);
  h.choose(row, 'comment'); h.elements['change-body'].value = 'Permitted write-only reply';
  await h.elements['discussion-change'].fire('submit');
  await h.elements['send-change'].fire('click');
  assert.match(h.elements['discussion-status'].textContent, /^Committed/);
  assert.equal(h.client.pending, null);
});

async function savedDiscussion(body = 'Original recovery draft') {
  const h = harness(); await h.connect(); h.choose(row, 'comment'); h.elements['change-body'].value = body;
  await h.elements['discussion-change'].fire('submit');
  const serialized = h.client.exportReceipt();
  return { serialized, bytes: new TextEncoder().encode(serialized), request: h.client.pending };
}

test('valid UTF-8 discussion receipt import preserves exact custody without sending', async () => {
  const saved = await savedDiscussion(), h = harness(); await h.connect();
  h.elements['restore-receipt'].files = [new File([saved.bytes], 'retry.json')];
  await h.elements['restore-receipt'].fire('change');
  assert.equal(h.client.pending.key, saved.request.key);
  assert.equal(h.client.pending.body, saved.request.body);
  assert.equal(h.calls.length, 1);
});

test('a discussion receipt selected before reconnect cannot restore into the new session', async () => {
  const saved = await savedDiscussion(), h = harness(); await h.connect();
  let finish;
  h.elements['restore-receipt'].files = [{ size: saved.bytes.length,
    text: () => new Promise(resolve => { finish = () => resolve(saved.serialized); }),
    arrayBuffer: () => new Promise(resolve => { finish = () => resolve(saved.bytes.buffer); }),
  }];
  const importing = h.elements['restore-receipt'].fire('change');
  await settled(); assert.equal(typeof finish, 'function');
  h.elements['discussion-disconnect'].fire('click'); await h.connect();
  finish(); await importing;
  assert.equal(h.client.pending, null);
  assert.equal(h.calls.length, 2, 'stale import must not send any request');
});

test('malformed UTF-8 receipt bytes refuse even when lossy decoding would recover a valid draft', async () => {
  const saved = await savedDiscussion('Original \ufffd recovery draft');
  const at = saved.bytes.findIndex((byte, index) => byte === 0xef && saved.bytes[index + 1] === 0xbf && saved.bytes[index + 2] === 0xbd);
  assert(at >= 0);
  const bytes = new Uint8Array(saved.bytes.length - 2);
  bytes.set(saved.bytes.subarray(0, at)); bytes[at] = 0xff; bytes.set(saved.bytes.subarray(at + 3), at + 1);
  const h = harness(); await h.connect();
  h.elements['restore-receipt'].files = [new File([bytes], 'malformed.json')];
  await h.elements['restore-receipt'].fire('change');
  assert.equal(h.client.pending, null);
  assert.match(h.elements['discussion-status'].textContent, /UTF|encoded|valid/i);
  assert.equal(h.calls.length, 1);
});

test('a superseded read cannot disconnect a reconnect awaiting its real credential hash', async () => {
  const started = Promise.withResolvers(), digest = Promise.withResolvers();
  let hold = false, reply;
  const cryptoImpl = { getRandomValues: value => webcrypto.getRandomValues(value), subtle: {
    async digest(...args) {
      const result = await webcrypto.subtle.digest(...args);
      if (hold) { started.resolve(); await digest.promise; }
      return result;
    },
  } };
  const h = harness((_call, count) => count === 2 ? new Promise(resolve => { reply = resolve; }) : json(page()), cryptoImpl);
  await h.connect(); h.elements['show-number'].value = '7';
  const reading = h.elements['discussion-show'].fire('submit');
  await settled(); assert.equal(typeof reply, 'function');
  hold = true; const connecting = h.connect(); await started.promise;
  reply(json(history())); await reading;
  digest.resolve(); await connecting;
  assert.equal(h.client.connected, true);
  assert.match(h.elements['discussion-status'].textContent, /discussions shown/);
});
