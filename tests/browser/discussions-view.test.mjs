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
function harness(respond = call => json(call.url.includes('/discussions?') ? page() : history())) {
  const names = [...readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/discussions.html', import.meta.url), 'utf8').matchAll(/id="([^"]+)"/g)].map(match => match[1]);
  const elements = Object.fromEntries(names.map(name => [name, new Element()])); elements['change-action'].value = 'open';
  const lifecycle = new Element(), document = { getElementById: id => elements[id], createElement: tag => new Element(tag), defaultView: lifecycle };
  const calls = [], receipts = [];
  const mounted = mountDiscussions(document, new URL('https://forge.example/repo.git/ui/discussions/'), {
    fetchImpl: (url, options) => { const call = { url: String(url), ...options }; calls.push(call); return respond(call, calls.length); },
    cryptoImpl: webcrypto, saveReceipt: value => receipts.push(value),
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
for (const state of ['open', 'closed']) test(`locked ${state} discussion disables comments and preserves exact unlock version`, async () => {
  const events = [...history().events, { version: 2, actor, action: { name: 'lock' } }];
  if (state === 'closed') events.push({ version: 3, actor, action: { name: 'close' } });
  const current = { ...row, version: events.length, locked: true, state };
  const h = harness(call => json(call.url.includes('/discussions?') ? page({ discussions: [current] }) : history({ discussion: current, events })));
  await h.connect(); await h.read(7);
  assert.equal(buttons(h.elements['discussion-content']).find(b => b.textContent === 'Comment').disabled, true);
  h.choose(current, 'comment'); assert.equal(h.elements['prepare-change'].disabled, true);
  await h.elements['discussion-change'].fire('submit'); assert.equal(h.client.pending, null);
  await click(h.elements['discussion-content'], 'Unlock comments');
  assert.equal(h.elements['change-version'].value, String(events.length));
  assert.equal(h.elements['prepare-change'].disabled, false);
  await h.elements['discussion-change'].fire('submit');
  assert.equal(h.client.pending.action, 'unlock'); assert.equal(h.client.pending.expected_version, events.length);
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
