import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ActivityClient } from '../../crates/fgit-node/src/smart_http/server/browser/activity.mjs';
import { mountActivity } from '../../crates/fgit-node/src/smart_http/server/browser/activity-view.mjs';

const root = '../../crates/fgit-node/src/smart_http/server/browser/';
const shell = readFileSync(new URL(root + 'activity.html', import.meta.url), 'utf8');
const token = 'a'.repeat(64), head = 'alg:1:' + 'ab'.repeat(32);
const event = (cursor = '1:0', extra = {}) => ({ cursor, repository_sequence: cursor.split(':')[0], event_index: cursor.split(':')[1],
  tx_id: 'tx:fixture', policy_epoch: '1', aggregate: 'issue/1', aggregate_version: '1', kind: 1, event_frame_hex: 'abcd', ...extra });
const page = (extra = {}) => ({ type: 'forge_event_page', schema_version: 1, tenant_id: 'tenant', repository_id: 'repository',
  repository_incarnation: 'incarnation', object_format: 'sha256', source_head: 'head:first', snapshot_token: head, read_only: true,
  disclosure_profile: 'issues-pulls-v1', issues_read: true, pulls_read: false, omits_other_event_families: true,
  cursor_discloses_repository_activity: true, events: [event()], next_after: null, resume_after: '1:0', has_more: false, complete: true, ...extra });
const response = data => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const tick = () => new Promise(resolve => setImmediate(resolve));
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = new Map(); this.attributes = {}; this.value = ''; this.disabled = false; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('Repository text must remain inert'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(name, callback) { const callbacks = this.listeners.get(name) ?? []; callbacks.push(callback); this.listeners.set(name, callbacks); }
  async fire(name) { for (const callback of this.listeners.get(name) ?? []) await callback({ target: this }); }
  async click() { if (!this.disabled) await this.fire('click'); }
}
function fixture(replies = []) {
  const nodes = new Map(), created = [], requests = [], saved = [], events = new Element('window');
  // Derive controls from the served shell, so a missing HTML control cannot be
  // concealed by a more permissive hand-maintained fake DOM fixture.
  for (const match of shell.matchAll(/<([a-z0-9]+)\b[^>]*\bid="([^"]+)"[^>]*>/g)) {
    const element = new Element(match[1]), value = /\bvalue="([^"]*)"/.exec(match[0]);
    if (value) element.value = value[1]; nodes.set(match[2], element);
  }
  const doc = { getElementById: id => nodes.get(id), createElement: tag => { created.push(tag); return new Element(tag); } };
  const client = new ActivityClient({ href: 'https://forge.example/repo.git/ui/activity/', fetchImpl: (url, init) => {
    requests.push({ url: new URL(url), init }); const reply = replies.shift(); return typeof reply === 'function' ? reply(url, init) : reply;
  } });
  const view = mountActivity(doc, { client, events, savePage: value => saved.push(value) });
  return { client, view, nodes, created, requests, saved, events,
    el: id => nodes.get(id), click: id => nodes.get(id).click(),
    connect: async () => { nodes.get('token').value = token; await nodes.get('connect').click(); } };
}

test('served shell boots disconnected without a network request, inline code, or an authorization promise', () => {
  const f = fixture(); assert.equal(f.requests.length, 0);
  for (const id of ['load', 'next', 'refresh', 'save']) assert.equal(f.el(id).disabled, true);
  assert.equal(f.el('connect').disabled, false); assert.match(f.el('scope').textContent, /No authenticated/);
  assert.doesNotMatch(shell, /<script\s*>|\son[a-z]+\s*=/i); assert.match(shell, /does not.*verify inclusion proofs/);
  assert.match(shell, /role="status"/); assert.match(shell, /aria-live="polite"/);
});
test('connect clears the input without fetching; load renders scope, watermark and opaque native frames', async () => {
  const f = fixture([response(page())]); await f.connect();
  assert.equal(f.el('token').value, ''); assert.equal(f.requests.length, 0); assert.equal(f.el('load').disabled, false);
  await f.click('load'); assert.equal(f.requests.length, 1);
  assert.match(f.el('scope').textContent, /Granted families: issues/); assert.match(f.el('scope').textContent, /sha256/);
  assert.match(f.el('snapshot').textContent, /alg:1:/); assert.match(f.el('watermark').textContent, /Resume after 1:0/);
  assert.match(f.el('events').textContent, /issue\/1/); assert.match(f.el('events').textContent, /version 1/);
  assert.match(f.el('events').textContent, /opaque hexadecimal/); assert.match(f.el('events').textContent, /abcd/);
  assert.equal(f.el('next').disabled, true); assert.equal(f.el('refresh').disabled, false);
});
test('empty disclosed page is not EOF: next preserves the exact pin, refresh preserves the EOF watermark', async () => {
  const first = page({ events: [], next_after: '9007199254740993:1', resume_after: '9007199254740993:1', has_more: true, complete: false });
  const eof = page({ events: [], resume_after: '9007199254740994:0' });
  const f = fixture([response(first), response(eof), response(eof)]); await f.connect(); await f.click('load');
  assert.match(f.el('events').textContent, /Continue with Next page/); assert.equal(f.el('next').disabled, false);
  await f.click('next'); assert.equal(f.requests[1].url.searchParams.get('after'), '9007199254740993:1');
  assert.equal(f.requests[1].url.searchParams.get('expected_head'), head); assert.equal(f.el('next').disabled, true);
  assert.match(f.el('page-note').textContent, /not proof that no newer activity exists/);
  await f.click('refresh'); assert.equal(f.requests[2].url.searchParams.get('after'), '9007199254740994:0');
  assert.equal(f.requests[2].url.searchParams.has('expected_head'), false);
});
test('load honors exact cursor and page size while invalid size never dispatches', async () => {
  const f = fixture([response(page({ events: [], resume_after: '9:0' }))]); await f.connect();
  f.el('after').value = '9:0'; f.el('limit').value = '1'; await f.click('load');
  assert.equal(f.requests[0].url.searchParams.get('after'), '9:0'); assert.equal(f.requests[0].url.searchParams.get('limit'), '1');
  for (const value of ['0', '101', '1.5', '01', '']) { f.el('limit').value = value; await f.click('load'); }
  assert.equal(f.requests.length, 1); assert.match(f.el('status').textContent, /integer from 1 to 100/);
});
test('explicit export contains only the displayed bounded page, exact coordinates and no credential', async () => {
  const f = fixture([response(page())]); await f.connect(); await f.click('load'); await f.click('save');
  assert.equal(f.saved.length, 1); assert.equal(f.saved[0].filename, 'frankengit-activity-page.json');
  assert.deepEqual(JSON.parse(f.saved[0].text), f.client.page); assert.ok(!f.saved[0].text.includes(token));
  assert.equal(f.requests.length, 1); assert.match(f.el('status').textContent, /keep it secure/);
});
test('hostile metadata is inert, and bidi formatting characters are visibly escaped', async () => {
  const f = fixture([response(page({ events: [event('1:0', { aggregate: '<img/src=x>\u202e', tx_id: '<svg/onload=alert(1)>' })] }))]);
  await f.connect(); await f.click('load');
  assert.match(f.el('events').textContent, /<img\/src=x>/); assert.match(f.el('events').textContent, /\\u202e/);
  assert.ok(!f.el('events').textContent.includes('\u202e')); assert.ok(!f.created.includes('img')); assert.ok(!f.created.includes('svg'));
});
test('snapshot conflict is not swallowed, retained observations remain labelled, and retry is explicit', async () => {
  const f = fixture([response(page({ has_more: true, complete: false, next_after: '1:0' })), new Response('', { status: 409 })]);
  await f.connect(); await f.click('load'); await f.click('next');
  assert.equal(f.requests.length, 2); assert.match(f.el('status').textContent, /snapshot moved/);
  assert.match(f.el('status').textContent, /last successful page is still displayed/); assert.match(f.el('events').textContent, /issue\/1/);
});
for (const status of [401, 403]) {
  test(`HTTP ${status} clears rendered data and prevents export`, async () => {
    const f = fixture([response(page()), new Response('', { status })]); await f.connect(); await f.click('load'); await f.click('refresh');
    assert.equal(f.client.connected, false); assert.equal(f.el('events').children.length, 0); assert.equal(f.el('snapshot').textContent, '');
    assert.equal(f.el('save').disabled, true); await f.click('save'); assert.equal(f.saved.length, 0);
  });
}
test('pagehide disconnects and clears credentials, rows and cursors without any write', async () => {
  const f = fixture([response(page())]); await f.connect(); await f.click('load'); await f.events.fire('pagehide');
  assert.equal(f.client.connected, false); assert.equal(f.el('events').children.length, 0); assert.equal(f.el('watermark').textContent, '');
  assert.equal(f.el('after').value, '0'); assert.ok(f.requests.every(request => request.init.method === 'GET'));
});
test('cancel unblocks controls immediately; an old finally cannot clear a newer read or overwrite its status', async () => {
  const old = deferred(), fresh = deferred(), f = fixture([old.promise, fresh.promise]); await f.connect();
  const firstRead = f.click('load'); await tick(); assert.equal(f.el('load').disabled, true);
  await f.click('cancel'); assert.equal(f.el('load').disabled, false);
  const secondRead = f.click('load'); await tick(); await firstRead;
  assert.equal(f.el('load').disabled, true); assert.equal(f.el('events').attributes['aria-busy'], 'true');
  old.reject(new Error('late failure')); fresh.resolve(response(page())); await secondRead; await tick();
  assert.match(f.el('status').textContent, /Activity page loaded/); assert.equal(f.el('load').disabled, false);
});
test('disconnect during a body read never permits late rows or export after reconnection', async () => {
  const pending = deferred(); let stream;
  const reply = new Response(new ReadableStream({ start(controller) { stream = controller; } }), { headers: { 'Content-Type': 'application/json' } });
  const f = fixture([reply, pending.promise]); await f.connect(); const firstRead = f.click('load'); await tick();
  await f.click('disconnect'); await firstRead; await f.connect(); const secondRead = f.click('load');
  assert.throws(() => stream.enqueue(new TextEncoder().encode(JSON.stringify(page()))));
  pending.resolve(response(page({ events: [], resume_after: null }))); await secondRead;
  assert.match(f.el('events').textContent, /No granted event/); assert.doesNotMatch(f.el('events').textContent, /issue\/1/);
});
