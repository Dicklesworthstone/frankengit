// Production browser clients/controllers with real Node WebCrypto and explicit
// Response/DOM contract doubles. These are not Rust authority, persistence,
// native HTTP authentication, or real-browser rendering evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  DiscussionNotificationClient, NotificationClient, notificationMutationRequest,
  notificationState, notificationPage, notificationThread,
} from '../../crates/fgit-node/src/smart_http/server/browser/notifications.mjs';
import {
  NotificationInboxController, mountNotificationInbox, threadAction,
} from '../../crates/fgit-node/src/smart_http/server/browser/notifications-view.mjs';
import { Element, tick } from './search-dom-fixture.mjs';

const href = 'https://forge.example/repo.git/ui/discussion-notifications/';
const issueHref = 'https://forge.example/repo.git/ui/notifications/';
const token = 'c'.repeat(64), head = 'alg:2:' + 'b'.repeat(64);
const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
  principal_id: '3'.repeat(32), repository_incarnation: '4'.repeat(32) };
const binding = { tenant: ids.tenant_id, repository: ids.repository_id,
  principal: ids.principal_id, incarnation: ids.repository_incarnation };
const positions = { authority_head_generation: 9, forge_position_root: 'alg:2:' + '5'.repeat(64),
  outbox_root: 'alg:2:' + '6'.repeat(64), complete: true };
const row = { number: 7, discussion_version: 4, title: 'Design 雪 <script>inert</script>', state: 'open',
  preference_version: 2, mode: 'automatic', read_through: 1, latest_other_version: 3,
  unread: true, reasons: ['author', 'participant'] };
const page = (patch = {}) => ({ ...ids, type: 'discussion_notification_page', target_kind: 'discussion',
  snapshot_token: head, source_positions: positions, after: 0, limit: 20,
  unread_only: false, include_muted: false, next_after: null, threads: [row], ...patch });
const thread = (patch = {}) => ({ ...ids, type: 'discussion_notification_thread', target_kind: 'discussion',
  snapshot_token: head, source_positions: positions, found: true, thread: row, ...patch });
// Native publication replies carry the principal, but do not echo incarnation.
const terminal = { schema_version: 1, tenant_id: ids.tenant_id, repository_id: ids.repository_id,
  principal_id: ids.principal_id, type: 'discussion_notification_publication', target_kind: 'discussion',
  number: 7, expected_version: 2, action: 'read', tx_id: 'original-discussion-notification-tx',
  outcome: 'committed', decision_sequence: 10, repository_commit_id: 'original-rcr',
  refusal_record_id: null, refusal_code: null, delivery_acknowledged: null };
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
});
const fresh = fetchImpl => new DiscussionNotificationClient({ href, fetchImpl, cryptoImpl: webcrypto });
const observe = async client => { await client.connect(token); await client.read(); };
const prepare = async client => { await observe(client); await client.stage(7, 2, 'read', { read_through: 4 }); };
const recorded = (url, init) => ({ url: String(url), ...init });
const deferred = () => {
  let resolve;
  const promise = new Promise(accept => { resolve = accept; });
  return { promise, resolve };
};
const recovery = state => {
  const settled = state === 'committed';
  return { ...ids, type: 'transaction_outcome', selector: 'transaction', command_index: null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false,
    session_completeness_established: false, terminal: settled, state,
    transaction: settled || state === 'undecided' ? { tx_id: terminal.tx_id } : null,
    decision: settled ? { kind: state, decision_sequence: 10, repository_commit_id: terminal.repository_commit_id } : null };
};

test('discussion notification state keeps namespaces separate and derives unread from other actors', () => {
  assert.equal(notificationState(row, 'discussion'), row);
  for (const reasons of [['author'], ['participant'], ['author', 'participant']]) {
    assert.deepEqual(notificationState({ ...row, reasons }, 'discussion').reasons, reasons);
  }
  assert.equal(notificationState({ ...row, read_through: 3, unread: false }, 'discussion').unread, false);
  const ownOnly = { ...row, preference_version: null, read_through: null,
    latest_other_version: null, unread: false, reasons: ['author'] };
  assert.equal(notificationState(ownOnly, 'discussion').unread, false);
  assert.equal(notificationState({ ...row, mode: 'subscribed', reasons: ['subscribed'] }, 'discussion').mode, 'subscribed');
  assert.equal(notificationState({ ...row, mode: 'muted', reasons: [] }, 'discussion').mode, 'muted');
  for (const patch of [
    { discussion_version: undefined, issue_version: 4 }, { issue_version: 4 },
    { discussion_version: 0 }, { read_through: 5 }, { latest_other_version: 5 },
    { unread: false }, { reasons: ['assignee'] }, { reasons: ['participant', 'author'] },
    { reasons: ['author', 'author'] }, { mode: 'subscribed' },
    { mode: 'muted', reasons: ['subscribed'] }, { preference_version: null },
  ]) assert.throws(() => notificationState({ ...row, ...patch }, 'discussion'));
  assert.throws(() => notificationState(row), 'a discussion row is never accepted as an issue');
});

test('discussion inbox pages bind kind, recipient, source, predicates and exact-thread absence', () => {
  assert.deepEqual(notificationPage(page(), { binding, kind: 'discussion' }).binding, binding);
  assert.equal(notificationThread(thread(), 7, { binding, head, kind: 'discussion' }).reply.thread, row);
  for (const patch of [
    { target_kind: undefined }, { target_kind: 'issue' }, { type: 'notification_page' },
    { threads: [{ ...row, issue_version: 4 }] }, { threads: [row, row] },
    { source_positions: { ...positions, complete: false } }, { next_after: 7 },
    { threads: [{ ...row, reasons: [] }] },
  ]) assert.throws(() => notificationPage(page(patch), { kind: 'discussion' }));
  for (const field of ['tenant_id', 'repository_id', 'principal_id', 'repository_incarnation']) {
    assert.throws(() => notificationPage(page({ [field]: '9'.repeat(32) }), { binding, kind: 'discussion' }));
  }
  assert.throws(() => notificationPage(page(), { kind: 'discussion', head: 'alg:2:' + 'a'.repeat(64) }));
  assert.throws(() => notificationPage(page()), 'default issue profile cannot accept a discussion page');
  const muted = page({ include_muted: true, threads: [{ ...row, mode: 'muted', reasons: [] }] });
  assert.equal(notificationPage(muted, { kind: 'discussion', includeMuted: true }).reply.threads.length, 1);
  assert.throws(() => notificationPage(muted, { kind: 'discussion' }));
  const read = page({ unread_only: true, threads: [{ ...row, read_through: 3, unread: false }] });
  assert.throws(() => notificationPage(read, { kind: 'discussion', unreadOnly: true }));
  assert.equal(notificationThread(thread({ thread: { ...row, reasons: [] } }), 7,
    { kind: 'discussion' }).reply.found, true, 'an unrelated exact lookup can offer subscription');
  assert.equal(notificationThread(thread({ found: false, thread: null }), 7,
    { kind: 'discussion' }).reply.found, false);
  for (const patch of [{ target_kind: 'issue' }, { type: 'notification_thread' }, { found: false }]) {
    assert.throws(() => notificationThread(thread(patch), 7, { kind: 'discussion' }));
  }
});

test('discussion transport requires an observed identity and uses guarded dedicated routes', async () => {
  const calls = [], client = fresh(async (url, init) => {
    calls.push(recorded(url, init));
    return json(init.method === 'POST' ? terminal : new URL(url).pathname.endsWith('/7') ? thread() : page());
  });
  assert.throws(() => new DiscussionNotificationClient({ href: issueHref, cryptoImpl: webcrypto }));
  assert.throws(() => new DiscussionNotificationClient({ href: href.replace('https:', 'http:'), cryptoImpl: webcrypto }));
  await client.connect(token);
  await assert.rejects(client.stage(7, 2, 'read', { read_through: 4 }), /Read your notification identity/);
  assert.equal(calls.length, 0);
  await client.read();
  await assert.rejects(client.stage(7, 2, 'mute', {}, binding), /Read your notification identity/);
  await client.read(7, { head });
  await assert.rejects(client.read(null, { after: 7 }), /original snapshot/);
  await assert.rejects(client.read(7, { unreadOnly: true }));
  await assert.rejects(client.read(null, { render: true }));
  await client.stage(7, 2, 'read', { read_through: 4 });
  assert.equal(calls.length, 2, 'preparing and rejecting local options never dispatch');
  assert.equal((await client.send()).outcome, 'committed');
  assert.equal(new URL(calls[0].url).pathname, '/repo.git/api/v1/notifications/discussions');
  assert.equal(new URL(calls[0].url).searchParams.get('unread_only'), 'false');
  assert.equal(new URL(calls[1].url).pathname, '/repo.git/api/v1/notifications/discussions/7');
  assert.equal(new URL(calls[1].url).searchParams.get('expected_head'), head);
  assert.equal(new URL(calls[2].url).pathname, '/repo.git/api/v1/notifications/discussions/7/read');
  for (const call of calls) {
    assert.equal(call.headers.Authorization, 'Bearer ' + token);
    assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error');
    assert.equal(call.mode, 'same-origin'); assert.equal(call.cache, 'no-store');
    assert.equal(call.referrerPolicy, 'no-referrer');
  }
  assert.equal(calls[0].headers['Idempotency-Key'], undefined);
  assert.equal(calls[1].headers['Idempotency-Key'], undefined);
  assert.match(calls[2].headers['Idempotency-Key'], /^fgdn-[0-9a-f]{32}-[0-9a-f]{64}$/);
  const form = new URLSearchParams(calls[2].body);
  assert.equal(form.get('expected_principal'), binding.principal);
  assert.equal(form.get('expected_incarnation'), binding.incarnation);
  assert.equal(form.get('read_through'), '4');
  client.disconnect();
});

test('discussion actions capture the observed prefix and retain only applicable guarded fields', () => {
  assert.deepEqual(threadAction(row, 'read', 'discussion'), [7, 2, 'read', { read_through: 4 }]);
  const implicit = { ...row, preference_version: null, read_through: null };
  assert.deepEqual(threadAction(implicit, 'subscribe', 'discussion'), [7, 0, 'subscribe', {}]);
  for (const action of ['subscribe', 'mute', 'automatic', 'unread']) {
    assert.deepEqual(threadAction(row, action, 'discussion'), [7, 2, action, {}]);
    const form = new URLSearchParams(notificationMutationRequest(7, 2, action, {}, binding).body);
    assert.equal(form.has('read_through'), false);
    assert.throws(() => notificationMutationRequest(7, 2, action, { read_through: 4 }, binding));
  }
  assert.throws(() => threadAction(row, 'delete', 'discussion'));
  assert.throws(() => threadAction({ ...row, issue_version: 4 }, 'read', 'discussion'));
  assert.throws(() => notificationMutationRequest(7, 2, 'read',
    { read_through: 4, principal: binding.principal }, binding));
});

test('identical issue and discussion preference bodies use different key digests and receipt domains', async () => {
  const cryptoImpl = { subtle: webcrypto.subtle, getRandomValues(value) { value.fill(5); return value; } };
  const { discussion_version: _, ...issueRow } = row;
  const { target_kind: omitted, ...issuePage } = page();
  issuePage.type = 'notification_page'; issuePage.threads = [{ ...issueRow, issue_version: 4 }];
  const issue = new NotificationClient({ href: issueHref, cryptoImpl, fetchImpl: async () => json(issuePage) });
  const discussion = new DiscussionNotificationClient({ href, cryptoImpl, fetchImpl: async () => json(page()) });
  await prepare(issue); await prepare(discussion);
  const issueReceipt = JSON.parse(issue.exportReceipt()), discussionReceipt = JSON.parse(discussion.exportReceipt());
  assert.equal(issueReceipt.request.body, discussionReceipt.request.body);
  assert.equal(issueReceipt.request.key.split('-')[1], discussionReceipt.request.key.split('-')[1]);
  assert.notEqual(issueReceipt.request.key.split('-')[2], discussionReceipt.request.key.split('-')[2]);
  assert.match(issueReceipt.request.key, /^fgni-/);
  assert.match(discussionReceipt.request.key, /^fgdn-/);
  assert.equal(discussionReceipt.schema, 'frankengit-discussion_notification-retry-v1');
  assert.equal(JSON.stringify(discussionReceipt).includes(token), false);
  let dispatches = 0;
  const fetchImpl = async () => { dispatches += 1; throw new Error('restore must not dispatch'); };
  const issueReceiver = new NotificationClient({ href: issueHref, cryptoImpl, fetchImpl });
  const discussionReceiver = new DiscussionNotificationClient({ href, cryptoImpl, fetchImpl });
  await issueReceiver.connect(token); await discussionReceiver.connect(token);
  await assert.rejects(issueReceiver.restoreReceipt(JSON.stringify(discussionReceipt)), /does not belong/);
  await assert.rejects(discussionReceiver.restoreReceipt(JSON.stringify(issueReceipt)), /does not belong/);
  const forged = structuredClone(issueReceipt);
  forged.schema = discussionReceipt.schema; forged.request.key = forged.request.key.replace(/^fgni/, 'fgdn');
  await assert.rejects(discussionReceiver.restoreReceipt(JSON.stringify(forged)), /does not commit/);
  assert.equal(dispatches, 0);
  for (const client of [issue, discussion, issueReceiver, discussionReceiver]) client.disconnect();
});

test('lost discussion preference responses resend the identical key, path and body', async () => {
  const calls = []; let posts = 0;
  const client = fresh(async (url, init) => {
    calls.push(recorded(url, init));
    if (init.method === 'GET') return json(page());
    if (++posts === 1) throw new Error('response lost');
    return json(terminal);
  });
  await prepare(client);
  const pending = client.pending;
  await assert.rejects(client.send(), error => error.outcomeUnknown === true);
  assert.equal(client.pending.key, pending.key); assert.equal(client.pending.body, pending.body);
  assert.equal(client.pending.sent, true);
  await assert.rejects(client.stage(7, 3, 'mute', {}));
  assert.throws(() => client.discardUnsent());
  assert.equal((await client.send()).tx, terminal.tx_id);
  assert.equal(client.pending, null);
  const mutations = calls.filter(call => call.method === 'POST');
  assert.equal(mutations.length, 2);
  for (const call of mutations) {
    assert.equal(call.url, mutations[0].url);
    assert.equal(call.body, pending.body);
    assert.equal(call.headers['Idempotency-Key'], pending.key);
  }
  client.disconnect();
});

test('foreign or missing publication target kinds cannot settle a discussion preference', async () => {
  let patch = {};
  const calls = [], client = fresh(async (url, init) => {
    calls.push(recorded(url, init));
    return json(init.method === 'GET' ? page() : { ...terminal, ...patch });
  });
  await prepare(client);
  const pending = client.pending;
  for (patch of [{ target_kind: 'issue' }, { target_kind: undefined },
    { type: 'notification_publication' }, { principal_id: '9'.repeat(32) }]) {
    await assert.rejects(client.send(), error => error.outcomeUnknown === true);
    assert.equal(client.pending.key, pending.key); assert.equal(client.pending.body, pending.body);
  }
  patch = {};
  assert.equal((await client.send()).outcome, 'committed');
  assert.equal(client.pending, null);
  assert.ok(calls.filter(call => call.method === 'POST').every(call =>
    call.headers['Idempotency-Key'] === pending.key && call.body === pending.body));
  client.disconnect();
});

test('discussion receipts retain immutable identity guards and reject altered read prefixes', async () => {
  const original = fresh(async () => json(page()));
  await prepare(original);
  const receipt = JSON.parse(original.exportReceipt()); original.disconnect();
  let dispatches = 0;
  const client = fresh(async () => { dispatches += 1; return json(page()); });
  await observe(client);
  for (const change of [
    value => { value.request.fields.read_through = 3; },
    value => { value.request.binding.principal = '9'.repeat(32); },
    value => { value.request.binding.incarnation = '8'.repeat(32); },
    value => { delete value.request.binding.principal; },
  ]) {
    const altered = structuredClone(receipt); change(altered);
    await assert.rejects(client.restoreReceipt(JSON.stringify(altered)));
    assert.equal(client.pending, null);
  }
  await client.restoreReceipt(JSON.stringify(receipt));
  assert.equal(client.pending.key, receipt.request.key);
  assert.equal(client.pending.body, receipt.request.body);
  assert.equal(client.pending.sent, true);
  assert.throws(() => client.discardUnsent());
  assert.equal(dispatches, 1, 'receipt import only used the earlier identity read');
  client.disconnect();
});

test('discussion recovery uses the original key without replay and preserves nonterminal responsibility', async () => {
  const original = fresh(async () => json(page())); await prepare(original);
  const serialized = original.exportReceipt(); original.disconnect();
  let answer = recovery('key_not_observed');
  const calls = [], client = fresh(async (url, init) => {
    calls.push(recorded(url, init)); return json(answer);
  });
  await client.connect(token); await client.restoreReceipt(serialized);
  const pending = client.pending;
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    answer = recovery(state);
    assert.deepEqual(await client.recover(), { state, terminal: false });
    assert.equal(client.pending.key, pending.key); assert.equal(client.pending.body, pending.body);
    assert.throws(() => client.discardUnsent());
  }
  for (const field of ['principal_id', 'repository_incarnation']) {
    answer = { ...recovery('committed'), [field]: '9'.repeat(32) };
    await assert.rejects(client.recover(), /identity changed/);
    assert.equal(client.pending.key, pending.key);
  }
  answer = recovery('committed');
  assert.equal((await client.recover()).tx, terminal.tx_id);
  assert.equal(client.pending, null);
  assert.equal(calls.length, 6);
  for (const call of calls) {
    assert.equal(new URL(call.url).pathname, '/repo.git/api/v1/outcomes');
    assert.equal(call.method, 'POST'); assert.equal(call.body, undefined);
    assert.equal(call.headers['Idempotency-Key'], pending.key);
  }
  client.disconnect();
});

test('discussion controller continuation pins source and filters and discards superseded pages', async () => {
  const first = { reply: page({ limit: 1, next_after: 7, unread_only: true }), binding, head };
  const next = { reply: page({ after: 7, threads: [{ ...row, number: 8 }], unread_only: true }), binding, head };
  const old = deferred(), current = deferred();
  const responses = [Promise.resolve(first), Promise.resolve(next), old.promise, current.promise];
  const calls = [];
  // The controller double deliberately resolves an ignored cancellation so
  // the controller's own epoch guard, independent of fetch, is exercised.
  const client = { targetKind: 'discussion', cancelReads() {},
    read(number, options) { calls.push({ number, options }); return responses.shift(); } };
  const controller = new NotificationInboxController(client);
  assert.equal(await controller.load({ unreadOnly: true, includeMuted: false }), first);
  assert.equal(await controller.load({ unreadOnly: false, includeMuted: true }, true), next);
  assert.deepEqual(calls[1], { number: null,
    options: { unreadOnly: true, includeMuted: false, after: 7, head } });
  const oldRead = controller.load({ unreadOnly: false, includeMuted: false });
  const currentRead = controller.load({ unreadOnly: false, includeMuted: true });
  const newer = { ...first, head: 'alg:2:' + 'a'.repeat(64) };
  current.resolve(newer); assert.equal(await currentRead, newer);
  old.resolve(first); assert.equal(await oldRead, null);
  assert.equal(controller.page, newer);
});

test('discussion controller captures displayed versions before asynchronous staging and never replaces a lost request', async () => {
  const calls = [], client = fresh(async (url, init) => {
    calls.push(recorded(url, init));
    if (init.method === 'GET') return json(page());
    throw new Error('response lost');
  });
  await observe(client);
  const controller = new NotificationInboxController(client), displayed = structuredClone(row);
  const changing = controller.change(displayed, 'read');
  displayed.discussion_version = 99; displayed.preference_version = 98;
  await assert.rejects(changing, error => error.outcomeUnknown === true);
  assert.equal(client.pending.expected_version, 2);
  assert.deepEqual(client.pending.fields, { read_through: 4 });
  const key = client.pending.key;
  await assert.rejects(controller.change(displayed, 'mute'), /Resolve the original/);
  assert.equal(client.pending.key, key);
  assert.equal(calls.filter(call => call.method === 'POST').length, 1);
  client.disconnect();
});

// Reuse the repository's event/text DOM oracle with the real shipped HTML.
// Only the selector used by this view is added; this is not a browser engine.
function notificationDom() {
  const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/discussion-notifications.html', import.meta.url), 'utf8');
  class InboxElement extends Element {
    querySelectorAll(selector) {
      assert.equal(selector, 'button');
      return this.descendants().filter(child => child.tagName === 'BUTTON');
    }
  }
  const elements = new Map();
  const document = { downloads: [],
    createElement(tag) { return new InboxElement(tag, document); },
    getElementById(id) { return elements.get(id) ?? null; } };
  for (const match of html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)) {
    const element = document.createElement(match[1]); element.id = match[2];
    element.checked = /\bchecked\b/.test(match[0]); element.hidden = /\bhidden\b/.test(match[0]);
    elements.set(element.id, element);
  }
  return { document, get: id => document.getElementById(id) };
}
async function until(predicate) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await tick();
  }
  assert.ok(predicate(), 'mounted view did not reach its expected state');
}

test('mounted discussion inbox renders literal titles and retains unresolved observed-prefix requests on disconnect', async () => {
  const { document, get } = notificationDom();
  const client = fresh(async (_url, init) => {
    if (init.method === 'GET') return json(page());
    throw new Error('response lost');
  });
  mountNotificationInbox({ document, href, client });
  get('inbox-token').value = token;
  assert.equal(get('inbox-connect').emit('submit').defaultPrevented, true);
  await until(() => get('inbox-status').textContent === '1 discussion shown.');
  assert.equal(get('inbox-token').value, '');
  assert.ok(get('inbox-content').textContent.includes(row.title));
  assert.ok(get('inbox-content').textContent.includes('discussion version 4'));
  assert.equal(get('inbox-content').descendants().some(element => element.tagName === 'SCRIPT'), false);
  get('inbox-content').querySelectorAll('button').find(button => button.textContent === 'Mark read').click();
  await until(() => get('inbox-status').textContent.startsWith('Outcome unknown:'));
  assert.ok(get('inbox-pending-summary').textContent.startsWith('Discussion #7: read'));
  assert.equal(get('inbox-discard').disabled, true);
  assert.ok(get('inbox-content').querySelectorAll('button').every(button => button.disabled));
  assert.deepEqual(client.pending.fields, { read_through: 4 });
  const key = client.pending.key;
  get('inbox-number').value = '7'; get('inbox-disconnect').click();
  assert.equal(get('inbox-content').textContent, '');
  assert.equal(get('inbox-snapshot').textContent, '');
  assert.equal(get('inbox-number').value, '');
  assert.equal(client.connected, false);
  assert.equal(client.pending.key, key, 'disconnect preserves the token-free recovery responsibility');
});

test('mounted discussion receipt imports cannot cross a connection change', async () => {
  const { document, get } = notificationDom(), client = fresh(async () => json(page()));
  let restores = 0;
  const restore = client.restoreReceipt.bind(client);
  client.restoreReceipt = async value => { restores += 1; return restore(value); };
  mountNotificationInbox({ document, href, client });
  get('inbox-token').value = token; get('inbox-connect').emit('submit');
  await until(() => get('inbox-status').textContent === '1 discussion shown.');
  const pendingFile = deferred();
  let fileRead = false;
  get('inbox-restore').files = [{ size: 2, arrayBuffer() { fileRead = true; return pendingFile.promise; } }];
  const importing = Promise.all(get('inbox-restore').listeners.get('change').map(handler => handler({})));
  assert.equal(fileRead, true, 'the selected File byte read really started');
  get('inbox-disconnect').click();
  pendingFile.resolve(new TextEncoder().encode('{}').buffer);
  await importing;
  assert.equal(restores, 0); assert.equal(client.pending, null);
  assert.equal(client.connected, false);
  assert.equal(get('inbox-status').textContent, 'Disconnected.', 'an old import must not overwrite the current session status');
  assert.equal(get('inbox-content').textContent, '');
});
