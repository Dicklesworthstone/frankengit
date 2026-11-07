// Production clients and views with real Node WebCrypto and explicit HTTP/DOM
// contract doubles. Native authority and permission enforcement are tested in Rust.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  NotificationClient, DiscussionNotificationClient, PullRequestNotificationClient,
  notificationState, notificationPage, notificationThread,
} from '../../crates/fgit-node/src/smart_http/server/browser/notifications.mjs';
import {
  mountNotificationInbox, NotificationInboxController, threadAction,
} from '../../crates/fgit-node/src/smart_http/server/browser/notifications-view.mjs';
import { Element, tick } from './search-dom-fixture.mjs';

const href = 'https://forge.example/repo.git/ui/pull-notifications/';
const token = 'c'.repeat(64), head = 'alg:2:' + 'b'.repeat(64);
const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
  principal_id: '3'.repeat(32), repository_incarnation: '4'.repeat(32) };
const binding = { tenant: ids.tenant_id, repository: ids.repository_id,
  principal: ids.principal_id, incarnation: ids.repository_incarnation };
const positions = { authority_head_generation: 9, forge_position_root: 'alg:2:' + '5'.repeat(64),
  outbox_root: 'alg:2:' + '6'.repeat(64), complete: true };
const row = { number: 7, activity_version: 4, title: 'Review 雪 <script>literal</script>', state: 'merged',
  preference_version: 2, mode: 'automatic', read_through: 1, latest_other_version: 3,
  unread: true, reasons: ['author', 'participant'] };
const page = (patch = {}) => ({ ...ids, type: 'pull_request_notification_page', target_kind: 'pull_request',
  snapshot_token: head, source_positions: positions, after: 0, limit: 20,
  unread_only: false, include_muted: false, next_after: null, threads: [row], ...patch });
const thread = (patch = {}) => ({ ...ids, type: 'pull_request_notification_thread', target_kind: 'pull_request',
  snapshot_token: head, source_positions: positions, found: true, thread: row, ...patch });
const terminal = { schema_version: 1, tenant_id: ids.tenant_id, repository_id: ids.repository_id,
  principal_id: ids.principal_id, type: 'pull_request_notification_publication', target_kind: 'pull_request',
  number: 7, expected_version: 2, action: 'read', tx_id: 'original-pull-notification-tx',
  outcome: 'committed', decision_sequence: 10, repository_commit_id: 'original-rcr',
  refusal_record_id: null, refusal_code: null, delivery_acknowledged: null };
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
});
const fresh = fetchImpl => new PullRequestNotificationClient({ href, fetchImpl, cryptoImpl: webcrypto });
const observe = async client => { await client.connect(token); await client.read(); };

test('PR inbox accepts lifecycle, comment and review activity cursors without confusing metadata versions', () => {
  assert.equal(notificationState(row, 'pull_request'), row);
  for (const state of ['open', 'closed', 'merged']) {
    assert.equal(notificationState({ ...row, state }, 'pull_request').state, state);
  }
  for (const patch of [
    { activity_version: undefined, pull_request_version: 4 }, { pull_request_version: 1 },
    { issue_version: 4 }, { discussion_version: 4 }, { activity_version: 0 },
    { read_through: 5 }, { latest_other_version: 5 }, { unread: false },
    { reasons: ['assignee'] }, { reasons: ['reviewer'] }, { reasons: ['participant', 'author'] },
  ]) assert.throws(() => notificationState({ ...row, ...patch }, 'pull_request'));
  const ownOnly = { ...row, latest_other_version: null, unread: false };
  assert.equal(notificationState(ownOnly, 'pull_request').unread, false);
  assert.deepEqual(threadAction(row, 'read', 'pull_request'), [7, 2, 'read', { read_through: 4 }]);
  assert.throws(() => notificationState(row, 'discussion'));
  const { activity_version: _, ...merged } = row;
  for (const [kind, field] of [['issue', 'issue_version'], ['discussion', 'discussion_version']]) {
    assert.throws(() => notificationState({ ...merged, [field]: 4 }, kind), 'merged is a PR-only state');
  }
});

test('PR pages and exact lookups bind kind, recipient, snapshot and complete source positions', () => {
  assert.deepEqual(notificationPage(page(), { kind: 'pull_request', binding }).binding, binding);
  assert.equal(notificationThread(thread(), 7, { kind: 'pull_request', binding, head }).reply.thread, row);
  for (const patch of [
    { target_kind: undefined }, { target_kind: 'discussion' }, { type: 'notification_page' },
    { threads: [row, row] }, { next_after: 7 }, { threads: [{ ...row, pull_request_version: 1 }] },
    { source_positions: { ...positions, complete: false } },
  ]) assert.throws(() => notificationPage(page(patch), { kind: 'pull_request' }));
  for (const field of ['tenant_id', 'repository_id', 'principal_id', 'repository_incarnation']) {
    assert.throws(() => notificationPage(page({ [field]: '9'.repeat(32) }), { kind: 'pull_request', binding }));
  }
  assert.throws(() => notificationPage(page(), { kind: 'discussion' }));
  assert.throws(() => notificationPage(page(), { kind: 'pull_request', head: 'alg:2:' + 'a'.repeat(64) }));
  assert.equal(notificationThread(thread({ found: false, thread: null }), 7, { kind: 'pull_request' }).reply.found, false);
  assert.throws(() => notificationThread(thread({ target_kind: 'discussion' }), 7, { kind: 'pull_request' }));
});

test('PR read actions capture the displayed activity prefix and preserve the exact request after reply loss', async () => {
  const calls = []; let posts = 0;
  const client = fresh(async (url, init) => {
    calls.push({ url: String(url), ...init });
    if (init.method === 'GET') return json(new URL(url).pathname.endsWith('/7') ? thread() : page());
    if (++posts === 1) throw Error('response lost');
    return json(terminal);
  });
  await client.connect(token);
  await assert.rejects(client.stage(7, 2, 'read', { read_through: 4 }), /Read your notification identity/);
  await client.read(); await client.read(7, { head });
  const controller = new NotificationInboxController(client), displayed = structuredClone(row);
  const changing = controller.change(displayed, 'read');
  displayed.activity_version = 99; displayed.preference_version = 98;
  await assert.rejects(changing, error => error.outcomeUnknown === true);
  const pending = client.pending;
  assert.equal(pending.expected_version, 2); assert.deepEqual(pending.fields, { read_through: 4 });
  assert.match(pending.key, /^fgpn-[0-9a-f]{32}-[0-9a-f]{64}$/);
  assert.equal(new URL(calls[0].url).pathname, '/repo.git/api/v1/notifications/pulls');
  assert.equal(new URL(calls[1].url).pathname, '/repo.git/api/v1/notifications/pulls/7');
  assert.equal(new URL(calls[1].url).searchParams.get('expected_head'), head);
  await assert.rejects(controller.change(displayed, 'mute'), /Resolve the original/);
  assert.equal((await client.send()).outcome, 'committed');
  for (const call of calls.filter(call => call.method === 'POST')) {
    assert.equal(new URL(call.url).pathname, '/repo.git/api/v1/notifications/pulls/7/read');
    assert.equal(call.headers['Idempotency-Key'], pending.key); assert.equal(call.body, pending.body);
    const form = new URLSearchParams(call.body);
    assert.equal(form.get('read_through'), '4');
    assert.equal(form.get('expected_principal'), binding.principal);
    assert.equal(form.get('expected_incarnation'), binding.incarnation);
    assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error');
  }
  assert.equal(client.pending, null); client.disconnect();
});

test('PR receipt digests cannot be repurposed for same-number issue or discussion preferences', async () => {
  const cryptoImpl = { subtle: webcrypto.subtle, getRandomValues(value) { value.fill(5); return value; } };
  const profiles = [
    ['issue', NotificationClient, 'notifications', 'issue_version', 'fgni'],
    ['discussion', DiscussionNotificationClient, 'discussion-notifications', 'discussion_version', 'fgdn'],
    ['pull_request', PullRequestNotificationClient, 'pull-notifications', 'activity_version', 'fgpn'],
  ];
  const clients = [], receipts = [];
  for (const [kind, Client, suffix, version, prefix] of profiles) {
    const { activity_version: _, ...selected } = row;
    const reply = page({ type: kind === 'issue' ? 'notification_page' : `${kind}_notification_page`,
      target_kind: kind === 'issue' ? undefined : kind, threads: [{ ...selected, state: 'open', [version]: 4 }] });
    const client = new Client({ href: href.replace('pull-notifications', suffix), cryptoImpl, fetchImpl: async () => json(reply) });
    await observe(client); await client.stage(7, 2, 'read', { read_through: 4 });
    clients.push(client); receipts.push(JSON.parse(client.exportReceipt()));
    assert.match(client.pending.key, new RegExp('^' + prefix + '-'));
    assert.equal(client.exportReceipt().includes(token), false);
  }
  assert.equal(new Set(receipts.map(receipt => receipt.request.body)).size, 1);
  assert.equal(new Set(receipts.map(receipt => receipt.request.key.split('-')[1])).size, 1);
  assert.equal(new Set(receipts.map(receipt => receipt.request.key.split('-')[2])).size, 3);
  assert.equal(receipts[2].schema, 'frankengit-pull_request_notification-retry-v1');
  clients.forEach(client => client.disconnect());
  for (const [index, [kind, Client, suffix]] of profiles.entries()) {
    let calls = 0;
    const client = new Client({ href: href.replace('pull-notifications', suffix), cryptoImpl,
      fetchImpl: async () => { calls++; throw Error('restore does not dispatch'); } });
    await client.connect(token);
    for (const [other, receipt] of receipts.entries()) if (other !== index) {
      await assert.rejects(client.restoreReceipt(JSON.stringify(receipt)), /does not belong/);
    }
    const forged = structuredClone(receipts[(index + 1) % profiles.length]);
    forged.schema = receipts[index].schema;
    forged.request.key = forged.request.key.replace(/^[^-]+/, profiles[index][4]);
    await assert.rejects(client.restoreReceipt(JSON.stringify(forged)), /does not commit/);
    assert.equal(client.pending, null); assert.equal(calls, 0, kind); client.disconnect();
  }
});

test('foreign notification publications cannot settle a PR preference or replace its retry key', async () => {
  let patch = {};
  const client = fresh(async (_url, init) => json(init.method === 'GET' ? page() : { ...terminal, ...patch }));
  await observe(client); await client.stage(7, 2, 'read', { read_through: 4 });
  const pending = client.pending;
  for (patch of [{ target_kind: 'discussion' }, { target_kind: undefined },
    { type: 'discussion_notification_publication' }, { principal_id: '9'.repeat(32) }]) {
    await assert.rejects(client.send(), error => error.outcomeUnknown === true);
    assert.equal(client.pending.key, pending.key); assert.equal(client.pending.body, pending.body);
  }
  patch = {}; assert.equal((await client.send()).outcome, 'committed'); client.disconnect();
});

function inboxDom() {
  const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/pull-notifications.html', import.meta.url), 'utf8');
  class InboxElement extends Element {
    querySelectorAll(selector) {
      assert.equal(selector, 'button');
      return this.descendants().filter(child => child.tagName === 'BUTTON');
    }
  }
  const elements = new Map();
  const document = { downloads: [], createElement(tag) { return new InboxElement(tag, document); },
    getElementById(id) { return elements.get(id) ?? null; } };
  for (const match of html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)) {
    const element = document.createElement(match[1]); element.id = match[2];
    element.checked = /\bchecked\b/.test(match[0]); element.hidden = /\bhidden\b/.test(match[0]);
    elements.set(element.id, element);
  }
  return { document, get: id => document.getElementById(id) };
}
async function until(predicate) {
  for (let attempt = 0; attempt < 100 && !predicate(); attempt++) await tick();
  assert.ok(predicate(), 'PR inbox did not reach its expected state');
}

test('mounted PR inbox renders merged activity, captures the observed prefix and retains pending recovery on disconnect', async () => {
  const { document, get } = inboxDom();
  const client = fresh(async (_url, init) => {
    if (init.method === 'GET') return json(page());
    throw Error('response lost');
  });
  mountNotificationInbox({ document, href, client });
  get('inbox-token').value = token; get('inbox-connect').emit('submit');
  await until(() => get('inbox-status').textContent === '1 pull request shown.');
  assert.equal(get('inbox-token').value, '');
  assert.ok(get('inbox-content').textContent.includes(row.title));
  assert.ok(get('inbox-content').textContent.includes('merged'));
  assert.ok(get('inbox-content').textContent.includes('activity version 4'));
  assert.equal(get('inbox-content').descendants().some(element => element.tagName === 'SCRIPT'), false);
  get('inbox-content').querySelectorAll('button').find(button => button.textContent === 'Mark read').click();
  await until(() => get('inbox-status').textContent.startsWith('Outcome unknown:'));
  assert.ok(get('inbox-pending-summary').textContent.startsWith('Pull request #7: read'));
  assert.deepEqual(client.pending.fields, { read_through: 4 });
  const key = client.pending.key;
  get('inbox-disconnect').click();
  assert.equal(get('inbox-content').textContent, ''); assert.equal(client.connected, false);
  assert.equal(client.pending.key, key);
});
