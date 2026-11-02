// Browser response-schema and controller contract doubles, not Rust authority,
// persistence, HTTP authentication, or interoperability evidence. Real Node
// WebCrypto derives request keys; Response doubles exercise bounded decoding.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { IssueClient } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { MilestoneClient } from '../../crates/fgit-node/src/smart_http/server/browser/milestones.mjs';
import {
  NotificationClient, notificationMutationRequest, notificationState,
  notificationPage, notificationThread,
} from '../../crates/fgit-node/src/smart_http/server/browser/notifications.mjs';
import { NotificationInboxController, threadAction }
  from '../../crates/fgit-node/src/smart_http/server/browser/notifications-view.mjs';

const href = 'https://forge.example/repo.git/ui/notifications/';
const issueHref = 'https://forge.example/repo.git/ui/issues/';
const token = 'c'.repeat(64), head = `alg:2:${'b'.repeat(64)}`;
const ids = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
  principal_id: '3'.repeat(32), repository_incarnation: '4'.repeat(32) };
const binding = { tenant: ids.tenant_id, repository: ids.repository_id,
  principal: ids.principal_id, incarnation: ids.repository_incarnation };
const positions = { authority_head_generation: 9, forge_position_root: `alg:2:${'5'.repeat(64)}`,
  outbox_root: `alg:2:${'6'.repeat(64)}`, complete: true };
const row = { number: 7, issue_version: 4, title: 'Review 雪 <script>inert</script>', state: 'open',
  preference_version: 2, mode: 'automatic', read_through: 1, latest_other_version: 3,
  unread: true, reasons: ['author', 'participant'] };
const page = { ...ids, type: 'notification_page', snapshot_token: head, source_positions: positions,
  after: 0, limit: 20, unread_only: false, include_muted: false, next_after: null, threads: [row] };
const thread = { ...ids, type: 'notification_thread', snapshot_token: head, source_positions: positions,
  found: true, thread: row };
const terminal = { ...ids, type: 'notification_publication', number: 7, expected_version: 2,
  action: 'read', tx_id: 'original-notification-tx', outcome: 'committed', decision_sequence: 10,
  repository_commit_id: 'original-notification-rcr', refusal_record_id: null, refusal_code: null,
  delivery_acknowledged: null };
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' },
});
const fresh = fetchImpl => new NotificationClient({ href, fetchImpl, cryptoImpl: webcrypto });
const recovery = (state = 'committed') => {
  const settled = state === 'committed' || state === 'refused';
  return { ...ids, type: 'transaction_outcome', selector: 'transaction', command_index: null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false,
    session_completeness_established: false, terminal: settled, state,
    transaction: settled || state === 'undecided' ? { tx_id: terminal.tx_id } : null,
    decision: settled ? { kind: state, decision_sequence: 10, repository_commit_id: terminal.repository_commit_id } : null };
};
const observe = async client => { await client.connect(token); await client.read(); };
const prepare = async client => { await observe(client); await client.stage(7, 2, 'read', { read_through: 4 }); };
const recorded = (url, init) => ({ url: String(url), ...init });
const deferred = () => {
  let resolve;
  const promise = new Promise(accept => { resolve = accept; });
  return { promise, resolve };
};

test('notification forms require bounded fields and explicit expected identity guards', () => {
  const request = notificationMutationRequest(7, 2, 'read', { read_through: 4 }, binding);
  const form = new URLSearchParams(request.body);
  assert.deepEqual([...form.keys()].sort(), ['expected_incarnation', 'expected_principal', 'expected_version', 'read_through']);
  assert.equal(form.get('expected_principal'), binding.principal);
  assert.equal(form.get('expected_incarnation'), binding.incarnation);
  assert.equal(form.get('expected_version'), '2');
  assert.equal(form.get('read_through'), '4');
  assert.deepEqual(request.fields, { read_through: 4 });
  for (const action of ['subscribe', 'mute', 'automatic', 'unread']) {
    const value = notificationMutationRequest(7, 0, action, {}, binding);
    assert.equal(new URLSearchParams(value.body).get('expected_version'), '0');
    assert.equal(new URLSearchParams(value.body).has('read_through'), false);
    assert.throws(() => notificationMutationRequest(7, 2, action, { read_through: 4 }, binding));
  }
  for (const fields of [{}, { read_through: 0 }, { read_through: 1.5 }, { read_through: '4' },
    { read_through: 4, principal: binding.principal }, { read_through: 4, expected_incarnation: binding.incarnation }]) {
    assert.throws(() => notificationMutationRequest(7, 2, 'read', fields, binding));
  }
  for (const invalid of [null, {}, { ...binding, principal: 'other' }, { ...binding, incarnation: 'A'.repeat(32) }]) {
    assert.throws(() => notificationMutationRequest(7, 2, 'read', { read_through: 4 }, invalid));
  }
  assert.throws(() => notificationMutationRequest(7, 2, 'read', { read_through: 4 }));
  assert.throws(() => notificationMutationRequest(0, 2, 'mute', {}, binding));
  assert.throws(() => notificationMutationRequest(7, Number.MAX_SAFE_INTEGER, 'mute', {}, binding));
  assert.throws(() => notificationMutationRequest(7, 2, 'delete', {}, binding));
});

test('notification unread state derives from canonical versions and excludes own-only activity', () => {
  assert.equal(notificationState(row), row);
  assert.equal(notificationState({ ...row, read_through: 3, unread: false }).unread, false);
  assert.equal(notificationState({ ...row, latest_other_version: null, unread: false }).unread, false);
  assert.equal(notificationState({ ...row, preference_version: null, read_through: null }).unread, true);
  assert.equal(notificationState({ ...row, mode: 'muted', reasons: [] }).mode, 'muted');
  assert.equal(notificationState({ ...row, mode: 'subscribed', reasons: ['subscribed'] }).mode, 'subscribed');
  for (const patch of [{ unread: false }, { read_through: 5 }, { latest_other_version: 5 },
    { latest_other_version: null, unread: true }, { preference_version: 0 }, { issue_version: 0 },
    { preference_version: null }, { mode: 'subscribed' }, { reasons: ['participant', 'author'] },
    { reasons: ['author', 'author'] }, { reasons: ['watcher'] }, { title: '\ud800' }, { title: ' ' }, { state: 'gone' }]) {
    assert.throws(() => notificationState({ ...row, ...patch }));
  }
});

test('notification pages and exact threads require matching source, recipient, filters and order', () => {
  assert.deepEqual(notificationPage(page, { binding }).binding, binding);
  assert.equal(notificationThread(thread, 7, { binding, head }).reply.thread, row);
  for (const field of ['tenant_id', 'repository_id', 'principal_id', 'repository_incarnation']) {
    assert.throws(() => notificationPage({ ...page, [field]: '9'.repeat(32) }, { binding }));
  }
  for (const patch of [{ threads: [row, row] }, { threads: [{ ...row, number: 8 }, row] },
    { next_after: 7 }, { unread_only: true }, { include_muted: true }, { type: 'issue_page' },
    { source_positions: { ...positions, complete: false } },
    { source_positions: { ...positions, outbox_root: '' } }]) {
    assert.throws(() => notificationPage({ ...page, ...patch }, { binding }));
  }
  assert.throws(() => notificationPage(page, { head: `alg:2:${'a'.repeat(64)}` }));
  assert.throws(() => notificationPage({ ...page, after: 7 }, { after: 7 }));
  assert.throws(() => notificationPage({ ...page, threads: [{ ...row, mode: 'muted', reasons: [] }] }));
  assert.throws(() => notificationPage({ ...page, unread_only: true, threads: [{ ...row, read_through: 3, unread: false }] }, { unreadOnly: true }));
  const first = { ...page, limit: 1, next_after: 7 };
  assert.equal(notificationPage(first, { limit: 1 }).reply.next_after, 7);
  const missing = { ...thread, found: false, thread: null };
  assert.equal(notificationThread(missing, 7).reply.found, false);
  assert.throws(() => notificationThread(thread, 8));
  assert.throws(() => notificationThread({ ...missing, thread: row }, 7));
});

test('notification transport uses repository routes, safe credential headers and guarded fgni keys', async () => {
  const calls = [], client = fresh(async (url, init) => {
    calls.push(recorded(url, init));
    return json(init.method === 'POST' ? terminal : String(url).includes('/notifications/7?') ? thread : page);
  });
  assert.throws(() => new NotificationClient({ href: issueHref, cryptoImpl: webcrypto }));
  assert.throws(() => new NotificationClient({ href: href.replace('https:', 'http:'), cryptoImpl: webcrypto }));
  await observe(client);
  await client.read(7, { head });
  await client.stage(7, 2, 'read', { read_through: 4 });
  assert.equal((await client.send()).outcome, 'committed');
  assert.equal(calls.length, 3);
  assert.ok(calls[0].url.includes('/repo.git/api/v1/notifications?'));
  assert.equal(new URL(calls[1].url).searchParams.get('expected_head'), head);
  assert.ok(calls[2].url.endsWith('/repo.git/api/v1/notifications/7/read'));
  for (const call of calls) {
    assert.equal(call.headers.Authorization, `Bearer ${token}`);
    assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error');
    assert.equal(call.mode, 'same-origin'); assert.equal(call.cache, 'no-store');
    assert.equal(call.referrerPolicy, 'no-referrer');
  }
  assert.equal(calls[0].headers['Idempotency-Key'], undefined);
  assert.equal(calls[1].headers['Idempotency-Key'], undefined);
  assert.match(calls[2].headers['Idempotency-Key'], /^fgni-[0-9a-f]{32}-[0-9a-f]{64}$/);
  assert.equal(new URLSearchParams(calls[2].body).get('expected_principal'), binding.principal);
  assert.equal(new URLSearchParams(calls[2].body).get('expected_incarnation'), binding.incarnation);
  client.disconnect();
});

test('notification staging requires an observed full binding and refuses offline two-field replacement', async () => {
  const calls = [], client = fresh(async (url, init) => { calls.push(recorded(url, init)); return json(page); });
  await client.connect(token);
  await assert.rejects(client.stage(7, 2, 'mute', {}), /Read your notification identity/);
  await assert.rejects(client.stage(7, 2, 'mute', {}, { tenant: binding.tenant, repository: binding.repository }));
  assert.equal(calls.length, 0); assert.equal(client.pending, null);
  await client.read();
  assert.deepEqual(client.binding, binding);
  await assert.rejects(client.stage(7, 2, 'mute', {}, { tenant: binding.tenant, repository: binding.repository }));
  await client.stage(7, 2, 'mute', {});
  assert.deepEqual(client.pending.binding, binding);
  assert.equal(calls.length, 1, 'staging never dispatches');
  client.discardUnsent(); client.disconnect();
});

test('a lost notification response retains the original body and key for an identical resend', async () => {
  const calls = []; let attempted = false;
  const client = fresh(async (url, init) => {
    calls.push(recorded(url, init));
    if (init.method === 'GET') return json(page);
    if (!attempted) { attempted = true; throw new Error('response lost'); }
    return json(terminal);
  });
  await prepare(client);
  const prepared = client.pending;
  await assert.rejects(client.send(), error => error.outcomeUnknown === true);
  assert.equal(client.pending.key, prepared.key); assert.equal(client.pending.body, prepared.body);
  assert.equal(client.pending.sent, true);
  await assert.rejects(client.stage(7, 3, 'mute', {}));
  assert.throws(() => client.discardUnsent());
  assert.equal((await client.send()).tx, terminal.tx_id); assert.equal(client.pending, null);
  const posts = calls.filter(call => call.method === 'POST');
  assert.equal(posts.length, 2);
  assert.equal(posts[0].body, posts[1].body); assert.equal(posts[0].url, posts[1].url);
  assert.equal(posts[0].headers['Idempotency-Key'], posts[1].headers['Idempotency-Key']);
  client.disconnect();
});

test('notification receipts reject cross-profile, tampered and rebound identity recovery before dispatch', async () => {
  const original = fresh(async () => json(page)); await prepare(original);
  const serialized = original.exportReceipt(), receipt = JSON.parse(serialized);
  assert.equal(receipt.schema, 'frankengit-notification-retry-v1');
  assert.equal(serialized.includes(token), false); assert.deepEqual(receipt.request.binding, binding);
  original.disconnect();
  for (const Client of [IssueClient, MilestoneClient]) {
    const foreign = new Client({ href: issueHref, cryptoImpl: webcrypto });
    await foreign.connect(token);
    await assert.rejects(foreign.restoreReceipt(serialized)); foreign.disconnect();
  }
  for (const change of [
    value => { value.schema = 'frankengit-issue-retry-v1'; },
    value => { value.request.key = value.request.key.replace(/^fgni/, 'fgui'); },
    value => { value.request.fields.read_through = 3; },
    value => { value.request.body = value.request.body.replace(`expected_principal=${binding.principal}`, `expected_principal=${'9'.repeat(32)}`); },
    value => { delete value.request.binding.principal; },
    value => { value.request.binding.extra = 'authority'; },
    value => { value.request.key = value.request.key.slice(0, -1) + (value.request.key.endsWith('0') ? '1' : '0'); },
  ]) {
    const altered = structuredClone(receipt); change(altered);
    let requests = 0;
    const client = fresh(async () => { requests += 1; return json(page); });
    await observe(client);
    await assert.rejects(client.restoreReceipt(JSON.stringify(altered)));
    assert.equal(client.pending, null); assert.equal(requests, 1, 'restore never posts'); client.disconnect();
  }
  for (const changedPage of [{ ...page, principal_id: '9'.repeat(32) }, { ...page, repository_incarnation: '8'.repeat(32) }]) {
    const calls = [], client = fresh(async (url, init) => { calls.push(recorded(url, init)); return json(changedPage); });
    await observe(client);
    await assert.rejects(client.restoreReceipt(serialized), /identity changed/);
    assert.equal(client.pending, null); assert.equal(calls.length, 1); client.disconnect();
  }
  const restored = fresh(async () => json(page)); await observe(restored);
  await restored.restoreReceipt(serialized);
  assert.equal(restored.pending.body, receipt.request.body); assert.equal(restored.pending.key, receipt.request.key);
  assert.equal(restored.pending.sent, true); assert.throws(() => restored.discardUnsent()); restored.disconnect();
});

test('foreign terminal or recovery identities cannot settle the pending notification', async () => {
  let mode = 'terminal'; const calls = [];
  const client = fresh(async (url, init) => {
    calls.push(recorded(url, init));
    if (init.method === 'GET') return json(page);
    if (mode === 'terminal') return json({ ...terminal, principal_id: '9'.repeat(32) });
    const reply = recovery();
    if (mode === 'principal') reply.principal_id = '9'.repeat(32);
    if (mode === 'incarnation') reply.repository_incarnation = '8'.repeat(32);
    return json(reply);
  });
  await prepare(client);
  const key = client.pending.key;
  await assert.rejects(client.send(), error => error.outcomeUnknown === true); assert.equal(client.pending.key, key);
  for (mode of ['principal', 'incarnation']) {
    await assert.rejects(client.recover(), /identity changed/); assert.equal(client.pending.key, key);
  }
  mode = 'correct'; assert.equal((await client.recover()).tx, terminal.tx_id); assert.equal(client.pending, null);
  assert.ok(calls.filter(call => call.method === 'POST').every(call => call.headers['Idempotency-Key'] === key));
  client.disconnect();
});

test('outcome lookup absence and undecided seals preserve the exact notification request', async () => {
  const original = fresh(async () => json(page)); await prepare(original);
  const receipt = original.exportReceipt(); original.disconnect();
  const calls = [], states = ['key_not_observed', 'undecided', 'committed'];
  const client = fresh(async (url, init) => {
    calls.push(recorded(url, init));
    assert.ok(String(url).endsWith('/outcomes'), 'recovery never reexecutes notification mutation');
    return json(recovery(states.shift()));
  });
  await client.connect(token); await client.restoreReceipt(receipt);
  const pending = client.pending;
  for (const state of ['key_not_observed', 'undecided']) {
    const result = await client.recover(); assert.equal(result.state, state); assert.equal(result.terminal, false);
    assert.equal(client.pending.key, pending.key); assert.equal(client.pending.body, pending.body);
    assert.throws(() => client.discardUnsent());
  }
  assert.equal((await client.recover()).outcome, 'committed'); assert.equal(client.pending, null);
  assert.equal(calls.length, 3);
  assert.ok(calls.every(call => call.headers['Idempotency-Key'] === pending.key && call.body === undefined));
  client.disconnect();
});

test('controller continuation freezes predicates and source while superseded responses are discarded', async () => {
  const first = { reply: { ...page, limit: 1, next_after: 7, unread_only: true }, binding, head };
  const next = { reply: { ...page, after: 7, threads: [{ ...row, number: 8 }], unread_only: true }, binding, head };
  const stale = deferred(), current = deferred(), responses = [Promise.resolve(first), Promise.resolve(next), stale.promise, current.promise];
  const calls = []; let cancellations = 0;
  const client = { cancelReads() { cancellations += 1; },
    read(number, options) { calls.push({ number, options }); return responses.shift(); } };
  const controller = new NotificationInboxController(client);
  assert.equal(await controller.load({ unreadOnly: true, includeMuted: false }), first);
  assert.equal(await controller.load({ unreadOnly: false, includeMuted: true }, true), next);
  assert.deepEqual(calls[1], { number: null, options: { unreadOnly: true, includeMuted: false, after: 7, head } });
  const oldRead = controller.load({ unreadOnly: false, includeMuted: false });
  const newRead = controller.load({ unreadOnly: false, includeMuted: true });
  const newer = { ...first, head: `alg:2:${'a'.repeat(64)}` };
  current.resolve(newer); assert.equal(await newRead, newer);
  stale.resolve(first); assert.equal(await oldRead, null);
  assert.equal(controller.page, newer); assert.equal(cancellations, 4);
});

test('controller actions capture the displayed versions and never replace unresolved mutation responsibility', async () => {
  const displayed = structuredClone(row), calls = [];
  const client = { pending: null, async stage(...args) {
    calls.push(args); this.pending = { key: 'original', args: structuredClone(args) };
  }, async send() { const error = new Error('response lost'); error.outcomeUnknown = true; throw error; } };
  const controller = new NotificationInboxController(client);
  assert.deepEqual(threadAction(displayed, 'read'), [7, 2, 'read', { read_through: 4 }]);
  assert.deepEqual(threadAction({ ...row, preference_version: null, read_through: null }, 'subscribe'), [7, 0, 'subscribe', {}]);
  assert.throws(() => threadAction(row, 'delete'));
  await assert.rejects(controller.change(displayed, 'read'), error => error.outcomeUnknown === true);
  displayed.issue_version = 5; displayed.preference_version = 3;
  assert.deepEqual(calls[0], [7, 2, 'read', { read_through: 4 }]);
  await assert.rejects(controller.change(displayed, 'mute'), /Resolve the original/);
  assert.equal(calls.length, 1); assert.equal(client.pending.key, 'original');
});
