import test from 'node:test';
import assert from 'node:assert/strict';
import { ActivityClient, activityCursor, activityPage, ACTIVITY_LIMITS } from '../../crates/fgit-node/src/smart_http/server/browser/activity.mjs';

const href = 'https://forge.example/team/repo.git/ui/activity/', token = 'a'.repeat(64);
const head = 'alg:1:' + 'ab'.repeat(32);
const event = (cursor = '1:0', extra = {}) => ({ cursor, repository_sequence: cursor.split(':')[0], event_index: cursor.split(':')[1],
  tx_id: 'tx:fixture', policy_epoch: '1', aggregate: 'issue:1', aggregate_version: '1', kind: 1, event_frame_hex: 'abcd', ...extra });
const page = (extra = {}) => ({ type: 'forge_event_page', schema_version: 1, tenant_id: 'tenant', repository_id: 'repository',
  repository_incarnation: 'incarnation', object_format: 'sha1', source_head: 'head:first', snapshot_token: head, read_only: true,
  disclosure_profile: 'issues-pulls-v1', issues_read: true, pulls_read: false, omits_other_event_families: true,
  cursor_discloses_repository_activity: true, events: [event()], next_after: null, resume_after: '1:0', has_more: false, complete: true, ...extra });
const response = data => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture(replies = [], options = {}) {
  const requests = [];
  const client = new ActivityClient({ href, fetchImpl: function (url, init) {
    assert.equal(this, undefined, 'WebIDL fetch must be invoked as a plain function');
    requests.push({ url: new URL(url), init });
    const next = replies.shift(); return typeof next === 'function' ? next(url, init) : next;
  }, ...options });
  client.connect(token); return { client, requests };
}

test('exact cursor domains retain u64/u32 maxima without Number conversion', () => {
  assert.deepEqual(activityCursor('18446744073709551615:4294967295'), [18446744073709551615n, 4294967295n]);
  const cursor = '9007199254740993:0';
  assert.equal(activityPage(page({ events: [event(cursor)], resume_after: cursor })).events[0].cursor, cursor);
});
for (const value of [null, 0, 1, '', '01:0', '0:0', '1:00', '-1:0', '1:0:0', '1:4294967296', '18446744073709551616:0', '1e3:0', '1: 0']) {
  test(`reject inexact cursor ${JSON.stringify(value)}`, () => assert.throws(() => activityCursor(value)));
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: read-only request, bounded page and defensive snapshots`, async () => {
    const raw = page({ object_format: format }), { client, requests } = fixture([response(raw)]);
    const result = await client.open({ limit: 1 });
    assert.equal(requests[0].url.href, 'https://forge.example/team/repo.git/api/v1/events?after=0&limit=1');
    const init = requests[0].init;
    assert.equal(init.method, 'GET'); assert.equal(init.body, undefined); assert.equal(init.redirect, 'error');
    assert.equal(init.credentials, 'omit'); assert.equal(init.mode, 'same-origin'); assert.equal(init.cache, 'no-store');
    assert.equal(init.headers.Authorization, `Bearer ${token}`); assert.equal(init.referrerPolicy, 'no-referrer');
    result.events[0].cursor = 'changed'; const retained = client.page; retained.events.length = 0;
    assert.equal(client.page.events[0].cursor, '1:0'); assert.ok(!JSON.stringify(client.page).includes(token));
  });
}
test('empty filtered pages continue, EOF watermarks survive, and refresh unpins without restarting', async () => {
  const first = page({ events: [], has_more: true, complete: false, next_after: '7:2', resume_after: '7:2' });
  const eof = page({ events: [], resume_after: '9:0' });
  const later = page({ source_head: 'head:second', snapshot_token: 'alg:1:' + 'cd'.repeat(32), events: [event('10:0')], resume_after: '10:0' });
  const { client, requests } = fixture([response(first), response(eof), response(later)]);
  assert.equal((await client.open()).events.length, 0); assert.equal(client.page.has_more, true);
  await client.next(); assert.equal(requests[1].url.searchParams.get('after'), '7:2');
  assert.equal(requests[1].url.searchParams.get('expected_head'), head);
  await client.refresh(); assert.equal(requests[2].url.searchParams.get('after'), '9:0');
  assert.equal(requests[2].url.searchParams.has('expected_head'), false);
  assert.equal(client.page.events[0].cursor, '10:0'); await assert.rejects(client.next(), /No next/);
});
test('initial empty history and empty EOF after an existing cursor are complete permitted twins', () => {
  assert.equal(activityPage(page({ events: [], resume_after: null })).complete, true);
  assert.equal(activityPage(page({ events: [], resume_after: '8:0' }), { after: '8:0' }).resume_after, '8:0');
});
const invalidPages = [
  ['unknown fields', p => { p.actor = 'admin'; }],
  ['schema version', p => { p.schema_version = 2; }],
  ['write authority', p => { p.read_only = false; }],
  ['ungranted families', p => { p.issues_read = false; }],
  ['invented completeness', p => { p.omits_other_event_families = false; }],
  ['unlabelled cursor disclosure', p => { p.cursor_discloses_repository_activity = false; }],
  ['unknown format', p => { p.object_format = 'sha512'; }],
  ['invalid snapshot', p => { p.snapshot_token = 'not-a-head'; }],
  ['nonboolean completeness', p => { p.complete = 1; }],
  ['numeric cursor', p => { p.events[0].repository_sequence = 1; }],
  ['mismatched cursor', p => { p.events[0].cursor = '2:0'; }],
  ['duplicate event', p => { p.events.push(event()); }],
  ['descending events', p => { p.events = [event('2:0'), event()]; }],
  ['unsafe version', p => { p.events[0].aggregate_version = 9007199254740992; }],
  ['kind overflow', p => { p.events[0].kind = 4294967296; }],
  ['odd hex frame', p => { p.events[0].event_frame_hex = 'abc'; }],
  ['invalid hex frame', p => { p.events[0].event_frame_hex = 'ABCD'; }],
  ['empty frame', p => { p.events[0].event_frame_hex = ''; }],
  ['oversized frame', p => { p.events[0].event_frame_hex = 'aa'.repeat(ACTIVITY_LIMITS.frame + 1); }],
  ['frame sum', p => { p.events = [1, 2, 3].map(n => event(`${n}:0`, { event_frame_hex: 'aa'.repeat(ACTIVITY_LIMITS.frame) })); p.resume_after = '3:0'; }],
  ['missing watermark', p => { p.resume_after = null; }],
  ['cursor reset', p => { p.resume_after = '0'; }],
  ['contradictory end', p => { p.has_more = true; }],
  ['next watermark disagreement', p => { p.next_after = '2:0'; p.has_more = true; p.complete = false; }],
  ['stalled empty continuation', p => { p.events = []; p.next_after = p.resume_after = '1:0'; p.has_more = true; p.complete = false; }],
];
for (const [name, mutate] of invalidPages) {
  test(`reject ${name} without manufacturing an empty page`, () => {
    const raw = page(); mutate(raw);
    assert.throws(() => activityPage(raw, { after: name === 'stalled empty continuation' ? '1:0' : '0' }));
  });
}
test('events before the requested cursor and pages larger than the limit refuse', () => {
  assert.throws(() => activityPage(page(), { after: '2:0' }));
  assert.throws(() => activityPage(page({ events: [event(), event('2:0')], resume_after: '2:0' }), { limit: 1 }));
});
test('snapshot movement keeps the last success recoverable and never retries automatically', async () => {
  const first = page({ next_after: '1:0', has_more: true, complete: false });
  const { client, requests } = fixture([response(first), new Response('', { status: 409 }), response(page({ events: [event('2:0')], resume_after: '2:0' }))]);
  await client.open(); await assert.rejects(client.next(), /snapshot moved/);
  assert.equal(requests.length, 2); assert.equal(client.page.resume_after, '1:0');
  await client.refresh(); assert.equal(requests[2].url.searchParams.get('after'), '1:0');
});
test('a falsely successful response cannot substitute a different pinned snapshot', async () => {
  const first = page({ next_after: '1:0', has_more: true, complete: false });
  const changed = page({ events: [event('2:0')], resume_after: '2:0', source_head: 'head:other' });
  const { client } = fixture([response(first), response(changed)]);
  await client.open(); await assert.rejects(client.next(), /snapshot moved/); assert.equal(client.page.source_head, 'head:first');
});
for (const field of ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'issues_read', 'pulls_read']) {
  test(`scope change clears the connection: ${field}`, async () => {
    const changed = page({ events: [], resume_after: '1:0', [field]: field === 'object_format' ? 'sha256' : field === 'pulls_read' ? true : field === 'issues_read' ? false : 'other' });
    if (field === 'issues_read') changed.pulls_read = true;
    const { client } = fixture([response(page()), response(changed)]);
    await client.open(); await assert.rejects(client.refresh(), /Reconnect/);
    assert.equal(client.connected, false); assert.equal(client.page, null);
  });
}
for (const status of [401, 403, 404, 413, 429, 503]) {
  test(`HTTP ${status} is a refusal, not an empty feed`, async () => {
    const { client, requests } = fixture([response(page()), new Response('private diagnostics', { status })]);
    await client.open(); await assert.rejects(client.refresh(), error => error.status === status && !error.message.includes('private diagnostics'));
    assert.equal(requests.length, 2); assert.equal(client.connected, ![401, 403].includes(status));
    if ([401, 403].includes(status)) assert.equal(client.page, null);
  });
}
for (const badHref of ['http://forge.example/repo.git/ui/activity/', 'https://user:password@forge.example/repo.git/ui/activity/',
  `${href}?token=secret`, `${href}#other`, 'https://forge.example/ui/activity/', 'file:///repo.git/ui/activity/']) {
  test(`refuse unsafe endpoint ${badHref}`, () => assert.throws(() => new ActivityClient({ href: badHref })));
}
for (const mode of ['fetch', 'body']) {
  test(`disconnect races ${mode} and late work cannot resurrect an observation`, async () => {
    const pending = deferred(); let cancelled = false;
    const waiting = mode === 'fetch' ? pending.promise : new Response(new ReadableStream({ start(controller) {
      pending.promise.then(value => { try { controller.enqueue(new TextEncoder().encode(JSON.stringify(value))); controller.close(); } catch { /* Already cancelled. */ } });
    }, cancel() { cancelled = true; } }), { headers: { 'Content-Type': 'application/json' } });
    const { client } = fixture([waiting]); const read = client.open();
    const refused = assert.rejects(read); await tick(); client.disconnect(); await refused;
    pending.resolve(mode === 'fetch' ? response(page()) : page()); await tick();
    assert.equal(client.page, null); assert.equal(client.connected, false); if (mode === 'body') assert.equal(cancelled, true);
  });
}
test('a superseded late rejection cannot revoke a newer connection or generate an unhandled rejection', async () => {
  const pending = deferred(), { client } = fixture([pending.promise, response(page())]);
  const old = assert.rejects(client.open()); client.connect('b'.repeat(64)); await client.open();
  pending.reject(Object.assign(new Error('old credential'), { status: 401 })); await old; await tick();
  assert.equal(client.connected, true); assert.equal(client.page.events.length, 1);
});
test('timeout rejects a fetch that ignores AbortSignal and disposes its late response', async () => {
  const pending = deferred(), { client } = fixture([pending.promise], { timeoutMs: 5 }); let cancelled = false;
  await assert.rejects(client.open(), error => error.name === 'TimeoutError');
  pending.resolve(new Response(new ReadableStream({ cancel() { cancelled = true; } })));
  await tick(); assert.equal(cancelled, true); assert.equal(client.page, null);
});
test('stream byte cap and invalid JSON/UTF-8 refuse without admitting a page', async () => {
  const replies = [new Response(new Uint8Array(ACTIVITY_LIMITS.reply + 1), { headers: { 'Content-Type': 'application/json' } }),
    new Response(Uint8Array.of(255), { headers: { 'Content-Type': 'application/json' } }),
    new Response('{invalid', { headers: { 'Content-Type': 'application/json' } }),
    new Response('{}', { headers: { 'Content-Type': 'text/html' } }),
    new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': '99999999999999' } })];
  for (const reply of replies) { const { client } = fixture([reply]); await assert.rejects(client.open()); assert.equal(client.page, null); }
});
test('redirects, including a mismatched final URL without redirected flag, refuse', async () => {
  for (const attributes of [{ redirected: true }, { url: 'https://other.example/api/v1/events' }]) {
    const reply = response(page()); for (const [key, value] of Object.entries(attributes)) Object.defineProperty(reply, key, { value });
    const { client } = fixture([reply]); await assert.rejects(client.open(), /redirect/);
  }
});
test('decoded byte limits survive proxy compression without confusing wire length with JSON length', async () => {
  const reply = response(page()); reply.headers.set('Content-Encoding', 'gzip'); reply.headers.set('Content-Length', '12');
  const { client } = fixture([reply]); assert.equal((await client.open()).events.length, 1);
  const wrong = response(page()); wrong.headers.set('Content-Length', '12');
  await assert.rejects(fixture([wrong]).client.open(), /length mismatch/);
});
test('invalid input does not dispatch, and reconnect discards old observations', async () => {
  const { client, requests } = fixture([response(page())]);
  for (const limit of [0, 101, '20', 1.5]) await assert.rejects(client.open({ limit }));
  await assert.rejects(client.open({ after: '01:0' })); assert.equal(requests.length, 0);
  await client.open(); assert.throws(() => client.connect('bad')); assert.equal(client.connected, false); assert.equal(client.page, null);
  await assert.rejects(client.open()); assert.equal(requests.length, 1);
});
