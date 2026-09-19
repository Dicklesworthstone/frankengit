// Contract tests against native response schemas; not a live-node campaign.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { metadataCommand, form, integer, decimal, oid, listReply, showReply, reviewsReply, rootFor, Transport, readBytes } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { token, head, ids, scope, row, page, show, data, reviewRow, reviews, metadata, json, options, deferred } from './pulls-fixtures.mjs';

test('metadata commands preserve all explicit coordinates, Unicode and percent-encoded content', () => {
  for (const action of ['open', 'update', 'close']) {
    const fields = metadata({ expected_version: action === 'open' ? 0 : 1, body: '%2f\n&principal=admin' });
    const result = new URLSearchParams(form(metadataCommand(action, fields)));
    assert.equal(result.get('body'), fields.body); assert.equal(result.get('source_ref'), fields.source_ref);
    assert.equal(result.get('expected_version'), String(fields.expected_version)); assert.equal(result.has('principal'), false);
  }
});
test('both native hash domains are explicit and formatted display OIDs normalize losslessly', () => {
  for (const algorithm of ['sha1', 'sha256']) {
    const hash = 'a'.repeat(algorithm === 'sha1' ? 40 : 64);
    const command = metadataCommand('update', metadata({ object_format: algorithm, source_tip: `${algorithm}:${hash}`, target_tip: hash.replaceAll('a', 'b') }));
    assert.equal(command.source_tip, hash);
    assert.throws(() => oid(hash, algorithm === 'sha1' ? 'sha256' : 'sha1'));
  }
});
for (const [name, action, fields] of [
  ['forged principal', 'update', metadata({ principal: 'admin' })],
  ['implicit version', 'update', metadata({ expected_version: undefined })],
  ['zero close version', 'close', metadata({ expected_version: 0 })],
  ['reopen unsupported', 'reopen', metadata()], ['merge is not metadata', 'merge', metadata()],
  ['unsafe version', 'update', metadata({ expected_version: Number.MAX_SAFE_INTEGER })],
  ['wrong hash domain', 'update', metadata({ source_tip: 'a'.repeat(64) })],
  ['zero OID', 'update', metadata({ target_tip: '0'.repeat(40) })],
  ['same refs', 'update', metadata({ source_ref: 'refs/heads/main' })],
  ['tag not branch', 'update', metadata({ source_ref: 'refs/tags/a' })],
  ['bad ref', 'update', metadata({ target_ref: 'refs/heads/../secret' })],
  ['surrogate', 'update', metadata({ body: '\ud800' })], ['NUL', 'update', metadata({ body: '\0' })],
  ['oversize UTF8 title', 'update', metadata({ title: 'é'.repeat(129) })],
  ['oversize body', 'update', metadata({ body: 'a'.repeat(65537) })],
]) test(`metadata refuses ${name} before any transport`, () => assert.throws(() => metadataCommand(action, fields)));

test('integers and decimal inputs refuse rounding, infinity and ambiguous spelling', () => {
  for (const value of [NaN, Infinity, -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => integer(value, 'counter'));
  for (const value of ['01', '1e2', '-1', '9007199254740992', '']) assert.throws(() => decimal(value, 'counter'));
});
test('PR pages enforce repository incarnation, complete ordering and exact continuations', () => {
  assert.equal(listReply(page()).head, head);
  for (const bad of [page({ after: 2 }), page({ pull_requests: [row(2), row(1)] }), page({ next_after: 1 }),
    page({ pull_requests: [row(1, { data: null })] }), page({ pull_requests: [row(1, { merge_only: true })] }),
    page({ pull_requests: [row(1, { data: data({ source_ref_hex: '61' }) })] })]) assert.throws(() => listReply(bad));
  assert.throws(() => listReply(page(), { scope: { ...scope, incarnation: 'another' } }));
  assert.throws(() => listReply(page(), { head: `alg:1:${'c'.repeat(64)}` }));
  assert.equal(listReply(page({ limit: 1, next_after: 1 }), { limit: 1 }).reply.next_after, 1);
});
test('byte-only refs and merge-only historical records are readable, never lossy form inputs', () => {
  const merge = { ...data(), source_tip: 'a'.repeat(40), target_tip_before: 'b'.repeat(40), base_tip: 'e'.repeat(40), merge_commit: 'd'.repeat(40) };
  assert.equal(listReply(page({ pull_requests: [row(1, { data: null, state: 'merged', merge_only: true, merge })] })).reply.pull_requests[0].merge_only, true);
  const bytes = data({ source_ref: null, source_ref_hex: `${data().source_ref_hex}ff` });
  assert.equal(listReply(page({ pull_requests: [row(1, { data: bytes })] })).reply.pull_requests[0].data.source_ref, null);
  assert.throws(() => metadataCommand('update', metadata({ source_ref: null })));
});
test('PR lookup never accepts a different visible number for an absent selected PR', () => {
  assert.equal(showReply(show(), 1).reply.found, true);
  assert.throws(() => showReply(show({ pull_request: row(2) }), 1));
  assert.throws(() => showReply(show({ found: false }), 1));
  assert.equal(showReply(show({ found: false, pull_request: null }), 1).reply.found, false);
});
test('review pages retain candidate identity, freshness and explicit non-authority', () => {
  const checked = reviewsReply(reviews(), 1); assert.equal(checked.reply.merge_authorized, false);
  for (const bad of [reviews({ merge_authorized: true }), reviews({ reviews: [reviewRow(), reviewRow()] }),
    reviews({ reviews: [reviewRow({ freshness: 'automatic-approval' })] }), reviews({ policy_epoch: 2 }),
    reviews({ reviews: [reviewRow({ subject: { ...reviewRow().subject, number: 2 } })] }), reviews({ next_after: reviewRow().reviewer })]) assert.throws(() => reviewsReply(bad, 1));
  assert.equal(reviewsReply(reviews({ reviews: [reviewRow({ freshness: 'source_moved' })] }), 1).reply.reviews[0].freshness, 'source_moved');
});
test('same-origin requests use no ambient credentials and carry no mutation key for reads', async () => {
  const calls = []; const client = new PullClient(options((url, opts) => { calls.push({ url: String(url), ...opts }); return json(page()); }));
  await client.connect(token); await client.list();
  const call = calls[0]; assert.equal(call.url, 'https://forge.example/team/repo.git/api/v1/pulls?after=0&limit=20');
  for (const [name, expected] of Object.entries({ credentials: 'omit', mode: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer' })) assert.equal(call[name], expected);
  assert.equal(call.headers.Authorization, `Bearer ${token}`); assert.equal(call.headers['Idempotency-Key'], undefined);
});
test('PR and review paging carry the original head, and reject unpinned continuations locally', async () => {
  const calls = []; const client = new PullClient(options((url) => {
    calls.push(String(url)); return json(calls.length === 1 ? page() : reviews({ after: '0'.repeat(32), limit: 1 }));
  }));
  await client.connect(token); await client.list(); await client.reviews(1, { after: '0'.repeat(32), head, limit: 1 });
  assert.match(calls[1], /expected_head=alg%3A1%3A/);
  await assert.rejects(client.list({ after: 1 })); await assert.rejects(client.reviews(1, { after: '0'.repeat(32) })); assert.equal(calls.length, 2);
});
test('missing independent grant neither disconnects valid credentials nor invents empty views', async () => {
  const client = new PullClient(options(() => json({ error: 'forbidden' }, 403))); await client.connect(token);
  await assert.rejects(client.reviews(1), /scope/); assert.equal(client.connected, true);
});
test('late old-token 401 cannot clear a newly connected credential', async () => {
  const wait = deferred(), client = new PullClient(options(() => wait.promise)); await client.connect(token);
  const old = client.list(); await client.connect('d'.repeat(64)); wait.resolve(json({}, 401));
  await assert.rejects(old); assert.equal(client.connected, true); assert.equal(client.binding, null);
});
test('disconnect cancels view results and cannot install late repository identity', async () => {
  const wait = deferred(), client = new PullClient(options(() => wait.promise)); await client.connect(token);
  const old = client.list(); client.disconnect(); wait.resolve(json(page())); await assert.rejects(old);
  assert.equal(client.connected, false); assert.equal(client.binding, null);
});
test('malformed JSON, HTML, wrong identity and redirected responses fail closed', async () => {
  const choices = [() => new Response('<html>', { headers: { 'Content-Type': 'text/html' } }),
    () => new Response('{', { headers: { 'Content-Type': 'application/json' } }),
    () => json(page({ schema_version: 2 })),
    () => { const response = json(page()); Object.defineProperty(response, 'redirected', { value: true }); return response; }];
  for (const respond of choices) { const client = new PullClient(options(respond)); await client.connect(token); await assert.rejects(client.list()); assert.equal(client.binding, null); }
});
test('stream byte limits and declared length mismatches reject before JSON validation', async () => {
  for (const [body, headers, maximum] of [['abcd', { 'Content-Length': '5' }, 10], ['abcd', { 'Content-Length': '4' }, 3], ['abcd', {}, 3]]) {
    await assert.rejects(readBytes(new Response(body, { headers }), new AbortController().signal, maximum));
  }
});
test('transport timeout covers delayed body reads', async () => {
  const t = new Transport({ ...options(() => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{')); } }), { headers: { 'Content-Type': 'application/json' } })), timeoutMs: 10 });
  await t.connect(token); await assert.rejects(t.request('pulls'));
});
test('untrusted page URL cannot select an off-origin credential destination', () => {
  for (const href of ['https://forge.example/r.git/ui/pulls/?token=x', 'https://user:secret@forge.example/r.git/ui/pulls/',
    'http://public.example/r.git/ui/pulls/', 'file:///r.git/ui/pulls/', 'https://forge.example/r.git/ui/pulls/#x']) assert.throws(() => rootFor(href));
});
