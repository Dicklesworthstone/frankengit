import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { capturePullReviews, validateReviewCapture, parseReviewJson, REVIEW_LIMITS, reviewCanonical, reviewHash } from '../../scripts/operator/pull_review_snapshot.mjs';
import { peer, TOKEN, HEAD, NUMBER, VERSION, EPOCH, person, wire, respond } from './pull_review_snapshot_fixture.mjs';

for (const format of ['sha1', 'sha256']) test(`${format}: complete pinned reviews, exact u64s and offline replay`, async t => {
  const p = await peer(t, { format });
  const capture = await capturePullReviews(p.selected, TOKEN, { pageLimit: 2 });
  assert.equal(capture.pull.number, NUMBER); assert.equal(capture.pull.pull_request.version, VERSION);
  assert.equal(capture.review_pages[1].policy_epoch, EPOCH); assert.equal(capture.review_pages.length, 2);
  assert.equal(capture.complete, true); assert.equal(capture.merge_authorized, false);
  assert.deepEqual(validateReviewCapture(parseReviewJson(Buffer.from(reviewCanonical(capture)))), capture);
  const copy = validateReviewCapture(capture); copy.review_pages[0].reviews[0].reason = 'edited';
  assert.notEqual(copy.review_pages[0].reviews[0].reason, capture.review_pages[0].reviews[0].reason);
  assert.equal(reviewCanonical(capture).includes(TOKEN), false); assert.equal(p.requests.length, 3);
  for (const [i, r] of p.requests.entries()) {
    assert.equal(r.method, 'GET'); assert.equal(r.body.length, 0); assert.equal(r.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(r.headers['idempotency-key'], undefined); assert.equal(r.headers.cookie, undefined);
    assert.equal(r.url.searchParams.get('render'), null);
    assert.equal(r.url.searchParams.get('expected_head'), i ? HEAD : null);
  }
  assert.equal(p.requests[2].url.searchParams.get('after'), person(11));
});
for (const state of ['open', 'closed', 'merged']) test(`inspect ${state} PR without inferring permission`, async t => {
  const p = await peer(t, { state }); const result = await capturePullReviews(p.selected, TOKEN);
  assert.equal(result.pull.pull_request.state, state); assert.equal(result.merge_authorized, false);
});
test('merge-only legacy metadata and byte-only refs remain inspectable', async t => {
  const legacy = await peer(t, { state: 'merged', legacyMerge: true });
  assert.equal((await capturePullReviews(legacy.selected, TOKEN)).pull.pull_request.merge_only, true);
  const bytes = await peer(t, { byteOnly: true });
  const captured = await capturePullReviews(bytes.selected, TOKEN);
  assert.equal(captured.pull.pull_request.data.source_ref, null);
  assert.ok(captured.pull.pull_request.data.source_ref_hex.endsWith('ff'));
});
test('typed missing PR and empty review stream are distinct complete observations', async t => {
  const absent = await peer(t, { found: false }); const missing = await capturePullReviews(absent.selected, TOKEN);
  assert.equal(missing.pull.found, false); assert.deepEqual(missing.review_pages, []); assert.equal(absent.requests.length, 1);
  const p = await peer(t, { count: 0 }); const empty = await capturePullReviews(p.selected, TOKEN);
  assert.equal(empty.pull.found, true); assert.equal(empty.review_pages.length, 1); assert.deepEqual(empty.review_pages[0].reviews, []);
});
test('explicit starting head and detached caller scope survive asynchronous acquisition', async t => {
  let selected;
  const p = await peer(t, { handle(r, res, s) { if (s.requests.length === 1) { selected.scope.repository_id = person(100); selected.number = '1'; } } });
  selected = structuredClone(p.selected); selected.expected_head = HEAD;
  const captured = await capturePullReviews(selected, TOKEN);
  assert.equal(captured.selection.number, NUMBER); assert.equal(p.requests[0].url.searchParams.get('expected_head'), HEAD);
});
for (const field of ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format']) test(`wrong ${field} on review page refuses the whole capture`, async t => {
  const p = await peer(t, { handle(r, res, s) { if (r.url.pathname.endsWith('/reviews')) {
    const page = s.native.page(null, 50); page[field] = field === 'object_format' ? 'sha256' : person(101); respond(res, page); return true;
  } } });
  await assert.rejects(capturePullReviews(p.selected, TOKEN), { code: 'review_scope_changed' }); assert.equal(p.requests.length, 2);
});
for (const field of ['snapshot_token', 'source_head', 'pull_request_version', 'policy_epoch']) test(`changed ${field} across pages cannot make a mixed report`, async t => {
  const p = await peer(t, { handle(r, res, s) { if (r.url.searchParams.has('after')) {
    const page = s.native.page(r.url.searchParams.get('after'), 2);
    page[field] = field === 'snapshot_token' ? 'alg:1:' + 'e'.repeat(64) : field === 'source_head' ? 'other-head' : '7';
    respond(res, page); return true;
  } } });
  await assert.rejects(capturePullReviews(p.selected, TOKEN, { pageLimit: 2 })); assert.equal(p.requests.length, 3);
});
for (const mutate of [
  p => p.after = person(1), p => p.next_after = person(1), p => p.limit = 1,
  p => p.reviews.reverse(), p => p.reviews.push(p.reviews[0]), p => p.merge_authorized = true,
  p => p.reviews[0].subject.source_tip = 'sha256:' + 'a'.repeat(64),
  p => p.reviews[0].subject.source_ref = 'refs/heads/other',
  p => p.reviews[0].subject.pull_request_version = '1', p => p.reviews[0].subject.policy_epoch = '1',
  p => p.reviews[0].reviewer_is_opener = true, p => p.reviews[0].candidate.candidate_commit = 'sha1:' + '0'.repeat(40),
]) test(`reject inconsistent page: ${mutate}`, async t => {
  const p = await peer(t, { handle(r, res, s) { if (r.url.pathname.endsWith('/reviews')) {
    const page = s.native.page(null, 2); mutate(page); respond(res, page); return true;
  } } });
  await assert.rejects(capturePullReviews(p.selected, TOKEN, { pageLimit: 2 }));
});
test('stale votes retain their original subject and predecessor, not a refreshed approval', async t => {
  const p = await peer(t); p.native.reviews[0].freshness = 'policy_changed'; p.native.reviews[0].subject.policy_epoch = '1';
  const capture = await capturePullReviews(p.selected, TOKEN);
  assert.equal(capture.review_pages[0].reviews[0].subject.policy_epoch, '1');
  assert.equal(capture.review_pages[0].policy_epoch, EPOCH);
});
for (const status of [401, 403, 404, 409, 429, 503]) test(`HTTP ${status} on a required review read never becomes an empty page`, async t => {
  const p = await peer(t, { handle(r, res) { if (r.url.pathname.endsWith('/reviews')) {
    res.writeHead(status, { 'Content-Type': 'application/json' }); res.end('{"secret":"untrusted error"}'); return true;
  } } });
  await assert.rejects(capturePullReviews(p.selected, TOKEN), e => !e.message.includes('secret')); assert.equal(p.requests.length, 2);
});
test('starting snapshot mismatch refuses after one request', async t => {
  const p = await peer(t); p.selected.expected_head = 'alg:1:' + 'f'.repeat(64);
  await assert.rejects(capturePullReviews(p.selected, TOKEN), { code: 'review_snapshot_changed' }); assert.equal(p.requests.length, 1);
});
for (const type of ['redirect', 'duplicate-key', 'duplicate-header', 'gzip', 'utf8', 'truncated', 'declared-limit', 'stream-limit']) test(`hostile transport ${type}`, async t => {
  const p = await peer(t, { handle(r, res, s) {
    const body = wire(s.native.pull);
    if (type === 'redirect') { res.writeHead(302, { Location: '/evil' }); res.end(); }
    if (type === 'duplicate-key') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(body.replace('"schema_version":1', '"schema_version":0,"schema_version":1')); }
    if (type === 'duplicate-header') { res.writeHead(200, ['Content-Type', 'application/json', 'Content-Type', 'application/json']); res.end(body); }
    if (type === 'gzip') { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }); res.end(body); }
    if (type === 'utf8') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(Buffer.from([255])); }
    if (type === 'truncated') { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': body.length + 100 }); res.end(body); }
    if (type === 'declared-limit') { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': REVIEW_LIMITS.reply + 1 }); res.end('x'); }
    if (type === 'stream-limit') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(' '.repeat(REVIEW_LIMITS.reply + 1)); }
    return true;
  } });
  await assert.rejects(capturePullReviews(p.selected, TOKEN, { timeoutMs: 1000 })); assert.equal(p.requests.length, 1);
});
test('page/reviewer/wire ceilings have exact permitted and one-under refusal twins', async t => {
  for (const [options, pass] of [[{ pageLimit: 2, maxPages: 2, maxReviewers: 3 }, true],
    [{ pageLimit: 2, maxPages: 1 }, false], [{ maxReviewers: 2 }, false]]) {
    const p = await peer(t);
    if (pass) await capturePullReviews(p.selected, TOKEN, options); else await assert.rejects(capturePullReviews(p.selected, TOKEN, options));
  }
  const p = await peer(t), bytes = Buffer.byteLength(wire(p.native.pull)) + Buffer.byteLength(wire(p.native.page(null, 50)));
  await capturePullReviews(p.selected, TOKEN, { maxWireBytes: bytes });
  await assert.rejects(capturePullReviews(p.selected, TOKEN, { maxWireBytes: bytes - 1 }));
});
test('timeout/cancellation close the owned request and never start another page', async t => {
  const controller = new AbortController();
  const p = await peer(t, { handle(r, res, s) { if (r.url.pathname.endsWith('/reviews')) { controller.abort(); return true; } } });
  await assert.rejects(capturePullReviews(p.selected, TOKEN, { signal: controller.signal }), { code: 'review_cancelled' });
  const n = p.requests.length;
  await assert.rejects(capturePullReviews(p.selected, TOKEN, { signal: controller.signal })); assert.equal(p.requests.length, n);
  const stalled = await peer(t, { handle() { return true; } });
  await assert.rejects(capturePullReviews(stalled.selected, TOKEN, { timeoutMs: 30 }), { code: 'review_timeout' });
});
test('offline validation rejects missing final page, append after terminal and changed page scopes', async t => {
  const p = await peer(t), capture = await capturePullReviews(p.selected, TOKEN, { pageLimit: 2 });
  for (const edit of [c => c.review_pages.pop(), c => c.review_pages.push(c.review_pages.at(-1)),
    c => c.review_pages[0].repository_incarnation = person(9), c => c.complete = false]) {
    const bad = structuredClone(capture); edit(bad); assert.throws(() => validateReviewCapture(bad));
  }
  assert.notEqual(reviewHash(reviewCanonical(capture)), reviewHash(reviewCanonical({ ...capture, page_limit: 1 })));
});
test('JSON lexemes, duplicate escaped keys, depth and resource limits are strict', () => {
  assert.equal(parseReviewJson(Buffer.from('{"version":18446744073709551615}'), { wire: true }).version, EPOCH);
  for (const raw of ['{"version":18446744073709551616}', '{"version":1e3}', '{"version":-0}',
    '{"version":1,"vers\\u0069on":2}', '['.repeat(17) + ']'.repeat(17), '{"limit":9007199254740993}']) {
    assert.throws(() => parseReviewJson(Buffer.from(raw), { wire: true }));
  }
});
test('certificate verification is mandatory; explicit private CA permits the same HTTPS workflow', async t => {
  const root = await mkdtemp(join(tmpdir(), 'fg-review-tls-')); t.after(() => rm(root, { recursive: true, force: true }));
  for (const [name, alt] of [['right', 'IP:127.0.0.1'], ['wrong', 'DNS:wrong.example']]) {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(root, name + '.key'),
      '-out', join(root, name + '.crt'), '-days', '1', '-subj', '/CN=' + name, '-addext', 'subjectAltName=' + alt], { stdio: 'ignore', timeout: 15000 });
    const cert = await readFile(join(root, name + '.crt')), key = await readFile(join(root, name + '.key'));
    const p = await peer(t, { tls: { cert, key } });
    await assert.rejects(capturePullReviews(p.selected, TOKEN)); assert.equal(p.requests.length, 0);
    if (name === 'right') assert.equal((await capturePullReviews(p.selected, TOKEN, { ca: cert })).complete, true);
    else { await assert.rejects(capturePullReviews(p.selected, TOKEN, { ca: cert })); assert.equal(p.requests.length, 0); }
  }
});
test('closed read grammar refuses credentials, route injection and unsupported resource options before I/O', async t => {
  const p = await peer(t);
  for (const edit of [s => s.endpoint += '?redirect=evil', s => s.endpoint += '/', s => s.endpoint = 'http://localhost/repo.git',
    s => s.number = '../reviews', s => s.number = '01', s => s.scope.principal_id = person(9),
    s => s.scope.object_format = 'sha512', s => s.expected_head = 'latest']) {
    const bad = structuredClone(p.selected); edit(bad); await assert.rejects(capturePullReviews(bad, TOKEN));
  }
  for (const options of [{ timeoutMs: 0 }, { maxPages: 33 }, { maxReviewers: 1025 }, { pageLimit: 101 },
    { maxWireBytes: REVIEW_LIMITS.wire + 1 }, { method: 'POST' }, { rejectUnauthorized: false }]) {
    await assert.rejects(capturePullReviews(p.selected, TOKEN, options));
  }
  await assert.rejects(capturePullReviews(p.selected, 'bad')); assert.equal(p.requests.length, 0);
  assert.equal((await capturePullReviews(p.selected, TOKEN)).complete, true);
});
