import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { IssueClient, issueSearchQuery, issueSearchPage }
  from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { token, head, actor, issue, predicate, searchPage, json, terminal, deferred }
  from './issues-search-fixture.mjs';
const fresh = fetchImpl => new IssueClient({ href: 'https://forge.example/repo.git/ui/issues/', fetchImpl, cryptoImpl: webcrypto });
const page = (extra = {}, query = {}, options = {}) => issueSearchPage(searchPage(extra, query), query, options);

test('search freezes a canonical UTF-8 predicate without mutating its input', () => {
  const input = { labels: ['😀', '\uE000'], text: 'HTTP', state: 'open', opened_by: actor };
  const query = issueSearchQuery(input);
  assert.deepEqual(query.labels, ['\uE000', '😀']);
  assert.deepEqual(input.labels, ['😀', '\uE000']);
  input.labels.push('later'); input.text = 'changed';
  assert.equal(query.text, 'HTTP'); assert.equal(query.labels.length, 2);
  assert.ok(Object.isFrozen(query)); assert.ok(Object.isFrozen(query.labels));
});

test('invalid, oversized and ambiguous predicates refuse before transport', async () => {
  const client = fresh(() => assert.fail('invalid query dispatched')); await client.connect(token);
  for (const query of [null, [], '', { principal: actor }, { state: 'all' },
    { opened_by: 'admin' }, { opened_by: 'A'.repeat(32) }, { text: '' }, { text: '\0' },
    { text: '\ud800' }, { text: 'é'.repeat(129) }, { case_sensitive: true },
    { text: 'x', case_sensitive: 'true' }, { labels: ['x', 'x'] },
    { labels: ['x\ny'] }, { labels: ['é'.repeat(33)] }, { labels: Array(33).fill('x') }]) {
    await assert.rejects(client.search(query));
  }
  assert.equal(issueSearchQuery({ text: 'é'.repeat(128) }).text.length, 128);
});

test('search parameters are bounded and every nonzero cursor must be pinned', async () => {
  const client = fresh(() => assert.fail('invalid bounds dispatched')); await client.connect(token);
  for (const options of [{ after: 1 }, { after: -1 }, { after: Number.MAX_SAFE_INTEGER + 1 },
    { after: 1.5, head }, { after: '1', head }, { limit: 0 }, { limit: 101 },
    { maxScan: 0 }, { maxScan: 1001 }, { maxScan: 0.1 }, { head: 'latest' }]) {
    await assert.rejects(client.search({}, options));
  }
});

test('native search POST preserves the predicate and snapshot without a mutation key', async () => {
  let call;
  const input = predicate({ state: 'open', text: 'body&principal=admin', labels: ['urgent', 'bug'], opened_by: actor });
  const canonical = issueSearchQuery(input);
  const client = fresh(async (url, options) => { call = { url: String(url), ...options };
    return json(searchPage({ after: 42, limit: 10, max_scan: 100, issues: [], scanned: 0 }, canonical)); });
  await client.connect(token);
  const found = await client.search(input, { after: 42, limit: 10, maxScan: 100, head });
  assert.equal(call.url, 'https://forge.example/repo.git/api/v1/issues/search');
  assert.equal(call.method, 'POST'); assert.equal(call.headers['Idempotency-Key'], undefined);
  assert.equal(call.headers.Authorization, `Bearer ${token}`);
  assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error');
  const form = new URLSearchParams(call.body);
  assert.equal(form.get('query'), input.text); assert.equal(form.has('principal'), false);
  assert.deepEqual(form.getAll('label'), ['bug', 'urgent']);
  assert.equal(form.get('opened_by'), actor); assert.equal(form.get('expected_head'), head);
  assert.equal(form.get('after'), '42'); assert.equal(form.get('max_scan'), '100');
  assert.deepEqual(found.query, canonical); assert.equal(client.pending, null);
});

test('an empty scan-limited page retains the last examined candidate cursor', () => {
  const result = page({ issues: [], scanned: 200, complete: false,
    has_more_candidates: true, stop_reason: 'scan_limit', next_after: 350 });
  assert.equal(result.reply.count, 0); assert.equal(result.reply.next_after, 350);
  assert.equal(result.reply.complete, false);
});

test('result limits and exhausted suffixes are distinct complete page outcomes', () => {
  const result = page({ issues: [issue(4)], limit: 1, scanned: 3, complete: false,
    has_more_candidates: true, stop_reason: 'result_limit', next_after: 5 }, {}, { limit: 1 });
  assert.equal(result.reply.next_after, 5); // Not the last matching issue 4.
  assert.equal(page({ issues: [], after: 350 }, {}, { after: 350, head }).reply.complete, true);
  assert.equal(page({ object_format: 'sha256' }).reply.count, 1);
});

test('echoed predicates, native scope and read-only guarantees are checked', () => {
  const input = predicate({ state: 'open', labels: ['bug'], text: 'HTTP', opened_by: actor });
  const valid = searchPage({}, input);
  assert.equal(issueSearchPage(valid, input).reply.count, 1);
  for (const changed of [{ state: null }, { opened_by: null }, { text: 'native' },
    { labels: [] }, { case_sensitive: true }, { text_scope: 'comments' }]) {
    assert.throws(() => issueSearchPage({ ...valid, query: { ...valid.query, ...changed } }, input));
  }
  for (const changed of [{ type: 'issue_page' }, { scope: 'all_repositories' },
    { refs_changed: true }, { transaction_created: true }, { schema_version: 2 }]) {
    assert.throws(() => issueSearchPage({ ...valid, ...changed }, input));
  }
});

test('mixed snapshots and repository identities are not silent restarts', () => {
  assert.throws(() => page({}, {}, { head: `alg:1:${'a'.repeat(64)}` }), /snapshot/);
  assert.throws(() => page({}, {}, { binding: { tenant: 'other', repository: 'repo' } }), /identity/);
  assert.throws(() => page({}, {}, { binding: { tenant: 'tenant', repository: 'other' } }), /identity/);
});

test('malformed counters, unsafe integers and dishonest stopping states refuse', () => {
  for (const extra of [{ count: 2 }, { scanned: 0 }, { scanned: 201 }, { scanned: 1.5 },
    { after: 1 }, { limit: 21 }, { max_scan: 201 }, { next_after: 1 },
    { stop_reason: 'partial' }, { complete: false }, { has_more_candidates: true },
    { complete: false, has_more_candidates: true, stop_reason: 'scan_limit', next_after: 1 },
    { complete: false, has_more_candidates: true, stop_reason: 'result_limit', next_after: 1 },
    { issues: [issue(Number.MAX_SAFE_INTEGER + 1)] }]) assert.throws(() => page(extra));
  const scan = { issues: [], scanned: 200, complete: false, has_more_candidates: true, stop_reason: 'scan_limit' };
  for (const next_after of [0, 199, -1, 1.5, '350', Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => page({ ...scan, next_after }));
  }
});

test('all filters are conjunctive and nonmatching rows cannot be displayed', () => {
  const input = { state: 'open', opened_by: actor, labels: ['bug'], text: 'HTTP' };
  for (const extra of [{ state: 'closed' }, { opened_by: 'e'.repeat(32) },
    { labels: [] }, { title: 'different' }, { labels: ['bug', 'bug'] }]) {
    assert.throws(() => page({ issues: [issue(1, extra)] }, input));
  }
  assert.throws(() => page({ issues: [issue(2), issue(1)] }));
  assert.throws(() => page({ issues: [issue(1), issue(1)] }));
});

test('literal matching folds ASCII only and never joins title and body', () => {
  assert.equal(page({}, { text: 'http' }).reply.count, 1);
  assert.throws(() => page({}, { text: 'http', case_sensitive: true }));
  assert.throws(() => page({ issues: [issue(1, { title: 'É', body: '' })] }, { text: 'é' }));
  assert.throws(() => page({ issues: [issue(1, { title: 'ab', body: 'cd' })] }, { text: 'bc' }));
  assert.equal(page({ issues: [issue(1, { title: 'é🦀', body: '' })] }, { text: 'é🦀' }).reply.count, 1);
});

test('a search does not mutate the exact staged request or its recovery receipt', async () => {
  const client = fresh(async () => json(searchPage())); await client.connect(token);
  await client.stage(1, 1, 'comment', { body: 'original' });
  const before = client.pending;
  await client.search({});
  assert.deepEqual(client.pending, before); assert.equal(client.pending.sent, false);
  const receipt = client.exportReceipt();
  await client.search({});
  assert.equal(client.exportReceipt(), receipt);
});

test('canceling a search does not cancel an already dispatched change', async () => {
  const write = deferred(), read = deferred(); const calls = [];
  const client = fresh((url, options) => {
    calls.push({ url: String(url), ...options });
    return String(url).endsWith('/search') ? read.promise : write.promise;
  });
  await client.connect(token); await client.stage(1, 1, 'comment', { body: 'original' });
  const sending = client.send(); const searching = client.search({});
  client.cancelReads();
  assert.equal(calls[0].signal.aborted, false); assert.equal(calls[1].signal.aborted, true);
  const refused = assert.rejects(searching);
  read.resolve(json(searchPage())); write.resolve(json(terminal));
  await refused; assert.equal((await sending).outcome, 'committed');
  assert.equal(client.pending, null);
});

test('authorization failure has no empty success or automatic search retry', async () => {
  let calls = 0;
  const client = fresh(async () => { calls += 1; return json({}, 403); });
  await client.connect(token); await assert.rejects(client.search({}), /scope/);
  assert.equal(calls, 1); assert.equal(client.binding, null); assert.equal(client.pending, null);
});

test('input changes during transport cannot rewrite the checked predicate', async () => {
  const reply = deferred(), input = { labels: ['bug'], text: 'HTTP' };
  const client = fresh(() => reply.promise); await client.connect(token);
  const reading = client.search(input);
  input.labels.push('later'); input.text = 'different';
  reply.resolve(json(searchPage({}, { labels: ['bug'], text: 'HTTP' })));
  const result = await reading;
  assert.deepEqual(result.query.labels, ['bug']); assert.equal(result.query.text, 'HTTP');
});
