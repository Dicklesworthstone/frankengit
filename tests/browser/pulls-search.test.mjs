// Browser protocol and DOM boundaries with actual production modules. HTTP
// replies and the DOM are controlled; native search execution is tested in Rust.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { pullSearchQuery, pullSearchReply, Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { token, actor, head, ids, scope, row, page, show, data, metadata, json, options, deferred, hex, webcrypto } from './pulls-fixtures.mjs';
import { terminal } from './pulls-candidate-fixtures.mjs';
import { labelsReply } from './pulls-labels-fixtures.mjs';
import { fakeDocument, until } from './helpers/pulls-workflow-fixture.mjs';

const predicate = extra => ({ state: 'all', opened_by: null, source_ref_hex: null,
  target_ref_hex: null, query: null, case_sensitive: false, ...extra });
const resultRow = (number = 7, extra = {}) => row(number, { data: data({ title: 'Fix HTTP', body: 'Native branch behavior' }), ...extra });
function searchPage(extra = {}, filters = {}) {
  const rows = extra.pull_requests ?? [resultRow()];
  return { ...ids, type: 'pull_request_search', source_head: 'head-id', snapshot_token: head,
    filters: predicate(filters), after: 0, limit: 20, max_scan: 200, scanned: rows.length,
    count: rows.length, complete: true, stop_reason: 'exhausted', next_after: null, pull_requests: rows, ...extra };
}
const checked = (extra = {}, query = {}, parameters = {}) => pullSearchReply(searchPage(extra, query), query, parameters);
const fresh = fetch => new PullClient(options(fetch));

test('search captures an immutable predicate and canonical exact reference bytes', () => {
  const input = { state: 'open', opened_by: actor, query: 'HTTP', source_ref: 'refs/heads/topic+one',
    target_ref_hex: `${hex('refs/heads/')}ff` };
  const query = pullSearchQuery(input);
  assert.deepEqual(query, predicate({ state: 'open', opened_by: actor, query: 'HTTP',
    source_ref_hex: hex('refs/heads/topic+one'), target_ref_hex: `${hex('refs/heads/')}ff` }));
  assert.ok(Object.isFrozen(query));
  assert.equal(input.source_ref, 'refs/heads/topic+one'); assert.equal(input.source_ref_hex, undefined);
  input.query = 'changed'; input.target_ref_hex = hex('refs/heads/other');
  assert.equal(query.query, 'HTTP'); assert.equal(query.target_ref_hex, `${hex('refs/heads/')}ff`);
  assert.deepEqual(pullSearchQuery(query), query);
});

test('invalid or ambiguous filters refuse before any credential-bearing request', async () => {
  const client = fresh(() => assert.fail('invalid filter dispatched')); await client.connect(token);
  for (const input of [null, [], '', { principal: actor }, { state: 'pending' }, { state: null },
    { opened_by: 'admin' }, { opened_by: 'A'.repeat(32) }, { query: '' }, { query: '\0' }, { query: '\ud800' },
    { query: 'é'.repeat(129) }, { query: 'x', case_sensitive: 'true' }, { case_sensitive: null }, { case_sensitive: true },
    { source_ref: 'topic' }, { target_ref: 'refs/tags/v1' }, { source_ref: 'refs/heads/../secret' },
    { source_ref: 'refs/heads/a', source_ref_hex: hex('refs/heads/a') },
    { target_ref_hex: 'f' }, { target_ref_hex: 'AA' }, { target_ref_hex: hex('refs/heads/a\0') }]) {
    await assert.rejects(client.search(input), undefined, JSON.stringify(input));
  }
  assert.equal(pullSearchQuery({ query: 'é'.repeat(128) }).query.length, 128);
  assert.equal(pullSearchQuery({ source_ref_hex: `${hex('refs/heads/')}ff` }).source_ref_hex, `${hex('refs/heads/')}ff`);
});

test('search bounds are exact and a nonzero continuation requires its original head', async () => {
  const client = fresh(() => assert.fail('invalid bounds dispatched')); await client.connect(token);
  for (const parameters of [null, [], { after: 1 }, { after: -1 }, { after: '1' }, { after: 0.5 },
    { after: Number.MAX_SAFE_INTEGER + 1, head }, { head: 'latest' }, { limit: 0 }, { limit: 101 },
    { maxScan: 0 }, { maxScan: 1001 }, { maxScan: 0.5 }, { max_scan: 20 }, { render: 'html_safe' }]) {
    await assert.rejects(client.search({}, parameters));
  }
});

test('search sends bodyless authenticated GET with exact filters, limits and pinned snapshot', async () => {
  let call;
  const filters = predicate({ state: 'open', opened_by: actor, query: 'body&principal=admin + é',
    source_ref_hex: hex('refs/heads/topic+one'), target_ref_hex: `${hex('refs/heads/')}ff`, case_sensitive: true });
  const client = fresh(async (url, request) => { call = { url: new URL(url), ...request };
    return json(searchPage({ after: 42, limit: 10, max_scan: 100, pull_requests: [], scanned: 0 }, filters)); });
  await client.connect(token);
  const result = await client.search({ ...filters, source_ref_hex: null, source_ref: 'refs/heads/topic+one' },
    { after: 42, limit: 10, maxScan: 100, head, render: true });
  assert.equal(call.url.pathname, '/team/repo.git/api/v1/pulls/search');
  assert.equal(call.method, 'GET'); assert.equal(call.body, undefined);
  assert.equal(call.headers.Authorization, `Bearer ${token}`); assert.equal(call.headers['Idempotency-Key'], undefined);
  for (const [name, expected] of Object.entries({ credentials: 'omit', mode: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer' })) assert.equal(call[name], expected);
  for (const [name, value] of Object.entries(filters)) assert.equal(call.url.searchParams.get(name), String(value));
  assert.equal(call.url.searchParams.has('principal'), false); assert.equal(call.url.searchParams.has('source_ref'), false);
  assert.equal(call.url.searchParams.get('expected_head'), head); assert.equal(call.url.searchParams.get('after'), '42');
  assert.equal(call.url.searchParams.get('limit'), '10'); assert.equal(call.url.searchParams.get('max_scan'), '100');
  assert.equal(call.url.searchParams.get('render'), 'html_safe');
  assert.deepEqual(result.query, filters); assert.deepEqual(client.binding, scope); assert.equal(client.pending, null);
});

test('the transport never sends search as a mutation, binary fetch, or recovery lookup', async () => {
  const transport = new Transport(options(() => assert.fail('invalid search dispatched'))); await transport.connect(token);
  for (const request of [{ method: 'POST' }, { body: 'query=x' }, { key: 'write-key' }, { read: false },
    { binary: true }, { statuses: [200, 404] }, { maximum: 8 * 1024 * 1024 + 1 }]) {
    await assert.rejects(transport.request('pulls/search?query=x', request));
  }
  const client = fresh(() => assert.fail('recovery credential used for search'));
  await client.connect(token, { recoveryOnly: true, originalPrincipal: actor });
  await assert.rejects(client.search({}), /Recovery-only/);
});

test('zero matching rows preserve a scan-limited last-examined cursor', () => {
  const result = checked({ pull_requests: [], scanned: 200, complete: false, stop_reason: 'scan_limit', next_after: 350 });
  assert.equal(result.reply.count, 0); assert.equal(result.reply.next_after, 350); assert.equal(result.reply.complete, false);
  const tail = checked({ after: 350, pull_requests: [], scanned: 0 }, {}, { after: 350, head });
  assert.equal(tail.reply.complete, true); assert.equal(tail.reply.next_after, null);
});

test('result limits and exhausted boundaries remain distinct in both native hash domains', () => {
  for (const object_format of ['sha1', 'sha256']) {
    const width = object_format === 'sha1' ? 40 : 64;
    const rows = [resultRow(7, { data: data({ object_format, source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width) }) })];
    const extra = { object_format, pull_requests: rows, limit: 1, max_scan: 2, scanned: 2 };
    assert.equal(checked(extra, {}, { limit: 1, maxScan: 2 }).reply.complete, true);
    assert.equal(checked({ ...extra, complete: false, stop_reason: 'result_limit', next_after: 7 }, {},
      { limit: 1, maxScan: 2 }).reply.complete, false);
  }
});

test('echoed filters, authority identity, and snapshot must match the original read', () => {
  const filters = predicate({ state: 'open', query: 'HTTP', opened_by: actor, source_ref_hex: hex('refs/heads/topic') });
  const valid = searchPage({}, filters);
  assert.equal(pullSearchReply(valid, filters).reply.count, 1);
  for (const change of [{ state: 'all' }, { query: null }, { opened_by: null }, { source_ref_hex: null },
    { target_ref_hex: hex('refs/heads/main') }, { case_sensitive: true }, { scope: 'comments' }]) {
    assert.throws(() => pullSearchReply({ ...valid, filters: { ...valid.filters, ...change } }, filters));
  }
  for (const change of [{ type: 'pull_request_page' }, { schema_version: 2 }, { snapshot_token: `alg:1:${'a'.repeat(64)}` },
    { repository_id: 'other' }, { repository_incarnation: 'other' }, { object_format: 'sha256' }]) {
    assert.throws(() => pullSearchReply({ ...valid, ...change }, filters, { head, scope }));
  }
});

test('dishonest counters, cursors, ordering and stopping states fail closed', () => {
  for (const extra of [{ count: 2 }, { scanned: 0 }, { scanned: 201 }, { scanned: 1.5 }, { after: 1 },
    { limit: 21 }, { max_scan: 201 }, { complete: false }, { stop_reason: 'partial' }, { next_after: 7 },
    { complete: false, stop_reason: 'result_limit', next_after: 7 },
    { complete: false, stop_reason: 'scan_limit', next_after: 7 },
    { pull_requests: [resultRow(8), resultRow(7)] }, { pull_requests: [resultRow(7), resultRow(7)] },
    { pull_requests: [resultRow(Number.MAX_SAFE_INTEGER + 1)] }]) assert.throws(() => checked(extra));
  const scan = { pull_requests: [], scanned: 200, complete: false, stop_reason: 'scan_limit' };
  for (const next_after of [null, 0, 199, -1, 0.5, '350', Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => checked({ ...scan, next_after }));
  assert.throws(() => checked({ limit: 1, max_scan: 1, scanned: 1, complete: false, stop_reason: 'scan_limit', next_after: 7 }, {}, { limit: 1, maxScan: 1 }));
});

test('every returned PR must match all selected metadata and native reference filters', () => {
  const filters = { state: 'open', opened_by: actor, query: 'HTTP', source_ref_hex: hex('refs/heads/topic'), target_ref_hex: hex('refs/heads/main') };
  for (const changed of [{ state: 'closed' }, { opened_by: 'f'.repeat(32) },
    { data: data({ title: 'different', body: '' }) },
    { data: data({ title: 'HTTP', source_ref: 'refs/heads/other', source_ref_hex: hex('refs/heads/other') }) },
    { data: data({ title: 'HTTP', target_ref: 'refs/heads/other', target_ref_hex: hex('refs/heads/other') }) }]) {
    assert.throws(() => checked({ pull_requests: [resultRow(7, changed)] }, filters));
  }
  const source_ref_hex = `${hex('refs/heads/')}ff`, selected = resultRow(7, { data: data({ source_ref: null, source_ref_hex }) });
  assert.equal(checked({ pull_requests: [selected] }, { source_ref_hex }).reply.pull_requests[0].data.source_ref, null);
});

test('literal text uses ASCII folding only and never joins title with body', () => {
  assert.equal(checked({}, { query: 'http' }).reply.count, 1);
  assert.throws(() => checked({}, { query: 'http', case_sensitive: true }));
  assert.throws(() => checked({ pull_requests: [resultRow(7, { data: data({ title: 'É', body: '' }) })] }, { query: 'é' }));
  assert.throws(() => checked({ pull_requests: [resultRow(7, { data: data({ title: 'ab', body: 'cd' }) })] }, { query: 'bc' }));
  assert.equal(checked({ pull_requests: [resultRow(7, { data: data({ title: 'é🦀', body: '' }) })] }, { query: 'é🦀' }).reply.count, 1);
});

test('search rows retain and validate the independent canonical label stream', () => {
  const labels = { labels: ['bug', 'needs review'], labels_version: 3, labels_actor: actor };
  const result = checked({ pull_requests: [resultRow(7, labels)] }, { query: 'HTTP' });
  assert.deepEqual(result.reply.pull_requests[0].labels, labels.labels);
  assert.equal(result.reply.pull_requests[0].labels_version, 3);
  for (const invalid of [{ labels: ['bug', 'bug'] }, { labels: ['needs review', 'bug'] },
    { labels_version: 0 }, { labels_actor: null }]) {
    assert.throws(() => checked({ pull_requests: [resultRow(7, { ...labels, ...invalid })] }));
  }
});

test('merge-only records match their real merge refs and never invented opener or text', () => {
  const merged = resultRow(7, { state: 'merged', data: null, opened_by: null, last_metadata_actor: null, merge_only: true,
    merge: { ...data(), target_tip_before: 'b'.repeat(40), base_tip: 'e'.repeat(40), merge_commit: 'd'.repeat(40) } });
  const filters = { state: 'merged', source_ref_hex: hex('refs/heads/topic'), target_ref_hex: hex('refs/heads/main') };
  assert.equal(checked({ pull_requests: [merged] }, filters).reply.count, 1);
  for (const extra of [{ opened_by: actor }, { query: 'Title' }, { state: 'open' }]) {
    assert.throws(() => checked({ pull_requests: [merged] }, { ...filters, ...extra }));
  }
  assert.throws(() => checked({ pull_requests: [{ ...merged, opened_by: actor }] }, { ...filters, opened_by: actor }));
});

test('search cannot rewrite a staged request or its exported recovery receipt', async () => {
  const client = fresh(async () => json(searchPage())); await client.connect(token); await client.search();
  await client.stageMetadata(7, 'update', metadata());
  const pending = client.pending; await client.search(); assert.deepEqual(client.pending, pending);
  const receipt = client.exportReceipt(); await client.search(); assert.equal(client.exportReceipt(), receipt);
});

test('search preserves an exact staged label replacement and its recovery identity', async () => {
  const selectedRow = resultRow(7, { labels: ['bug'], labels_version: 2, labels_actor: actor });
  const observed = show({ number: 7, pull_request: selectedRow });
  const client = fresh(async url => json(new URL(url).pathname.endsWith('/search')
    ? searchPage({ pull_requests: [selectedRow] }) : new URL(url).pathname.endsWith('/labels') ? labelsReply(observed) : observed));
  await client.connect(token); await client.search();
  const selected = await client.show(7, head), labels = await client.labels(7, selected);
  await client.stageLabels(7, labels, ['reviewed']);
  const receipt = client.exportReceipt(), pending = client.pending;
  await client.search();
  assert.deepEqual(client.pending, pending); assert.equal(client.exportReceipt(), receipt);
  assert.equal(client.pending.action, 'set-labels'); assert.equal(client.pending.fields.expected_version, 2);
});

test('canceling search leaves an already dispatched mutation alive and recoverable', async () => {
  const read = deferred(), write = deferred(), calls = [];
  let searching = false;
  const client = fresh((url, request) => { calls.push({ url: new URL(url), ...request });
    return new URL(url).pathname.endsWith('/update') ? write.promise : searching ? read.promise : json(searchPage()); });
  await client.connect(token); await client.search(); await client.stageMetadata(7, 'update', metadata());
  const pending = client.pending, sending = client.send(); searching = true;
  const finding = client.search(), refused = assert.rejects(finding);
  client.cancelReads();
  assert.equal(calls.at(-2).signal.aborted, false); assert.equal(calls.at(-1).signal.aborted, true);
  read.resolve(json(searchPage())); write.resolve(json(terminal(pending)));
  await refused; assert.equal((await sending).outcome, 'committed'); assert.equal(client.pending, null);
});

test('authorization refusal neither fabricates an empty page nor retries automatically', async () => {
  let calls = 0;
  const client = fresh(async () => { calls++; return json({}, 403); }); await client.connect(token);
  await assert.rejects(client.search(), /scope/); assert.equal(calls, 1);
  assert.equal(client.connected, true); assert.equal(client.binding, null); assert.equal(client.pending, null);
});

test('edits during an in-flight request cannot change its checked predicate', async () => {
  const wait = deferred(), input = { query: 'HTTP', state: 'open' };
  const client = fresh(() => wait.promise); await client.connect(token);
  const finding = client.search(input); input.query = 'changed'; input.state = 'closed';
  wait.resolve(json(searchPage({}, { query: 'HTTP', state: 'open' })));
  const result = await finding; assert.equal(result.query.query, 'HTTP'); assert.equal(result.query.state, 'open');
});

async function browser(respond = () => null) {
  const document = fakeDocument(), calls = [], node = id => document.getElementById(id);
  const app = mountPulls(document, { href: 'https://forge.example/team/repo.git/ui/pulls/', cryptoImpl: webcrypto,
    fetchImpl: async (url, request) => {
      const call = { url: new URL(url), ...request }; calls.push(call);
      const result = await respond(call);
      if (result !== null && result !== undefined) return result;
      if (call.url.pathname.endsWith('/pulls')) return json(page());
      const selected = call.url.pathname.match(/\/pulls\/([1-9][0-9]*)$/);
      if (selected) return json(show({ number: Number(selected[1]), pull_request: resultRow(Number(selected[1])) }));
      throw new Error(`Unexpected test route ${call.url}`);
    } });
  await app.client.connect(token); await app.loadList();
  const submit = async () => { node('pr-search').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => !node('search-submit').disabled); };
  const click = async (container, prefix) => {
    const find = parent => parent.children.find(child => child.tagName === 'BUTTON' && child.textContent.startsWith(prefix))
      ?? parent.children.map(find).find(Boolean);
    const button = find(node(container)); assert.ok(button, `missing ${prefix}`); button.click();
    await until(() => !node('search-submit').disabled);
  };
  return { app, calls, document, node, submit, click };
}

test('the actual search form continues an empty scan with frozen filters and opens at its snapshot', async () => {
  let pages = 0;
  const filters = { state: 'open', query: 'HTTP', opened_by: actor, source_ref_hex: hex('refs/heads/topic') };
  const h = await browser(call => {
    if (!call.url.pathname.endsWith('/search')) return null;
    pages++;
    return json(searchPage(pages === 1
      ? { limit: 1, max_scan: 2, pull_requests: [], scanned: 2, complete: false, stop_reason: 'scan_limit', next_after: 10 }
      : { after: 10, limit: 1, max_scan: 2, pull_requests: [resultRow(12)] }, filters));
  });
  h.node('search-query').value = 'HTTP'; h.node('search-state').value = 'open'; h.node('search-opened-by').value = actor;
  h.node('search-source-ref').value = 'refs/heads/topic'; h.node('search-limit').value = '1'; h.node('search-max-scan').value = '2';
  await h.submit();
  assert.match(h.node('pr-list').textContent, /0 matches; 2 PRs examined/);
  assert.match(h.node('pr-list').textContent, /No matches on this page.*Continue searching/);
  h.node('search-query').value = 'changed'; h.node('search-state').value = 'closed'; h.node('search-opened-by').value = '';
  h.node('search-source-ref').value = 'refs/heads/other'; h.node('search-limit').value = '10'; h.node('search-max-scan').value = '20';
  await h.click('list-paging', 'Continue PR search');
  const next = h.calls.at(-1).url.searchParams;
  assert.equal(next.get('after'), '10'); assert.equal(next.get('expected_head'), head);
  assert.equal(next.get('query'), 'HTTP'); assert.equal(next.get('state'), 'open'); assert.equal(next.get('opened_by'), actor);
  assert.equal(next.get('source_ref_hex'), hex('refs/heads/topic')); assert.equal(next.get('limit'), '1'); assert.equal(next.get('max_scan'), '2');
  assert.match(h.node('pr-list').textContent, /Search complete/); assert.match(h.node('pr-list').textContent, /#12/);
  assert.equal(h.node('list-paging').children.length, 0);
  // The existing row reader receives the search snapshot, never a fresh head.
  h.calls.length = 0;
  await h.click('pr-list', '#12');
  assert.equal(h.calls[0].url.searchParams.get('expected_head'), head);
  assert.match(h.node('selected').textContent, /#12 · open/);
});

test('refresh repeats applied filters at latest head; clear restores the ordinary PR list', async () => {
  const h = await browser(call => call.url.pathname.endsWith('/search')
    ? json(searchPage({}, { query: 'HTTP' })) : null);
  h.node('search-query').value = 'HTTP'; await h.submit();
  h.node('search-query').value = 'unsaved';
  h.node('refresh').click(); await until(() => !h.node('search-submit').disabled);
  const refresh = h.calls.at(-1).url.searchParams;
  assert.equal(refresh.get('query'), 'HTTP'); assert.equal(refresh.get('after'), '0'); assert.equal(refresh.has('expected_head'), false);
  h.node('label-filter-values').value = 'unsubmitted label filter';
  h.node('search-clear').click(); await until(() => !h.node('search-submit').disabled);
  assert.equal(h.calls.at(-1).url.pathname.endsWith('/pulls'), true);
  assert.deepEqual(h.calls.at(-1).url.searchParams.getAll('label'), []); assert.equal(h.node('label-filter-values').value, '');
  assert.equal(h.node('search-query').value, ''); assert.equal(h.node('search-state').value, 'all');
  assert.equal(h.node('refresh').textContent, 'Refresh PR list');
});

test('stale continuation clears old results and never silently restarts the search', async () => {
  let searches = 0;
  const h = await browser(call => !call.url.pathname.endsWith('/search') ? null : ++searches === 1
    ? json(searchPage({ pull_requests: [], scanned: 200, complete: false, stop_reason: 'scan_limit', next_after: 350 }))
    : json({}, 409));
  await h.submit(); await h.click('list-paging', 'Continue PR search');
  assert.equal(searches, 2); assert.equal(h.node('pr-list').textContent, ''); assert.equal(h.node('list-paging').textContent, '');
  assert.match(h.node('status').textContent, /snapshot changed.*refresh explicitly/i);
});

test('raw branch searches and hostile literal metadata remain exact inert display text', async () => {
  const source_ref_hex = `${hex('refs/heads/')}ff`, title = '<img src=x onerror=alert(1)>', filters = { source_ref_hex, query: '<img' };
  const h = await browser(call => call.url.pathname.endsWith('/search') ? json(searchPage({ pull_requests: [resultRow(7,
    { data: data({ title, source_ref: null, source_ref_hex }), labels: ['bug'], labels_version: 2, labels_actor: actor })] }, filters)) : null);
  h.node('search-source-encoding').value = 'hex'; h.node('search-source-ref').value = source_ref_hex;
  h.node('search-query').value = '<img'; await h.submit();
  assert.equal(h.calls.at(-1).url.searchParams.get('source_ref_hex'), source_ref_hex);
  assert.match(h.node('pr-list').textContent, /<img src=x onerror=alert\(1\)>/);
  assert.match(h.node('pr-list').textContent, /Applied filters/);
  assert.match(h.node('pr-list').textContent, /labels: "bug"/);
  h.app.disconnect();
  for (const id of ['search-query', 'search-source-ref', 'search-opened-by']) assert.equal(h.node(id).value, '');
  assert.equal(h.node('pr-list').textContent, ''); assert.equal(h.node('search-submit').disabled, true);
});
