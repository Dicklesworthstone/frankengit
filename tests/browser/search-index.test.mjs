import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { Transport, form } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { indexQuery, indexReply, verifyWordSpans, INDEX_WORK, INDEX_PAYLOAD } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { crypto, token, href, hex, fixture, json, deferred } from './search-index-fixtures.mjs';
const input = (channel = 'content') => ({ mode: 'indexed', channel, termsHex: [hex('BETA'), hex('alpha'), hex('beta')], maxMatches: 1 });
async function connect(f, options = {}) { const c = new CodeSearch({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto, ...options }); await c.connect(token, f.common.ref, f.algorithm); return c; }
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: query normalizes all terms and freezes source/index pagination`, async () => {
    const f = fixture(algorithm), c = await connect(f), q = input(), first = await c.search(q);
    q.termsHex[0] = hex('else'); first.query.termsHex[0] = hex('else'); first.index.token = 'bad';
    assert.equal(f.calls.length, 1); assert.equal(c.state.result.complete, false);
    assert.deepEqual(f.calls[0].params.getAll('term_hex'), [hex('alpha'), hex('beta')]);
    assert.equal(f.calls[0].headers['idempotency-key'], undefined);
    assert.equal(f.calls[0].headers.authorization, `Bearer ${token}`);
    assert.equal(f.calls[0].redirect, 'error'); assert.equal(f.calls[0].credentials, 'omit');
    // The current index head may advance; the queried immutable index may not.
    f.config.selected = { token: `alg:2:${'6'.repeat(64)}`, number: 8 };
    const second = await c.nextIndexed(), p = f.calls.at(-1).params;
    assert.equal(second.hits[0].documentId, 2); assert.equal(second.index.token, f.index.token);
    for (const [key, value] of Object.entries({ expected_head: f.common.snapshot_token, expected_commit: f.common.source_commit,
      index_token: f.index.token, index_number: '7', after: '1', minimum_index_token: f.index.token, minimum_index_number: '7' })) assert.equal(p.get(key), value);
    const last = await c.nextIndexed(); assert.equal(last.complete, true); assert.equal(last.nextAfter, null); assert.equal(last.seen, 3);
    assert.equal(f.calls.at(-1).params.get('minimum_index_number'), '8'); await assert.rejects(c.nextIndexed());
  });
  test(`${algorithm}: complete native blob and first content word spans are independently verified`, async () => {
    const f = fixture(algorithm), c = await connect(f); await c.search(input()); const opened = await c.openIndexed(0);
    assert.deepEqual(opened.bytes, new Uint8Array(f.docs[0].bytes));
    assert(opened.blobVerified && opened.wordSpansVerified); assert.equal(opened.coverageVerified, false);
    assert.equal(f.calls.at(-1).params.get('expected_head'), f.common.snapshot_token);
    assert.equal(f.calls.at(-1).params.get('expected_commit'), f.common.source_commit);
    await assert.rejects(c.openMatch(0, 0));
  });
  test(`${algorithm}: path channel verifies byte spans, including empty file and non-UTF-8 path`, async () => {
    const f = fixture(algorithm, [{ path: Buffer.concat([Buffer.from('src/ALPHA_1-'), Buffer.from([255])]), bytes: Buffer.alloc(0) }]), c = await connect(f);
    const r = await c.search({ ...input('path'), termsHex: [hex('alpha_1'), hex('src')] });
    assert.equal(r.hits.length, 1); assert.equal(r.hits[0].contentBytes, 0);
    const v = await c.openIndexed(0); assert.equal(v.bytes.length, 0); assert.equal(v.channel, 'path'); assert(v.wordSpansVerified);
  });
  test(`${algorithm}: paged file verification never accepts truncation or changing modes`, async () => {
    const f = fixture(algorithm, [{ path: Buffer.from('large'), bytes: Buffer.from('alpha beta\n' + '\0'.repeat(131080)) }]), c = await connect(f);
    await c.search(input()); const full = await c.openIndexed(0); assert.equal(full.bytes.length, f.docs[0].bytes.length);
    assert.equal(f.calls.filter(c => c.path === 'source/blob').length, 3);
    f.config.blob = r => { if (r.offset) r.kind = 'executable'; }; await assert.rejects(c.openIndexed(0), /mode changed/);
    f.config.blob = r => { r.next_offset = null; }; await assert.rejects(c.openIndexed(0), /page/);
  });
}
test('query grammar rejects patterns, Unicode, unsupported controls and widened bounds before HTTP', async () => {
  for (const q of [ { ...input(), channel: 'symbol' }, { ...input(), termsHex: [] }, { ...input(), termsHex: [hex('a b')] },
    { ...input(), termsHex: [hex('.*')] }, { ...input(), termsHex: [hex('é')] }, { ...input(), termsHex: [hex('x'.repeat(129))] },
    { ...input(), termsHex: Array(33).fill(hex('a')) }, { ...input(), force: true }, { ...input(), maxMatches: 101 },
    { ...input(), maxWork: INDEX_WORK + 1 }, { ...input(), maxPayloadBytes: INDEX_PAYLOAD + 1 },
    { ...input(), prefixesHex: [hex('../bad')] }, { ...input(), prefixesHex: [hex('.GiT/config')] },
    { ...input(), prefixesHex: [hex('a/'.repeat(64) + 'b')] }, { ...input(), prefixesHex: Array(9).fill(hex('a'.repeat(4096))) } ]) {
    const f = fixture(), c = await connect(f); await assert.rejects(c.search(q)); assert.equal(f.calls.length, 0);
  }
});
const invalid = [
  ['profile', r => r.profile = 'literal-bytes-v1'], ['channel', r => r.channel = 'path'], ['term echo', r => r.terms_hex.reverse()],
  ['prefix echo', r => r.path_prefix_hex = [hex('src')]], ['wrong reference', r => r.ref = 'refs/heads/other'],
  ['wrong format', r => r.object_format = 'sha256'], ['write claim', r => r.published = true], ['wrong after', r => r.after = 1],
  ['wrong limit', r => r.limit = 2], ['hit count', r => r.returned_hits++], ['unsafe document ID', r => r.hits[0].document_id = 2**53],
  ['zero document ID', r => r.hits[0].document_id = 0], ['foreign blob', r => r.hits[0].blob = 'a'.repeat(64)],
  ['unsafe path', r => r.hits[0].path_hex = hex('../file')], ['span index', r => r.hits[0].spans[0].query_index = 1],
  ['span length', r => r.hits[0].spans[0].byte_length++], ['span outside file', r => r.hits[0].spans[0].byte_offset = 100],
  ['missing term', r => r.hits[0].spans.pop()], ['false complete', r => r.complete = true], ['missing lookahead cursor', r => r.next_after = null],
  ['cursor mismatch', r => r.next_after = 2], ['index token', r => r.index_token = 'a'.repeat(40)], ['zero token', r => r.index_token = `alg:2:${'0'.repeat(64)}`],
  ['unsafe index number', r => r.index_number = 2**53], ['selected index behind', r => r.selected_index_number = 6],
  ['same-position fork', r => r.selected_index_token = `alg:2:${'9'.repeat(64)}`], ['work overflow', r => r.work_units = INDEX_WORK + 1],
  ['payload overflow', r => r.payload_bytes_read = INDEX_PAYLOAD + 1], ['corpus too small', r => r.indexed_documents = 1],
];
for (const [name, change] of invalid) test(`invalid ${name} cannot retain a result or continuation`, async () => {
  const f = fixture(), c = await connect(f); f.config.query = change;
  await assert.rejects(c.search(input())); assert.equal(c.state.result, null); await assert.rejects(c.nextIndexed());
});
for (const [name, change] of [ ['different index', r => { r.index_token = `alg:2:${'6'.repeat(64)}`; r.index_number = 8; r.selected_index_token = r.index_token; r.selected_index_number = 8; }],
  ['source head', r => r.snapshot_token = `alg:2:${'a'.repeat(64)}`], ['source commit', r => r.source_commit = 'c'.repeat(40)],
  ['incarnation', r => r.repository_incarnation = '9'.repeat(32)], ['document order', r => r.hits[0].document_id = 1],
  ['path order', r => r.hits[0].path_hex = hex('a')], ['corpus changes', r => r.indexed_documents = 4],
  ['empty continuation', r => { r.hits = []; r.returned_hits = 0; r.complete = true; r.next_after = null; }] ]) {
  test(`continuation refuses ${name} without switching to current data`, async () => {
    const f = fixture(), c = await connect(f); await c.search(input()); f.config.query = change;
    await assert.rejects(c.nextIndexed()); assert.equal(c.state.result, null); assert.equal(f.calls.length, 2);
  });
}
for (const status of [400, 403, 404, 409, 413, 429, 503]) test(`HTTP ${status} never triggers build, refresh, fallback or retry`, async () => {
  const f = fixture(), c = await connect(f); f.config.fail = () => json({ type: 'source_error', code: 'source_index_stale' }, status);
  await assert.rejects(c.search(input()), e => e.status === status); assert.equal(f.calls.length, 1); assert.equal(c.state.result, null);
});
test('scope filters are slash-component based and terms use first WHOLE words', async () => {
  const f = fixture(), c = await connect(f);
  f.config.query = r => { r.hits[0].path_hex = hex('src-more/alpha'); };
  await assert.rejects(c.search({ ...input(), prefixesHex: [hex('src')] }));
  f.config.query = r => { r.hits[0].spans[0].byte_offset = 11; };
  await c.search(input()); await assert.rejects(c.openIndexed(0), /first complete words/);
  const q = indexQuery({ ...input(), termsHex: [hex('alpha')] });
  assert.throws(() => verifyWordSpans(Buffer.from('alphabet'), q, [{ queryIndex: 0, offset: 0, length: 5 }]));
});
test('path spans are checked before accepting the index page', async () => {
  const f = fixture(), c = await connect(f); f.config.query = r => { r.hits[0].spans[0].byte_offset++; };
  await assert.rejects(c.search({ ...input('path'), termsHex: [hex('src')] }));
});
test('file corruption, stale source and advertised length changes cannot be verified', async () => {
  for (const change of [r => { r.content_hex = r.content_hex.replace('41', '42'); }, r => { r.source_commit = 'd'.repeat(40); },
    r => { r.total_bytes++; }, r => { r.symlink_followed = true; }, r => { r.object_id = 'd'.repeat(40); }]) {
    const f = fixture(), c = await connect(f); await c.search(input()); f.config.blob = change; await assert.rejects(c.openIndexed(0));
  }
});
test('navigation byte ceiling refuses before any file fetch', async () => {
  const f = fixture(), c = await connect(f); await c.search({ ...input(), maxFileBytes: 1 });
  await assert.rejects(c.openIndexed(0)); assert.equal(f.calls.length, 1);
});
test('refresh releases source pins but retains index anti-rollback floor until disconnect', async () => {
  const f = fixture(), c = await connect(f); await c.search(input()); c.refreshSnapshot();
  assert.equal(c.state.pin, null); assert.deepEqual(c.state.indexMinimum, f.index);
  f.config.query = r => { r.index_number = 6; r.selected_index_number = 6; };
  await assert.rejects(c.search(input()), /checkpoint/); c.disconnect(); assert.equal(c.state.indexMinimum, null);
});
test('superseded replies cannot restore canceled query, file or a newer credential', async () => {
  const f = fixture(), c = await connect(f), d = deferred(); f.config.query = () => d.promise;
  const searching = c.search(input()); c.discardResults(); d.resolve(); await assert.rejects(searching); assert.equal(c.state.result, null);
  f.config.query = null; await c.search(input()); const file = deferred(); f.config.blob = () => file.promise;
  const opening = c.openIndexed(0); c.disconnect(); file.resolve(); await assert.rejects(opening); assert.equal(c.state.pin, null);
  const stale = deferred(); f.config.fail = () => stale.promise;
  await c.connect(token, f.common.ref, f.algorithm); const old = c.search(input());
  await c.connect('8'.repeat(64), f.common.ref, f.algorithm); stale.resolve(json({}, 401));
  await assert.rejects(old); assert(c.connected);
});
test('one operation deadline bounds all file pages, not one timer per page', async () => {
  const f = fixture(), c = await connect(f, { timeoutMs: 25 }); await c.search(input());
  const d = deferred(); f.config.blob = () => d.promise; const pending = c.openIndexed(0);
  await new Promise(r => setTimeout(r, 45)); d.resolve(); await assert.rejects(pending, /time limit/);
});
test('search transport admits the native index ONLY as a bounded bodyful read', async () => {
  const calls = []; const t = new Transport({ href, pageSuffix: '/ui/search/', cryptoImpl: crypto, fetchImpl: (u, o) => { calls.push(o); return json({}); } }); await t.connect(token);
  for (const options of [{ method: 'GET' }, { key: 'write' }, { read: false }, { binary: true }, { contentType: 'application/json' },
    { body: undefined }, { maximum: 0 }, { maximum: 9 * 1024 * 1024 }, { statuses: [200, 409] }]) {
    await assert.rejects(t.request('source/search-index', { method: 'POST', body: 'a=b', ...options }));
  }
  for (const path of ['source/index/build', 'source/search-index/refresh', 'source/initial/apply', 'source/apply', 'outcomes', 'source/search-index?x=1']) {
    await assert.rejects(t.request(path, { method: 'POST', body: 'a=b' }));
  }
  assert.equal(calls.length, 0); await t.request('source/search-index', { method: 'POST', body: 'a=b' }); assert.equal(calls.length, 1);
});
test('other browser write profiles do not acquire an indexed search route', async () => {
  for (const suffix of ['/ui/pulls/', '/ui/source/', '/ui/initial/', '/ui/branches/', '/ui/tags/', '/ui/replay/', '/ui/transfers/']) {
    const t = new Transport({ href: href.replace('/ui/search/', suffix), pageSuffix: suffix, cryptoImpl: crypto, fetchImpl: () => assert.fail('unexpected network') });
    await t.connect(token); await assert.rejects(t.request('source/search-index', { method: 'POST', body: 'a=b' }));
  }
});
test('native index module is in the existing source-gated asset graph', async () => {
  const route = await readFile(new URL('../../crates/fgit-node/src/smart_http/server/browser/search.rs', import.meta.url), 'utf8');
  assert(route.includes('b"/ui/search/search-index.mjs"')); assert(route.includes('profile.allow_source'));
});
test('real loopback HTTP/fetch carries exact pins and only read requests (server is a protocol double)', async () => {
  const f = fixture(), received = [];
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString(); received.push({ url: req.url, headers: req.headers, method: req.method, body });
    const response = await f.fetchImpl(`http://localhost${req.url}`, { method: req.method, body, headers: req.headers });
    res.writeHead(response.status, { 'Content-Type': 'application/json' }); res.end(Buffer.from(await response.arrayBuffer()));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const c = new CodeSearch({ href: `http://127.0.0.1:${server.address().port}/repo.git/ui/search/`, cryptoImpl: crypto });
    await c.connect(token, f.common.ref, 'sha1'); await c.search(input()); await c.nextIndexed(); await c.openIndexed(0); c.disconnect();
    assert.equal(received.length, 3); assert(received.every(r => r.method === 'POST' && !r.headers.cookie && !r.headers['idempotency-key']));
    assert(received.every(r => !r.url.includes(token) && !r.body.includes(token)));
    assert.equal(new URLSearchParams(received[1].body).get('index_token'), f.index.token);
  } finally { server.closeAllConnections(); await new Promise(r => server.close(r)); }
});
