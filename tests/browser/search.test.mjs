import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { byteInput, query, pathHex } from '../../crates/fgit-node/src/smart_http/server/browser/search-data.mjs';
import { TOKEN, HREF, fixture, literal, batch, regex, encode, response, hex } from './search-fixtures.mjs';

async function connected(f = fixture(), extra = {}) {
  const client = new CodeSearch({ ...f.options, ...extra });
  await client.connect(TOKEN, 'refs/heads/main', f.algorithm);
  return { client, f };
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: literal, batch and regex navigate only exact pinned and hash-verified source`, async () => {
    for (const input of [literal(), batch(), regex()]) {
      const { client, f } = await connected(fixture(algorithm));
      const result = await client.search(input);
      assert.equal(result.query.mode, input.mode);
      assert.equal(result.pin.commit, f.identity.source_commit);
      assert.ok(result.totalMatches > 0);
      const loaded = await client.openMatch(0, 0);
      const file = f.files.find(x => x.pathHex === loaded.hit.pathHex);
      assert.deepEqual(Buffer.from(loaded.bytes), file.body);
      assert.equal(loaded.blobVerified, true); assert.equal(loaded.coordinatesVerified, true);
      assert.equal(loaded.literalVerified, input.mode !== 'regex');
      assert.equal(loaded.regexEvaluatedBy, input.mode === 'regex' ? 'native-server' : null);
      for (const call of f.calls) {
        assert.equal(call.method, 'POST'); assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error');
        assert.equal(call.mode, 'same-origin'); assert.equal(call.cache, 'no-store'); assert.equal(call.referrerPolicy, 'no-referrer');
        assert.equal(call.headers.Authorization, `Bearer ${TOKEN}`); assert.equal(call.headers['Idempotency-Key'], undefined);
        assert.equal(call.url.includes(TOKEN), false);
      }
      for (const call of f.calls.slice(1)) {
        const fields = new URLSearchParams(call.body);
        assert.equal(fields.get('expected_head'), result.pin.head);
        assert.equal(fields.get('expected_commit'), result.pin.commit);
      }
      client.disconnect(); assert.equal(client.state.result, null); assert.equal(client.state.pin, null);
    }
  });
  test(`${algorithm}: multibyte/binary paths and needles preserve raw coordinates and case`, async () => {
    const f = fixture(algorithm, [[Buffer.from([0x73, 0x72, 0x63, 0x2f, 0xff]), Buffer.from([0xc3, 0xa9, 0, 255, 65, 10])]]);
    const { client } = await connected(f);
    const result = await client.search(batch({ needlesHex: ['00ff', 'ff61'], case: 'ascii-insensitive', prefixesHex: [encode('src')] }));
    assert.equal(result.groups[0].matches[0].offset, 2);
    assert.equal(result.groups[1].matches[0].column, 4);
    assert.equal((await client.openMatch(1, 0)).blobVerified, true);
    client.disconnect();
  });
  test(`${algorithm}: complete file is paged and hashed once, with every continuation pinned`, async () => {
    const body = Buffer.concat([Buffer.alloc(65534, 120), Buffer.from('needle\n'), Buffer.alloc(70000, 121)]);
    const { client, f } = await connected(fixture(algorithm, [['big', body]]));
    await client.search(literal()); const result = await client.openMatch(0, 0);
    assert.equal(result.hit.offset, 65534); assert.deepEqual(Buffer.from(result.bytes), body);
    assert.deepEqual(f.calls.slice(1).map(c => Number(new URLSearchParams(c.body).get('offset'))), [0, 65536, 131072]);
    client.disconnect();
  });
  test(`${algorithm}: long and empty regex spans verify file bytes without browser regex execution`, async () => {
    const { client } = await connected(fixture(algorithm, [['empty-line', '\n'], ['long', `${'x'.repeat(5000)}\n`]]));
    const result = await client.search(regex('.*'));
    assert.equal(result.groups[0].matches[0].length, 0);
    assert.equal(result.groups[0].matches[1].length, 5000);
    assert.equal(result.groups[0].matches[1].truncated, true);
    assert.equal((await client.openMatch(0, 0)).coordinatesVerified, true);
    assert.equal((await client.openMatch(0, 1)).coordinatesVerified, true);
    client.disconnect();
  });
}

test('batch keeps duplicates, submission order, independent completion, and shared work', async () => {
  const { client, f } = await connected();
  const result = await client.search(batch({ needlesHex: [encode('needle'), encode('absent'), encode('needle')], maxMatches: 1 }));
  assert.deepEqual(result.groups.map(g => g.complete), [false, true, false]);
  assert.deepEqual(result.groups.map(g => g.queryIndex), [0, 1, 2]);
  assert.deepEqual(result.groups[0].matches, result.groups[2].matches);
  assert.equal(result.stats.bytesRead, f.files.reduce((n, f) => n + f.body.length, 0));
  client.disconnect();
});
test('an exact bound stays complete; absent results are explicit rather than a request error', async () => {
  const { client } = await connected();
  assert.equal((await client.search(literal({ maxMatches: 2 }))).groups[0].complete, true);
  const absent = await client.search(literal({ needlesHex: [encode('absent')] }));
  assert.equal(absent.groups[0].complete, true); assert.equal(absent.totalMatches, 0);
  await assert.rejects(client.openMatch(0, 0)); client.disconnect();
});
test('prefix canonicalization preserves component boundaries and caller query arrays are captured', async () => {
  const { client, f } = await connected();
  const input = batch({ prefixesHex: [encode('src'), encode('src')], needlesHex: [encode('needle')] });
  const pending = client.search(input); input.needlesHex[0] = encode('absent'); input.prefixesHex[0] = encode('src2');
  const result = await pending;
  assert.deepEqual(result.query.prefixesHex, [encode('src')]); assert.equal(result.stats.filesSelected, 1);
  assert.equal(result.groups[0].matches[0].pathHex, encode('src/code.rs'));
  const fields = new URLSearchParams(f.calls[0].body); assert.deepEqual(fields.getAll('path_prefix_hex'), [encode('src')]);
  client.disconnect();
});
test('new searches retain the same snapshot until an explicit refresh, never a new incarnation', async () => {
  const { client, f } = await connected(); const first = await client.search(literal());
  f.identity.snapshot_token = `alg:1:${'cd'.repeat(32)}`; f.identity.source_head = 'head-two'; f.identity.source_rcr = 'rcr-two';
  await assert.rejects(client.search(literal()), /snapshot changed/);
  assert.equal(client.state.result, null); assert.equal(client.state.pin.head, first.pin.head);
  client.refreshSnapshot(); const second = await client.search(literal());
  assert.notEqual(second.pin.head, first.pin.head);
  f.identity.repository_incarnation = 'other-incarnation'; client.refreshSnapshot();
  await assert.rejects(client.search(literal()), /incarnation changed/);
  client.disconnect();
});
test('returned result edits cannot redirect later source requests or change internal state', async () => {
  const { client, f } = await connected(); const result = await client.search(literal());
  result.groups[0].matches[0].pathHex = encode('src2/private'); result.pin.commit = 'f'.repeat(40);
  client.state.result.groups[0].matches[0].blob = 'e'.repeat(40);
  await client.openMatch(0, 0);
  assert.equal(new URLSearchParams(f.calls.at(-1).body).get('path_hex'), encode('src/code.rs'));
  assert.equal(new URLSearchParams(f.calls.at(-1).body).get('expected_commit'), f.identity.source_commit);
  client.disconnect();
});
const corruptions = [
  ['identity', r => { r.repository_id = 'foreign'; }], ['incarnation', r => { r.repository_incarnation = 'foreign'; }],
  ['format', r => { r.object_format = 'sha256'; }], ['ref', r => { r.ref = 'refs/heads/other'; }],
  ['ref bytes', r => { r.ref_hex = encode('refs/heads/other'); }], ['read flag', r => { r.read_only = false; }],
  ['transaction flag', r => { r.transaction_created = true; }], ['publication flag', r => { r.published = true; }],
  ['schema', r => { r.schema_version = 2; }], ['snapshot', r => { r.snapshot_token += 'x'; }],
  ['root tree', r => { r.root_tree = 'f'.repeat(40); }], ['source RCR', r => { r.source_rcr = 'other-rcr'; }],
  ['source head', r => { r.source_head = 'other-head'; }], ['case', r => { r.case = 'unicode'; }],
  ['profile', r => { r.profile = 'fuzzy'; }], ['result count', r => { r.returned_matches++; }],
  ['completion', r => { r.complete = false; }], ['incomplete scan', r => { r.files_read--; }],
  ['unsafe counters', r => { r.bytes_read = Number.MAX_SAFE_INTEGER + 1; }], ['searched bytes', r => { r.bytes_searched++; }],
  ['missing lookahead bound', r => { r.completion = 'match_limit'; r.complete = false; }],
  ['ordering', r => { r.matches.reverse(); }], ['duplicate', r => { r.matches[1] = r.matches[0]; }],
  ['path escape', r => { r.matches[0].path_hex = encode('../secret'); }],
  ['wrong needle bytes', r => { r.matches[0].excerpt_hex = '78'.repeat(r.matches[0].excerpt_hex.length / 2); }],
  ['zero line', r => { r.matches[0].line = 0; }], ['impossible column', r => { r.matches[0].byte_column = 999; }],
  ['negative offset', r => { r.matches[0].byte_offset = -1; }], ['foreign OID', r => { r.matches[0].blob = 'f'.repeat(64); }],
  ['oversized excerpt', r => { r.matches[0].excerpt_hex = '61'.repeat(417); }],
];
for (const [name, corrupt] of corruptions) test(`rejects ${name} without adopting a partial search view`, async () => {
  const { client, f } = await connected(); await client.search(literal()); const pin = client.state.pin;
  f.setIntercept(value => { corrupt(value); return response(value); });
  await assert.rejects(client.search(literal())); assert.equal(client.state.result, null); assert.deepEqual(client.state.pin, pin);
  client.disconnect();
});
for (const [name, corrupt] of [
  ['query order', r => { r.results.reverse(); }], ['query count', r => { r.query_count++; }],
  ['needle echo', r => { r.results[0].needle_hex = '61'; }], ['prefix echo', r => { r.path_prefixes_hex = ['61']; }],
  ['shared scan', r => { r.shared_scan = false; }], ['per-query count', r => { r.results[0].returned_matches++; }],
]) test(`batch rejects ${name}`, async () => {
  const { client, f } = await connected(); f.setIntercept(r => { corrupt(r); return response(r); });
  await assert.rejects(client.search(batch())); assert.equal(client.state.pin, null); client.disconnect();
});
for (const [name, corrupt] of [
  ['pattern echo', r => { r.pattern_hex = '61'; }], ['match policy', r => { r.match_policy = 'leftmost-first'; }],
  ['VM overrun', r => { r.vm_steps = r.max_steps + 1; }], ['state overrun', r => { r.program_states = 513; }],
  ['line work', r => { r.lines_searched = 0; }], ['truncation lie', r => { r.matches[0].match_truncated_in_excerpt = true; }],
]) test(`regex rejects ${name}`, async () => {
  const { client, f } = await connected(); f.setIntercept(r => { corrupt(r); return response(r); });
  await assert.rejects(client.search(regex())); client.disconnect();
});
test('cross-query blob substitution and prefix disclosure are rejected', async () => {
  const { client, f } = await connected();
  f.setIntercept(r => { r.results[1].matches[0].blob = 'f'.repeat(40); return response(r); });
  await assert.rejects(client.search(batch({ needlesHex: [encode('needle'), encode('needle')] })), /conflicting blob/);
  f.setIntercept(r => { r.matches[0].path_hex = encode('src2/private'); return response(r); });
  await assert.rejects(client.search(literal({ prefixesHex: [encode('src')] })), /path scope/); client.disconnect();
});
for (const [name, mutate] of [
  ['wrong blob', r => { r.object_id = 'f'.repeat(40); }], ['wrong path', r => { r.path_hex = encode('src2/private'); }],
  ['wrong snapshot', r => { r.snapshot_token = `alg:1:${'cc'.repeat(32)}`; }], ['wrong root', r => { r.root_tree = 'f'.repeat(40); }],
  ['symlink', r => { r.kind = 'symlink'; }], ['followed link', r => { r.symlink_followed = true; }],
  ['truncated body', r => { r.content_hex = r.content_hex.slice(0, -2); }], ['false EOF', r => { r.next_offset = 0; }],
  ['overlarge file', r => { r.total_bytes = 8 * 1024 * 1024 + 1; }], ['wrong offset', r => { r.offset++; }],
  ['corrupt content with unchanged ID', r => { r.content_hex = `00${r.content_hex.slice(2)}`; }],
]) test(`file navigation rejects ${name}`, async () => {
  const { client, f } = await connected(); await client.search(literal());
  f.setIntercept(r => { mutate(r); return response(r); });
  await assert.rejects(client.openMatch(0, 0)); client.disconnect();
});
test('hash-valid file cannot validate false search line, excerpt or span coordinates', async () => {
  for (const change of [r => { r.matches[0].line--; }, r => { r.matches[0].excerpt_hex = `00${r.matches[0].excerpt_hex.slice(2)}`; }]) {
    const { client, f } = await connected(fixture('sha1', [['src/code.rs', 'prefix\néNeedle needle\r\n']]));
    f.setIntercept(r => { change(r); return response(r); });
    await client.search(literal()); f.setIntercept(null);
    await assert.rejects(client.openMatch(0, 0), /coordinates|excerpt/); client.disconnect();
  }
});
test('second-page identity/mode changes cannot leak a completed file', async () => {
  for (const mutate of [r => { r.source_commit = 'f'.repeat(40); }, r => { r.kind = 'executable'; }, r => { r.total_bytes--; }]) {
    const { client, f } = await connected(fixture('sha1', [['large', `needle${'x'.repeat(70000)}`]]));
    await client.search(literal());
    f.setIntercept((r, u, init) => { if (Number(new URLSearchParams(init.body).get('offset')) > 0) mutate(r); return response(r); });
    await assert.rejects(client.openMatch(0, 0)); client.disconnect();
  }
});

test('invalid requests fail before network and cannot widen authority or resource ceilings', async () => {
  const { client, f } = await connected();
  const invalid = [literal({ mode: 'semantic' }), literal({ principal: 'admin' }), literal({ needlesHex: [''] }), literal({ needlesHex: ['0A'] }),
    literal({ needlesHex: ['0a'] }), literal({ needlesHex: ['61'.repeat(257)] }), literal({ needlesHex: ['61', '62'] }),
    batch({ needlesHex: Array(33).fill('61') }), literal({ maxMatches: 4097 }), literal({ maxBytes: 0 }),
    literal({ maxFileBytes: Infinity }), literal({ maxSteps: 1 }), regex('a', { maxSteps: 67108865 }),
    literal({ prefixesHex: [encode('.git/config')] }), literal({ prefixesHex: [encode('a//b')] }), literal({ case: 'unicode' }),
    regex('a', { needlesHex: ['61'] }), literal({ patternHex: '61' })];
  for (const input of invalid) await assert.rejects(client.search(input));
  assert.equal(f.calls.length, 0); client.disconnect();
  assert.equal(byteInput('\0\xff', 'utf8', 3), '00c3bf'); assert.equal(byteInput('00ff', 'hex', 2), '00ff');
  assert.throws(() => byteInput('\ud800', 'utf8', 256)); assert.throws(() => pathHex(encode('a/..')));
  assert.deepEqual(query(literal({ needlesHex: ['0d'] })).needlesHex, ['0d']);
});
test('the search transport structurally excludes writes, recovery, bodyless reads, keys, artifacts and cross-origin paths', async () => {
  const f = fixture(), transport = new Transport({ ...f.options, pageSuffix: '/ui/search/' }); await transport.connect(TOKEN);
  for (const path of ['source/apply', 'source/initial/apply', 'source/prepare', 'source/bundle/import', 'source/tree', 'outcomes', 'pulls',
    'https://evil.example/source/search', '../source/search', '/source/search', 'source/search?x=y']) {
    await assert.rejects(transport.request(path, { method: 'POST', body: 'x=y' }));
  }
  await assert.rejects(transport.request('source/search'));
  for (const options of [{ method: 'GET' }, { key: '' }, { key: 'retry' }, { read: false }, { binary: true },
    { maximum: Infinity }, { maximum: 8388609 }, { statuses: [200, 409] }, { contentType: 'text/plain' }, { body: undefined }]) {
    await assert.rejects(transport.request('source/search', { method: 'POST', body: 'x=y', ...options }));
  }
  assert.equal(f.calls.length, 0); transport.disconnect();
});
test('existing authoring/initial/PR transport profiles do not inherit any search route', async () => {
  for (const suffix of ['pulls', 'source', 'initial', 'branches']) {
    const f = fixture(), transport = new Transport({ ...f.options, href: HREF.replace('/search/', `/${suffix}/`), pageSuffix: `/ui/${suffix}/` });
    await transport.connect(TOKEN);
    for (const path of ['source/search', 'source/search-batch', 'source/search-regex']) await assert.rejects(transport.request(path, { method: 'POST', body: 'x=y' }));
    assert.equal(f.calls.length, 0); transport.disconnect();
  }
});
test('unsafe locations and malformed tokens never reach a network request', async () => {
  for (const href of ['http://forge.example/repo.git/ui/search/', `${HREF}?token=${TOKEN}`, `${HREF}#x`, 'https://user:pass@forge.example/repo.git/ui/search/',
    'https://forge.example/repo.git/ui/other/', 'file:///repo.git/ui/search/']) assert.throws(() => new CodeSearch({ href }));
  for (const href of ['http://127.0.0.1/repo.git/ui/search/', 'http://[::1]/repo.git/ui/search/', 'http://localhost/repo.git/ui/search/']) {
    const client = new CodeSearch({ href }); client.disconnect();
  }
  const { client, f } = await connected();
  await assert.rejects(client.connect('bad', 'refs/heads/main', 'sha1')); assert.equal(client.connected, false);
  await assert.rejects(client.connect(TOKEN, 'refs/heads/../other', 'sha1')); assert.equal(f.calls.length, 0);
});
for (const status of [401, 403, 404, 409, 413, 429, 500, 503]) test(`HTTP ${status} never becomes empty successful search or a write retry`, async () => {
  const { client, f } = await connected(); f.setIntercept(() => response({ token: 'never reflect response diagnostics' }, status));
  await assert.rejects(client.search(literal()), error => error.status === status && !error.message.includes('diagnostics'));
  assert.equal(client.state.result, null); assert.equal(f.calls.length, 1);
  if (status === 401) assert.equal(client.connected, false);
  client.disconnect();
});
test('response truncation, oversized declarations, wrong media and redirect are rejected', async () => {
  const variants = [value => response(value, 200, { 'Content-Length': '1' }), value => response(value, 200, { 'Content-Length': '8388609' }),
    value => response(value, 200, { 'Content-Type': 'text/html' }), value => { const r = response(value); Object.defineProperty(r, 'redirected', { value: true }); return r; },
    value => { const r = response(value); Object.defineProperty(r, 'url', { value: 'https://evil.example/' }); return r; }];
  for (const intercept of variants) {
    const { client, f } = await connected(); f.setIntercept(intercept); await assert.rejects(client.search(literal())); client.disconnect();
  }
});
test('cancel, supersession and disconnect defeat late HTTP replies even when the fetch double ignores abort', async () => {
  for (const action of ['cancel', 'discardResults', 'disconnect']) {
    const { client, f } = await connected(); let release;
    f.setIntercept(r => new Promise(resolve => { release = () => resolve(response(r)); }));
    const pending = client.search(literal()); const rejection = assert.rejects(pending);
    client[action](); release(); await rejection; assert.equal(client.state.result, null); client.disconnect();
  }
  const { client, f } = await connected(); let release;
  f.setIntercept(r => new Promise(resolve => { release = () => resolve(response(r)); }));
  const first = client.search(literal()); const rejected = assert.rejects(first);
  f.setIntercept(null); const next = await client.search(literal({ needlesHex: [encode('absent')] }));
  release(); await rejected; assert.deepEqual(client.state.result, next); client.disconnect();
});
test('disconnect during blob hashing prevents late verified source from resurfacing', async () => {
  let release;
  const cryptoImpl = { subtle: { async digest(algorithm, data) {
    if (Buffer.from(data).subarray(0, 5).toString() === 'blob ') await new Promise(resolve => { release = resolve; });
    return webcrypto.subtle.digest(algorithm, data);
  } } };
  const { client } = await connected(fixture(), { cryptoImpl }); await client.search(literal());
  const pending = client.openMatch(0, 0), rejected = assert.rejects(pending);
  while (!release) await new Promise(resolve => setTimeout(resolve, 1));
  client.disconnect(); release(); await rejected;
  assert.equal(client.state.result, null); assert.equal(client.connected, false);
});
test('whole-operation deadline aborts a stalled response body', async () => {
  const { client, f } = await connected(fixture(), { timeoutMs: 20 }); let cancelled = false;
  f.setIntercept(() => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { headers: { 'Content-Type': 'application/json' } }));
  await assert.rejects(client.search(literal())); assert.equal(cancelled, true); assert.equal(client.state.result, null); client.disconnect();
});
