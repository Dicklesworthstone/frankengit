import test from 'node:test';
import assert from 'node:assert/strict';
import { initialQuery, initialCommand, initialReply, indexQuery, symbolQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { clone, fixture, harness, hex, token, selected, response, fileReply, webcrypto } from './search-initial-fixtures.mjs';
const accepted = f => initialReply(f.reply, selected(f.format), initialQuery(f.input));

test('normalization keeps two lexical channels and case-sensitive symbols distinct', () => {
  const input = fixture().input;
  input.termsHex.push(hex('NEEDLE')); input.prefixesHex.push(hex('src')); input.symbol.kinds.push('struct', 'function', 'function');
  const q = initialQuery(input);
  assert.deepEqual(q.termsHex, [hex('needle')]); assert.deepEqual(q.prefixesHex, [hex('src')]);
  assert.deepEqual(q.symbol, { nameHex: hex('Needle'), match: 'exact', kinds: ['function', 'struct'], policy: 'optional' });
  input.termsHex[0] = hex('other'); input.symbol.kinds[0] = 'enum';
  assert.deepEqual(q.termsHex, [hex('needle')]); assert.deepEqual(q.symbol.kinds, ['function', 'struct']);
});

test('inapplicable authority, revalidation, pagination and pattern options refuse', () => {
  const good = fixture().input; assert.doesNotThrow(() => initialQuery(good));
  for (const patch of [{ sourceMode: 'revalidated' }, { after: 1 }, { mode: 'indexed' }, { case: 'exact' },
    { patternHex: hex('.*') }, { channel: 'semantic' }, { termsHex: [] }, { termsHex: [hex('a b')] }, { termsHex: [hex('a'.repeat(129))] },
    { prefixesHex: [hex('../secret')] }, { symbol: { nameHex: hex('r#type') } }, { symbol: { nameHex: hex('Needle'), policy: 'ignore-error' } },
    { symbol: { nameHex: hex('Needle'), policy: null } }, { symbol: { nameHex: hex('Needle'), sourceMode: 'revalidated' } }]) {
    assert.throws(() => initialQuery({ ...good, ...patch }), JSON.stringify(patch));
  }
});

test('aggregate allowances require a positive share for every requested channel', () => {
  for (const symbols of ['available', 'not_requested']) {
    const f = fixture({ symbols }), count = symbols === 'available' ? 3 : 2;
    assert.doesNotThrow(() => initialQuery({ ...f.input, maxWork: count, maxPayloadBytes: count, maxResultBytes: 1 }));
    for (const patch of [{ maxWork: count - 1 }, { maxPayloadBytes: count - 1 }, { maxMatches: 101 }, { maxMatches: 0 },
      { maxWork: 16777217 }, { maxPayloadBytes: 33554433 }, { maxResultBytes: 2097153 }, { maxResultBytes: 0 }, { maxResultBytes: '12' }]) {
      assert.throws(() => initialQuery({ ...f.input, ...patch }));
    }
  }
});

test('one command carries independent floors without dropping a large exact integer', () => {
  const f = fixture(), q = initialQuery(f.input), pin = { head: f.source.snapshot_token, commit: f.source.source_commit };
  const floors = { lexical: { token: token('a'), number: '18446744073709551615' }, symbols: { token: token('d'), number: 4 } };
  const form = new URLSearchParams(initialCommand(selected('sha1'), pin, q, floors));
  assert.equal(form.get('minimum_lexical_number'), '18446744073709551615'); assert.equal(form.get('minimum_symbol_number'), '4');
  assert.equal(form.get('symbol_name_hex'), hex('Needle')); assert.equal(form.get('symbol_policy'), 'optional');
  assert.equal(form.get('expected_head'), pin.head); assert.equal(form.get('expected_commit'), pin.commit);
  assert.equal(form.get('source_mode'), null); assert.equal(form.get('max_file_bytes'), null);
  const absent = new URLSearchParams(initialCommand(selected('sha1'), null, initialQuery({ ...f.input, symbol: null }), floors));
  assert.equal(absent.get('minimum_symbol_token'), null); assert.equal(floors.symbols.number, 4);
});

for (const format of ['sha1', 'sha256']) test(`native ${format} envelope binds all channels without invented outer fields`, () => {
  const f = fixture({ format }), result = accepted(f);
  assert.equal('source_head' in f.reply, false); assert.equal('published' in f.reply, false);
  assert.equal(result.totalHits, 6); assert.equal(result.complete, true);
  assert.deepEqual(result.content.pin, result.path.pin); assert.deepEqual(result.content.pin, result.symbols.result.pin);
  assert.deepEqual(result.vector.lexical, result.content.index); assert.deepEqual(result.vector.symbols, result.symbols.result.index);
});

test('each outer source coordinate is bound to the actual lexical receipt', () => {
  const f = fixture(); accepted(f);
  for (const field of ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref', 'ref_hex',
    'snapshot_token', 'source_rcr', 'source_commit', 'root_tree']) {
    const r = clone(f.reply); r[field] += 'a';
    assert.throws(() => initialReply(r, selected(f.format), initialQuery(f.input)), field);
  }
});

test('mixed channel source, scope, query, generation and unsafe numeric identities refuse', () => {
  const f = fixture(), q = initialQuery(f.input); accepted(f);
  for (const mutate of [r => { r.path.snapshot_token = token('4'); }, r => { r.path.source_head = 'head-two'; },
    r => { r.path.source_rcr = 'rcr-two'; }, r => { r.path.root_tree = 'e'.repeat(40); }, r => { r.path.ref = 'refs/heads/other'; },
    r => { r.path.terms_hex = [hex('other')]; }, r => { r.path.path_prefix_hex = []; },
    r => { r.path.index_token = token('b'); }, r => { r.generation_vector.lexical.index_number = 8; },
    r => { r.path.indexed_documents++; }, r => { r.generation_vector.symbols.index_token = token('c'); },
    r => { r.symbols.result.source_commit = 'e'.repeat(40); }, r => { r.symbols.result.name_hex = hex('needle'); },
    r => { r.content.index_number = Number.MAX_SAFE_INTEGER + 1; }, r => { r.generation_vector.symbols.index_number = '4'; },
    r => { r.content.hits[0].blob = 'a'.repeat(64); }]) {
    const r = clone(f.reply); mutate(r); assert.throws(() => initialReply(r, selected('sha1'), q));
  }
});

test('maintenance may advance observed heads without changing the queried generation', () => {
  const f = fixture(); f.reply.path.selected_index_number = 8; f.reply.path.selected_index_token = token('b');
  const r = accepted(f); assert.equal(r.vector.lexical.number, 7); assert.equal(r.lexicalCheckpoint.number, 8);
  f.reply.content.selected_index_number = 8; f.reply.content.selected_index_token = token('c');
  assert.throws(() => accepted(f), /Contradictory/);
  f.reply.content.selected_index_token = token('b'); assert.equal(accepted(f).lexicalCheckpoint.number, 8);
});

test('same-tree channel claims cannot disagree on document IDs, blobs or file lengths', () => {
  const f = fixture(); accepted(f);
  for (const mutate of [r => { r.path.hits[0].blob = 'f'.repeat(40); }, r => { r.path.hits[0].content_bytes++; },
    r => { r.path.hits[0].document_id = 3; r.path.hits[1].document_id = 4; },
    r => { r.symbols.result.matches[0].blob = 'f'.repeat(40); }]) {
    const x = clone(f); mutate(x.reply); assert.throws(() => accepted(x));
  }
});

for (const reason of ['stale', 'uninitialized']) test(`optional ${reason} symbols are unavailable, not empty success`, () => {
  const f = fixture({ symbols: reason }); const r = accepted(f);
  assert.equal(r.complete, false); assert.deepEqual(r.symbols, { state: 'unavailable', reason, result: null });
  assert.equal(r.totalHits, 4); assert.equal(r.vector.symbols, null);
  assert.throws(() => initialReply(f.reply, selected('sha1'), initialQuery({ ...f.input, symbol: { ...f.input.symbol, policy: 'required' } })));
  assert.throws(() => initialReply(f.reply, selected('sha1'), initialQuery(f.input), null, null, { symbols: { token: token('d'), number: 4 } }));
});

test('optional symbols cannot hide corruption or fabricate an unrequested channel', () => {
  const f = fixture({ symbols: 'stale' });
  for (const patch of [{ reason: 'corrupt' }, { result: {} }, { state: 'not_requested' }, { result: undefined }]) {
    const x = clone(f); Object.assign(x.reply.symbols, patch); assert.throws(() => accepted(x));
  }
  const absent = fixture({ symbols: 'not_requested' }); assert.equal(accepted(absent).complete, true);
  absent.reply.symbols = fixture().reply.symbols; assert.throws(() => accepted(absent));
});

test('per-channel work and payload partitions cannot borrow spare allowance', () => {
  const f = fixture(); accepted(f);
  for (const [channel, field, value] of [['content', 'work_units', 334], ['path', 'work_units', 333],
    ['content', 'payload_bytes_read', 1002], ['path', 'payload_bytes_read', 1001]]) {
    const x = clone(f); x.reply[channel][field] = value; assert.throws(() => accepted(x));
  }
  const x = clone(f); x.reply.symbols.result.payload_bytes_read = 1001; assert.throws(() => accepted(x));
  const work = clone(f); work.reply.symbols.result.work_units = 333; assert.throws(() => accepted(work));
});

test('aggregate accounting is recomputed exactly including duplicate paths in separate channels', () => {
  const f = fixture(); const r = accepted(f);
  assert.equal(r.stats.payloadBytes, 510); assert.equal(r.stats.work, 90);
  assert.equal(r.stats.retainedBytes, f.reply.retained_result_bytes);
  for (const field of ['retained_result_bytes', 'completed_payload_bytes_read', 'completed_work_units']) {
    for (const delta of [-1, 1]) { const x = clone(f); x.reply[field] += delta; assert.throws(() => accepted(x)); }
  }
  f.input.maxResultBytes = f.reply.retained_result_bytes; f.reply.max_result_bytes = f.input.maxResultBytes;
  assert.equal(accepted(f).stats.retainedBytes, f.input.maxResultBytes);
  f.input.maxResultBytes--; f.reply.max_result_bytes--; assert.throws(() => accepted(f));
});

test('truncation stays per-channel and prevents a complete joined claim', () => {
  const f = fixture({ limit: 1 }), r = accepted(f);
  assert.equal(r.complete, false); assert.equal(r.content.nextAfter, 1); assert.equal(r.symbols.result.complete, false);
  f.reply.complete = true; assert.throws(() => accepted(f));
  f.reply.complete = false; f.reply.symbols.result.complete = true; f.reply.symbols.result.completion = 'complete';
  assert.equal(accepted(f).complete, false);
});

test('a genuinely empty complete index remains distinct from missing channels', () => {
  const f = fixture({ symbols: 'not_requested' });
  for (const c of [f.reply.content, f.reply.path]) Object.assign(c, { hits: [], returned_hits: 0, indexed_documents: 0,
    indexed_source_bytes: 0, segments_read: 0, payload_bytes_read: 0, work_units: 0 });
  Object.assign(f.reply, { retained_result_bytes: 0, completed_payload_bytes_read: 0, completed_work_units: 0 });
  assert.equal(accepted(f).totalHits, 0); assert.equal(accepted(f).complete, true);
  f.reply.content = null; assert.throws(() => accepted(f));
});

test('controller uses one read-only request and installs a joined result atomically', async () => {
  const f = fixture(), h = harness(f); await h.connect();
  const r = await h.client.search(f.input);
  assert.deepEqual(h.calls.map(c => c.path), ['source/search-initial']); assert.equal(h.calls[0].init.method, 'POST');
  assert.equal(h.calls[0].init.redirect, 'error'); assert.equal(h.calls[0].init.headers['Idempotency-Key'], undefined);
  assert.equal(h.client.state.indexMinimum.number, 7); assert.equal(h.client.state.symbolMinimum.number, 4);
  r.vector.lexical.number = 99; r.content.hits[0].blob = 'bad';
  assert.equal(h.client.state.result.vector.lexical.number, 7);
  const before = h.client.state;
  f.reply.symbols.result.matches[0].blob = 'f'.repeat(40);
  await assert.rejects(h.client.search(f.input));
  assert.equal(h.client.state.result, null); assert.deepEqual(h.client.state.pin, before.pin);
  assert.deepEqual(h.client.state.indexMinimum, before.indexMinimum); assert.deepEqual(h.client.state.symbolMinimum, before.symbolMinimum);
});

test('unrequested symbols keep their independent checkpoint across query and snapshot changes', async () => {
  const f = fixture(), h = harness(f); await h.connect(); await h.client.search(f.input);
  const noSymbols = fixture({ symbols: 'not_requested' }); f.reply = noSymbols.reply;
  h.client.refreshSnapshot(); await h.client.search(noSymbols.input);
  assert.equal(h.calls.at(-1).fields.get('minimum_symbol_token'), null);
  assert.equal(h.calls.at(-1).fields.get('minimum_lexical_number'), '7'); assert.equal(h.client.state.symbolMinimum.number, 4);
  f.reply = fixture({ symbols: 'stale' }).reply;
  await assert.rejects(h.client.search(f.input), /checkpointed/);
  assert.equal(h.calls.at(-1).fields.get('minimum_symbol_number'), '4'); assert.equal(h.client.state.symbolMinimum.number, 4);
  h.client.disconnect(); assert.equal(h.client.state.indexMinimum, null); assert.equal(h.client.state.symbolMinimum, null);
});

for (const format of ['sha1', 'sha256']) test(`${format} every combined channel navigates to pinned, independently verified file bytes`, async () => {
  const f = fixture({ format }), h = harness(f); await h.connect(); await h.client.search(f.input);
  for (const channel of ['content', 'path', 'symbols']) {
    const r = await h.client.openInitial(channel, 0);
    assert.deepEqual(r.bytes, f.files[0].bytes); assert.equal(r.blobVerified, true); assert.equal(r.initialChannel, channel);
    assert.equal(channel === 'symbols' ? r.symbolNameVerified : r.wordSpansVerified, true);
    assert.equal(h.calls.at(-1).fields.get('expected_head'), f.source.snapshot_token);
    assert.equal(h.calls.at(-1).fields.get('expected_commit'), f.source.source_commit);
    assert.deepEqual(r.generationVector, h.client.state.result.vector);
  }
  await assert.rejects(h.client.nextIndexed()); await assert.rejects(h.client.openInitial('constructor', 0));
  assert.equal(h.calls.length, 4);
});

test('navigation refuses modified bytes without losing the verified search result', async () => {
  const f = fixture(), h = harness(f, call => {
    if (call.path !== 'source/blob') return;
    const r = fileReply(f, f.files[0]); r.content_hex = hex('x'.repeat(f.files[0].bytes.length)); return response(r);
  });
  await h.connect(); await h.client.search(f.input);
  await assert.rejects(h.client.openInitial('content', 0), /blob identity/);
  await assert.rejects(h.client.openInitial('symbols', 0), /blob identity/);
  assert.equal(h.client.state.result.query.mode, 'initial');
});

test('navigation byte budget is independent of source-index result coverage', async () => {
  const f = fixture(), h = harness(f); await h.connect(); await h.client.search({ ...f.input, maxFileBytes: 1 });
  await assert.rejects(h.client.openInitial('content', 0), /navigation byte limit/); assert.equal(h.calls.length, 1);
  await assert.rejects(h.client.openInitial('symbols', 0), /complete file bytes/); assert.equal(h.calls.length, 2);
});

test('canceled and disconnected delayed combined responses never install partial state', async () => {
  for (const action of ['cancel', 'disconnect']) {
    let release, started;
    const called = new Promise(resolve => { started = resolve; });
    const f = fixture(), h = harness(f, () => { started(); return new Promise(resolve => { release = resolve; }); });
    await h.connect(); const pending = h.client.search(f.input); await called;
    h.client[action](); release(response(f.reply)); await assert.rejects(pending);
    assert.equal(h.client.state.result, null); assert.equal(h.client.state.pin, null);
    assert.equal(h.client.state.indexMinimum, null); assert.equal(h.client.state.symbolMinimum, null);
  }
});

test('HTTP errors stay errors without single-channel retries or scans', async () => {
  for (const status of [401, 403, 409, 503]) {
    const f = fixture(), h = harness(f, () => response({ error: 'symbol_index_stale' }, status));
    await h.connect(); await assert.rejects(h.client.search(f.input), e => e.status === status);
    assert.equal(h.calls.length, 1); assert.equal(h.client.state.result, null);
    assert.equal(h.client.connected, status !== 401);
  }
});

test('the added route cannot acquire write authority or accept server prose as diagnostics', async () => {
  const calls = [], transport = new Transport({ href: 'https://forge.example/repo.git/ui/search/', pageSuffix: '/ui/search/', cryptoImpl: webcrypto,
    fetchImpl: async (_, init) => { calls.push(init); return response({ error: 'index_generation_mismatch', message: '<script>invented</script>' }, 409); } });
  await transport.connect('a'.repeat(64));
  for (const options of [{ method: 'GET' }, { key: 'write-key' }, { read: false }, { binary: true }, { statuses: [200, 409] }]) {
    await assert.rejects(transport.request('source/search-initial', { method: 'POST', body: 'x=1', ...options }));
  }
  assert.equal(calls.length, 0);
  await assert.rejects(transport.request('source/search-initial', { method: 'POST', body: 'x=1' }), e =>
    e.status === 409 && e.code === 'index_generation_mismatch' && !e.message.includes('script'));
  assert.equal(calls.length, 1);
});

test('existing standalone lexical and symbol query grammars stay separate', () => {
  assert.equal(indexQuery({ mode: 'indexed', channel: 'content', termsHex: [hex('NEEDLE')] }).termsHex[0], hex('needle'));
  assert.equal(symbolQuery({ mode: 'symbols', nameHex: hex('Needle') }).nameHex, hex('Needle'));
  assert.throws(() => symbolQuery({ mode: 'symbols', nameHex: hex('Needle'), symbol: {} }));
});

test('native symbol echo retains the parser ceiling while lookup work uses its fixed share', () => {
  const f = fixture();
  assert.equal(f.reply.symbols.result.max_work, 16777216);
  assert.equal(accepted(f).symbols.result.stats.work, 40);
  f.reply.symbols.result.max_work = Math.floor(f.input.maxWork / 3);
  assert.throws(() => accepted(f), /query echo/);
});
