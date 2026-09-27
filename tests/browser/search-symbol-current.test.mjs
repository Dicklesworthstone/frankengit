// Production client/validators and real WebCrypto; injected native-format HTTP.
import test from 'node:test';
import assert from 'node:assert/strict';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { symbolQuery, symbolCommand, symbolReply, initialQuery } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { symbolSources } from '../../crates/fgit-node/src/smart_http/server/browser/search-current.mjs';
import { currentFixture, currentTransport, selected, token, response, deferred, hex, utf8 } from './search-symbol-current-fixtures.mjs';
const parse = (f, reply = f.wrapper(), pin = null, minimum = null) =>
  symbolReply(reply, selected(f.source.object_format), symbolQuery(f.currentInput), null, pin, minimum);
async function connected(f, intercept, extra = {}) {
  const t = currentTransport(f, intercept), client = new CodeSearch({ ...t.options, ...extra });
  await client.connect(token, f.source.ref, f.source.object_format);
  return { ...t, client };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: distinct current source and original receipt are validated without mutation`, () => {
    const f = currentFixture(format), reply = f.wrapper(), before = structuredClone(reply), result = parse(f, reply);
    assert.deepEqual(reply, before);
    assert.equal(result.pin.head, f.current.snapshot_token);
    assert.equal(result.pin.rcr, f.current.source_rcr);
    assert.equal(result.pin.sourceHead, f.current.source_head);
    assert.equal(result.pin.commit, f.indexed.source_commit);
    assert.deepEqual(result.sources, { current: f.current, indexed: f.indexed, distinct: true });
    assert.deepEqual(result.index, { token: f.reply.index_token, number: f.reply.index_number });
    assert.equal(result.query.sourceMode, 'revalidated');
    assert.equal(result.hits[0].blob, f.blob);
    reply.current_source.source_head = 'changed'; reply.result.matches[0].blob = '0'.repeat(40);
    assert.equal(result.sources.current.source_head, f.current.source_head);
    assert.equal(result.hits[0].blob, f.blob);
  });
  test(`${format}: already-current indexes have explicit non-distinct provenance`, () => {
    const f = currentFixture(format); Object.assign(f.current, f.indexed);
    const result = parse(f);
    assert.equal(result.sources.distinct, false);
    assert.equal(result.pin.head, f.indexed.snapshot_token);
  });
  test(`${format}: existing CodeSearch installs current pins and verifies every file page`, async () => {
    const f = currentFixture(format, { name: 'type', raw: true, path: Buffer.from([0x73, 0x2f, 0xff, 0x2e, 0x72, 0x73]),
      prefix: '// long file\n' + '\n'.repeat(65536) });
    const { client, calls } = await connected(f);
    const result = await client.search(f.currentInput);
    assert.equal(client.state.indexMinimum, null);
    assert.deepEqual(client.state.symbolMinimum, result.index);
    assert.equal(calls[0].fields.get('source_mode'), 'revalidated');
    const file = await client.openSymbol(0);
    assert.equal(file.symbolNameVerified, true); assert.equal(file.blobVerified, true);
    assert.equal(file.coverageVerified, false);
    assert.deepEqual(file.bytes, new Uint8Array(f.body));
    assert.equal(calls.length, 3);
    for (const call of calls.slice(1)) {
      assert.equal(call.fields.get('expected_head'), f.current.snapshot_token);
      assert.equal(call.fields.get('expected_commit'), f.current.source_commit);
      assert.equal(call.fields.get('path_hex'), f.row.path_hex);
      assert.equal(call.fields.has('source_mode'), false);
      assert.equal(call.options.headers['Idempotency-Key'], undefined);
    }
    await assert.rejects(client.nextIndexed(), /No indexed continuation/);
    client.disconnect();
  });
  test(`${format}: an original-source file reply cannot be reused for current navigation`, async () => {
    const f = currentFixture(format);
    const { client } = await connected(f, call => call.url.endsWith('/source/blob') ? response(f.file(0)) : null);
    await client.search(f.currentInput);
    await assert.rejects(client.openSymbol(0), /snapshot changed/);
    assert.equal(client.state.pin.head, f.current.snapshot_token);
    client.disconnect();
  });
}

test('source mode is explicit and normalized before any I/O; Initial remains strict', async () => {
  const f = currentFixture(), q = symbolQuery(f.input);
  assert.deepEqual(symbolQuery({ ...f.input, sourceMode: 'exact' }), q);
  const strict = new URLSearchParams(symbolCommand(selected('sha1'), null, q));
  assert.equal(strict.has('source_mode'), false);
  const { client, calls } = await connected(f);
  for (const mode of [null, '', 'current', 'REVALIDATED', true, {}]) {
    await assert.rejects(client.search({ ...f.input, sourceMode: mode }));
  }
  assert.equal(calls.length, 0);
  assert.throws(() => initialQuery({ mode: 'initial', termsHex: [hex('Thing')], sourceMode: 'revalidated' }));
  assert.throws(() => initialQuery({ mode: 'initial', termsHex: [hex('Thing')], symbol: { nameHex: hex('Thing'), sourceMode: 'revalidated' } }));
  client.disconnect();
});
test('strict and revalidated responses are not interchangeable or auto-detected', () => {
  const f = currentFixture();
  assert.throws(() => symbolReply(f.wrapper(), selected('sha1'), symbolQuery(f.input)));
  assert.throws(() => parse(f, f.reply));
  assert.equal(symbolReply(f.reply, selected('sha1'), symbolQuery(f.input)).sources, undefined);
});
test('every envelope field is required; extra effects and alternate profiles refuse', () => {
  const f = currentFixture(), valid = f.wrapper();
  for (const name of Object.keys(valid)) {
    const reply = structuredClone(valid); delete reply[name]; assert.throws(() => parse(f, reply), undefined, name);
  }
  for (const change of [{ type: 'source_search_index_current' }, { schema_version: 2 }, { source_mode: 'exact' },
    { read_only: false }, { transaction_created: true }, { published: true }, { distinct_provenance: true },
    { result: null }, { result: [] }]) assert.throws(() => parse(f, { ...valid, ...change }));
});
test('all current/original source fields are required, bounded and schema-closed', () => {
  const f = currentFixture();
  for (const side of ['current_source', 'indexed_source']) for (const name of Object.keys(f.indexed)) {
    for (const value of [undefined, null, '', 'x'.repeat(8193), '\0', '\ud800']) {
      const reply = f.wrapper();
      if (value === undefined) delete reply[side][name]; else reply[side][name] = value;
      assert.throws(() => parse(f, reply), undefined, `${side}.${name}`);
    }
  }
  for (const side of ['current_source', 'indexed_source']) {
    const reply = f.wrapper(); reply[side].grants = ['write']; assert.throws(() => parse(f, reply));
  }
});
test('namespace, reference, commit and tree substitutions refuse even for individually valid IDs', () => {
  const f = currentFixture();
  const changes = { tenant_id: 'a'.repeat(32), repository_id: 'a'.repeat(32), repository_incarnation: 'a'.repeat(32),
    ref_hex: hex('refs/heads/other'), ref: 'refs/heads/other', object_format: 'sha256',
    source_commit: 'a'.repeat(40), root_tree: 'b'.repeat(40) };
  for (const side of ['current_source', 'indexed_source']) for (const [key, value] of Object.entries(changes)) {
    const reply = f.wrapper(); reply[side][key] = value; assert.throws(() => parse(f, reply), undefined, `${side}.${key}`);
  }
  const sameTree = f.wrapper(); sameTree.current_source.source_commit = 'd'.repeat(40);
  assert.throws(() => parse(f, sameTree), /native source changed/);
});
test('same-head metadata contradictions and mismatched head-token pairs refuse', () => {
  const f = currentFixture();
  for (const change of [{ snapshot_token: f.indexed.snapshot_token }, { source_head: f.indexed.source_head },
    { snapshot_token: f.indexed.snapshot_token, source_head: f.indexed.source_head },
    { ...f.indexed, forge_position_root: 'changed' }, { ...f.indexed, source_rcr: 'changed' }]) {
    const reply = f.wrapper(); Object.assign(reply.current_source, change);
    assert.throws(() => parse(f, reply), /Contradictory/);
  }
});
test('the nested strict receipt must retain every original source coordinate', () => {
  const f = currentFixture();
  for (const key of Object.keys(f.indexed).filter(k => k !== 'forge_position_root')) {
    const reply = f.wrapper(); reply.result[key] = 'substituted';
    assert.throws(() => parse(f, reply), /Nested declaration receipt/);
  }
  const reply = f.wrapper(); Object.assign(reply.result, f.current);
  assert.throws(() => parse(f, reply), /original source/);
});
test('strict name, kind, path, span, count and work validation still checks the nested rows', () => {
  const f = currentFixture();
  const changes = [{ profile: 'other' }, { read_only: false }, { published: true }, { schema_version: 2 },
    { compiler_resolved: true }, { macro_expansion: true }, { source_blobs_read: 1 }, { source_bytes_read: 1 },
    { returned_matches: 0 }, { work_units: f.reply.max_work + 1 }, { max_work: 1 }, { name_hex: hex('Other') },
    { kinds: ['function'] }, { path_prefix_hex: [hex('other')] }, { matches: [] }, { complete: false }];
  for (const change of changes) { const reply = f.wrapper(); Object.assign(reply.result, change); assert.throws(() => parse(f, reply)); }
  for (const change of [{ name_hex: hex('Other') }, { kind: 'constant' }, { byte_column: 0 }, { byte_offset: 10000 },
    { path_hex: hex('../thing.rs') }, { blob: '0'.repeat(40) }, { raw_identifier: true }, { excerpt_hex: '' }]) {
    const reply = f.wrapper(); Object.assign(reply.result.matches[0], change); assert.throws(() => parse(f, reply));
  }
});
test('numeric generations are retained exactly or refused, never rounded into a checkpoint', () => {
  const f = currentFixture(), reply = f.wrapper(); reply.result.index_number = Number.MAX_SAFE_INTEGER;
  assert.equal(parse(f, reply).index.number, Number.MAX_SAFE_INTEGER);
  for (const number of [0, -1, 1.5, '7', Number.MAX_SAFE_INTEGER + 1]) {
    reply.result.index_number = number; assert.throws(() => parse(f, reply));
  }
  assert.throws(() => parse(f, f.wrapper(), null, { token: f.reply.index_token, number: 2 }), /checkpoint/);
  assert.throws(() => parse(f, f.wrapper(), null, { token: `alg:2:${'a'.repeat(64)}`, number: 1 }), /checkpoint/);
});
test('mode switches retain both the source pin and symbol floor until explicit source release', async () => {
  const f = currentFixture(), { client, calls } = await connected(f);
  const strict = await client.search(f.input);
  await assert.rejects(client.search(f.currentInput), /snapshot changed/);
  assert.equal(client.state.result, null); assert.deepEqual(client.state.pin, strict.pin);
  assert.deepEqual(client.state.symbolMinimum, strict.index);
  assert.equal(calls[1].fields.get('expected_head'), f.indexed.snapshot_token);
  client.refreshSnapshot();
  const current = await client.search(f.currentInput);
  assert.equal(calls[2].fields.get('expected_head'), null);
  assert.equal(calls[2].fields.get('minimum_index_token'), strict.index.token);
  assert.equal(calls[2].fields.get('minimum_index_number'), String(strict.index.number));
  assert.equal(current.pin.head, f.current.snapshot_token);
  await assert.rejects(client.search(f.input), /snapshot changed/);
  assert.deepEqual(client.state.symbolMinimum, current.index);
  client.disconnect();
});
test('malformed newer results cannot advance checkpoints or select the first source', async () => {
  const f = currentFixture(); let broken = false;
  const { client } = await connected(f, call => {
    if (!broken) return null;
    const reply = f.wrapper(); reply.result.index_number = 2; reply.result.matches[0].excerpt_hex = '';
    return response(reply);
  });
  await client.search(f.currentInput); const before = client.state;
  broken = true; await assert.rejects(client.search(f.currentInput));
  assert.deepEqual(client.state.symbolMinimum, before.symbolMinimum); assert.deepEqual(client.state.pin, before.pin);
  assert.equal(client.state.result, null);
  client.disconnect(); await client.connect(token, f.source.ref, f.source.object_format);
  await assert.rejects(client.search(f.currentInput));
  assert.equal(client.state.pin, null); assert.equal(client.state.scope, null); assert.equal(client.state.symbolMinimum, null);
  client.disconnect();
});
test('missing, stale, corrupt, denied and revoked reads never retry or switch profiles', async () => {
  for (const status of [400, 401, 403, 404, 409, 413, 503]) {
    const f = currentFixture(); const { client, calls } = await connected(f, () => response({ error: 'symbol_index_stale' }, status));
    await assert.rejects(client.search(f.currentInput));
    assert.equal(calls.length, 1); assert.equal(calls[0].fields.get('source_mode'), 'revalidated');
    assert.equal(client.state.result, null); assert.equal(client.state.symbolMinimum, null);
    if (status === 401) assert.equal(client.connected, false);
    client.disconnect();
  }
});
test('late canceled or disconnected replies cannot install source or checkpoint state', async () => {
  for (const cancel of ['cancel', 'disconnect']) {
    const f = currentFixture(), d = deferred();
    const { client, calls } = await connected(f, () => d.promise);
    const pending = client.search(f.currentInput); const refused = assert.rejects(pending);
    client[cancel](); d.resolve(response(f.wrapper())); await refused;
    assert.equal(calls.length, 1); assert.equal(calls[0].options.signal.aborted, true);
    assert.equal(client.state.pin, null); assert.equal(client.state.symbolMinimum, null); assert.equal(client.state.result, null);
    client.disconnect();
  }
});
test('a late old-credential refusal cannot revoke a newly connected read session', async () => {
  const f = currentFixture(), d = deferred(); let delayed = true;
  const { client } = await connected(f, () => delayed ? d.promise : null);
  const pending = client.search(f.currentInput); const refused = assert.rejects(pending);
  delayed = false; await client.connect('b'.repeat(64), f.source.ref, 'sha1');
  await client.search(f.currentInput); d.resolve(response({}, 401)); await refused;
  assert.equal(client.connected, true); assert.equal(client.state.pin.head, f.current.snapshot_token);
  assert.equal(client.state.symbolMinimum.number, 1); client.disconnect();
});
test('caller input is copied before awaiting and returned provenance does not expose mutable state', async () => {
  const f = currentFixture(), d = deferred(), { client } = await connected(f, () => d.promise);
  const input = { ...f.currentInput, kinds: [], prefixesHex: [] }, pending = client.search(input);
  input.sourceMode = 'exact'; input.kinds.push('function'); input.prefixesHex.push(hex('other'));
  d.resolve(response(f.wrapper())); const result = await pending;
  result.sources.current.source_rcr = 'mutated'; result.pin.head = 'mutated'; result.index.number = 123;
  assert.equal(client.state.result.query.sourceMode, 'revalidated');
  assert.equal(client.state.result.sources.current.source_rcr, f.current.source_rcr);
  assert.equal(client.state.symbolMinimum.number, 1); client.disconnect();
});
test('one total navigation deadline spans every file page in revalidated mode', async t => {
  const f = currentFixture('sha1', { prefix: '// x\n' + '\n'.repeat(65536) }); let now = performance.now();
  t.mock.method(performance, 'now', () => now);
  const { client, calls } = await connected(f, call => { if (call.url.endsWith('/source/blob')) now += 30_000; return null; }, { timeoutMs: 45_000 });
  await client.search(f.currentInput);
  await assert.rejects(client.openSymbol(0), /total time limit/);
  assert.equal(calls.length, 3); assert.equal(client.state.pin.head, f.current.snapshot_token);
  client.disconnect();
});
test('unknown-length oversized responses remain bounded before parsing the wrapper', async () => {
  const f = currentFixture(); let canceled = false;
  const stream = new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(1024 * 1024)); }, cancel() { canceled = true; } });
  const { client, calls } = await connected(f, () => new Response(stream, { headers: { 'Content-Type': 'application/json' } }));
  await assert.rejects(client.search(f.currentInput), /byte limit/);
  assert.equal(canceled, true); assert.equal(calls.length, 1); assert.equal(client.state.result, null); client.disconnect();
});
test('partial and empty successful receipts retain honest completion without inventing a cursor', () => {
  const f = currentFixture(), partial = f.wrapper();
  partial.result.max_matches = 1; partial.result.indexed_declarations = 2; partial.result.complete = false; partial.result.completion = 'match_limit';
  const result = symbolReply(partial, selected('sha1'), symbolQuery({ ...f.currentInput, maxMatches: 1 }));
  assert.equal(result.complete, false); assert.equal(result.hits.length, 1); assert.equal(result.nextAfter, undefined);
  const empty = f.wrapper(); Object.assign(empty.result, { indexed_files: 0, indexed_declarations: 0, indexed_source_bytes: 0,
    matches: [], returned_matches: 0, tables_read: 0 });
  assert.equal(parse(f, empty).complete, true); assert.equal(parse(f, empty).hits.length, 0);
});
