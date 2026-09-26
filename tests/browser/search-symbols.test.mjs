import test from 'node:test';
import assert from 'node:assert/strict';
import { symbolQuery, symbolCommand, symbolReply, indexQuery, indexReply } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { verifyFile } from '../../crates/fgit-node/src/smart_http/server/browser/search-data.mjs';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, hex, selected, transport, response, webcrypto, token, deferred } from './search-symbol-fixtures.mjs';
const parsed = (f, extra = {}) => symbolQuery({ ...f.input, ...extra });
const validated = (f, q = parsed(f)) => symbolReply(f.reply, selected(f.source.object_format), q);
const client = async (f, intercept) => { const env = transport(f, intercept), value = new CodeSearch(env.options); await value.connect(token, 'refs/heads/main', f.source.object_format); return { ...env, value }; };

test('names retain case and kinds and byte scopes are copied, sorted and deduplicated', () => {
  const input = { mode: 'symbols', nameHex: hex('Thing'), match: 'prefix', kinds: ['struct', 'function', 'struct'], prefixesHex: [hex('src'), hex('src')] };
  const q = symbolQuery(input); input.kinds.push('enum'); input.prefixesHex[0] = hex('other');
  assert.equal(q.nameHex, hex('Thing')); assert.deepEqual(q.kinds, ['function', 'struct']); assert.deepEqual(q.prefixesHex, [hex('src')]);
  const fields = new URLSearchParams(symbolCommand(selected('sha256'), { head: 'pin', commit: 'commit' }, q, { token: 'symbol', number: 3 }));
  assert.deepEqual(fields.getAll('kind'), q.kinds); assert.equal(fields.get('expected_head'), 'pin');
  assert.equal(fields.get('minimum_index_token'), 'symbol'); assert.equal(fields.has('source_mode'), false); assert.equal(fields.has('after'), false);
});
test('unsupported grammar, privilege fields and wrong limit boundaries refuse before I/O', () => {
  const f = fixture();
  for (const name of ['', '1Thing', 'r#type', 'a b', 'é', 'Thing.*', 'x'.repeat(129)]) assert.throws(() => symbolQuery({ ...f.input, nameHex: hex(name) }), name);
  assert.equal(symbolQuery({ ...f.input, nameHex: hex('x'.repeat(128)) }).nameHex.length, 256);
  for (const extra of [{ sourceMode: 'revalidated' }, { after: 1 }, { principal: 'admin' }, { maxPayloadBytes: 1 }, { match: 'regex' }, { kinds: ['call'] },
    { kinds: Array(9).fill('struct') }, { maxMatches: 101 }, { maxMatches: 0 }, { maxBytes: 0 }, { maxFileBytes: 8388609 }, { maxWork: 16777217 },
    { prefixesHex: [hex('../x')] }, { prefixesHex: [hex('.GiT/x')] }, { prefixesHex: [hex('a/'.repeat(64) + 'b')] }]) assert.throws(() => parsed(f, extra), JSON.stringify(extra));
  assert.doesNotThrow(() => parsed(f, { maxMatches: 100, maxWork: 1, maxFileBytes: 1, maxBytes: 1 }));
});
for (const format of ['sha1', 'sha256']) {
  test(`${format}: a prefix query verifies the full raw identifier and exact binary-path file`, async () => {
    const f = fixture(format, { name: 'type', raw: true, path: Buffer.from('src/ff\xff.rs', 'latin1') });
    f.reply.name_hex = hex('ty'); f.reply.match = 'prefix';
    const q = parsed(f, { nameHex: hex('ty'), match: 'prefix' }), r = validated(f, q);
    const result = await verifyFile(f.body, r.hits[0], q, 0, format, webcrypto, () => {});
    assert.equal(result.symbolNameVerified, true); assert.equal(result.coverageVerified, false); assert.equal(result.declarationEvaluatedBy, 'native-server');
    assert.equal(r.hits[0].nameHex, hex('type')); assert.equal(r.hits[0].rawIdentifier, true);
    const { value, calls } = await client(f);
    const found = await value.search({ ...f.input, nameHex: hex('ty'), match: 'prefix' });
    found.hits[0].nameHex = 'bad';
    const opened = await value.openSymbol(0); assert.deepEqual(Buffer.from(opened.bytes), f.body);
    assert.equal(opened.hit.nameHex, hex('type')); assert.equal(calls.length, 2);
    assert.equal(calls[1].fields.get('expected_head'), f.source.snapshot_token); assert.equal(calls[1].fields.get('path_hex'), f.row.path_hex);
    value.disconnect();
  });
}
test('case folding is never applied to symbol replies', () => {
  const f = fixture(); f.reply.name_hex = hex('thing');
  assert.throws(() => validated(f, parsed(f, { nameHex: hex('thing') })));
  const good = fixture('sha1', { name: 'thing' }); assert.equal(validated(good).hits.length, 1);
});
test('wire responses cannot claim compiler resolution or bypass read and source checks', () => {
  const f = fixture();
  for (const [field, value] of Object.entries({ profile: 'compiler', index_profile: 'other', authority_class: 'exact', compiler_resolved: true,
    macro_expansion: true, cfg_evaluated: true, source_blobs_read: 1, source_bytes_read: 1, published: true, transaction_created: true,
    ref: 'refs/heads/other', object_format: 'sha256', name_hex: hex('other'), match: 'prefix', max_work: 1, max_matches: 1 })) {
    const bad = { ...f, reply: structuredClone(f.reply) }; bad.reply[field] = value; assert.throws(() => validated(bad), field);
  }
  const good = validated(f);
  for (const field of ['snapshot_token', 'source_rcr', 'source_head', 'source_commit', 'root_tree', 'repository_incarnation']) {
    const bad = structuredClone(f.reply); bad[field] = field === 'snapshot_token' ? `alg:2:${'9'.repeat(64)}` : '9'.repeat(40);
    assert.throws(() => symbolReply(bad, selected('sha1'), parsed(f), good.scope, good.pin), field);
  }
});
test('rows enforce native domain, kind, name, scope, excerpt, raw notation and coordinates', () => {
  const f = fixture();
  for (const extra of [{ path_hex: hex('other.txt') }, { path_hex: hex('../bad.rs') }, { name_hex: hex('ThingX') }, { kind: 'call' },
    { blob: 'a'.repeat(64) }, { match_length: 1 }, { byte_column: 0 }, { line: 999 }, { byte_offset: 8388608 },
    { raw_identifier: true }, { raw_identifier: 'false' }, { excerpt_hex: hex('Thing\n') }, { excerpt_offset: 0 }, { match_truncated_in_excerpt: true }]) {
    const bad = { ...f, reply: structuredClone(f.reply) }; Object.assign(bad.reply.matches[0], extra); assert.throws(() => validated(bad), JSON.stringify(extra));
  }
  f.reply.path_prefix_hex = [hex('elsewhere')]; assert.throws(() => validated(f, parsed(f, { prefixesHex: f.reply.path_prefix_hex })));
  f.reply.path_prefix_hex = [hex('src')]; assert.doesNotThrow(() => validated(f, parsed(f, { prefixesHex: f.reply.path_prefix_hex })));
});
test('ordering, conflicting same-path blobs and impossible corpus counts are rejected atomically', () => {
  const f = fixture();
  for (const [field, value] of Object.entries({ indexed_files: 0, indexed_declarations: 0, tables_read: 0, tables_read_extra: 4,
    payload_bytes_read: 33554433, work_units: 16777217, indexed_source_bytes: 1, returned_matches: 0, unsupported_language_files: 20000 })) {
    const bad = { ...f, reply: structuredClone(f.reply) }; bad.reply[field === 'tables_read_extra' ? 'tables_read' : field] = value; assert.throws(() => validated(bad), field);
  }
  const bad = { ...f, reply: structuredClone(f.reply) }; bad.reply.indexed_declarations = 2; bad.reply.returned_matches = 2;
  bad.reply.matches.push(structuredClone(f.row)); assert.throws(() => validated(bad));
  bad.reply.matches[1].byte_offset++; bad.reply.matches[1].byte_column++; bad.reply.matches[1].excerpt_hex = hex('pub struct  Thing {}'); bad.reply.matches[1].blob = 'a'.repeat(40);
  assert.throws(() => validated(bad));
});
test('empty completion and bounded truncation are distinguished without invented cursors', () => {
  const f = fixture(); f.reply.matches = []; f.reply.returned_matches = 0;
  assert.equal(validated(f).complete, true);
  f.reply.complete = false; f.reply.completion = 'match_limit'; assert.throws(() => validated(f));
  const limited = fixture(); limited.reply.max_matches = 1; limited.reply.complete = false; limited.reply.completion = 'match_limit'; limited.reply.indexed_declarations = 2;
  const r = validated(limited, parsed(limited, { maxMatches: 1 })); assert.equal(r.complete, false); assert.equal('nextAfter' in r, false);
  limited.reply.indexed_declarations = 1; assert.throws(() => validated(limited, parsed(limited, { maxMatches: 1 })));
});
test('generation floors detect rollback and same-number substitution; unsafe numeric u64 refuses', () => {
  const f = fixture(), q = parsed(f), r = validated(f);
  assert.doesNotThrow(() => symbolReply(f.reply, selected('sha1'), q, null, null, r.index));
  assert.throws(() => symbolReply(f.reply, selected('sha1'), q, null, null, { ...r.index, number: 2 }));
  assert.throws(() => symbolReply(f.reply, selected('sha1'), q, null, null, { ...r.index, token: `alg:2:${'a'.repeat(64)}` }));
  f.reply.index_number = Number.MAX_SAFE_INTEGER; assert.doesNotThrow(() => validated(f));
  for (const number of [Number.MAX_SAFE_INTEGER + 1, '1', 0, -1, 1.5]) { f.reply.index_number = number; assert.throws(() => validated(f)); }
});
test('symbol checkpoints are independent and retained across explicit snapshot release', async () => {
  const f = fixture(), { value, calls } = await client(f);
  await value.search(f.input); const pin = value.state.pin;
  assert.equal(value.state.indexMinimum, null); assert.equal(value.state.symbolMinimum.number, 1);
  value.discardResults(); assert.deepEqual(value.state.pin, pin);
  value.refreshSnapshot(); assert.equal(value.state.pin, null); assert.equal(value.state.symbolMinimum.number, 1);
  await value.search(f.input); assert.equal(calls[1].fields.get('minimum_index_token'), f.reply.index_token);
  assert.equal(calls[1].fields.has('expected_head'), false);
  await assert.rejects(value.nextIndexed()); await assert.rejects(value.openMatch(0, 0));
  value.disconnect(); assert.equal(value.state.symbolMinimum, null);
});
test('normal transport options remain scoped, read-only and credential-ephemeral', async () => {
  const f = fixture(), { value, calls } = await client(f); await value.search(f.input);
  const call = calls[0]; assert.equal(call.url, 'https://forge.invalid/r.git/api/v1/source/search-symbols-index');
  for (const [k, v] of Object.entries({ method: 'POST', redirect: 'error', mode: 'same-origin', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' })) assert.equal(call.options[k], v);
  assert.equal(call.options.headers.Authorization, `Bearer ${token}`); assert.equal(call.options.headers['Idempotency-Key'], undefined);
  const t = new Transport({ ...transport(f).options, pageSuffix: '/ui/search/' }); await t.connect(token);
  for (const path of ['source/search-symbols', 'source/apply', 'outcomes', '../source/search-symbols-index', 'https://evil.invalid/']) await assert.rejects(t.request(path, { method: 'POST', body: '' }));
  await assert.rejects(t.request('source/search-symbols-index', { method: 'POST', body: '', key: 'write' }));
  t.disconnect(); value.disconnect();
});
test('missing/stale/corrupt/quota refusals never fall back, build, retry or fabricate empty results', async () => {
  for (const [status, code] of [[409, 'symbol_index_stale'], [409, 'symbol_index_uninitialized'], [409, 'index_checkpoint_unavailable'], [503, 'unavailable'], [413, 'too_large']]) {
    const f = fixture(), { value, calls } = await client(f, () => response({ error: code }, status));
    await assert.rejects(value.search(f.input), e => e.status === status && (status !== 409 || e.code === code));
    assert.equal(calls.length, 1); assert.equal(value.state.result, null); assert.equal(value.state.symbolMinimum, null); value.disconnect();
  }
});
test('malformed results do not advance either snapshot or checkpoint', async () => {
  const f = fixture(), env = await client(f); await env.value.search(f.input); const before = env.value.state;
  f.reply.index_number = 2; f.reply.matches[0].match_length = 1;
  await assert.rejects(env.value.search(f.input));
  assert.deepEqual(env.value.state.pin, before.pin); assert.deepEqual(env.value.state.symbolMinimum, before.symbolMinimum); assert.equal(env.value.state.result, null);
  env.value.disconnect();
});
test('authentication failure disconnects and discards source/checkpoint state', async () => {
  const f = fixture(); let revoked = false;
  const { value } = await client(f, () => revoked ? response({ error: 'unauthorized' }, 401) : null);
  await value.search(f.input); revoked = true; await assert.rejects(value.search(f.input), e => e.status === 401);
  assert.equal(value.connected, false); assert.equal(value.state.pin, null); assert.equal(value.state.symbolMinimum, null);
});
test('cancelled or disconnected late replies cannot install a source or checkpoint', async () => {
  for (const action of ['cancel', 'disconnect']) {
    const f = fixture(), gate = deferred(), entered = deferred();
    const { value, calls } = await client(f, async () => { entered.resolve(); return gate.promise; });
    const search = value.search(f.input); const refusal = assert.rejects(search); await entered.promise;
    value[action](); gate.resolve(response(f.reply)); await refusal;
    assert.equal(value.state.result, null); assert.equal(value.state.symbolMinimum, null); assert.equal(value.state.pin, null); assert.equal(calls.length, 1); value.disconnect();
  }
});
test('caller mutations during a pending request cannot alter the pinned query', async () => {
  const f = fixture(), gate = deferred(), entered = deferred(), input = { ...f.input, kinds: ['struct'] };
  const { value } = await client(f, async call => { entered.resolve(); await gate.promise; return null; });
  const waiting = value.search(input); await entered.promise; input.kinds[0] = 'enum'; input.nameHex = hex('Other'); gate.resolve();
  const report = await waiting; assert.deepEqual(report.query.kinds, ['struct']); assert.equal(report.query.nameHex, hex('Thing')); value.disconnect();
});
test('multi-page source navigation pins every page and verifies the complete SHA-256 blob', async () => {
  const f = fixture('sha256', { prefix: '// ' + 'x'.repeat(70000) + '\n' });
  const { value, calls } = await client(f); await value.search(f.input); const file = await value.openSymbol(0);
  assert.deepEqual(Buffer.from(file.bytes), f.body); assert.equal(calls.length, 3);
  assert.deepEqual(calls.slice(1).map(c => c.fields.get('offset')), ['0', '65536']);
  for (const c of calls.slice(1)) assert.equal(c.fields.get('expected_head'), f.source.snapshot_token);
  value.disconnect();
});
test('file navigation refuses changed source, symlinks, lengths, native hashes and coordinates', async () => {
  for (const change of [r => { r.snapshot_token = `alg:2:${'a'.repeat(64)}`; }, r => { r.kind = 'symlink'; }, r => { r.total_bytes++; },
    r => { r.content_hex = '00' + r.content_hex.slice(2); }, r => { r.next_offset = 1; }]) {
    const f = fixture(); const { value } = await client(f, call => {
      if (!call.url.endsWith('/blob')) return null;
      const file = f.file(0); change(file); return response(file);
    });
    await value.search(f.input); await assert.rejects(value.openSymbol(0)); value.disconnect();
  }
  const f = fixture(), r = validated(f), q = parsed(f);
  for (const extra of [{ line: 1 }, { column: 1 }, { rawIdentifier: true }, { nameHex: hex('Other') }]) {
    await assert.rejects(verifyFile(f.body, { ...r.hits[0], ...extra }, q, 0, 'sha1', webcrypto, () => {}));
  }
});
test('raw notation and name boundaries cannot be fabricated from a valid blob substring', async () => {
  const f = fixture('sha1', { name: 'ThingLong' }); const q = parsed(f), hit = validated(f).hits[0];
  await assert.rejects(verifyFile(f.body, { ...hit, nameHex: hex('Thing'), length: 5 }, q, 0, 'sha1', webcrypto, () => {}));
  const offset = hit.offset + 5;
  await assert.rejects(verifyFile(f.body, { ...hit, nameHex: hex('Long'), length: 4, offset, column: hit.column + 5 }, q, 0, 'sha1', webcrypto, () => {}));
});
test('cancellation after a file digest never returns a verified declaration', async () => {
  const f = fixture(), hit = validated(f).hits[0]; let checks = 0;
  await assert.rejects(verifyFile(f.body, hit, parsed(f), 0, 'sha1', webcrypto, () => { if (++checks === 2) throw new Error('cancelled'); }), /cancelled/);
});
test('lexical content/path replies still retain their original channel and generation contracts', () => {
  const f = fixture(), q = indexQuery({ mode: 'indexed', channel: 'content', termsHex: [hex('thing')] });
  const reply = { ...f.source, type: 'source_search_index', profile: 'ascii-word-postings-v1', channel: 'content',
    terms_hex: q.termsHex, path_prefix_hex: [], after: null, limit: 100, hits: [{ document_id: 1, path_hex: f.row.path_hex,
      blob: f.blob, content_bytes: f.body.length, spans: [{ query_index: 0, byte_offset: f.row.byte_offset, byte_length: 5 }] }],
    returned_hits: 1, complete: true, next_after: null, index_token: `alg:2:${'8'.repeat(64)}`, index_number: 4,
    selected_index_token: `alg:2:${'8'.repeat(64)}`, selected_index_number: 4, indexed_documents: 1,
    indexed_source_bytes: f.body.length, non_regular_entries: 0, segments_read: 1, payload_bytes_read: 512, generation_bytes_read: 200, work_units: 30 };
  assert.equal(indexReply(reply, selected('sha1'), q).index.number, 4);
  const path = indexQuery({ mode: 'indexed', channel: 'path', termsHex: [hex('thing')] });
  reply.channel = 'path'; reply.hits[0].spans[0].byte_offset = 4;
  assert.equal(indexReply(reply, selected('sha1'), path).hits[0].documentId, 1);
});
for (const mode of ['literal', 'regex']) test(`${mode}: existing full-file verification keeps its result shape`, async () => {
  const f = fixture(), hit = validated(f).hits[0];
  const q = { mode, case: 'exact', needlesHex: [hex('Thing')] };
  const result = await verifyFile(f.body, hit, q, 0, 'sha1', webcrypto, () => {});
  assert.deepEqual(result, { blobVerified: true, coordinatesVerified: true, literalVerified: mode !== 'regex', regexEvaluatedBy: mode === 'regex' ? 'native-server' : null });
});
test('lexical and symbol controllers never exchange their retained index checkpoints', async () => {
  const f = fixture(); const lexicalToken = `alg:2:${'8'.repeat(64)}`;
  const { value, calls } = await client(f, call => {
    if (!call.url.endsWith('/source/search-index')) return null;
    return response({ ...f.source, type: 'source_search_index', profile: 'ascii-word-postings-v1', channel: 'content',
      terms_hex: [hex('absent')], path_prefix_hex: [], after: null, limit: 100, hits: [], returned_hits: 0, complete: true, next_after: null,
      index_token: lexicalToken, index_number: 7, selected_index_token: lexicalToken, selected_index_number: 7,
      indexed_documents: 1, indexed_source_bytes: f.body.length, non_regular_entries: 0, segments_read: 1,
      payload_bytes_read: 512, generation_bytes_read: 200, work_units: 20 });
  });
  const q = { mode: 'indexed', channel: 'content', termsHex: [hex('absent')] };
  await value.search(q); await value.search(f.input); await value.search(q); await value.search(f.input);
  assert.equal(calls[1].fields.has('minimum_index_token'), false);
  assert.equal(calls[2].fields.get('minimum_index_token'), lexicalToken);
  assert.equal(calls[3].fields.get('minimum_index_token'), f.reply.index_token);
  assert.equal(value.state.indexMinimum.number, 7); assert.equal(value.state.symbolMinimum.number, 1); value.disconnect();
});
