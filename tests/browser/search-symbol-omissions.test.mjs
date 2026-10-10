import test from 'node:test';
import assert from 'node:assert/strict';
import { symbolQuery, symbolReply, initialQuery, initialReply } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { fixture, hex, selected, transport, token } from './search-symbol-fixtures.mjs';
import { currentFixture, currentTransport } from './search-symbol-current-fixtures.mjs';
import { fixture as combined } from './search-initial-fixtures.mjs';
import { omission, partialReply } from './search-symbol-omission-fixtures.mjs';

const validate = (f, extra = {}) => symbolReply(f.reply, selected(f.source.object_format), symbolQuery({ ...f.input, ...extra }));
for (const format of ['sha1', 'sha256']) {
  test(`${format}: v1 identities stay covered and v2 omissions are independent of exact full or empty match pages`, () => {
    const legacy = fixture(format);
    assert.equal(validate(legacy).coverageComplete, true); assert.deepEqual(validate(legacy).omissions, []);
    for (const truncated of [false, true]) {
      const f = fixture(format); partialReply(f.reply);
      f.reply.max_matches = 1; f.reply.indexed_declarations = truncated ? 2 : 1;
      f.reply.complete = !truncated; f.reply.completion = truncated ? 'match_limit' : 'complete';
      f.reply.path_prefix_hex = [hex('src')];
      const r = validate(f, { maxMatches: 1, prefixesHex: [hex('src')] });
      assert.equal(r.complete, !truncated); assert.equal(r.coverageComplete, false);
      assert.equal(r.omissions.length, 1); assert.equal(r.omissions[0].pathHex, f.reply.omissions[0].path_hex);
      assert.equal(r.omissions[0].blob, f.reply.omissions[0].blob);
      assert.equal(r.omissions[0].reason, 'unbalanced_delimiter');
    }
    const f = fixture(format); partialReply(f.reply); f.reply.matches = []; f.reply.returned_matches = 0;
    const r = validate(f); assert.equal(r.hits.length, 0); assert.equal(r.complete, true); assert.equal(r.coverageComplete, false);
  });
  test(`${format}: revalidated v2 keeps original omissions and current pinned file navigation`, async () => {
    const f = currentFixture(format); partialReply(f.reply);
    const env = currentTransport(f), client = new CodeSearch(env.options);
    await client.connect(token, 'refs/heads/main', format);
    const result = await client.search(f.currentInput);
    assert.equal(result.coverageComplete, false); assert.equal(result.sources.distinct, true);
    assert.equal(result.omissions[0].blob, f.reply.omissions[0].blob);
    result.omissions[0].blob = 'caller mutation';
    const opened = await client.openSymbol(0);
    assert.deepEqual(Buffer.from(opened.bytes), f.body);
    assert.equal(env.calls[1].fields.get('expected_head'), f.current.snapshot_token);
    assert.equal(client.state.result.omissions[0].blob, f.reply.omissions[0].blob);
    assert.equal(env.calls.length, 2); client.disconnect();
  });
}

test('omission version, profile, shape, order, scope, diagnostics and native identities fail closed', () => {
  const base = fixture(); partialReply(base.reply);
  const edits = [
    r => { r.schema_version = 3; }, r => { r.schema_version = 1; r.index_profile = 'rust-declaration-tables-v1'; },
    r => { r.index_profile = 'rust-declaration-tables-v1'; }, r => { r.coverage_complete = true; },
    r => { r.coverage_scope = 'query'; }, r => { r.omitted_files = 0; }, r => { r.omitted_source_bytes++; },
    r => { r.omissions = []; r.omitted_files = 0; r.omitted_source_bytes = 0; },
    r => { r.omissions[0].path_hex = hex('../x.rs'); }, r => { r.omissions[0].path_hex = hex('.git/x.rs'); },
    r => { r.omissions[0].path_hex = hex('x.txt'); }, r => { r.omissions[0].path_hex = r.matches[0].path_hex; },
    r => { r.omissions[0].blob = '1'.repeat(64); }, r => { r.omissions[0].blob = '0'.repeat(40); },
    r => { r.omissions[0].source_bytes = 0; r.omitted_source_bytes = 0; },
    r => { r.omissions[0].reason = 'authorization'; }, r => { r.omissions[0].reason = 'work_limit'; },
    r => { r.omissions[0].byte_offset++; }, r => { r.omissions[0].byte_offset = null; },
    r => { r.omissions[0].limit = 1; }, r => { r.omissions[0].ignored = true; },
    r => { r.omissions.push(structuredClone(r.omissions[0])); r.omitted_files++; r.omitted_source_bytes *= 2; },
    r => { const a = omission('sha1', Buffer.from('a.rs')); r.omissions.push(a); r.omitted_files++; r.omitted_source_bytes += a.source_bytes; },
    r => { r.indexed_files = 20_000; }, r => { r.indexed_source_bytes = 64 * 1024 * 1024; },
  ];
  for (const edit of edits) {
    const bad = { ...base, reply: structuredClone(base.reply) }; edit(bad.reply);
    assert.throws(() => validate(bad), edit.toString());
  }
});

test('file and table size omissions use independent closed diagnostics and bounded source accounting', () => {
  for (const [reason, size, limit] of [['file_bytes', 8388609, 8388608], ['table_bytes', 8388608, 1048576]]) {
    const f = fixture(), entry = omission();
    Object.assign(entry, { reason, source_bytes: size, byte_offset: null, limit }); partialReply(f.reply, [entry]);
    const parsed = validate(f); assert.equal(parsed.omissions[0].limit, limit); assert.equal(parsed.omissions[0].offset, null);
    for (const edit of [r => { r.omissions[0].limit = 0; }, r => { r.omissions[0].byte_offset = 0; },
      r => { r.omissions[0].source_bytes = 67108864; r.omitted_source_bytes = 67108864; }]) {
      const bad = { ...f, reply: structuredClone(f.reply) }; edit(bad.reply); assert.throws(() => validate(bad));
    }
  }
});

test('invalid omission data cannot replace a valid snapshot or advance a retained checkpoint', async () => {
  const f = fixture(); partialReply(f.reply);
  const env = transport(f), client = new CodeSearch(env.options); await client.connect(token, 'refs/heads/main', 'sha1');
  await client.search(f.input); const before = client.state;
  f.reply.index_number = 2; f.reply.omissions[0].reason = 'unknown';
  await assert.rejects(client.search(f.input));
  assert.equal(client.state.result, null); assert.deepEqual(client.state.pin, before.pin);
  assert.deepEqual(client.state.symbolMinimum, before.symbolMinimum); assert.equal(env.calls.length, 2); client.disconnect();
});

test('combined Initial receipts charge omissions and never call all available channels complete', () => {
  const f = combined({ policy: 'required' }), child = f.reply.symbols.result;
  partialReply(child); f.reply.complete = false;
  const omissionBytes = child.omissions[0].path_hex.length / 2 + 96;
  f.reply.retained_result_bytes += omissionBytes;
  const q = initialQuery(f.input), good = initialReply(f.reply, selected(f.format), q);
  assert.equal(good.complete, false); assert.equal(good.symbols.state, 'available');
  assert.equal(good.symbols.result.complete, true); assert.equal(good.symbols.result.coverageComplete, false);
  assert.equal(good.stats.retainedBytes, f.reply.retained_result_bytes);
  for (const edit of [r => { r.complete = true; }, r => { r.retained_result_bytes -= omissionBytes; }]) {
    const bad = structuredClone(f.reply); edit(bad); assert.throws(() => initialReply(bad, selected(f.format), q));
  }
  const cap = f.reply.retained_result_bytes - 1;
  f.reply.max_result_bytes = cap;
  assert.throws(() => initialReply(f.reply, selected(f.format), initialQuery({ ...f.input, maxResultBytes: cap })));
});
