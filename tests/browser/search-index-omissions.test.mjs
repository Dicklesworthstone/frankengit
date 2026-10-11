import test from 'node:test';
import assert from 'node:assert/strict';
import { indexQuery, indexCommand, indexReply, initialQuery, initialReply } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { crypto, token, href, hex, fixture } from './search-index-fixtures.mjs';
import { fixture as combined, selected } from './search-initial-fixtures.mjs';
import { omission, partialReply, partialInitial, revalidatedReply } from './search-index-omission-fixtures.mjs';

const input = (extra = {}) => ({ mode: 'indexed', channel: 'content', termsHex: [hex('alpha')], maxMatches: 1, ...extra });
const reply = (f, q) => f.reply(new URLSearchParams(indexCommand(selected(f.algorithm), null, q)));
const validate = (f, raw, q = indexQuery(input())) => indexReply(raw, selected(f.algorithm), q);
async function connect(f) {
  const client = new CodeSearch({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto });
  await client.connect(token, f.common.ref, f.algorithm); return client;
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: lexical omissions preserve useful full, limited and empty pages in both channels`, () => {
    const f = fixture(format);
    for (const channel of ['content', 'path']) for (const maxMatches of [1, 100]) {
      const q = indexQuery(input({ channel, termsHex: [hex(channel === 'content' ? 'alpha' : 'src')],
        prefixesHex: [hex('src')], maxMatches, maxFileBytes: 1 }));
      const legacy = validate(f, reply(f, q), q);
      assert.equal(legacy.coverageComplete, true); assert.deepEqual(legacy.omissions, []);
      const raw = partialReply(reply(f, q)), value = validate(f, raw, q);
      assert.equal(value.complete, maxMatches === 100); assert.equal(value.coverageComplete, false);
      assert.equal(value.hits.length, maxMatches === 100 ? 3 : 1);
      assert.equal(value.omissions[0].pathHex, hex('vendor/oversized.bin'));
      assert.equal(value.omissions[0].blob, raw.omissions[0].blob.split(':')[1]);
      assert.equal(value.omissions[0].limit, 64); // Build limit is independent of navigation and query scope.
      assert.equal(value.omissions[0].offset, null);
      const absent = indexQuery({ ...q, termsHex: [hex('missing')] });
      const empty = validate(f, partialReply(reply(f, absent)), absent);
      assert.equal(empty.hits.length, 0); assert.equal(empty.complete, true); assert.equal(empty.coverageComplete, false);
    }
    const emptyCorpus = fixture(format, []), q = indexQuery(input());
    const value = validate(emptyCorpus, partialReply(reply(emptyCorpus, q)), q);
    assert.equal(value.stats.documents, 0); assert.equal(value.stats.sourceBytes, 0);
    assert.equal(value.complete, true); assert.equal(value.coverageComplete, false);
  });

  for (const mode of ['exact', 'revalidated']) {
    test(`${format} ${mode}: omissions stay pinned across continuation and verified file navigation`, async () => {
      const f = fixture(format), entries = [omission(format)];
      f.config.query = raw => { partialReply(raw, entries); if (mode === 'revalidated') revalidatedReply(raw); };
      const client = await connect(f), first = await client.search(input({ sourceMode: mode }));
      assert.equal(first.coverageComplete, false); assert.equal(first.complete, false);
      first.omissions[0].pathHex = hex('caller-mutation');
      assert.notEqual(client.state.result.omissions[0].pathHex, first.omissions[0].pathHex);
      const second = await client.nextIndexed(), opened = await client.openIndexed(0);
      assert.equal(second.omissions[0].pathHex, entries[0].path_hex);
      assert.equal(opened.blobVerified, true); assert.equal(opened.wordSpansVerified, true);
      assert.equal(opened.coverageVerified, false); assert.deepEqual(Buffer.from(opened.bytes), f.docs[1].bytes);
      assert.equal(f.calls.at(-1).params.get('expected_head'), f.common.snapshot_token);
      const last = await client.nextIndexed();
      assert.equal(last.complete, true); assert.equal(last.coverageComplete, false); assert.deepEqual(last.omissions, second.omissions);
      if (mode === 'revalidated') {
        assert.equal(last.sources.distinct, true); assert.equal(last.index.number, '9007199254740993');
        assert.equal(f.calls.at(-1).params.get('index_number'), '9007199254740993');
      }
      assert.equal(f.calls.length, 4); client.disconnect();
    });
  }
}

test('lexical v2 rejects missing, forged, overlapping or unbounded omission inventories', () => {
  const f = fixture(), q = indexQuery(input()), base = partialReply(reply(f, q));
  const edits = [
    r => { r.schema_version = 3; }, r => { r.schema_version = 1; },
    r => { delete r.index_profile; }, r => { r.index_profile = 'ascii-word-postings-v1'; },
    r => { r.coverage_complete = true; }, r => { delete r.coverage_complete; }, r => { r.coverage_scope = 'query'; },
    r => { delete r.omissions; }, r => { r.omissions = null; },
    r => { r.omissions = []; r.omitted_files = 0; r.omitted_source_bytes = 0; },
    r => { r.omitted_files++; }, r => { r.omitted_files = '1'; }, r => { r.omitted_source_bytes++; },
    r => { delete r.omitted_source_bytes; }, r => { r.omissions[0].reason = 'work_limit'; },
    r => { r.omissions[0].reason = 'invalid_utf8'; }, r => { r.omissions[0].limit = 0; },
    r => { r.omissions[0].limit = 8 * 1024 * 1024 + 1; }, r => { r.omissions[0].limit = '64'; },
    r => { r.omissions[0].limit = r.omissions[0].source_bytes; },
    r => { r.omissions[0].source_bytes = 0; r.omitted_source_bytes = 0; },
    r => { r.omissions[0].source_bytes = 1.5; r.omitted_source_bytes = 1.5; },
    r => { r.omissions[0].byte_offset = null; }, r => { delete r.omissions[0].blob; },
    r => { r.omissions[0].blob = 'sha256:' + '1'.repeat(64); }, r => { r.omissions[0].blob = '0'.repeat(40); },
    r => { r.omissions[0].path_hex = hex('../oversized'); }, r => { r.omissions[0].path_hex = hex('.git/index'); },
    r => { r.omissions[0].path_hex = hex('bad\0file'); }, r => { r.omissions[0].path_hex = hex('a/'.repeat(64) + 'file'); },
    r => { r.omissions[0].path_hex = hex('a'.repeat(4097)); }, r => { r.omissions[0].path_hex = r.hits[0].path_hex; },
    r => { r.omissions.push(structuredClone(r.omissions[0])); r.omitted_files++; r.omitted_source_bytes *= 2; },
    r => { r.omissions.push(omission('sha1', Buffer.from('a.bin'))); r.omitted_files++; r.omitted_source_bytes *= 2; },
    r => { r.indexed_documents = 20_000; }, r => { r.indexed_source_bytes = 64 * 1024 * 1024; },
  ];
  for (const edit of edits) {
    const bad = structuredClone(base); edit(bad); assert.throws(() => validate(f, bad, q), edit.toString());
  }
  for (const field of ['index_profile', 'coverage_complete', 'coverage_scope', 'omitted_files', 'omitted_source_bytes', 'omissions']) {
    const bad = reply(f, q); bad[field] = field === 'omissions' ? [] : field === 'coverage_complete' ? true : 0;
    assert.throws(() => validate(f, bad, q), `invented v1 ${field}`);
  }
});

test('indexed file inventory and retained-result ceilings include omissions with exact boundary twins', () => {
  const f = fixture(), q = indexQuery(input()), entry = omission();
  const corpus = partialReply(reply(f, q), [entry]);
  corpus.indexed_documents = 19_999;
  corpus.indexed_source_bytes = 64 * 1024 * 1024 - entry.source_bytes;
  assert.doesNotThrow(() => validate(f, corpus, q));
  for (const field of ['indexed_documents', 'indexed_source_bytes']) {
    const bad = structuredClone(corpus); bad[field]++; assert.throws(() => validate(f, bad, q));
  }
  const entries = Array.from({ length: 500 }, (_, i) => omission('sha1', Buffer.from(`z/${String(i).padStart(5, '0')}${'x'.repeat(4089)}`)));
  const bounded = partialReply(reply(f, q), entries);
  assert.doesNotThrow(() => validate(f, bounded, q));
  // Each part separately fits: 500 * (4096 + 96) omission bytes, and one hit.
  // Their combined retained bytes cross the 2 MiB limit with the larger path.
  bounded.hits[0].path_hex = hex('a'.repeat(4096));
  assert.throws(() => validate(f, bounded, q), /result budget/);
});

for (const mode of ['exact', 'revalidated']) test(`${mode}: changed continuation omissions cannot install results or advance checkpoints`, async () => {
  const edits = [
    r => { r.omissions[0].path_hex = hex('vendor/different.bin'); },
    r => { r.omissions[0].blob = 'c'.repeat(40); },
    r => { r.omissions[0].source_bytes++; r.omitted_source_bytes++; },
    r => { r.omissions[0].limit++; },
    r => { r.omissions[0].path_hex = r.hits[0].path_hex; },
    r => { r.schema_version = 1; for (const key of ['index_profile', 'coverage_complete', 'omitted_files', 'omitted_source_bytes', 'omissions']) delete r[key]; },
  ];
  for (const edit of edits) {
    const f = fixture(); let changed = false;
    f.config.query = raw => { partialReply(raw); if (mode === 'revalidated') revalidatedReply(raw); if (changed) edit(raw); };
    const client = await connect(f); await client.search(input({ sourceMode: mode })); const before = client.state;
    changed = true;
    await assert.rejects(client.nextIndexed(), edit.toString());
    assert.equal(client.state.result, null); assert.deepEqual(client.state.pin, before.pin);
    assert.deepEqual(client.state.indexMinimum, before.indexMinimum); assert.equal(f.calls.length, 2);
    client.disconnect();
  }
});

for (const format of ['sha1', 'sha256']) test(`${format}: Initial requires one lexical coverage inventory and charges it to each channel`, () => {
  const f = combined({ format, symbols: 'not_requested' }); partialInitial(f.reply);
  const q = initialQuery(f.input), good = initialReply(f.reply, selected(format), q);
  assert.equal(good.complete, false); assert.equal(good.content.complete, true); assert.equal(good.path.complete, true);
  assert.deepEqual(good.content.omissions, good.path.omissions); assert.equal(good.content.coverageComplete, false);
  assert.equal(good.stats.retainedBytes, f.reply.retained_result_bytes);
  const omissionBytes = f.reply.content.omissions[0].path_hex.length / 2 + 96;
  const edits = [
    r => { r.complete = true; }, r => { r.retained_result_bytes -= omissionBytes; },
    r => { r.path.omissions[0].path_hex = hex('vendor/other.bin'); },
    r => { r.path.omissions[0].blob = 'd'.repeat(format === 'sha1' ? 40 : 64); },
    r => { r.path.omissions[0].source_bytes++; r.path.omitted_source_bytes++; },
    r => { r.path.omissions[0].limit++; },
    r => { r.path.schema_version = 1; for (const key of ['index_profile', 'coverage_complete', 'omitted_files', 'omitted_source_bytes', 'omissions']) delete r.path[key]; },
  ];
  for (const edit of edits) {
    const bad = structuredClone(f.reply); edit(bad); assert.throws(() => initialReply(bad, selected(format), q), edit.toString());
  }
  f.reply.max_result_bytes = f.reply.retained_result_bytes;
  assert.doesNotThrow(() => initialReply(f.reply, selected(format), initialQuery({ ...f.input, maxResultBytes: f.reply.max_result_bytes })));
  f.reply.max_result_bytes--;
  assert.throws(() => initialReply(f.reply, selected(format), initialQuery({ ...f.input, maxResultBytes: f.reply.max_result_bytes })));
});
