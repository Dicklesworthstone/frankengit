// Native-schema peers exercise the real browser validators, not an index build.
import test from 'node:test';
import assert from 'node:assert/strict';
import { symbolQuery, symbolReply } from '../../crates/fgit-node/src/smart_http/server/browser/search-index.mjs';
import { fixture, selected } from './search-symbol-fixtures.mjs';
import { currentFixture } from './search-symbol-current-fixtures.mjs';
import { partialReply } from './search-symbol-omission-fixtures.mjs';

function corpus(reply, declarations) {
  reply.indexed_files = Math.ceil(declarations / 20_000);
  reply.indexed_declarations = declarations;
  reply.indexed_source_bytes = 4 * 1024 * 1024;
  return reply;
}
for (const format of ['sha1', 'sha256']) for (const current of [false, true]) {
  for (const partial of [false, true]) test(`${format}: ${current ? 'current' : 'strict'} ${partial ? 'partial' : 'complete'} symbol corpus exceeds one table`, () => {
    for (const declarations of [20_000, 20_001, 131_072]) {
      const f = current ? currentFixture(format) : fixture(format);
      corpus(f.reply, declarations);
      if (partial) partialReply(f.reply);
      const q = symbolQuery(current ? f.currentInput : f.input);
      const parsed = symbolReply(current ? f.wrapper() : f.reply, selected(format), q);
      assert.equal(parsed.stats.declarations, declarations);
      assert.equal(parsed.hits.length, 1);
      assert.equal(parsed.coverageComplete, !partial);
      assert.equal(parsed.query.maxWork, 16 * 1024 * 1024);
      assert.equal(parsed.query.maxMatches, 100);
    }
  });
}

test('a larger corpus preserves aggregate, per-table, payload and query bounds', () => {
  for (const change of [
    r => { r.indexed_declarations = 131_073; },
    r => { r.indexed_files = 1; r.indexed_declarations = 20_001; },
    r => { r.indexed_files = 0; r.indexed_declarations = 1; },
    r => { r.indexed_declarations = 131_071.5; },
    r => { r.indexed_source_bytes = 64 * 1024 * 1024 + 1; },
    r => { r.payload_bytes_read = 32 * 1024 * 1024 + 1; },
    r => { r.work_units = 16 * 1024 * 1024 + 1; },
    r => { r.max_work = 256 * 1024 * 1024; },
  ]) {
    const f = fixture(); corpus(f.reply, 131_072); change(f.reply);
    assert.throws(() => symbolReply(f.reply, selected('sha1'), symbolQuery(f.input)));
  }
});
