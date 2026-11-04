// Wire-schema validation only; the Rust module tests own actual index building.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validate } from '../../scripts/operator/source_context.mjs';
import { symbolInput, nativeSymbols } from './source_context_symbols_fixtures.mjs';
import { withRevalidatedSources } from './source_context_revalidated_fixtures.mjs';

function corpus(response, declarations) {
  const r = response.retrieval, s = r.symbols.result;
  s.indexed_files = Math.ceil(declarations / 20_000);
  s.indexed_declarations = declarations;
  s.indexed_source_bytes = 4 * 1024 * 1024;
  for (const channel of [r.content, r.path]) {
    channel.indexed_documents = s.indexed_files + s.unsupported_language_files;
    channel.indexed_source_bytes = s.indexed_source_bytes + 1024;
  }
  return response;
}
for (const format of ['sha1', 'sha256']) for (const current of [false, true]) {
  test(`${format}: ${current ? 'current-native' : 'strict'} context accepts a larger persisted symbol corpus`, () => {
    const q = symbolInput(format, current ? { index_source: 'current-native-v1' } : {});
    for (const declarations of [20_001, 131_072]) {
      let response = corpus(nativeSymbols(q), declarations);
      if (current) response = withRevalidatedSources(response);
      const checked = validate(response, q);
      assert.equal(checked.symbols.state, 'available');
      assert.equal(checked.symbols.complete, true);
      assert.equal(checked.returned_files, 3);
      assert.equal(checked.authority_verified, false);
    }
  });
}

test('context refuses excess aggregate declarations and impossible per-file counts', () => {
  for (const change of [
    s => { s.indexed_declarations = 131_073; },
    s => { s.indexed_files = 1; s.indexed_declarations = 20_001; },
    s => { s.indexed_declarations = Number.MAX_SAFE_INTEGER; },
    s => { s.indexed_source_bytes = 64 * 1024 * 1024 + 1; },
    s => { s.max_work = 256 * 1024 * 1024; },
  ]) {
    const q = symbolInput(), response = corpus(nativeSymbols(q), 131_072);
    change(response.retrieval.symbols.result);
    assert.throws(() => validate(response, q));
  }
});
