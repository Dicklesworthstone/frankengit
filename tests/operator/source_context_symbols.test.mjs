import test from 'node:test';
import assert from 'node:assert/strict';
import { acquire, command, query, validate, parse, LIMITS } from '../../scripts/operator/source_context.mjs';
import { peer, json, TOKEN } from './source_context_fixtures.mjs';
import { symbolInput, nativeSymbols, assemble, FILES, DECLARATIONS, hex } from './source_context_symbols_fixtures.mjs';

for (const format of ['sha1', 'sha256']) {
  test(`${format}: symbol-only raw paths join exact lexical context through one HTTP request`, async t => {
    const q = symbolInput(format), r = nativeSymbols(q), p = await peer(t, (_req, res) => json(res, r));
    const capture = await acquire(p.endpoint, TOKEN, q);
    const form = new URLSearchParams(p.calls[0].body);
    assert.equal(p.calls.length, 1); assert.equal(form.get('symbol_name_hex'), hex('Recover'));
    assert.equal(form.get('symbol_match'), 'prefix'); assert.equal(form.get('symbol_policy'), 'required');
    assert.equal(p.calls[0].headers['idempotency-key'], undefined);
    assert.equal(capture.summary.returned_files, 3); assert.equal(capture.summary.symbols.generation.number, '4');
    assert.equal(capture.summary.lexical_generation.number, '7'); assert.equal(capture.summary.complete, true);
    assert.deepEqual(capture.summary.full_blob_hash_verified_paths, FILES.map(f => hex(f.path)));
    assert.ok(r.files[0].anchors.some(a => a.channel === 'symbol')); assert.equal(r.files[2].anchors[0].channel, 'symbol');
    assert.equal(capture.summary.authority_verified, false); assert.equal(capture.summary.agent_context_packet, false);
    assert.equal(JSON.stringify(capture).includes(TOKEN), false);
  });
  test(`${format}: independent symbol checkpoint and exact case/kind/scope do not widen`, async t => {
    const q = symbolInput(format, { symbols: { name: 'Recover', match: 'exact', kinds: ['function', 'function'] },
      prefixes_hex: [hex('a')], minimum_symbol: { token: `alg:2:${'e'.repeat(64)}`, number: '4' } });
    const r = nativeSymbols(q), p = await peer(t, (_req, res) => json(res, r));
    assert.equal((await acquire(p.endpoint, TOKEN, q)).summary.returned_files, 1);
    const form = new URLSearchParams(p.calls[0].body);
    assert.deepEqual(form.getAll('symbol_kind'), ['function']); assert.equal(form.get('minimum_symbol_number'), '4');
    assert.equal(form.get('symbol_name_hex'), hex('Recover'));
    for (const minimum_symbol of [{ token: `alg:2:${'e'.repeat(64)}`, number: '5' }, { token: `alg:2:${'f'.repeat(64)}`, number: '4' }])
      assert.throws(() => validate(r, { ...q, minimum_symbol }), /checkpoint_regressed/);
  });
  test(`${format}: initialized empty symbol results are available, not optional absence`, () => {
    const q = symbolInput(format, { symbols: { name: 'Missing', policy: 'required' } });
    const checked = validate(nativeSymbols(q), q);
    assert.equal(checked.symbols.state, 'available'); assert.equal(checked.symbols.complete, true);
    assert.equal(checked.complete, true); assert.equal(checked.returned_files, 2);
  });
}

test('symbol grammar owns case, canonical kinds, checkpoint shape and pre-I/O shares', async t => {
  const original = symbolInput('sha1', { symbols: { name: 'Recover', kinds: ['union', 'function', 'union'] } });
  const q = query(original); original.symbols.name = 'Changed'; original.symbols.kinds[0] = 'macro';
  assert.equal(q.symbols.name, 'Recover'); assert.deepEqual(q.symbols.kinds, ['function', 'union']);
  const p = await peer(t, (_req, res) => json(res, nativeSymbols()));
  for (const symbols of [null, 'Recover', {}, { name: 'r#type' }, { name: '123' }, { name: 'é' },
    { name: 'x', match: 'regex' }, { name: 'x', policy: 'ignore-errors' }, { name: 'x', kinds: ['unknown'] },
    { name: 'x', kinds: ['function'], path: 'private' }, { name: 'x', kinds: new Array(9).fill('function') }])
    await assert.rejects(acquire(p.endpoint, TOKEN, symbolInput('sha1', { symbols })));
  for (const limits of [{ max_work: 2 }, { max_payload_bytes: 2 }])
    await assert.rejects(acquire(p.endpoint, TOKEN, symbolInput('sha1', { limits })));
  assert.equal(p.calls.length, 0);
});

for (const reason of ['uninitialized', 'stale']) test(`optional ${reason} stays incomplete and cannot erase a checkpoint`, async t => {
  const q = symbolInput('sha1', { symbols: { name: 'Recover', policy: 'optional' } }), r = nativeSymbols(q, FILES, DECLARATIONS, reason);
  const p = await peer(t, (_req, res) => json(res, r)); const checked = (await acquire(p.endpoint, TOKEN, q)).summary;
  assert.equal(checked.complete, false); assert.equal(checked.symbols.state, 'unavailable'); assert.equal(checked.symbols.reason, reason);
  assert.equal(checked.symbols.generation, null); assert.equal(checked.returned_files, 2);
  assert.throws(() => validate(r, { ...q, symbols: { ...q.symbols, policy: 'required' } }), /not_permitted/);
  assert.throws(() => validate(r, { ...q, minimum_symbol: { token: `alg:2:${'e'.repeat(64)}`, number: '1' } }), /not_permitted/);
  const invalid = structuredClone(r); invalid.retrieval.symbols.reason = 'corrupt'; assert.throws(() => validate(invalid, q));
  const inflated = structuredClone(r); inflated.retrieval.content.work_units = Math.floor(q.limits?.max_work ?? LIMITS.work / 3) + 2;
  assert.throws(() => validate(inflated, q));
});

test('raw identifiers and case-sensitive source bytes are checked without full-blob claims for small excerpts', () => {
  const path = Buffer.from('raw.rs'), bytes = Buffer.from('pub fn r#type() {}\n');
  for (const radius of [0, 2, 128]) {
    const q = symbolInput('sha1', { terms: ['missing'], symbols: { name: 'type', policy: 'required' }, limits: { context_radius_bytes: radius } });
    const r = nativeSymbols(q, [{ path, bytes }], [{ path, name: 'type', at: 9, raw: true }]);
    const checked = validate(r, q); assert.equal(checked.returned_files, 1);
    assert.equal(checked.full_blob_hash_verified_paths.length, Number(radius === 128));
    const altered = structuredClone(r); altered.files[0].excerpts[0].untrusted_bytes_hex = altered.files[0].excerpts[0].untrusted_bytes_hex.replace(hex('type'), hex('Type'));
    assert.throws(() => validate(altered, q), /symbol_source_mismatch/);
    const falseMarker = structuredClone(r); falseMarker.retrieval.symbols.result.matches[0].excerpt_hex = hex('pub fn   type() {}');
    assert.throws(() => validate(falseMarker, q), /symbol_excerpt_mismatch/);
  }
});

test('symbol excerpt overlaps must agree with hydrated bytes outside the matching name', () => {
  const q = symbolInput(), r = nativeSymbols(q);
  r.retrieval.symbols.result.matches[0].excerpt_hex = r.retrieval.symbols.result.matches[0].excerpt_hex.replace(hex('pub'), hex('xxx'));
  assert.throws(() => validate(r, q), /symbol_source_mismatch/);
});

test('returned symbol duplicates count as declarations, but path/blob identities never conflict', () => {
  const q = symbolInput('sha1', { limits: { max_results_per_channel: 1 } }), r = nativeSymbols(q);
  assert.equal(validate(r, q).complete, false); assert.equal(r.retrieval.symbols.result.complete, false);
  const malformed = nativeSymbols(); malformed.retrieval.symbols.result.matches[1].blob = 'f'.repeat(40);
  assert.throws(() => validate(malformed, symbolInput()), /identity/);
});

const corrupt = {
  foreign_tenant: s => s.tenant_id = 'f'.repeat(32), foreign_commit: s => s.source_commit = 'f'.repeat(40),
  foreign_tree: s => s.root_tree = 'f'.repeat(40), foreign_head: s => s.source_head = 'foreign',
  generation: s => s.index_number++, semantic_authority: s => s.authority_class = 'canonical',
  compiler: s => s.compiler_resolved = true, macro: s => s.macro_expansion = true,
  query_case: s => s.name_hex = hex('recover'), query_kind: s => s.kinds = ['macro'],
  scope: s => s.path_prefix_hex = [hex('secret')], work: s => s.work_units = LIMITS.work,
  payload: s => s.payload_bytes_read = LIMITS.payload, counter: s => s.returned_matches++,
  order: s => s.matches.reverse(), truncation: s => s.complete = false,
  match_length: s => s.matches[0].match_length++, line: s => s.matches[0].line = 0,
  raw: s => s.matches[0].raw_identifier = true, excerpt: s => s.matches[0].excerpt_offset++,
  scope_path: s => s.matches[0].path_hex = hex('../private.rs'), foreign_kind: s => s.matches[0].kind = 'call',
  uppercase_blob: s => s.matches[0].blob = 'F'.repeat(40), no_tables: s => s.tables_read = 0,
  hidden_coverage: s => s.coverage_complete = true,
};
for (const [name, change] of Object.entries(corrupt)) test(`symbol corruption fails the whole capture: ${name}`, () => {
  const q = symbolInput(), r = nativeSymbols(q); change(r.retrieval.symbols.result); assert.throws(() => validate(r, q));
});

test('every supported omission diagnostic is retained and prevents complete coverage', () => {
  for (const reason of ['file_bytes', 'invalid_utf8', 'unsupported_identifier', 'unterminated_comment', 'unterminated_literal', 'unbalanced_delimiter', 'depth_limit', 'name_limit', 'table_bytes']) {
    const q = symbolInput(), r = nativeSymbols(q), s = r.retrieval.symbols.result;
    const o = { path_hex: hex('omitted.rs'), blob: 'f'.repeat(40), source_bytes: 20, reason,
      byte_offset: ['file_bytes', 'table_bytes'].includes(reason) ? null : 19,
      limit: reason === 'file_bytes' ? 10 : reason === 'table_bytes' ? 1048576 : null };
    Object.assign(s, { schema_version: 2, index_profile: 'rust-declaration-omissions-v1', coverage_complete: false,
      coverage_scope: 'recorded-rust-files', omitted_files: 1, omitted_source_bytes: 20, omissions: [o] });
    assemble(r, q, FILES); const checked = validate(r, q);
    assert.equal(checked.complete, false); assert.equal(checked.symbols.coverage_complete, false);
    const malformed = structuredClone(r); malformed.retrieval.symbols.result.omissions[0].byte_offset = 21;
    assert.throws(() => validate(malformed, q));
    const missing = structuredClone(r); delete missing.retrieval.symbols.result.omissions; assert.throws(() => validate(missing, q));
  }
});

test('symbol uint64 generations survive numeric JSON parsing with their own retained floor', () => {
  const q = symbolInput('sha256'), r = nativeSymbols(q), number = '18446744073709551615';
  r.retrieval.symbols.result.index_number = r.retrieval.generation_vector.symbols.index_number = number;
  q.minimum_symbol = { token: r.retrieval.generation_vector.symbols.index_token, number };
  const wire = JSON.stringify(r).replaceAll(`"${number}"`, number);
  assert.equal(validate(parse(Buffer.from(wire)), q).symbols.generation.number, number);
});

test('symbol query and floor are copied before network I/O and are not renewed on rejection', async t => {
  const q = symbolInput(), r = nativeSymbols(q), p = await peer(t, (_req, res) => json(res, r));
  q.minimum_symbol = { token: r.retrieval.generation_vector.symbols.index_token, number: '4' };
  const pending = acquire(p.endpoint, TOKEN, q);
  q.symbols.name = 'Foreign'; q.minimum_symbol.number = '99';
  assert.equal((await pending).summary.symbols.generation.number, '4'); assert.equal(p.calls.length, 1);
  const errorPeer = await peer(t, (_req, res) => { res.writeHead(503); res.end('corrupt'); });
  await assert.rejects(acquire(errorPeer.endpoint, TOKEN, symbolInput('sha1', { symbols: { name: 'Recover', policy: 'optional' } })), e => e.status === 503);
  assert.equal(errorPeer.calls.length, 1);
});

test('selected symbol source sizes cannot exceed the recorded corpus even for symbol-only paths', () => {
  const q = symbolInput('sha1', { terms: ['missing'], limits: { context_radius_bytes: 0 } });
  const files = [{ path: Buffer.from('only.rs'), bytes: Buffer.from('pub fn Recover() {}\n' + 'x'.repeat(100)) }];
  const r = nativeSymbols(q, files, [{ path: files[0].path, name: 'Recover', at: 7 }]);
  r.retrieval.symbols.result.indexed_source_bytes = 20;
  assert.throws(() => validate(r, q), /symbol_source_accounting/);
});

test('symbol validation obeys cancellation before exposing the joined capture', () => {
  let checkpoints = 0; const q = symbolInput(), r = nativeSymbols(q);
  assert.throws(() => validate(r, q, () => { if (++checkpoints === 7) throw new Error('stop-symbol-read'); }), /stop-symbol-read/);
  assert.equal(checkpoints, 7);
});
