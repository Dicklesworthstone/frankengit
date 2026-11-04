// Real client parsing, validation and HTTP requests against explicit schema
// peers. These tests do not authenticate a Rust grant, index or label digest.
import test from 'node:test';
import assert from 'node:assert/strict';
import { acquire, command, query, validate, parse, RANKING_PROFILE } from '../../scripts/operator/source_context.mjs';
import { contextProvenance, CURRENT_INDEX_SOURCE } from '../../scripts/operator/source_context_provenance.mjs';
import { input, report, peer, json, TOKEN, withReadLabels } from './source_context_fixtures.mjs';
import { symbolInput, nativeSymbols } from './source_context_symbols_fixtures.mjs';
import { withRevalidatedSources } from './source_context_revalidated_fixtures.mjs';

const current = (q = input()) => ({ ...q, index_source: CURRENT_INDEX_SOURCE });
const stamp = digit => `alg:2:${digit.repeat(64)}`;

test('current-source selection is explicit, closed and incompatible with ranked context', () => {
  const strict = input(), fields = command(strict);
  assert.equal(fields.body, 'object_format=sha1&ref=refs%2Fheads%2Fmain&max_results_per_channel=100&max_work=16777216&max_payload_bytes=33554432&max_result_bytes=2097152&context_max_files=8&context_radius_bytes=128&context_max_source_bytes=67108864&context_max_excerpt_bytes=262144&term_hex=7265636f766572');
  assert.equal(Object.hasOwn(fields.query, 'index_source'), false);
  const selected = command(current(strict));
  assert.equal(selected.query.index_source, CURRENT_INDEX_SOURCE);
  const form = new URLSearchParams(selected.body);
  assert.deepEqual(form.getAll('index_source'), [CURRENT_INDEX_SOURCE]);
  form.delete('index_source'); assert.equal(form.toString(), fields.body);
  for (const index_source of [null, undefined, '', 'strict', 'current', 'CURRENT-NATIVE-V1', 'current-native-v2', 1, true, {}, []]) {
    assert.throws(() => query({ ...strict, index_source }), { code: 'unsupported_index_source' });
  }
  assert.equal(query({ ...strict, selection: RANKING_PROFILE }).selection, RANKING_PROFILE);
  assert.throws(() => query({ ...current(strict), selection: RANKING_PROFILE }), { code: 'unsupported_context_selection' });
  assert.equal(query({ ...current(strict), selection: 'raw-path-prefix' }).selection, 'raw-path-prefix');
});

for (const format of ['sha1', 'sha256']) {
  for (const includeSymbols of [false, true]) {
    test(`${format}: one current read preserves ${includeSymbols ? 'three independently positioned' : 'both lexical'} channels and exact source`, async t => {
      const base = includeSymbols ? symbolInput(format) : input(format), q = current(base);
      const strict = withReadLabels(includeSymbols ? nativeSymbols(base) : report(base)), savedStrict = JSON.stringify(strict);
      const raw = withRevalidatedSources(strict), original = structuredClone(raw);
      q.expected_head = raw.retrieval.current_source.snapshot_token;
      q.expected_commit = raw.retrieval.current_source.source_commit;
      q.minimum_lexical = { token: raw.retrieval.generation_vector.lexical.index_token, number: '7' };
      if (includeSymbols) q.minimum_symbol = { token: raw.retrieval.generation_vector.symbols.index_token, number: '4' };
      const p = await peer(t, (_req, res) => json(res, raw));
      const captured = await acquire(p.endpoint, TOKEN, q), summary = captured.summary, r = raw.retrieval;
      assert.equal(p.calls.length, 1);
      const form = new URLSearchParams(p.calls[0].body);
      assert.equal(form.get('index_source'), CURRENT_INDEX_SOURCE);
      assert.equal(form.get('expected_head'), r.current_source.snapshot_token);
      assert.equal(p.calls[0].url, '/team/repo.git/api/v1/source/context-initial');
      assert.equal(p.calls[0].headers['idempotency-key'], undefined);
      assert.equal(p.calls[0].headers.authorization, `Bearer ${TOKEN}`);
      assert.equal(summary.index_source, CURRENT_INDEX_SOURCE);
      assert.equal(summary.source.snapshot_token, stamp('f'));
      assert.equal(summary.source.source_commit, r.current_source.source_commit.slice(format.length + 1));
      assert.deepEqual(summary.current_source, r.current_source);
      assert.deepEqual(summary.index_sources, r.index_sources);
      assert.notEqual(summary.source.snapshot_token, summary.index_sources.lexical.snapshot_token);
      assert.equal(summary.index_sources.lexical.snapshot_token, r.content.snapshot_token);
      assert.equal(summary.index_sources.lexical.source_head, r.path.source_head);
      assert.equal(summary.lexical_generation.token, strict.retrieval.generation_vector.lexical.index_token);
      if (includeSymbols) {
        assert.notEqual(summary.index_sources.symbols.snapshot_token, summary.index_sources.lexical.snapshot_token);
        assert.notEqual(summary.index_sources.symbols.snapshot_token, summary.source.snapshot_token);
        assert.equal(summary.symbols.generation.token, strict.retrieval.generation_vector.symbols.index_token);
      } else assert.equal(summary.index_sources.symbols, null);
      assert.deepEqual(captured.native_response.files, strict.files);
      assert.deepEqual(summary.full_blob_hash_verified_paths, strict.files.map(f => f.path_hex));
      assert.equal(summary.lineage_metadata_bytes, strict.lineage_metadata_bytes);
      assert.equal(summary.authorization.binding, strict.retrieval.authorization.binding);
      assert.equal(summary.authorization.reusable_capability, false);
      assert.equal(summary.authority_verified, false); assert.equal(summary.agent_context_packet, false);
      assert.ok(!JSON.stringify(captured).includes(TOKEN));
      assert.deepEqual(raw, original); assert.equal(JSON.stringify(strict), savedStrict);
      summary.current_source.source_rcr = 'mutated-copy'; summary.index_sources.lexical.ref = 'refs/heads/other';
      assert.deepEqual(raw, original, 'normalized provenance must not alias response-owned objects');
    });
  }

  test(`${format}: unavailable optional symbols remain incomplete and cannot erase an observed floor`, () => {
    const q = current(symbolInput(format, { symbols: { name: 'Recover', policy: 'optional' } }));
    for (const reason of ['uninitialized', 'stale']) {
      const raw = withRevalidatedSources(nativeSymbols(q, undefined, undefined, reason));
      const checked = validate(raw, q);
      assert.equal(checked.index_sources.symbols, null);
      assert.equal(checked.symbols.state, 'unavailable'); assert.equal(checked.symbols.reason, reason);
      assert.equal(checked.complete, false);
      assert.throws(() => validate(raw, { ...q, minimum_symbol: { token: stamp('e'), number: '4' } }), /symbol_unavailable/);
      assert.throws(() => validate(raw, { ...q, symbols: { ...q.symbols, policy: 'required' } }), /symbol_unavailable/);
    }
  });

  test(`${format}: current-source provenance refuses inconsistent namespace, native identity or original positions`, () => {
    const q = current(symbolInput(format)), original = withRevalidatedSources(nativeSymbols(q));
    validate(original, q);
    const changes = [
      r => { r.profile = 'source-initial-context-v1'; },
      r => { delete r.index_source; },
      r => { r.index_source = 'current-native-v2'; },
      r => { r.retrieval.profile = 'source-initial-retrieval-v1'; },
      r => { delete r.retrieval.index_source; },
      r => { delete r.retrieval.current_source; },
      r => { r.retrieval.current_source.extra = 'unrequested'; },
      r => { r.retrieval.current_source.snapshot_token = stamp('5'); },
      r => { r.retrieval.current_source.source_head = r.retrieval.index_sources.lexical.source_head; },
      r => { r.retrieval.current_source.repository_incarnation = '4'.repeat(32); },
      r => { r.retrieval.current_source.source_rcr = 'different-current-rcr'; },
      r => { r.retrieval.current_source.forge_position_root = 'not-a-digest'; },
      r => { r.retrieval.current_source.source_commit = `${format}:${'4'.repeat(format === 'sha1' ? 40 : 64)}`; },
      r => { r.retrieval.index_sources.lexical.source_commit = `${format}:${'5'.repeat(format === 'sha1' ? 40 : 64)}`; },
      r => { r.retrieval.index_sources.lexical.root_tree = `${format}:${'4'.repeat(format === 'sha1' ? 40 : 64)}`; },
      r => { r.retrieval.index_sources.lexical.ref_hex = Buffer.from('refs/heads/other').toString('hex'); },
      r => { r.retrieval.index_sources.lexical.source_rcr = 'different-index-rcr'; },
      r => { r.retrieval.path.snapshot_token = r.retrieval.current_source.snapshot_token; },
      r => { r.retrieval.content.source_head = r.retrieval.current_source.source_head; },
      r => { r.retrieval.index_sources.symbols = null; },
      r => { r.retrieval.index_sources.symbols.tenant_id = '4'.repeat(32); },
      r => { r.retrieval.symbols.result.snapshot_token = r.retrieval.index_sources.lexical.snapshot_token; },
      r => { r.retrieval.content.published = true; },
      r => { r.retrieval.symbols.result.read_only = false; },
      r => { r.retrieval.published = true; },
      r => { r.transaction_created = true; },
      r => { r.selection = RANKING_PROFILE; },
      r => { r.ranking = {}; },
    ];
    for (const change of changes) {
      const altered = structuredClone(original); change(altered);
      assert.throws(() => validate(altered, q), change.toString());
    }
    const sameHead = withRevalidatedSources(nativeSymbols(q), { lexicalDigit: 'f', symbolDigit: 'f' });
    validate(sameHead, q);
    for (const name of ['lexical', 'symbols']) {
      const altered = structuredClone(sameHead);
      altered.retrieval.index_sources[name].forge_position_root = stamp('5');
      assert.throws(() => validate(altered, q), { code: 'context_provenance_head_changed' });
    }
    assert.throws(() => validate(original, symbolInput(format)), { code: 'context_index_source_changed' });
    assert.throws(() => validate(withReadLabels(nativeSymbols(symbolInput(format))), q), { code: 'context_index_source_changed' });
  });
}

test('current metadata never renews the original label, lineage or successful-channel budgets', () => {
  const q = current(), raw = withRevalidatedSources(report(q));
  const exact = raw.retrieval.retained_result_bytes + raw.lineage_metadata_bytes;
  const permitted = current(input('sha1', { limits: { max_result_bytes: exact } }));
  validate(withRevalidatedSources(report(permitted)), permitted);
  const short = current(input('sha1', { limits: { max_result_bytes: exact - 1 } }));
  assert.throws(() => validate(withRevalidatedSources(report(short)), short), /lineage_accounting/);
  for (const change of [r => { delete r.retrieval.authorization; },
    r => { r.retrieval.content.hits[0].authorization_label = 'f'.repeat(64); },
    r => { r.files[0].anchors[0].authorization_label = 'f'.repeat(64); },
    r => { r.files[0].excerpts[0].lineage_commitment = 'f'.repeat(64); },
    r => { r.retrieval.content.work_units = q.limits?.max_work ?? 16777216; },
    r => { r.retrieval.path.payload_bytes_read = 33554432; },
    r => { r.retrieval.retained_result_bytes--; },
    r => { r.lineage_metadata_bytes--; },
    r => { r.files[0].excerpts[0].untrusted_bytes_hex = r.files[0].excerpts[0].untrusted_bytes_hex.replace('666e', '686e'); }]) {
    const altered = structuredClone(raw); change(altered); assert.throws(() => validate(altered, q));
  }
  let checkpoints = 0;
  assert.throws(() => validate(raw, q, () => { if (++checkpoints === 6) throw new Error('original request expired'); }), /original request expired/);
});

test('full-width generations survive current-source parsing without rounding or source relabelling', () => {
  const q = current(symbolInput()), raw = withRevalidatedSources(nativeSymbols(q));
  const maximum = '18446744073709551615';
  for (const channel of [raw.retrieval.content, raw.retrieval.path]) {
    channel.index_number = maximum; channel.selected_index_number = maximum;
  }
  raw.retrieval.generation_vector.lexical.index_number = maximum;
  raw.retrieval.generation_vector.symbols.index_number = maximum;
  raw.retrieval.symbols.result.index_number = maximum;
  const wire = JSON.stringify(raw).replaceAll(`"${maximum}"`, maximum);
  const summary = validate(parse(Buffer.from(wire)), q);
  assert.equal(summary.lexical_generation.number, maximum);
  assert.equal(summary.lexical_checkpoint.number, maximum);
  assert.equal(summary.symbols.generation.number, maximum);
  assert.equal(summary.index_sources.lexical.snapshot_token, stamp('c'));
});

test('legacy strict summaries and source-only projection inputs retain their original representation', () => {
  const raw = report(), before = JSON.stringify(raw), summary = validate(raw, input());
  assert.deepEqual(Object.keys(summary), ['query', 'source', 'lexical_generation', 'lexical_checkpoint', 'complete',
    'candidate_files', 'returned_files', 'omitted_files', 'full_blob_hash_verified_paths', 'partial_excerpts_hash_verified',
    'source_material_untrusted', 'agent_context_packet', 'authority_verified', 'source_bytes_read', 'excerpt_bytes']);
  assert.equal(Object.hasOwn(summary.query, 'index_source'), false);
  assert.equal(contextProvenance(raw), null);
  const minimal = structuredClone(raw);
  for (const key of ['content', 'path', 'symbols', 'generation_vector']) delete minimal.retrieval[key];
  assert.equal(contextProvenance(minimal), null, 'byte-proof callers own strict source-only validation');
  validate(withRevalidatedSources(raw), current());
  assert.equal(JSON.stringify(raw), before);
  assert.equal(JSON.stringify(validate(raw, input())), JSON.stringify(summary));
});

test('HTTP current-mode refusal performs one read with no strict fallback or index mutation', async t => {
  for (const status of [403, 409]) {
    const p = await peer(t, (_req, res) => { res.writeHead(status); res.end('source unavailable'); });
    await assert.rejects(acquire(p.endpoint, TOKEN, current()), { code: 'context_http_refused', status });
    assert.equal(p.calls.length, 1);
    assert.equal(new URLSearchParams(p.calls[0].body).get('index_source'), CURRENT_INDEX_SOURCE);
    assert.equal(p.calls[0].headers['idempotency-key'], undefined);
  }
});
