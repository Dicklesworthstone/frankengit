import test from 'node:test';
import assert from 'node:assert/strict';
import { acquire, command, query, validate, RANKING_PROFILE, sha256 } from '../../scripts/operator/source_context.mjs';
import { input, report, peer, json, TOKEN, defaults } from './source_context_fixtures.mjs';
import { symbolInput, nativeSymbols, assemble } from './source_context_symbols_fixtures.mjs';
import { PROFILE, CORPUS, DECLARATIONS, nativeRanked, oracle, rank, hex } from './source_context_ranking_fixtures.mjs';
const ranked = (format = 'sha1', patch = {}) => symbolInput(format, { selection: PROFILE, ...patch });

for (const format of ['sha1', 'sha256']) {
  test(`${format}: a tight context limit selects corroborated code rather than alphabetical noise`, async t => {
    const q = ranked(format, { limits: { context_max_files: 1 } }), r = nativeRanked(q);
    const p = await peer(t, (_req, res) => json(res, r));
    const captured = await acquire(p.endpoint, TOKEN, q), priority = captured.summary.ranking.selected;
    assert.equal(p.calls.length, 1); assert.equal(new URLSearchParams(p.calls[0].body).get('context_selection'), PROFILE);
    assert.equal(priority.length, 1); assert.equal(priority[0].path_hex, hex('z/Recover.rs'));
    assert.equal(priority[0].score_q16, 4279); assert.deepEqual(priority[0].contributions, [
      { channel: 'content', document_rank: 2, weight: 1, score_q16: 1057 },
      { channel: 'path', document_rank: 1, weight: 1, score_q16: 1074 },
      { channel: 'symbol', document_rank: 1, weight: 2, score_q16: 2148 },
    ]);
    assert.equal(captured.summary.complete, false); assert.equal(captured.summary.omitted_files, 1);
    assert.equal(captured.native_response.files[0].path_hex, priority[0].path_hex);
    assert.equal(captured.summary.authority_verified, false); assert.equal(captured.summary.ranking.semantic_relevance, false);
    assert.deepEqual(captured.summary.full_blob_hash_verified_paths, [hex('z/Recover.rs')]);
    assert.equal(JSON.stringify(captured).includes(TOKEN), false);
  });
  test(`${format}: ranking receipt order and source inventory order remain independent`, () => {
    const q = ranked(format), r = nativeRanked(q), checked = validate(r, q);
    assert.deepEqual(r.files.map(f => f.path_hex), CORPUS.map(f => hex(f.path)));
    assert.deepEqual(checked.ranking.selected.map(f => f.path_hex), CORPUS.toReversed().map(f => hex(f.path)));
    const vector = r.retrieval.generation_vector;
    assert.equal(checked.lexical_generation.token, vector.lexical.index_token);
    assert.equal(checked.symbols.generation.token, vector.symbols.index_token);
    assert.equal(checked.complete, true);
    const wrong = structuredClone(r); wrong.files.reverse(); assert.throws(() => validate(wrong, q));
  });
  test(`${format}: self-consistent scores and source for the wrong winner still fail`, () => {
    const q = ranked(format, { limits: { context_max_files: 1 } }), r = nativeRanked(q);
    const runnerUp = oracle(r.retrieval)[1];
    assemble(r, q, CORPUS, [runnerUp.path_hex]);
    r.ranking.selected = [{ position: 1, ...runnerUp }];
    assert.equal(runnerUp.score_q16, 1074);
    assert.equal(r.files[0].blob, runnerUp.blob);
    assert.throws(() => validate(r, q), /ranking_selection_changed/);
  });
}

test('selection grammar is explicit and immutable before any network I/O', async t => {
  assert.equal(RANKING_PROFILE, PROFILE);
  const p = await peer(t, (_req, res) => json(res, nativeRanked(ranked())));
  for (const selection of [null, false, [], {}, '', 'latest', 'semantic', 'raw-path', `${PROFILE} `])
    await assert.rejects(acquire(p.endpoint, TOKEN, ranked('sha1', { selection })));
  for (const patch of [{ weights: [1, 1, 99] }, { rank_constant: 1 }, { limits: { selection: PROFILE } }])
    await assert.rejects(acquire(p.endpoint, TOKEN, ranked('sha1', patch)));
  assert.equal(p.calls.length, 0);
  const q = ranked(), request = command(q), pending = acquire(p.endpoint, TOKEN, q);
  q.selection = 'raw-path-prefix';
  const captured = await pending;
  assert.equal(captured.summary.query.selection, PROFILE);
  assert.equal(captured.request_sha256, sha256(request.body)); assert.equal(p.calls.length, 1);
});

test('omitted and explicit raw selection keep native payloads, legacy summary and text semantics', () => {
  const q = input(), r = report(q), legacy = validate(r, q);
  assert.equal(Object.hasOwn(legacy.query, 'selection'), false); assert.equal(Object.hasOwn(legacy, 'ranking'), false);
  assert.equal(new URLSearchParams(command(q).body).has('context_selection'), false);
  const explicit = { ...q, selection: 'raw-path-prefix' }, selected = validate(r, explicit);
  assert.equal(new URLSearchParams(command(explicit).body).get('context_selection'), 'raw-path-prefix');
  delete selected.query.selection;
  assert.deepEqual(selected, legacy);
  const withRanking = structuredClone(r); withRanking.ranking = nativeRanked(ranked()).ranking;
  assert.throws(() => validate(withRanking, q), /unsupported_native_context/);
});

test('an opted-in rank query never accepts a silent raw-path fallback or missing receipt', () => {
  const q = ranked(), r = nativeRanked(q), raw = nativeSymbols(q, CORPUS, DECLARATIONS);
  assert.throws(() => validate(raw, q), /unsupported_native_context/);
  delete r.ranking;
  assert.throws(() => validate(r, q));
});

test('multiple declarations contribute once and do not shift the next distinct document rank', () => {
  const files = [CORPUS[1], { path: Buffer.from('zz.rs'), bytes: Buffer.from('fn RecoverLast() {}\n') }];
  const declarations = [...DECLARATIONS, { path: files[1].path, name: 'RecoverLast', at: 3 }];
  const q = ranked(), r = nativeRanked(q, files, declarations), checked = validate(r, q);
  const second = checked.ranking.selected.find(e => e.path_hex === hex('zz.rs'));
  assert.deepEqual(second.contributions, [{ channel: 'symbol', document_rank: 2, weight: 2, score_q16: 2114 }]);
  const first = checked.ranking.selected.find(e => e.path_hex === hex('z/Recover.rs'));
  assert.equal(first.contributions.filter(c => c.channel === 'symbol').length, 1);
  const bad = structuredClone(r); const changed = bad.ranking.selected.find(e => e.path_hex === second.path_hex);
  changed.score_q16 = 2080; changed.contributions[0].document_rank = 3; changed.contributions[0].score_q16 = 2080;
  assert.throws(() => validate(bad, q), /ranking_selection_changed/);
});

test('equal cross-channel scores use raw bytes, not locale or decoded Unicode', () => {
  const files = [
    { path: Buffer.from('802f66696c65', 'hex'), bytes: Buffer.from('recover') },
    { path: Buffer.from('ff2f7265636f766572', 'hex'), bytes: Buffer.from('nothing') },
  ];
  const q = input('sha256', { selection: PROFILE }), r = nativeRanked(q, files, []);
  const checked = validate(r, q);
  assert.deepEqual(checked.ranking.selected.map(s => s.score_q16), [1074, 1074]);
  assert.deepEqual(checked.ranking.selected.map(s => s.path_hex), files.map(f => hex(f.path)));
  const reversed = structuredClone(r); reversed.ranking.selected.reverse(); reversed.ranking.selected.forEach((s, i) => s.position = i + 1);
  assert.throws(() => validate(reversed, q), /ranking_selection_changed/);
});

for (const reason of ['uninitialized', 'stale']) test(`ranking cannot hide optional symbol ${reason} or manufacture its contribution`, () => {
  const q = ranked('sha1', { symbols: { name: 'Recover', policy: 'optional' } });
  const r = nativeRanked(q, CORPUS, DECLARATIONS, reason), checked = validate(r, q);
  assert.equal(checked.complete, false); assert.equal(checked.symbols.reason, reason);
  assert.ok(checked.ranking.selected.every(r => r.contributions.every(c => c.channel !== 'symbol')));
  const fake = structuredClone(r); fake.ranking.selected[0].contributions.push({ channel: 'symbol', document_rank: 1, weight: 2, score_q16: 2148 });
  fake.ranking.selected[0].score_q16 += 2148;
  assert.throws(() => validate(fake, q), /ranking_selection_changed/);
});

test('empty returned candidates have an explicit empty ranking, not an unavailable channel', () => {
  for (const q of [input('sha1', { terms: ['missing'], selection: PROFILE }),
    ranked('sha256', { terms: ['missing'], symbols: { name: 'Missing', policy: 'required' } })]) {
    const r = nativeRanked(q), checked = validate(r, q);
    assert.equal(checked.complete, true); assert.deepEqual(checked.ranking.selected, []); assert.equal(checked.returned_files, 0);
    if (q.symbols) assert.equal(checked.symbols.state, 'available');
  }
});

test('scoped rankings use only scoped hits and retain the exact source and independent floors', async t => {
  const q = ranked('sha256', { prefixes_hex: [hex('z')], minimum_symbol: { token: `alg:2:${'e'.repeat(64)}`, number: '4' } });
  const r = nativeRanked(q), p = await peer(t, (_req, res) => json(res, r));
  const capture = await acquire(p.endpoint, TOKEN, q);
  assert.equal(capture.summary.candidate_files, 1); assert.equal(capture.summary.ranking.selected[0].score_q16, 4296);
  assert.ok(capture.summary.ranking.selected[0].contributions.every(c => c.document_rank === 1));
  const fields = new URLSearchParams(p.calls[0].body); assert.deepEqual(fields.getAll('path_prefix_hex'), [hex('z')]);
  assert.equal(fields.get('minimum_symbol_number'), '4');
  assert.throws(() => validate(r, { ...q, minimum_symbol: { ...q.minimum_symbol, number: '5' } }), /checkpoint_regressed/);
});

test('upstream truncation and source omissions cannot turn a ranking into complete coverage', () => {
  const q = ranked('sha1', { limits: { max_results_per_channel: 1 } }), r = nativeRanked(q), checked = validate(r, q);
  assert.equal(checked.complete, false); assert.equal(checked.omitted_files, 0);
  assert.equal(checked.ranking.ranked_over, 'returned-channel-hits');
  const other = ranked(), omitted = nativeRanked(other), rows = [
    { path_hex: hex('large.bin'), blob: 'f'.repeat(40), source_bytes: 20, reason: 'file_bytes', limit: 10 },
  ];
  for (const c of [omitted.retrieval.content, omitted.retrieval.path]) Object.assign(c, {
    schema_version: 2, index_profile: 'ascii-word-postings-omissions-v1', coverage_complete: false,
    omitted_files: 1, omitted_source_bytes: 20, omissions: structuredClone(rows),
  });
  rank(omitted, other, CORPUS);
  assert.equal(validate(omitted, other).complete, false);
  omitted.complete = omitted.retrieval.complete = true; assert.throws(() => validate(omitted, other));
});

const corruptions = {
  profile: r => r.profile = 'semantic-v1', constant: r => r.rank_constant++, scale: r => r.score_scale++,
  input_order: r => r.input_order = 'bm25', tie: r => r.tie_break = 'locale', scope: r => r.ranked_over = 'whole-repository',
  semantic: r => r.semantic_relevance = true, missing: r => r.selected.pop(), duplicate: r => r.selected.push(r.selected[0]),
  position: r => r.selected[0].position = 0, score: r => r.selected[0].score_q16++, blob: r => r.selected[0].blob = 'f'.repeat(40),
  path: r => r.selected[0].path_hex = hex('not-a-candidate'), weights: r => r.selected[0].contributions[0].weight++,
  channel: r => r.selected[0].contributions[0].channel = 'graph', rank: r => r.selected[0].contributions[0].document_rank++,
  contribution: r => r.selected[0].contributions[0].score_q16++, reordered: r => r.selected[0].contributions.reverse(),
  missing_contribution: r => r.selected[0].contributions.pop(), extra: r => r.authorized = true,
  row_extra: r => r.selected[0].trusted = true, contribution_extra: r => r.selected[0].contributions[0].authorized = true,
};
for (const [name, corrupt] of Object.entries(corruptions)) test(`rank receipt tampering rejects whole response: ${name}`, () => {
  const q = ranked(), r = nativeRanked(q); corrupt(r.ranking); assert.throws(() => validate(r, q));
});

test('rank witnesses are copied and canonicalized independently of wire property order', () => {
  const q = ranked(), r = nativeRanked(q);
  const reverse = x => Object.fromEntries(Object.entries(x).reverse());
  r.ranking.selected = r.ranking.selected.map(row => reverse({ ...row, contributions: row.contributions.map(reverse) }));
  const checked = validate(r, q); r.ranking.selected[0].score_q16 = 1;
  assert.equal(checked.ranking.selected[0].score_q16, 4279); assert.equal(checked.ranking.selected[0].contributions[0].document_rank, 2);
});

test('exact excerpt/source bounds remain mandatory for the ranked winner and cannot trigger substitution', () => {
  const q = ranked('sha1', { limits: { context_max_files: 1, context_max_source_bytes: CORPUS[1].bytes.length,
    context_max_excerpt_bytes: CORPUS[1].bytes.length } });
  assert.equal(validate(nativeRanked(q), q).returned_files, 1);
  for (const field of ['context_max_source_bytes', 'context_max_excerpt_bytes']) {
    const smaller = { ...q, limits: { ...q.limits, [field]: q.limits[field] - 1 } };
    assert.throws(() => validate(nativeRanked(smaller), smaller));
  }
});

test('a refused ranked request is not reissued with raw selection or wider budgets', async t => {
  const p = await peer(t, (_req, res) => { res.writeHead(413); res.end('winner exceeds source budget'); });
  await assert.rejects(acquire(p.endpoint, TOKEN, ranked()), e => e.status === 413);
  assert.equal(p.calls.length, 1); assert.equal(new URLSearchParams(p.calls[0].body).get('context_selection'), PROFILE);
});

test('cancellation probes cover score construction, comparison and receipt validation', () => {
  const q = ranked(), r = nativeRanked(q);
  let all = 0; validate(r, q, () => { all++; });
  for (let stop = 1; stop <= all; stop++) {
    let probes = 0;
    assert.throws(() => validate(r, q, () => { if (++probes === stop) throw new Error('rank-stopped'); }), /rank-stopped/);
    assert.equal(probes, stop);
  }
});
