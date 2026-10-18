import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { continueCapture } from '../../scripts/operator/source_context_continue.mjs';
import { loadBundle, inspectBundle, publishBundle, readPrivate } from '../../scripts/operator/source_context_export.mjs';
import { fixture, input, TOKEN } from './source_context_continue_fixtures.mjs';
import { hex } from './source_context_fixtures.mjs';
import { symbolInput } from './source_context_symbols_fixtures.mjs';
const follow = (f, delta = { terms: ['untrusted'] }, options = {}) =>
  continueCapture(f.bundle, f.receipt.manifest_sha256, TOKEN, delta, options);

for (const format of ['sha1', 'sha256']) test(`${format}: follow-up inherits source and checkpoints, never rewrites its parent`, async t => {
  const f = await fixture(t, input(format, { prefixes_hex: [hex('src')] }));
  const { capture, continued_from } = await follow(f);
  assert.equal(f.p.calls.length, 1);
  const form = new URLSearchParams(f.p.calls[0].body);
  assert.equal(form.get('expected_head'), f.capture.summary.source.snapshot_token);
  assert.equal(form.get('expected_commit'), f.capture.summary.source.source_commit);
  assert.equal(form.get('minimum_lexical_token'), f.capture.summary.lexical_checkpoint.token);
  assert.equal(form.get('minimum_lexical_number'), '7');
  assert.deepEqual(form.getAll('term_hex'), [hex('untrusted')]);
  assert.deepEqual(form.getAll('path_prefix_hex'), [hex('src')]);
  assert.equal(f.p.calls[0].headers['idempotency-key'], undefined);
  assert.deepEqual(capture.summary.source, f.capture.summary.source);
  assert.equal(capture.summary.returned_files, 1);
  assert.equal(continued_from.manifest_sha256, f.receipt.manifest_sha256);
  const saved = await publishBundle(join(f.root, 'child'), capture);
  assert.equal((await inspectBundle(saved.bundle, saved.manifest_sha256)).complete, true);
  assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('load and inspect share one pinned read; returned capture is detached from subsequent disk changes', async t => {
  const f = await fixture(t), loaded = await loadBundle(f.bundle, f.receipt.manifest_sha256);
  assert.deepEqual(loaded.receipt, await inspectBundle(f.bundle, f.receipt.manifest_sha256));
  await writeFile(join(f.bundle, 'capture.json'), '{}');
  assert.deepEqual(loaded.capture, f.capture);
  await assert.rejects(follow(f), /payload_changed/); assert.equal(f.p.calls.length, 0);
});

for (const key of ['scope', 'reference', 'endpoint', 'expected_head', 'expected_commit', 'minimum_lexical', 'minimum_symbol', 'force', 'after']) {
  test(`follow-up cannot override inherited control: ${key}`, async t => {
    const f = await fixture(t);
    await assert.rejects(follow(f, { terms: ['recover'], [key]: 'override' }), /followup_fields/);
    assert.equal(f.p.calls.length, 0);
  });
}
for (const prefix of [[], [hex('src2')], [hex('s')], [hex('src/private'), hex('elsewhere')]]) {
  test(`component-bounded path scope cannot widen: ${JSON.stringify(prefix)}`, async t => {
    const f = await fixture(t, input('sha1', { prefixes_hex: [hex('src')] }));
    await assert.rejects(follow(f, { terms: ['recover'], prefixes_hex: prefix }), /scope_widened/);
    assert.equal(f.p.calls.length, 0);
    assert.equal((await follow(f, { terms: ['recover'], prefixes_hex: [hex('src/recover.rs')] })).capture.summary.returned_files, 1);
  });
}

test('raw non-UTF-8 scopes narrow by slash-delimited bytes, not text normalization', async t => {
  const files = [{ path: Buffer.from('ff2f7265636f766572', 'hex'), bytes: Buffer.from('recover untrusted') }];
  const f = await fixture(t, input('sha256', { prefixes_hex: ['ff'] }), { files });
  assert.equal((await follow(f, { terms: ['untrusted'], prefixes_hex: ['ff2f7265636f766572'] })).capture.summary.returned_files, 1);
  await assert.rejects(follow(f, { terms: ['recover'], prefixes_hex: ['ff00'] }));
  await assert.rejects(follow(f, { terms: ['recover'], prefixes_hex: ['ffff'] }), /scope_widened/);
});

const envelopes = { max_results_per_channel: 2, max_work: 1000, max_payload_bytes: 1000,
  max_result_bytes: 1000, context_max_files: 1, context_radius_bytes: 1, context_max_source_bytes: 100, context_max_excerpt_bytes: 100 };
for (const [name, value] of Object.entries(envelopes)) test(`follow-up cannot renew a wider ${name} allowance`, async t => {
  const f = await fixture(t, input('sha1', { limits: envelopes }));
  await assert.rejects(follow(f, { terms: ['recover'], limits: { [name]: value + 1 } }), /budget_widened/);
  assert.equal(f.p.calls.length, 0);
  const success = await follow(f, { terms: ['recover'], limits: { [name]: value } });
  assert.equal(success.capture.summary.query.limits[name], value);
});

test('strongest observed lexical checkpoint is retained exactly beyond 2^53', async t => {
  const number = '9007199254740993', token = `alg:2:${'f'.repeat(64)}`;
  const f = await fixture(t, input(), { decorate: raw => {
    raw.retrieval.path.selected_index_number = number; raw.retrieval.path.selected_index_token = token; return raw;
  } });
  f.state.decorate = raw => {
    for (const c of [raw.retrieval.content, raw.retrieval.path]) {
      c.index_number = c.selected_index_number = number; c.index_token = c.selected_index_token = token;
    }
    raw.retrieval.generation_vector.lexical = { index_token: token, index_number: number }; return raw;
  };
  const { capture } = await follow(f);
  const fields = new URLSearchParams(f.p.calls[0].body);
  assert.equal(fields.get('minimum_lexical_number'), number); assert.equal(fields.get('minimum_lexical_token'), token);
  assert.equal(capture.summary.lexical_checkpoint.number, number);
  f.state.decorate = raw => raw;
  await assert.rejects(follow(f), /checkpoint_regressed/);
});

test('available optional symbols acquire an independent retained floor on follow-up', async t => {
  const f = await fixture(t, symbolInput('sha256', { symbols: { name: 'Recover', match: 'prefix', policy: 'optional' } }));
  const result = await follow(f, { terms: ['data'], symbols: { name: 'RecoverRaw', match: 'exact' } });
  const fields = new URLSearchParams(f.p.calls[0].body);
  assert.equal(fields.get('minimum_symbol_number'), '4');
  assert.equal(fields.get('minimum_symbol_token'), f.capture.summary.symbols.generation.token);
  assert.equal(result.continued_from.symbol_checkpoint.number, '4');
  assert.equal(result.capture.summary.symbols.state, 'available');
  f.state.decorate = raw => { raw.retrieval.symbols = { state: 'unavailable', reason: 'stale', result: null };
    raw.retrieval.generation_vector.symbols = null; return raw; };
  await assert.rejects(follow(f), /unavailable_not_permitted/);
});

test('required symbol policy cannot weaken, while an explicit new name preserves the policy', async t => {
  const f = await fixture(t, symbolInput());
  await assert.rejects(follow(f, { terms: ['recover'], symbols: { policy: 'optional' } }), /symbols_weakened/);
  assert.equal(f.p.calls.length, 0);
  const result = await follow(f, { terms: ['recover'], symbols: { name: 'RecoverRaw' } });
  assert.equal(result.capture.summary.query.symbols.policy, 'required');
  assert.equal(result.capture.summary.query.symbols.name, 'RecoverRaw');
});

for (const field of ['root_tree', 'source_rcr']) test(`matching head/commit cannot conceal changed ${field}`, async t => {
  const f = await fixture(t);
  f.state.decorate = raw => {
    for (const r of [raw.retrieval, raw.retrieval.content, raw.retrieval.path]) r[field] = field === 'root_tree' ? 'f'.repeat(40) : 'other-rcr';
    return raw;
  };
  await assert.rejects(follow(f), /followup_source_changed/);
  assert.equal(f.p.calls.length, 1); assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('source movement is refused without retry or replacement of the original capture', async t => {
  const f = await fixture(t);
  f.state.decorate = raw => {
    for (const r of [raw.retrieval, raw.retrieval.content, raw.retrieval.path]) r.snapshot_token = `alg:2:${'f'.repeat(64)}`;
    return raw;
  };
  await assert.rejects(follow(f), /snapshot_changed/); assert.equal(f.p.calls.length, 1);
  assert.deepEqual(await f.readParent(), f.originalBytes);
});

for (const status of [301, 401, 403, 409, 413, 503]) test(`follow-up HTTP ${status} makes one read and preserves evidence`, async t => {
  const f = await fixture(t); f.state.status = status;
  await assert.rejects(follow(f), e => e.status === status);
  assert.equal(f.p.calls.length, 1); assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('corrupt independently pinned manifest is refused before a connection', async t => {
  const f = await fixture(t);
  await assert.rejects(continueCapture(f.bundle, 'f'.repeat(64), TOKEN, { terms: ['recover'] }), /manifest_integrity/);
  await writeFile(join(f.bundle, 'context.txt'), 'changed');
  await assert.rejects(follow(f), /payload_changed/); assert.equal(f.p.calls.length, 0);
});

test('bounded caller-owned follow-up is copied before asynchronous bundle verification', async t => {
  const f = await fixture(t), delta = { terms: ['recover'], prefixes_hex: [hex('src')], limits: { context_max_files: 1 } };
  const running = follow(f, delta); delta.terms[0] = 'secret'; delta.prefixes_hex.length = 0; delta.limits.context_max_files = 32;
  const result = await running;
  assert.deepEqual(result.capture.summary.query.terms, ['recover']);
  assert.deepEqual(result.capture.summary.query.prefixes_hex, [hex('src')]);
  assert.equal(result.capture.summary.query.limits.context_max_files, 1);
});

test('further continuations retain the immediately previous narrowed scope and limits', async t => {
  const f = await fixture(t), first = await follow(f, { terms: ['recover'], prefixes_hex: [hex('src')], limits: { context_max_files: 1 } });
  const child = await publishBundle(join(f.root, 'child'), first.capture);
  await assert.rejects(continueCapture(child.bundle, child.manifest_sha256, TOKEN, { terms: ['recover'], prefixes_hex: [] }), /scope_widened/);
  await assert.rejects(continueCapture(child.bundle, child.manifest_sha256, TOKEN, { terms: ['recover'], limits: { context_max_files: 2 } }), /budget_widened/);
  assert.equal(f.p.calls.length, 1);
});

test('cancellation before and during file reads is observed without leaking a partial capture', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(follow(f, undefined, { signal: stop.signal })); assert.equal(f.p.calls.length, 0);
  const path = join(f.root, 'bounded'); await writeFile(path, Buffer.alloc(150000), { mode: 0o600 });
  let probes = 0;
  await assert.rejects(readPrivate(path, 200000, () => { if (++probes === 4) throw new Error('stop-file-read'); }), /stop-file-read/);
  assert.equal((await readPrivate(path, 200000)).length, 150000);
  assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('network cancellation drains the single follow-up connection', async t => {
  const f = await fixture(t); f.state.hang = true;
  const ready = new Promise(resolve => { f.state.started = resolve; });
  const stop = new AbortController(), pending = follow(f, undefined, { signal: stop.signal });
  await ready; stop.abort(); await assert.rejects(pending, /cancelled/);
  assert.equal(f.p.calls.length, 1);
});

test('one remaining deadline bounds bundle verification plus network work', async t => {
  const f = await fixture(t); f.state.hang = true;
  await assert.rejects(follow(f, undefined, { timeoutMs: 100 }), /deadline/);
  assert.ok(f.p.calls.length <= 1); assert.deepEqual(await f.readParent(), f.originalBytes);
});

for (const delta of [null, {}, { terms: [] }, { terms: ['a.*'] }, { terms: ['a'.repeat(129)] },
  { terms: ['a'], symbols: null }, { terms: ['a'], symbols: { kinds: Array(9).fill('function') } },
  { terms: ['a'], limits: { max_work: -1 } }, { terms: ['a'], limits: { other: 1 } }, { terms: ['a'], prefixes_hex: [hex('../outside')] }]) {
  test(`malformed follow-up refuses before network: ${JSON.stringify(delta)}`, async t => {
    const f = await fixture(t); await assert.rejects(follow(f, delta)); assert.equal(f.p.calls.length, 0);
  });
}

test('an originally unavailable optional symbol channel may initialize at the same source without inventing a floor', async t => {
  const { nativeSymbols } = await import('./source_context_symbols_fixtures.mjs');
  const f = await fixture(t, symbolInput('sha1', { symbols: { name: 'Recover', match: 'prefix', policy: 'optional' } }),
    { decorate: (_raw, q) => nativeSymbols(q, undefined, undefined, 'uninitialized') });
  assert.equal(f.capture.summary.complete, false);
  f.state.decorate = raw => raw;
  const { capture } = await follow(f, { terms: ['recover'] });
  assert.equal(new URLSearchParams(f.p.calls[0].body).has('minimum_symbol_token'), false);
  assert.equal(capture.summary.symbols.state, 'available');
  assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('ranked continuations preserve the profile and independently revalidate the new query ranking', async t => {
  const { RANKING_PROFILE } = await import('../../scripts/operator/source_context.mjs');
  const { FILES, DECLARATIONS } = await import('./source_context_symbols_fixtures.mjs');
  const f = await fixture(t, symbolInput('sha256', { selection: RANKING_PROFILE }), {
    files: [FILES[0]], declarations: DECLARATIONS.slice(0, 2), decorate: raw => {
      const r = raw.retrieval, contributions = [];
      // This fixture has exactly one candidate: each present channel is rank 1.
      if (r.content.hits.length) contributions.push({ channel: 'content', document_rank: 1, weight: 1, score_q16: 1074 });
      if (r.path.hits.length) contributions.push({ channel: 'path', document_rank: 1, weight: 1, score_q16: 1074 });
      contributions.push({ channel: 'symbol', document_rank: 1, weight: 2, score_q16: 2148 });
      raw.selection = RANKING_PROFILE;
      raw.ranking = { profile: RANKING_PROFILE, rank_constant: 60, score_scale: 65536,
        input_order: 'raw-path-distinct-documents', tie_break: 'raw-path-ascending', ranked_over: 'returned-channel-hits',
        semantic_relevance: false, selected: [{ position: 1, path_hex: raw.files[0].path_hex, blob: raw.files[0].blob,
          score_q16: contributions.reduce((n, c) => n + c.score_q16, 0), contributions }] };
      return raw;
    },
  });
  assert.equal(f.capture.summary.ranking.selected[0].score_q16, 4296);
  const { capture } = await follow(f, { terms: ['pub'] });
  assert.equal(new URLSearchParams(f.p.calls[0].body).get('context_selection'), RANKING_PROFILE);
  assert.equal(capture.summary.ranking.selected[0].score_q16, 3222);
  const saved = await publishBundle(join(f.root, 'ranked-next'), capture);
  assert.equal((await inspectBundle(saved.bundle, saved.manifest_sha256)).selection, RANKING_PROFILE);
});

test('completeness is per query; a useful new answer does not rewrite the earlier truncated result', async t => {
  const files = [{ path: Buffer.from('a'), bytes: Buffer.from('recover alpha') }, { path: Buffer.from('b'), bytes: Buffer.from('recover beta') }];
  const f = await fixture(t, input('sha1', { limits: { max_results_per_channel: 1 } }), { files });
  assert.equal(f.capture.summary.complete, false);
  const { capture } = await follow(f, { terms: ['beta'] });
  assert.equal(capture.summary.complete, true);
  assert.equal(capture.native_response.files[0].path_hex, hex('b'));
  assert.equal((await inspectBundle(f.bundle, f.receipt.manifest_sha256)).complete, false);
  assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('a follow-up takes a fresh explicit read credential and never recovers one from captured source', async t => {
  const f = await fixture(t), credential = '8'.repeat(64);
  const result = await continueCapture(f.bundle, f.receipt.manifest_sha256, credential, { terms: ['recover'] });
  assert.equal(f.p.calls[0].headers.authorization, `Bearer ${credential}`);
  assert.ok(!JSON.stringify(result).includes(credential));
  assert.deepEqual(await f.readParent(), f.originalBytes);
});
