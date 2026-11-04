import test from 'node:test';
import assert from 'node:assert/strict';
import { captureSourcePackage, inspectSourcePackage } from '../operator/source_package.mjs';
import { fixture, peer, TOKEN, sha256 } from './source_package_fixture.mjs';
import { revalidatedProjection } from '../../tests/operator/source_context_revalidated_projection_fixtures.mjs';

async function currentFixture(t, format = 'sha1', alter) {
  const f = fixture(format), snapshot = `alg:2:${'d'.repeat(64)}`;
  f.envelope.snapshot_token = snapshot; f.context.retrieval.snapshot_token = snapshot;
  f.context = revalidatedProjection(f.context, { symbols: true });
  f.envelope.source_head = f.context.retrieval.current_source.source_head;
  return peer(t, f, alter);
}
const capture = (p, options = {}) => captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, TOKEN, options);
const inspect = (p, result, options = {}) => inspectSourcePackage(result.bytes, sha256(result.bytes),
  p.context, p.contextHash, p.selected, p.expected, options);
function update(p, mutate) {
  const value = JSON.parse(p.context); mutate(value.native_response ?? value);
  p.context = Buffer.from(JSON.stringify(value)); p.contextHash = sha256(p.context);
}

for (const format of ['sha1', 'sha256']) for (const wrapped of [false, true]) {
  test(`${format}: ${wrapped ? 'saved capture' : 'raw current context'} acquires current bytes and replays offline`, async t => {
    const p = await currentFixture(t, format);
    if (!wrapped) { p.context = Buffer.from(JSON.stringify(p.f.context)); p.contextHash = sha256(p.context); }
    const original = Buffer.from(p.context), result = await capture(p), network = p.requests.length;
    const replay = await inspect(p, result);
    assert.deepEqual(replay, result.receipt); assert.equal(p.requests.length, network);
    assert.deepEqual(p.context, original); assert.equal(replay.verified.commit, p.f.commitId);
    assert.equal(replay.context_excerpt_bytes_verified, true); assert.equal(replay.search_evidence_verified, false);
    for (const name of ['authorityVerified', 'freshnessVerified', 'signatureVerified', 'searchCoverageVerified']) {
      assert.equal(replay.verified[name], false);
    }
    assert.equal(replay.remote_mutation_attempted, false); assert.equal(replay.source_executed, false);
    for (const { form } of p.requests) {
      assert.equal(form.get('expected_head'), p.f.envelope.snapshot_token);
      assert.equal(form.get('expected_commit'), p.f.commitId);
    }
    for (const text of ['fixture-lexical-rcr', 'fixture-symbol-rcr', 'index_sources', 'generation', p.selected.endpoint, TOKEN]) {
      assert.equal(result.bytes.includes(Buffer.from(text)), false);
    }
    assert.deepEqual((await capture(p)).bytes, result.bytes);
  });
}

test('a different original index observation never changes source package bytes or authenticates search', async t => {
  const p = await currentFixture(t), before = await capture(p);
  update(p, c => {
    for (const row of [c.retrieval.index_sources.lexical, c.retrieval.content, c.retrieval.path]) row.source_rcr = 'another-original-rcr';
  });
  const after = await capture(p);
  assert.deepEqual(after.bytes, before.bytes);
  assert.notEqual(after.receipt.context_sha256, before.receipt.context_sha256);
  assert.equal(after.receipt.search_evidence_verified, false);
});

test('current package pins cannot be replaced by original indexed source or independent selection claims', async t => {
  const p = await currentFixture(t), selected = p.selected;
  for (const replacement of [
    { ...selected, expected_head: p.f.context.retrieval.index_sources.lexical.snapshot_token },
    { ...selected, expected_commit: 'e'.repeat(40) },
    { ...selected, repository_incarnation: '4'.repeat(32) },
    { ...selected, ref: 'refs/heads/other' },
  ]) {
    p.selected = replacement; await assert.rejects(capture(p));
  }
  p.selected = selected;
  p.expected.files[0].blob = 'e'.repeat(40); await assert.rejects(capture(p));
  assert.equal(p.requests.length, 0);
});

for (const [name, change] of [
  ['strict context profile', c => c.profile = 'source-initial-context-v1'],
  ['strict retrieval profile', c => c.retrieval.profile = 'source-initial-retrieval-v1'],
  ['missing context selector', c => delete c.index_source],
  ['missing retrieval selector', c => delete c.retrieval.index_source],
  ['missing current record', c => delete c.retrieval.current_source],
  ['current RCR mismatch', c => c.retrieval.current_source.source_rcr = 'different-current-rcr'],
  ['current snapshot mismatch', c => c.retrieval.current_source.snapshot_token = `alg:2:${'e'.repeat(64)}`],
  ['original lexical snapshot conflict', c => c.retrieval.path.snapshot_token = `alg:2:${'e'.repeat(64)}`],
  ['one head with conflicting index forge root', c => {
    const current = c.retrieval.current_source;
    for (const row of [c.retrieval.index_sources.lexical, c.retrieval.content, c.retrieval.path]) {
      row.source_head = current.source_head; row.snapshot_token = current.snapshot_token; row.source_rcr = current.source_rcr;
    }
  }],
  ['different original source', c => {
    for (const row of [c.retrieval.index_sources.lexical, c.retrieval.content, c.retrieval.path]) row.root_tree = 'e'.repeat(40);
  }],
  ['missing symbol origin', c => c.retrieval.index_sources.symbols = null],
  ['symbol source conflict', c => c.retrieval.symbols.result.source_rcr = 'different-symbol-rcr'],
  ['published original channel', c => c.retrieval.path.published = true],
  ['joined publication claim', c => c.retrieval.published = true],
  ['transaction-created retrieval', c => c.retrieval.transaction_created = true],
  ['unexpected ranking', c => c.ranking = {}],
]) test(`current package refuses ${name} before independent source reads`, async t => {
  const p = await currentFixture(t); update(p, change);
  await assert.rejects(capture(p)); assert.equal(p.requests.length, 0);
});

test('current context does not bypass optional native verification independent-head requirement', async t => {
  const p = await currentFixture(t); p.selected = { ...p.selected, expected_head: null };
  await assert.rejects(capture(p, { nativeFg: process.execPath }), /independent.*head/i);
  assert.equal(p.requests.length, 0);
});

test('current provenance cannot turn altered excerpt bytes into a valid package online or offline', async t => {
  const p = await currentFixture(t, 'sha256'), result = await capture(p), before = p.requests.length;
  update(p, c => { c.files[1].excerpts[0].untrusted_bytes_hex = 'ff'.repeat(8); });
  await assert.rejects(inspect(p, result), /excerpt differs/); assert.equal(p.requests.length, before);
  await assert.rejects(capture(p), /excerpt differs/);
});

test('later server metadata cannot silently refresh a captured current head', async t => {
  const p = await currentFixture(t, 'sha1', value => { value.snapshot_token = `alg:2:${'e'.repeat(64)}`; });
  await assert.rejects(capture(p)); assert.equal(p.requests.length, 1);
});

test('current package retains exact source-byte budgets and pre-cancellation', async t => {
  const p = await currentFixture(t), size = p.f.rows.reduce((sum, row) => sum + row.bytes.length, 0);
  const result = await capture(p, { limits: { package: { maxSourceBytes: size } } });
  assert.equal(result.receipt.verified.logicalSourceBytes, size);
  const before = p.requests.length;
  await assert.rejects(capture(p, { limits: { package: { maxSourceBytes: size - 1 } } }));
  const stop = new AbortController(); stop.abort(new Error('selected stop'));
  await assert.rejects(capture(p, { signal: stop.signal }), /selected stop/);
  assert.equal(p.requests.length, before);
});

test('current package retains one operation deadline while a source response stalls', async t => {
  const p = await currentFixture(t, 'sha256', (_value, call) => {
    call.res.writeHead(200, { 'Content-Type': 'application/json' }); call.res.write('{'); return false;
  });
  // Leave time for the pinned context checks and connection under concurrent
  // test load so this exercises expiry of the stalled response, not pre-I/O expiry.
  const start = performance.now(); await assert.rejects(capture(p, { limits: { timeoutMs: 1000 } }));
  assert.ok(performance.now() - start < 3000); assert.equal(p.requests.length, 1);
});
