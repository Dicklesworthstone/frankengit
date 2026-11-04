import test from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '../../scripts/operator/source_archive.mjs';
import { captureContextProof, inspectContextProof } from '../../scripts/operator/source_context_proof.mjs';
import { setup, bytes, token, labelledContext } from './source_context_proof_fixtures.mjs';
import { revalidatedProjection } from './source_context_revalidated_projection_fixtures.mjs';

async function currentFixture(t, format = 'sha1') {
  const f = await setup(t, format);
  const context = revalidatedProjection(labelledContext(f.context), { symbols: true });
  // The HTTP peer remains a source-byte provider, not a native search oracle.
  f.repo.common.source_head = context.retrieval.current_source.source_head;
  return { ...f, context };
}
const capture = (f, input, selected = f.selection, options = {}) =>
  captureContextProof(input, sha256(input), selected, token, options);

for (const format of ['sha1', 'sha256']) for (const wrapped of [false, true]) {
  test(`${format}: ${wrapped ? 'saved capture' : 'raw current context'} proves current bytes with older independent indexes`, async t => {
    const f = await currentFixture(t, format);
    const value = wrapped ? { schema: 'frankengit-source-context-capture-v1', endpoint: f.selection.endpoint,
      native_response: f.context, summary: { authority_verified: true } } : f.context;
    const input = bytes(value), original = Buffer.from(input), result = await capture(f, input);
    const replay = inspectContextProof(result.bytes, sha256(result.bytes), input, sha256(input), f.selection);
    assert.deepEqual(replay, result.receipt); assert.deepEqual(input, original);
    assert.equal(replay.source_commit, f.repo.commit); assert.equal(replay.excerpt_bytes_verified, true);
    for (const name of ['search_evidence_verified', 'authority_verified', 'freshness_verified', 'agent_context_packet']) {
      assert.equal(replay[name], false);
    }
    const proof = JSON.parse(result.bytes);
    assert.equal(proof.capture.snapshot_token, f.context.retrieval.current_source.snapshot_token);
    assert.equal(proof.capture.source_rcr, f.context.retrieval.current_source.source_rcr);
    assert.notEqual(proof.capture.source_rcr, f.context.retrieval.index_sources.lexical.source_rcr);
    assert.equal(result.bytes.includes(Buffer.from('fixture-lexical-rcr')), false);
    assert.equal(result.bytes.includes(Buffer.from('fixture-symbol-rcr')), false);
    for (const call of f.calls) {
      assert.equal(call.form.get('expected_head'), f.repo.snapshot);
      assert.equal(call.form.get('expected_commit'), f.repo.commit);
    }
    assert.deepEqual((await capture(f, input)).bytes, result.bytes);
  });
}

test('current byte proof requires independent commit and current captured head, including saved wrappers', async t => {
  const f = await currentFixture(t), input = bytes(f.context);
  for (const selected of [
    { ...f.selection, expected_commit: 'e'.repeat(40) },
    { ...f.selection, expected_head: f.context.retrieval.index_sources.lexical.snapshot_token },
  ]) await assert.rejects(capture(f, input, selected), /independently selected source/);
  const wrapper = bytes({ schema: 'frankengit-source-context-capture-v1', endpoint: 'https://different.invalid/repo', native_response: f.context });
  await assert.rejects(capture(f, wrapper), /endpoint/);
  assert.equal(f.calls.length, 0);
});

for (const [name, change] of [
  ['strict context profile', c => c.profile = 'source-initial-context-v1'],
  ['strict retrieval profile', c => c.retrieval.profile = 'source-initial-retrieval-v1'],
  ['missing context selector', c => delete c.index_source],
  ['unknown retrieval selector', c => c.retrieval.index_source = 'anything-current'],
  ['missing current source', c => delete c.retrieval.current_source],
  ['current snapshot conflict', c => c.retrieval.current_source.snapshot_token = `alg:2:${'e'.repeat(64)}`],
  ['current RCR conflict', c => c.retrieval.current_source.source_rcr = 'changed-current-rcr'],
  ['original index commit', c => {
    const value = 'e'.repeat(40);
    for (const row of [c.retrieval.index_sources.lexical, c.retrieval.content, c.retrieval.path]) row.source_commit = value;
  }],
  ['original path head conflict', c => c.retrieval.path.source_head = 'not-the-original-head'],
  ['one head with conflicting index RCR', c => {
    const current = c.retrieval.current_source;
    for (const row of [c.retrieval.index_sources.lexical, c.retrieval.content, c.retrieval.path]) {
      row.source_head = current.source_head; row.snapshot_token = current.snapshot_token;
    }
  }],
  ['missing symbol origin', c => c.retrieval.index_sources.symbols = null],
  ['symbol origin tree', c => c.retrieval.index_sources.symbols.root_tree = 'e'.repeat(40)],
  ['publication claim', c => c.retrieval.content.published = true],
  ['joined publication claim', c => c.retrieval.published = true],
  ['ranked selection', c => c.selection = 'context-weighted-rrf-q16-v1'],
]) test(`current byte proof refuses ${name} before I/O`, async t => {
  const f = await currentFixture(t); change(f.context);
  await assert.rejects(capture(f, bytes(f.context))); assert.equal(f.calls.length, 0);
});

test('older index observations cannot make altered current excerpts pass capture or offline replay', async t => {
  const f = await currentFixture(t, 'sha256'), input = bytes(f.context), result = await capture(f, input);
  const edited = structuredClone(f.context);
  edited.files[0].excerpts[0].untrusted_bytes_hex = 'ff' + edited.files[0].excerpts[0].untrusted_bytes_hex.slice(2);
  const changed = bytes(edited), proof = JSON.parse(result.bytes); proof.context_sha256 = sha256(changed);
  const rewritten = bytes(proof);
  assert.throws(() => inspectContextProof(rewritten, sha256(rewritten), changed, sha256(changed), f.selection), /excerpt differs/);
  await assert.rejects(capture(f, changed), /excerpt differs/);
});

test('metadata movement after capture cannot replace the current source pin with an original index head', async t => {
  const f = await currentFixture(t), input = bytes(f.context);
  f.control.mutate = reply => { reply.snapshot_token = `alg:2:${'e'.repeat(64)}`; };
  await assert.rejects(capture(f, input)); assert.equal(f.calls.length, 1);
});

test('current proof preserves finite full-source budgets and cancellation before any I/O', async t => {
  const f = await currentFixture(t), input = bytes(f.context);
  const size = f.context.files.reduce((sum, file) => sum + file.source_bytes, 0);
  const result = await capture(f, input, f.selection, { limits: { maxTotalBlobBytes: size } });
  assert.equal(result.receipt.full_blob_bytes, size);
  await assert.rejects(capture(f, input, f.selection, { limits: { maxTotalBlobBytes: size - 1 } }), /budget/);
  const stop = new AbortController(); stop.abort(new Error('selected stop'));
  const before = f.calls.length;
  await assert.rejects(capture(f, input, f.selection, { signal: stop.signal }), /selected stop/);
  assert.equal(f.calls.length, before);
});
