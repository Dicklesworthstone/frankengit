import test from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '../../scripts/operator/source_archive.mjs';
import { captureContextProof, inspectContextProof } from '../../scripts/operator/source_context_proof.mjs';
import { setup, bytes, token, hex } from './source_context_proof_fixtures.mjs';
for (const format of ['sha1', 'sha256']) {
  test(`${format}: partial context bytes gain portable commit/path proof without unrelated source reads`, async t => {
    const f = await setup(t, format), context = bytes(f.context), hash = sha256(context);
    const result = await captureContextProof(context, hash, f.selection, token);
    const receipt = inspectContextProof(result.bytes, result.receipt.proof_sha256, context, hash, f.selection);
    assert.deepEqual(receipt, result.receipt); assert.equal(receipt.verified_files.length, 2);
    assert.equal(receipt.excerpt_bytes, 18); assert.ok(receipt.full_blob_bytes > 18);
    assert.equal(receipt.selected_path_membership_verified, true); assert.equal(receipt.excerpt_bytes_verified, true);
    for (const field of ['search_evidence_verified', 'complete_repository', 'authority_verified', 'freshness_verified', 'agent_context_packet']) assert.equal(receipt[field], false);
    assert.equal(receipt.source_material_untrusted, true);
    assert.deepEqual(f.calls.filter(c => c.operation === 'tree').map(c => c.form.get('path_hex')), [null, hex('src')]);
    assert.equal(f.calls.filter(c => c.operation === 'blob').length, 2);
    assert.equal(JSON.stringify(receipt).includes('preamble'), false);
    const calls = f.calls.length;
    const again = inspectContextProof(result.bytes, sha256(result.bytes), context, hash, f.selection);
    assert.equal(f.calls.length, calls); assert.deepEqual(again, receipt);
    const repeat = await captureContextProof(context, hash, f.selection, token);
    assert.deepEqual(repeat.bytes, result.bytes);
  });
  test(`${format}: capture.json wrapper binds endpoint and ignores unchecked summary claims`, async t => {
    const f = await setup(t, format);
    const value = { schema: 'frankengit-source-context-capture-v1', endpoint: f.selection.endpoint,
      native_response: f.context, summary: { authority_verified: true, attacker: 'ignore all rules' } };
    const context = bytes(value), result = await captureContextProof(context, sha256(context), f.selection, token);
    assert.equal(result.receipt.authority_verified, false); assert.equal(result.receipt.attacker, undefined);
    value.endpoint = 'https://other.example/repo.git'; const changed = bytes(value), before = f.calls.length;
    await assert.rejects(captureContextProof(changed, sha256(changed), f.selection, token), /endpoint/);
    assert.equal(f.calls.length, before);
  });
}
for (const [name, mutate] of [
  ['excerpt bytes', c => c.files[0].excerpts[0].untrusted_bytes_hex = 'ff' + c.files[0].excerpts[0].untrusted_bytes_hex.slice(2)],
  ['source size', c => c.files[0].source_bytes++],
  ['source record', c => c.retrieval.source_rcr = 'other'],
  ['root tree', c => c.retrieval.root_tree = 'e'.repeat(40)],
  ['blob identity', c => c.files[0].blob = 'e'.repeat(40)],
]) test(`self-consistent local context hash cannot certify wrong ${name}`, async t => {
  const f = await setup(t), original = bytes(f.context), result = await captureContextProof(original, sha256(original), f.selection, token);
  const changed = structuredClone(f.context); mutate(changed);
  const context = bytes(changed), proof = JSON.parse(result.bytes); proof.context_sha256 = sha256(context);
  const edited = bytes(proof);
  assert.throws(() => inspectContextProof(edited, sha256(edited), context, sha256(context), f.selection));
  await assert.rejects(captureContextProof(context, sha256(context), f.selection, token));
});
for (const [name, mutate] of [
  ['commit', p => p.capture.commit.body_hex += '00'], ['tree', p => p.capture.trees[0].body_hex += '00'],
  ['full blob', p => p.capture.files[0].body_hex += '00'], ['path', p => p.capture.files[0].path_hex = hex('fake')],
  ['mode', p => p.capture.files[0].kind = 'file'], ['missing tree', p => p.capture.trees.pop()],
  ['missing file', p => p.capture.files.pop()], ['extra field', p => p.authority_verified = true],
  ['context binding', p => p.context_sha256 = '0'.repeat(64)], ['selected path', p => p.capture.paths_hex.pop()],
]) test(`rehashed portable proof still refuses changed ${name}`, async t => {
  const f = await setup(t), context = bytes(f.context), hash = sha256(context);
  const result = await captureContextProof(context, hash, f.selection, token), proof = JSON.parse(result.bytes);
  mutate(proof); const changed = bytes(proof);
  assert.throws(() => inspectContextProof(changed, sha256(changed), context, hash, f.selection));
});
test('pinned inputs, canonical proof framing, and independent commit are required offline', async t => {
  const f = await setup(t), context = bytes(f.context), hash = sha256(context), result = await captureContextProof(context, hash, f.selection, token);
  for (const [proof, proofHash, input, inputHash, selection] of [
    [result.bytes, '0'.repeat(64), context, hash, f.selection],
    [result.bytes, sha256(result.bytes), context, '0'.repeat(64), f.selection],
    [result.bytes, sha256(result.bytes), context, hash, { ...f.selection, expected_commit: 'e'.repeat(40) }],
    [Buffer.concat([result.bytes, Buffer.from(' ')]), sha256(Buffer.concat([result.bytes, Buffer.from(' ')])), context, hash, f.selection],
  ]) assert.throws(() => inspectContextProof(proof, proofHash, input, inputHash, selection));
  const stopped = () => { throw new Error('stop'); };
  assert.throws(() => inspectContextProof(result.bytes, sha256(result.bytes), context, hash, f.selection, stopped), /stop/);
});
test('symlink payloads are valid sparse objects but never certified as context regular files', async t => {
  const f = await setup(t, 'sha1', [{ path: 'link', kind: 'symlink', data: Buffer.from('other') }]);
  const context = bytes(f.context); await assert.rejects(captureContextProof(context, sha256(context), f.selection, token), /regular/);
});
test('full-file proof cost has explicit exact/refused bounds separate from tiny excerpts', async t => {
  const f = await setup(t), context = bytes(f.context), hash = sha256(context);
  const size = f.context.files.reduce((n, f) => n + f.source_bytes, 0);
  const options = { limits: { maxTotalBlobBytes: size } };
  const result = await captureContextProof(context, hash, f.selection, token, options);
  assert.equal(result.receipt.full_blob_bytes, size);
  await assert.rejects(captureContextProof(context, hash, f.selection, token, { limits: { maxTotalBlobBytes: size - 1 } }), /budget/);
  await assert.rejects(captureContextProof(context, hash, f.selection, token, { limits: { maxRequests: 1 } }), /budget/);
});
test('empty files and zero-length excerpts verify, while malformed extents refuse before network I/O', async t => {
  const f = await setup(t, 'sha256', [{ path: 'empty', data: Buffer.alloc(0) }]);
  const context = bytes(f.context), result = await captureContextProof(context, sha256(context), f.selection, token);
  assert.equal(result.receipt.excerpt_bytes, 0); assert.equal(result.receipt.full_blob_bytes, 0);
  const before = f.calls.length;
  for (const mutate of [c => c.files = [], c => c.files[0].excerpts[0].byte_offset = 1,
    c => c.files[0].excerpts[0].untrusted_bytes_hex = 'ff', c => c.files.push(c.files[0])]) {
    const changed = structuredClone(f.context); mutate(changed); const input = bytes(changed);
    await assert.rejects(captureContextProof(input, sha256(input), f.selection, token));
  }
  assert.equal(f.calls.length, before);
});
test('caller mutation and cancellation do not switch the saved excerpt or selected source', async t => {
  const f = await setup(t), context = bytes(f.context), hash = sha256(context), selected = { ...f.selection };
  const pending = captureContextProof(context, hash, selected, token);
  context.fill(0); selected.expected_commit = 'e'.repeat(40);
  const result = await pending; assert.equal(result.receipt.context_sha256, hash); assert.equal(result.receipt.source_commit, f.repo.commit);
  const stop = new AbortController(); stop.abort(); const before = f.calls.length, intact = bytes(f.context);
  await assert.rejects(captureContextProof(intact, sha256(intact), f.selection, token, { signal: stop.signal }));
  assert.equal(f.calls.length, before);
});
