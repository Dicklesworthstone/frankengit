import test from 'node:test';
import assert from 'node:assert/strict';
import { compileSourceReplacements, captureSourceReplacements, DELTA_REPLACEMENT_PROFILE } from '../../scripts/operator/source_edit_replacements.mjs';
import { planBinaryMember } from '../../scripts/operator/source_edit_binary_delta.mjs';
import { emitBinaryMember, binaryMemberCost, binaryLiteralCost } from '../../scripts/operator/source_edit_binary_literal.mjs';
import { change, binaryPeer, TOKEN } from './source_edit_binary_fixture.mjs';
import { replayDelta, decodeMember, coldOracle } from './source_edit_delta_fixture.mjs';
const delta = { binary: 'delta' }, literal = { binary: 'literal' }, live = () => {};
const pattern = n => Buffer.from(Array.from({ length: n }, (_, i) => (i * 137 + (i >>> 8)) & 255));
function pair(base, at, remove, insert) { return Buffer.concat([base.subarray(0, at), insert, base.subarray(at + remove)]); }
function verifyMember(base, next) {
  const plan = planBinaryMember(base, next, live), lines = [];
  emitBinaryMember(plan.kind, plan.body, line => lines.push(line), live);
  assert.deepEqual(decodeMember(lines, base).body, next);
  assert.equal(plan.cost.bytes, Buffer.byteLength(lines.join(''))); assert.equal(plan.cost.records, lines.length);
  assert.ok(plan.cost.bytes <= binaryLiteralCost(next.length).bytes);
  if (plan.kind === 'delta') assert.ok(plan.cost.bytes < binaryLiteralCost(next.length).bytes);
  return plan;
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: one-byte edit to a full 1 MiB file fits without raising the patch ceiling`, () => {
    const old = pattern(1048576), next = Buffer.from(old); next[524288] ^= 255;
    const rows = [change(format, 'asset.bin', old, next)];
    assert.throws(() => compileSourceReplacements(format, rows, literal), /patch_limit/);
    const result = compileSourceReplacements(format, rows, delta);
    assert.equal(result.profile, DELTA_REPLACEMENT_PROFILE); assert.equal(result.delta_members, 2);
    assert.equal(result.literal_members, 0); assert.ok(result.patch.length < 512);
    assert.equal(result.source_bytes, 1048576); assert.equal(result.result_bytes, 1048576);
    coldOracle(format, rows, result.patch); coldOracle(format, rows, result.patch, true);
  });
  for (const [name, old, next] of [
    ['insert in the middle', pattern(131072), pair(pattern(131072), 65536, 0, Buffer.from([9, 0, 8]))],
    ['delete in the middle', pattern(131072), pair(pattern(131072), 65536, 127, Buffer.alloc(0))],
    ['changed first byte', pattern(65537), pair(pattern(65537), 0, 1, Buffer.from([255]))],
    ['changed last byte', pattern(65537), pair(pattern(65537), 65536, 1, Buffer.from([254]))],
    ['unrelated binary', Buffer.alloc(257, 0), Buffer.alloc(258, 255)],
    ['binary creation', null, pattern(257)], ['binary deletion', pattern(257), null],
    ['empty result', pattern(257), Buffer.alloc(0)],
  ]) test(`${format}: cold Git decodes forward and reverse ${name}`, () => {
    const rows = [change(format, Buffer.from([255, 32, 34, 92]), old, next, 0o100644, 0o100755)];
    const result = compileSourceReplacements(format, rows, delta);
    assert.equal(result.binary_files, 1); assert.equal(result.delta_members + result.literal_members, 2);
    coldOracle(format, rows, result.patch); coldOracle(format, rows, result.patch, true);
  });
  test(`${format}: real loopback capture keeps exact delta bytes through prepare and inspect`, async t => {
    const old = pattern(65537), next = pair(old, 10000, 2, Buffer.from([0, 123]));
    const f = await binaryPeer(t, format, [change(format, 'file', old, next)], delta);
    const result = await captureSourceReplacements(f.request, f.rows, TOKEN, delta);
    assert.equal(result.replacement_profile, DELTA_REPLACEMENT_PROFILE); assert.equal(result.candidate_commit, f.candidate);
    assert.equal(result.bundle_objects_independently_verified, false);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
    assert.ok(f.calls[0].body.includes(f.compiled.patch)); assert.equal(f.compiled.delta_members, 2);
  });
}
test('independent decoder checks size varints, copy offsets, 64 KiB special size and insert boundaries', () => {
  for (const size of [0, 1, 2, 126, 127, 128, 129, 16383, 16384, 65535, 65536, 65537, 1048576]) {
    const old = pattern(size);
    verifyMember(old, Buffer.from(old)); verifyMember(Buffer.alloc(0), old); verifyMember(old, Buffer.alloc(0));
    if (size) for (const at of [0, Math.floor(size / 2), size - 1]) {
      const next = Buffer.from(old); next[at] ^= 255; verifyMember(old, next); verifyMember(next, old);
    }
  }
  for (const count of [1, 126, 127, 128, 254, 255]) {
    const old = pattern(200000), next = pair(old, 65536, 0, Buffer.alloc(count, 42));
    const p = verifyMember(old, next); assert.equal(p.kind, 'delta');
    const r = replayDelta(old, p.body); assert.ok(r.instructions.some(i => i.opcode === 128 && i.count === 65536));
    assert.deepEqual(r.instructions.filter(i => i.kind === 'insert').map(i => i.count),
      Array.from({ length: Math.ceil(count / 127) }, (_, i) => Math.min(127, count - i * 127)));
    verifyMember(next, old);
  }
});
test('both directions choose independently; a large inserted middle uses a literal only where smaller', () => {
  const old = Buffer.from([0, 1, 2, 3]), next = Buffer.concat([old, Buffer.alloc(1024, 9)]);
  const r = compileSourceReplacements('sha1', [change('sha1', 'a', old, next)], delta);
  assert.equal(r.delta_members, 1); assert.equal(r.literal_members, 1);
  coldOracle('sha1', [change('sha1', 'a', old, next)], r.patch);
  coldOracle('sha1', [change('sha1', 'a', old, next)], r.patch, true);
});
test('unchanged literal mode and default text bytes remain exactly identical', () => {
  const rows = [change('sha1', 'a', 'old\n', 'new\n'), change('sha1', 'empty', null, '')];
  const baseline = compileSourceReplacements('sha1', rows), selected = compileSourceReplacements('sha1', rows, delta);
  assert.deepEqual(selected.patch, baseline.patch); assert.equal(selected.delta_members, 0); assert.equal(selected.literal_members, 0);
  const tiny = [change('sha1', 'tiny', Buffer.from([0]), Buffer.from([0, 1]))];
  assert.deepEqual(compileSourceReplacements('sha1', tiny, delta).patch, compileSourceReplacements('sha1', tiny, literal).patch);
});
test('nonoverlapping equal ends never duplicate repeated source bytes', () => {
  for (let size = 0; size <= 140; size++) for (const difference of [-1, 0, 1, 3]) {
    if (size + difference < 0) continue;
    verifyMember(Buffer.alloc(size), Buffer.alloc(size + difference));
  }
});
test('aggregate wire/record limits reserve forward AND reverse with exact permitted twins', () => {
  const old = pattern(60000), next = pair(old, 32768, 1, Buffer.from([255]));
  const rows = [change('sha256', 'a', old, next), change('sha256', 'b', Buffer.from([0]), pattern(100))];
  const r = compileSourceReplacements('sha256', rows, delta);
  for (const [key, n] of [['maxPatchBytes', r.patch.length], ['maxRecords', r.records]]) {
    assert.deepEqual(compileSourceReplacements('sha256', rows, { ...delta, [key]: n }).patch, r.patch);
    assert.throws(() => compileSourceReplacements('sha256', rows, { ...delta, [key]: n - 1 }), /patch_limit/);
  }
  assert.throws(() => compileSourceReplacements('sha256', rows, { ...delta, maxSourceBytes: old.length }), /bytes/);
  assert.throws(() => compileSourceReplacements('sha256', rows, { ...delta, maxResultBytes: next.length }), /bytes/);
});
test('an incompressible oversized creation still refuses; delta does not bypass source or output limits', () => {
  assert.throws(() => compileSourceReplacements('sha1', [change('sha1', 'a', null, pattern(1048576))], delta), /patch_limit/);
  assert.throws(() => compileSourceReplacements('sha1', [change('sha1', 'a', pattern(1048577), pattern(4))], delta), /file/);
});
test('cancellation interrupts common-prefix, common-suffix and insert planning without a fallback', () => {
  for (const [old, next] of [[pattern(1048576), pattern(1048576)],
    [pattern(1048576), pair(pattern(1048576), 0, 1, Buffer.from([255]))],
    [pattern(10000), pair(pattern(10000), 5000, 0, Buffer.alloc(1000, 42))]]) {
    for (const stopAt of [1, 3, 5]) {
      let visits = 0;
      assert.throws(() => planBinaryMember(old, next, () => { if (++visits === stopAt) throw Error('cancelled'); }), /cancelled/);
      assert.equal(visits, stopAt);
    }
  }
});
test('preimage mismatch, invalid profile, bad mode and unrequested paths refuse before network', async t => {
  const old = pattern(1000), next = pair(old, 500, 1, Buffer.from([255]));
  const f = await binaryPeer(t, 'sha1', [change('sha1', 'file', old, next)], delta);
  for (const binary of ['auto', 'delta-v2', 'Delta', true, null]) {
    await assert.rejects(captureSourceReplacements(f.request, f.rows, TOKEN, { binary }), /binary_profile/);
  }
  const bad = structuredClone(f.rows); bad[0].before.blob = 'a'.repeat(40);
  await assert.rejects(captureSourceReplacements(f.request, bad, TOKEN, delta), /preimage/);
  const stop = new AbortController(); stop.abort();
  await assert.rejects(captureSourceReplacements(f.request, f.rows, TOKEN, { ...delta, signal: stop.signal }), /cancelled/);
  assert.equal(f.calls.length, 0);
});
test('compiler owns images and preserves deterministic order under caller mutation', () => {
  const old = pattern(4096), next = pair(old, 2048, 1, Buffer.from([255]));
  const rows = [change('sha1', 'z', old, next), change('sha1', 'a', next, old)];
  const first = compileSourceReplacements('sha1', rows, delta), second = compileSourceReplacements('sha1', [...rows].reverse(), delta);
  rows[0].before.bytes.fill(0); rows[0].after.bytes.fill(0); assert.deepEqual(first, second);
});
test('cold oracle rejects corruption of each member and does not change its starting index', () => {
  const old = pattern(4096), next = pair(old, 2048, 1, Buffer.from([255]));
  const rows = [change('sha256', 'file', old, next)], good = compileSourceReplacements('sha256', rows, delta).patch;
  for (const reverse of [false, true]) {
    const bad = Buffer.from(good), marker = Buffer.from('delta ');
    const header = reverse ? bad.indexOf(marker, bad.indexOf(marker) + marker.length) : bad.indexOf(marker);
    assert.ok(header >= 0); const at = bad.indexOf(10, header) + 2; bad[at] = bad[at] === 48 ? 49 : 48;
    coldOracle('sha256', rows, bad, reverse, true);
  }
});
test('member helpers refuse unsupported kinds and malformed inputs', () => {
  for (const kind of ['auto', 'Delta', null, undefined]) {
    assert.throws(() => binaryMemberCost(kind, 1)); assert.throws(() => emitBinaryMember(kind, Buffer.alloc(1), live, live));
  }
  for (const value of [null, 'string', new Uint8Array(1), Buffer.alloc(1048577)]) {
    assert.throws(() => planBinaryMember(value, Buffer.alloc(1), live));
    assert.throws(() => planBinaryMember(Buffer.alloc(1), value, live));
  }
});
