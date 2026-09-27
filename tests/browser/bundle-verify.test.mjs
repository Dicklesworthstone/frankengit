import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { BUNDLE_VERIFY_LIMITS, BundleVerificationError, verifyGitBundleObjects } from '../../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';
import { bytes, hash, objectId, size, pack, bundle, literalDelta, webcrypto, constants, rewriteTrailer } from './bundle-verify-fixtures.mjs';
const verify = (input, options = {}) => verifyGitBundleObjects(input, { cryptoImpl: webcrypto, ...options });
const fails = (input, code, options) => assert.rejects(verify(input, options), error => error instanceof BundleVerificationError && error.code === code);

for (const format of ['sha1', 'sha256']) {
  for (const [name, compression] of [['stored', { level: 0 }], ['fixed', { strategy: constants.Z_FIXED }], ['dynamic', { level: 9 }]]) {
    test(`${format}: ${name} DEFLATE verifies exact object bytes, native trailer and artifact hash`, async () => {
      const body = bytes(Array.from({ length: 24000 }, (_, n) => n % 123 < 100 ? 65 + n % 11 : n % 256));
      const zlib = deflateSync(body, compression);
      assert.equal((zlib[2] >> 1) & 3, { stored: 0, fixed: 1, dynamic: 2 }[name], 'exercise the named block type');
      const input = bundle([{ body, zlib }], format), result = await verify(input);
      assert.equal(result.object_format, format); assert.equal(result.objects_verified, true);
      assert.equal(result.object_closure_verified, false); assert.equal(result.independently_authenticated, false);
      assert.equal(result.sha256, hash(input, 'sha256').toString('hex')); assert.equal(result.pack_objects, 1);
      assert.equal(result.refs[0].object_id, objectId('blob', body, format)); assert.equal(result.expanded_bytes, body.length);
    });
  }
  test(`${format}: zero-length and binary objects are hashed, never decoded as text`, async () => {
    for (const body of [bytes(''), bytes([0, 255, 13, 10, 128])]) assert.equal((await verify(bundle([{ body }], format))).objects_verified, true);
  });
  for (const type of [6, 7]) test(`${format}: type ${type} resolves chained deltas and checks their resulting Git IDs`, async () => {
    const base = bytes('base contents\n'), next = bytes('next\0contents\n'), final = bytes('third version');
    const rows = [{ body: base },
      { type, body: literalDelta(base, next), base: 0, baseId: objectId('blob', base, format) },
      { type, body: literalDelta(next, final), base: 1, baseId: objectId('blob', next, format) }];
    const input = bundle(rows, format, { refs: [{ name: 'refs/tags/result', id: objectId('blob', final, format) }] });
    const result = await verify(input); assert.equal(result.delta_objects, 2); assert.equal(result.maximum_delta_depth, 2);
    assert.equal(result.reconstructed_bytes, next.length + final.length);
    await fails(input, 'delta_depth_limit', { limits: { maxDeltaDepth: 1 } });
  });
  test(`${format}: forward REF_DELTA resolves from a later base without scanning or external reads`, async () => {
    const base = bytes('base'), next = bytes('result');
    const input = bundle([{ type: 7, baseId: objectId('blob', base, format), body: literalDelta(base, next) }, { body: base }], format,
      { refs: [{ name: 'refs/tags/result', id: objectId('blob', next, format) }] });
    assert.equal((await verify(input)).delta_objects, 1);
  });
  test(`${format}: checksum-valid but missing advertised objects are refused`, async () => {
    await fails(bundle([{ body: bytes('real') }], format, { refs: [{ name: 'refs/tags/result', id: 'a'.repeat(format === 'sha1' ? 40 : 64) }] }), 'advertised_object_missing');
  });
}
test('mixed offset/ref dependencies resolve in linear queue order even with a forward root', async () => {
  const a = bytes('a'), b = bytes('b'), c = bytes('c'), d = bytes('d');
  const input = bundle([
    { type: 7, baseId: objectId('blob', b), body: literalDelta(b, c) },
    { type: 6, base: 0, body: literalDelta(c, d) },
    { type: 7, baseId: objectId('blob', a), body: literalDelta(a, b) }, { body: a },
  ], 'sha1', { refs: [{ name: 'refs/tags/test', id: objectId('blob', d) }] });
  const result = await verify(input); assert.equal(result.maximum_delta_depth, 3); assert.equal(result.delta_objects, 3);
});
test('delta copies support optional byte positions and the zero-size 64 KiB copy encoding', async () => {
  const base = bytes(Array.from({ length: 65536 }, (_, n) => n % 251)), suffix = bytes('!');
  const program = Buffer.concat([size(base.length), size(base.length + 1), bytes([0x80, 1]), suffix]);
  const result = Buffer.concat([base, suffix]);
  assert.equal((await verify(bundle([{ body: base }, { type: 6, base: 0, body: program }], 'sha1',
    { refs: [{ name: 'refs/tags/test', id: objectId('blob', result) }] }))).delta_objects, 1);
  const selected = base.subarray(256, 258), shifted = Buffer.concat([size(base.length), size(2), bytes([0x92, 1, 2])]);
  assert.equal((await verify(bundle([{ body: base }, { type: 6, base: 0, body: shifted }], 'sha1',
    { refs: [{ name: 'refs/tags/test', id: objectId('blob', selected) }] }))).delta_objects, 1);
});
test('raw reference bytes, optional HEAD and v3 SHA-1 are preserved', async () => {
  const body = bytes('opaque commit bytes'), id = objectId('commit', body), name = bytes([...bytes('refs/heads/'), 255]);
  const header = Buffer.concat([bytes('# v3 git bundle\n@object-format=sha1\n'), bytes(`${id} `), name, bytes(`\n${id} HEAD\n\n`)]);
  const result = await verify(bundle([{ kind: 'commit', body }], 'sha1', { header }));
  assert.equal(result.advertised_head, id); assert.equal(result.refs[0].ref_hex, name.toString('hex'));
});
for (const [name, change, code] of [
  ['invalid type zero', rows => { rows[0].type = 0; }, 'invalid_pack_object_type'],
  ['reserved type five', rows => { rows[0].type = 5; }, 'invalid_pack_object_type'],
  ['understated inflation', rows => { rows[0].declared = 2; }, 'inflated_size_mismatch'],
  ['overstated inflation', rows => { rows[0].declared = 9; }, 'inflated_size_mismatch'],
  ['wrong Adler checksum', rows => { const z = deflateSync(rows[0].body); z[z.length - 1] ^= 1; rows[0].zlib = z; }, 'zlib_adler_mismatch'],
  ['wrong zlib header', rows => { const z = deflateSync(rows[0].body); z[0] = 0; rows[0].zlib = z; }, 'invalid_zlib_header'],
  ['preset dictionary', rows => { rows[0].zlib = bytes([0x78, 0x20]); }, 'zlib_dictionary_unsupported'],
  ['reserved DEFLATE block', rows => { rows[0].zlib = bytes([0x78, 0x9c, 7]); }, 'reserved_deflate_block'],
  ['stored length inverse', rows => { rows[0].zlib = bytes([0x78, 0x01, 1, 1, 0, 0, 0, 65]); }, 'stored_block_length_mismatch'],
]) test(`checksummed pack refuses ${name}`, async () => {
  const rows = [{ body: bytes('test') }], good = bundle(rows); assert.equal((await verify(good)).objects_verified, true);
  change(rows); await fails(bundle(rows), code);
});
test('pack object count and exact terminal boundary cannot hide trailing bytes or objects', async () => {
  const rows = [{ body: bytes('test') }];
  await fails(bundle(rows, 'sha1', { count: 0 }), 'pack_count_or_trailing_bytes');
  await fails(bundle(rows, 'sha1', { count: 2 }), 'truncated_pack');
  await fails(bundle(rows, 'sha1', { tail: bytes('hidden') }), 'pack_count_or_trailing_bytes');
  await fails(bundle(rows, 'sha1', { tail: deflateSync(bytes('second zlib stream')) }), 'pack_count_or_trailing_bytes');
  const bad = bundle(rows); bad[bad.length - 1] ^= 1; await fails(bad, 'pack_checksum_mismatch');
});
test('branch targets, duplicate objects and absent or invalid delta bases are not accepted', async () => {
  const base = bytes('base'), rows = [{ body: base }];
  await fails(bundle(rows, 'sha1', { refs: [{ name: 'refs/heads/main', id: objectId('blob', base) }] }), 'branch_target_not_commit');
  await fails(bundle([...rows, ...rows]), 'duplicate_pack_object');
  await fails(bundle([...rows, { type: 7, baseId: 'a'.repeat(40), body: literalDelta(base, bytes('a')) }]), 'unresolved_delta_base');
  for (const reference of [bytes([0]), bytes([1]), bytes([127]), bytes([255, 255, 255, 127])]) {
    await fails(bundle([...rows, { type: 6, base: 0, reference, body: literalDelta(base, bytes('a')) }]), 'invalid_delta_offset');
  }
});
for (const [name, program, code] of [
  ['base size', [5, 1, 1, 97], 'delta_base_size_mismatch'],
  ['reserved opcode', [4, 1, 0], 'reserved_delta_opcode'],
  ['copy overflow', [4, 1, 0x90, 2], 'delta_copy_out_of_bounds'],
  ['source overflow', [4, 1, 0x91, 4, 1], 'delta_copy_out_of_bounds'],
  ['insert overflow', [4, 1, 2, 97, 98], 'delta_insert_out_of_bounds'],
  ['truncated insertion', [4, 2, 2, 97], 'truncated_pack'],
  ['short result', [4, 2, 1, 97], 'delta_result_size_mismatch'],
]) test(`delta instructions refuse ${name}`, async () => {
  await fails(bundle([{ body: bytes('base') }, { type: 6, base: 0, body: bytes(program) }]), code);
});
test('every bundle framing cut refuses rather than accepting a partial pack', async () => {
  const input = bundle([{ body: bytes('test') }]);
  for (let length = 0; length < input.length; length++) await assert.rejects(verify(input.subarray(0, length)), BundleVerificationError);
});
test('unsupported prerequisites, capabilities, unsafe names and duplicate refs refuse', async () => {
  const body = bytes('test'), id = objectId('blob', body), header = '# v2 git bundle\n';
  for (const name of ['refs/heads/../main', 'refs//main', 'refs/tags/a.lock', 'refs/tags/a b', 'refs/tags/.hidden']) {
    await fails(bundle([{ body }], 'sha1', { refs: [{ name, id }] }), 'invalid_reference');
  }
  await fails(bundle([{ body }], 'sha1', { refs: [{ name: 'refs/tags/x', id }, { name: 'refs/tags/x', id }] }), 'duplicate_reference');
  await fails(bundle([{ body }], 'sha1', { header: bytes(`${header}-${id} missing\n${id} refs/tags/x\n\n`) }), 'prerequisites_not_self_contained');
  await fails(bundle([{ body }], 'sha1', { header: bytes(`# v3 git bundle\n@filter=blob:none\n${id} refs/tags/x\n\n`) }), 'unsupported_bundle_capability');
});
test('allocation, object counts, input bytes, work and depth are bounded with permitted exact twins', async () => {
  const input = bundle([{ body: bytes('1234') }]), good = await verify(input);
  assert.equal((await verify(input, { limits: { maxExpandedBytes: 4, maxObjectBytes: 4, maxInputBytes: input.length, maxWork: good.work } })).objects_verified, true);
  for (const [limits, code] of [[{ maxExpandedBytes: 3 }, 'expanded_byte_limit'], [{ maxObjectBytes: 3 }, 'object_size_limit'],
    [{ maxInputBytes: input.length - 1 }, 'input_byte_limit'], [{ maxWork: good.work - 1 }, 'work_limit']]) await fails(input, code, { limits });
  const huge = bundle([{ body: bytes('x') }], 'sha1', { count: 0xffffffff }); await fails(huge, 'object_count_limit');
  for (const limits of [{ maxObjects: 0 }, { maxObjects: Infinity }, { maxObjects: BUNDLE_VERIFY_LIMITS.maxObjects + 1 }, { unknown: 1 }]) await fails(input, 'invalid_limits', { limits });
});
test('cancellation before work and during a large single object leaves no result', async () => {
  const controller = new AbortController(); controller.abort(); await fails(bundle([{ body: bytes('x') }]), 'cancelled', { signal: controller.signal });
  const active = new AbortController(), input = bundle([{ body: Buffer.alloc(2 * 1024 * 1024, 65) }]);
  const promise = verify(input, { signal: active.signal }); setTimeout(() => active.abort(), 0);
  await assert.rejects(promise, error => error.code === 'cancelled');
  assert.equal((await verify(input)).objects_verified, true);
});
test('deadline includes decompression and checks after a delayed digest', async () => {
  const cryptoImpl = { subtle: { async digest(...args) { await new Promise(resolve => setTimeout(resolve, 15)); return webcrypto.subtle.digest(...args); } } };
  await fails(bundle([{ body: bytes('x') }]), 'deadline', { cryptoImpl, limits: { timeoutMs: 5 } });
});
test('input ownership prevents caller mutation while hashing from changing the checked bytes', async () => {
  const input = bundle([{ body: bytes('original') }]), expected = hash(input, 'sha256').toString('hex'); let mutated = false;
  const cryptoImpl = { subtle: { async digest(...args) { if (!mutated) { mutated = true; input.fill(0); } return webcrypto.subtle.digest(...args); } } };
  const result = await verify(input, { cryptoImpl }); assert.equal(result.sha256, expected); assert.equal(result.objects_verified, true);
});
test('checkpoint failure never produces a summary and deterministic reruns agree', async () => {
  const input = bundle([{ body: bytes('x') }]); let checks = 0;
  await assert.rejects(verify(input, { checkpoint() { if (++checks === 7) throw new Error('injected stop'); } }), /injected stop/);
  assert.deepEqual(await verify(input), await verify(input));
});
