import test from 'node:test';
import assert from 'node:assert/strict';
import { inflateSync } from 'node:zlib'; // Test-only independent zlib decoder.
import { binaryLiteralCost, emitBinaryLiteral } from '../../scripts/operator/source_edit_binary_literal.mjs';
import { compileSourceReplacements, captureSourceReplacements, BINARY_REPLACEMENT_PROFILE, REPLACEMENT_PROFILE } from '../../scripts/operator/source_edit_replacements.mjs';
import { change, oracle, withOracle, binaryPeer, TOKEN } from './source_edit_binary_fixture.mjs';
const literal = { binary: 'literal' }, nul = Buffer.from([0]);
const pattern = n => Buffer.from(Array.from({ length: n }, (_, i) => (i * 137 + (i >>> 8)) & 255));
// Deliberately independent of the encoder: test rows with bigint base85 folding
// and the platform decoder, including padding, checksum and consumed framing.
function decodedMember(lines) {
  assert.match(lines[0], /^literal (0|[1-9][0-9]*)\n$/);
  assert.equal(lines.at(-1), '\n');
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';
  const rows = lines.slice(1, -1).map(line => {
    const prefix = line.charCodeAt(0), count = prefix <= 90 ? prefix - 64 : prefix - 70;
    assert.ok(count >= 1 && count <= 52); assert.equal(line.length, 2 + Math.ceil(count / 4) * 5);
    const bytes = [];
    for (let p = 1; p < line.length - 1; p += 5) {
      let word = 0n;
      for (const c of line.slice(p, p + 5)) { assert.ok(alphabet.includes(c)); word = word * 85n + BigInt(alphabet.indexOf(c)); }
      assert.ok(word <= 0xffffffffn);
      bytes.push(Number(word >> 24n), Number((word >> 16n) & 255n), Number((word >> 8n) & 255n), Number(word & 255n));
    }
    assert.ok(bytes.slice(count).every(b => b === 0));
    return Buffer.from(bytes.slice(0, count));
  });
  return Buffer.concat(rows);
}
for (const format of ['sha1', 'sha256']) {
  for (const [name, old, next] of [
    ['creation', null, nul], ['deletion', nul, null], ['binary to empty', nul, Buffer.alloc(0)],
    ['empty to binary', Buffer.alloc(0), nul], ['binary to text', Buffer.from('old\0body'), Buffer.from('text\r\nlast')],
    ['text to binary', Buffer.from('text\r\nlast'), Buffer.from('new\0body')],
    ['all byte values', pattern(256), pattern(513)], ['stored block boundary', pattern(65535), pattern(65536)],
    ['multiple stored blocks', pattern(131071), pattern(131072)],
  ]) test(`${format}: Git applies and reverses ${name}`, () => {
    const r = oracle(format, [change(format, 'src/binary', old, next)]);
    assert.equal(r.profile, BINARY_REPLACEMENT_PROFILE); assert.equal(r.binary_files, 1);
    assert.equal(r.source_membership_verified, false); assert.equal(r.publication_authorized, false);
    assert.equal(r.patch.toString().split('literal ').length - 1, 2);
  });
  test(`${format}: mixed text/binary/raw paths/modes preserve unselected siblings in both directions`, () => {
    oracle(format, [change(format, Buffer.from([255, 32, 34, 92, 9, 10]), nul, pattern(26), 0o100644, 0o100755),
      change(format, 'added/bin', null, Buffer.from([0, 4, 255]), 0o100644, 0o100755),
      change(format, 'delete', Buffer.from('gone\0'), null), change(format, 'text', 'before\n', 'after'),
      change(format, 'empty', null, ''), change(format, 'mode', nul, nul, 0o100755, 0o100644)]);
  });
  test(`${format}: binary mode-only edits do not fabricate content changes`, () => {
    const r = oracle(format, [change(format, 'file', nul, nul, 0o100644, 0o100755)]);
    assert.equal(r.binary_files, 0); assert.ok(!r.patch.includes(Buffer.from('GIT binary patch')));
  });
  test(`${format}: binary result goes through the unchanged prepare/inspect protocol`, async t => {
    const f = await binaryPeer(t, format);
    const captured = await captureSourceReplacements(f.request, f.rows, TOKEN, literal);
    assert.equal(captured.candidate_commit, f.candidate); assert.equal(captured.replacement_profile, BINARY_REPLACEMENT_PROFILE);
    assert.equal(captured.bundle_objects_independently_verified, false);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
    assert.ok(f.calls[0].body.includes(f.compiled.patch)); assert.ok(f.calls[1].body.includes(f.bundle));
    assert.ok(f.calls.every(c => c.headers['idempotency-key'] === undefined));
  });
}
test('every short input length covers all row prefixes and base85 tail widths', () => {
  const prefixes = new Set();
  for (const size of [...Array(160).keys(), 65534, 65535, 65536, 65537, 1048576]) {
    const bytes = pattern(size), lines = [];
    emitBinaryLiteral(bytes, line => lines.push(line), () => {});
    const cost = binaryLiteralCost(size), framed = decodedMember(lines);
    assert.equal(cost.bytes, Buffer.byteLength(lines.join(''))); assert.equal(cost.records, lines.length);
    assert.equal(cost.framed_bytes, framed.length); assert.deepEqual(inflateSync(framed), bytes);
    assert.deepEqual(framed.subarray(0, 2), Buffer.from([0x78, 0x01]));
    for (const line of lines.slice(1, -1)) prefixes.add(line[0]);
  }
  assert.equal(prefixes.size, 52);
});
test('binary encoding requires explicit literal opt-in; unknown modes cannot fall back', async t => {
  const f = await binaryPeer(t);
  assert.throws(() => compileSourceReplacements('sha1', f.rows), /source_replacement_binary/);
  for (const binary of [true, null, undefined, 'delta', 'auto', 'literal-v2', 'Literal']) {
    assert.throws(() => compileSourceReplacements('sha1', f.rows, { binary }), /binary_profile/);
    await assert.rejects(captureSourceReplacements(f.request, f.rows, TOKEN, { binary }), /binary_profile/);
  }
  await assert.rejects(captureSourceReplacements(f.request, f.rows, TOKEN)); assert.equal(f.calls.length, 0);
});
test('text serialization is byte-identical with and without binary opt-in', () => {
  const rows = [change('sha256', 'file', 'old\r\nlast', 'new\r\nlast')];
  const a = compileSourceReplacements('sha256', rows), b = compileSourceReplacements('sha256', rows, literal);
  assert.equal(a.profile, REPLACEMENT_PROFILE); assert.equal(b.profile, BINARY_REPLACEMENT_PROFILE);
  assert.deepEqual(a.patch, b.patch); assert.equal(a.records, b.records);
  assert.equal(Object.hasOwn(a, 'binary_files'), false); assert.equal(b.binary_files, 0);
});
test('forward and reverse members share exact patch and record allowances', () => {
  const rows = [change('sha1', 'a', pattern(60), pattern(121)), change('sha1', 'b', null, pattern(35))];
  const r = compileSourceReplacements('sha1', rows, literal);
  for (const key of ['maxPatchBytes', 'maxRecords']) {
    const exact = key === 'maxPatchBytes' ? r.patch.length : r.records;
    assert.deepEqual(compileSourceReplacements('sha1', rows, { ...literal, [key]: exact }).patch, r.patch);
    assert.throws(() => compileSourceReplacements('sha1', rows, { ...literal, [key]: exact - 1 }), /patch_limit/);
  }
});
test('an oversized literal is refused before framing or per-row encoding', () => {
  let checks = 0;
  assert.throws(() => compileSourceReplacements('sha1', [change('sha1', 'file', null, pattern(1048576))],
    literal, () => checks++), /patch_limit/);
  assert.ok(checks < 12, `only preflight checkpoints expected, got ${checks}`);
});
test('binary source/result byte ceilings and preimage hashes remain enforced', () => {
  const rows = [change('sha1', 'a', pattern(4), pattern(5)), change('sha1', 'b', pattern(4), pattern(5))];
  assert.ok(compileSourceReplacements('sha1', rows, { ...literal, maxSourceBytes: 8, maxResultBytes: 10 }));
  for (const limits of [{ maxSourceBytes: 7 }, { maxResultBytes: 9 }, { maxPatchBytes: 1048577 }, { force: true }]) {
    assert.throws(() => compileSourceReplacements('sha1', rows, { ...literal, ...limits }));
  }
  rows[0].before.blob = 'f'.repeat(40);
  assert.throws(() => compileSourceReplacements('sha1', rows, literal), /preimage/);
});
test('input ordering and caller mutations do not change returned binary bytes', () => {
  const rows = [change('sha1', 'z', pattern(100), pattern(200)), change('sha1', 'a', null, pattern(70))];
  const a = compileSourceReplacements('sha1', rows, literal), b = compileSourceReplacements('sha1', [...rows].reverse(), literal);
  assert.deepEqual(a, b); rows[0].before.bytes.fill(7); rows[1].after.bytes.fill(3);
  assert.deepEqual(a, b);
});
test('cancellation is observed in stored framing and base85 rows without a successful prefix', () => {
  const rows = [change('sha1', 'file', pattern(8000), pattern(16000))];
  for (const at of [1, 8, 15, 60, 300]) {
    let n = 0;
    assert.throws(() => compileSourceReplacements('sha1', rows, literal, () => { if (++n === at) throw Error('stopped'); }), /stopped/);
    assert.equal(n, at);
  }
});
test('wrong result roots and cancelled acquisition do not broaden or retry', async t => {
  const f = await binaryPeer(t), stop = new AbortController(); stop.abort();
  await assert.rejects(captureSourceReplacements(f.request, f.rows, TOKEN, { ...literal, signal: stop.signal }), /cancelled/);
  assert.equal(f.calls.length, 0);
  await assert.rejects(captureSourceReplacements({ ...f.request, expected_result_tree: 'f'.repeat(40) }, f.rows, TOKEN, literal), /result_tree_mismatch/);
  assert.deepEqual(f.calls.map(c => c.operation), ['prepare']);
});
test('acquisition owns binary bodies and options before the first asynchronous response', async t => {
  const f = await binaryPeer(t), rows = structuredClone(f.rows), options = { ...literal }, request = structuredClone(f.request);
  const result = captureSourceReplacements(request, rows, TOKEN, options);
  rows[0].after.bytes.fill(1); request.expected_result_tree = 'f'.repeat(40); options.binary = 'delta';
  assert.equal((await result).candidate_commit, f.candidate);
  assert.ok(f.calls[0].body.includes(f.compiled.patch));
});
test('binary acquisition retains a single exact aggregate wire allowance', async t => {
  const f = await binaryPeer(t), r = await captureSourceReplacements(f.request, f.rows, TOKEN, literal);
  await captureSourceReplacements(f.request, f.rows, TOKEN, { ...literal, maxWireBytes: r.metrics.response_bytes });
  await assert.rejects(captureSourceReplacements(f.request, f.rows, TOKEN, { ...literal, maxWireBytes: r.metrics.response_bytes - 1 }));
});
test('tampered forward and reverse binary members cannot survive the Git oracle', () => {
  const rows = [change('sha1', 'file', pattern(75), pattern(120))], good = compileSourceReplacements('sha1', rows, literal).patch;
  for (const reverse of [false, true]) withOracle('sha1', rows, ({ git }) => {
    if (reverse) git(['apply', '--cached', '-'], good);
    const bad = Buffer.from(good), marker = Buffer.from('literal ');
    const header = reverse ? bad.indexOf(marker, bad.indexOf(marker) + marker.length) : bad.indexOf(marker);
    const line = bad.indexOf(10, header) + 1; bad[line + 4] = bad[line + 4] === 48 ? 49 : 48;
    assert.throws(() => git(['apply', '--cached', ...(reverse ? ['-R'] : []), '-'], bad));
  });
});
test('literal helpers reject malformed and oversized input', () => {
  for (const length of [-1, 0.5, NaN, 1048577]) assert.throws(() => binaryLiteralCost(length));
  for (const value of [new Uint8Array(1), 'text', null, Buffer.alloc(1048577)]) {
    assert.throws(() => emitBinaryLiteral(value, () => {}, () => {}));
  }
});
