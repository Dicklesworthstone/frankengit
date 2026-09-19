import test from 'node:test';
import assert from 'node:assert/strict';
import { unhex, hex, displayBytes, pathJoin, safeNumber, commitHex, sourceFields,
  snapshotOf, boundedJson, blobPreview } from '../../crates/fgit-node/src/smart_http/server/browser/browser.mjs';
const selection = { reference: 'refs/heads/main', format: 'sha1' };
const reply = { schema_version: 1, object_format: 'sha1', read_only: true,
  transaction_created: false, published: false, snapshot_token: `alg:1:${'b'.repeat(64)}`, source_commit: 'a'.repeat(40) };

test('all byte values round-trip without interpreting file names as UTF-8', () => {
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.deepEqual(unhex(hex(all)), all);
  assert.equal(displayBytes('61ff'), 'a\\xff');
});
test('hex parser rejects malformed, uppercase, oversized and non-string data', () => {
  for (const value of ['a', 'AA', 'xx', null, {}, '00\n']) assert.throws(() => unhex(value));
  assert.throws(() => unhex('0000', 1));
  assert.deepEqual(unhex(''), new Uint8Array());
});
test('paths preserve bytes and refuse traversal, NUL and slash child names', () => {
  assert.equal(pathJoin('737263', '61ff'), '7372632f61ff');
  for (const name of ['', '2e', '2e2e', '002e', '612f62']) assert.throws(() => pathJoin('', name));
  assert.throws(() => pathJoin('61'.repeat(4096), '62'));
});
test('untrusted display strings remain literal, with bidi and control characters visible', () => {
  assert.equal(displayBytes(hex(new TextEncoder().encode('<script>alert(1)</script>'))), '<script>alert(1)</script>');
  assert.equal(displayBytes('e280ae'), '\\u{202e}');
  assert.equal(displayBytes('0a'), '\\u{a}');
});
test('only exactly representable nonnegative byte offsets are accepted', () => {
  assert.equal(safeNumber(2 ** 40, 'offset'), 2 ** 40);
  for (const value of [NaN, Infinity, -1, 0.5, '4', Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => safeNumber(value, 'offset'));
});
test('both supported hash domains preserve exact commit comparison', () => {
  assert.equal(commitHex(`sha1:${'a'.repeat(40)}`, 'sha1'), 'a'.repeat(40));
  assert.equal(commitHex('b'.repeat(64), 'sha256'), 'b'.repeat(64));
  assert.throws(() => commitHex('b'.repeat(40), 'sha256'));
  assert.throws(() => commitHex(`sha256:${'a'.repeat(64)}`, 'sha1'));
});
test('root requests omit empty path bytes and continuations carry both snapshot comparisons', () => {
  assert.deepEqual(sourceFields(selection, null), { ref: 'refs/heads/main', object_format: 'sha1' });
  const snapshot = snapshotOf(reply, selection);
  assert.deepEqual(sourceFields(selection, snapshot, '61ff'), {
    ref: 'refs/heads/main', object_format: 'sha1', expected_head: reply.snapshot_token,
    expected_commit: reply.source_commit, path_hex: '61ff',
  });
  assert.throws(() => sourceFields({ reference: '../HEAD', format: 'sha1' }, null));
});
test('pages never mix snapshots or accept publication-shaped API responses', () => {
  const snapshot = snapshotOf(reply, selection);
  assert.deepEqual(snapshotOf(reply, selection, snapshot), snapshot);
  for (const change of [{ schema_version: 2 }, { object_format: 'sha256' }, { published: true },
    { read_only: false }, { transaction_created: true }, { snapshot_token: 'secret' },
    { source_commit: 'c'.repeat(40) }, { snapshot_token: `alg:1:${'d'.repeat(64)}` }]) {
    assert.throws(() => snapshotOf({ ...reply, ...change }, selection, snapshot));
  }
});
test('JSON responses are bounded during streaming, including unknown content length', async () => {
  assert.deepEqual(await boundedJson(new Response('{"ok":true}'), 11), { ok: true });
  let cancelled = false;
  const stream = new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(20)); }, cancel() { cancelled = true; } });
  await assert.rejects(boundedJson(new Response(stream), 10), /byte limit/);
  assert.equal(cancelled, true);
});
test('malformed UTF-8 and JSON never become success-shaped empty results', async () => {
  await assert.rejects(boundedJson(new Response(Uint8Array.of(255))));
  await assert.rejects(boundedJson(new Response('not json')));
});
test('source previews never execute markup, decode binary lossily, or follow symlinks', () => {
  assert.equal(blobPreview(new TextEncoder().encode('<svg onload=alert(1)>'), 0).text, '<svg onload=alert(1)>');
  assert.match(blobPreview(Uint8Array.of(0, 255), 64).text, /^000000000040/);
  assert.match(blobPreview(Uint8Array.of(0xc3), 0).label, /Hex preview/);
});

const { searchFields, searchRows } = await import('../../crates/fgit-node/src/smart_http/server/browser/browser.mjs');
test('literal search sends byte-exact queries and the same snapshot, without mutation keys', () => {
  const snapshot = snapshotOf(reply, selection);
  const fields = searchFields(selection, snapshot, 'é', 'ascii-insensitive');
  assert.equal(fields.needle_hex, 'c3a9');
  assert.equal(fields.expected_head, snapshot.head);
  assert.equal(fields.expected_commit, snapshot.commit);
  assert.equal(fields.case, 'ascii-insensitive');
  assert.equal(fields.max_matches, '100');
  assert.equal(fields['Idempotency-Key'], undefined);
  for (const text of ['', 'x'.repeat(257), 'é'.repeat(129), '\n', '\r']) assert.throws(() => searchFields(selection, snapshot, text));
});
test('search reports retain byte paths, byte offsets and literal hostile excerpts', () => {
  const result = { type: 'source_search', profile: 'literal-bytes-v1', completion: 'complete', complete: true,
    returned_matches: 1, matches: [{ path_hex: '61ff', byte_offset: 1, line: 1, byte_column: 2, match_length: 2,
      excerpt_offset: 0, excerpt_hex: hex(new TextEncoder().encode('<svg>')) }] };
  assert.equal(searchRows(result)[0].name, 'a\\xff');
  assert.equal(searchRows(result)[0].excerpt, '<svg>');
  assert.doesNotThrow(() => searchRows({ ...result, completion: 'match_limit', complete: false }));
  assert.throws(() => searchRows({ ...result, completion: 'match_limit', complete: true }));
  assert.throws(() => searchRows({ ...result, returned_matches: 0 }));
  for (const change of [{ path_hex: '2e2e2f61' }, { path_hex: '2f61' }, { path_hex: '612f' },
    { byte_offset: Number.MAX_SAFE_INTEGER + 1 }, { line: 0 }, { match_length: 256 }]) {
    assert.throws(() => searchRows({ ...result, matches: [{ ...result.matches[0], ...change }] }));
  }
});
test('zero object IDs and unsupported hash formats cannot become snapshot comparisons', () => {
  assert.throws(() => commitHex('0'.repeat(40), 'sha1'));
  assert.throws(() => commitHex('a'.repeat(64), 'md5'));
});
