import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { EDIT_LIMITS, buildPatch, bytesHex, pathBytes, textBytes, exactText, quotedPath, gitObjectId } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
const b = value => new TextEncoder().encode(value), p = value => bytesHex(b(value));
const side = (text, mode = 0o100644) => ({ bytes: b(text), mode });
const change = (old = 'old\n', next = 'new\n', name = 'file') => ({ path_hex: p(name), before: side(old), after: side(next) });
for (const algorithm of ['sha1', 'sha256']) {
  test(`full native ${algorithm} blob expectations and complete byte hunks`, async () => {
    const result = await buildPatch([change('a\r\nb', 'c\r\nd')], algorithm);
    const patch = new TextDecoder().decode(result.bytes);
    assert.match(patch, /@@ -1,2 \+1,2 @@\n-a\r\n-b\n\\ No newline at end of file\n\+c\r\n\+d\n\\ No newline at end of file\n/);
    const expected = createHash(algorithm).update('blob 4\0').update('a\r\nb').digest('hex');
    assert.equal(result.paths[0].old_blob, expected); assert.ok(patch.includes(expected));
  });
  test(`empty files and executable-only changes are not lost (${algorithm})`, async () => {
    const edits = [{ path_hex: p('create'), before: null, after: side('') },
      { path_hex: p('delete'), before: side(''), after: null },
      { path_hex: p('mode'), before: side('same'), after: side('same', 0o100755) }];
    const result = await buildPatch(edits, algorithm);
    assert.deepEqual(result.paths.map(x => [x.path_hex, x.hunks]), edits.map(x => [x.path_hex, 0]));
    assert.match(new TextDecoder().decode(result.bytes), /old mode 100644\nnew mode 100755/);
  });
}
test('quoted paths preserve spaces, control and non-UTF8 bytes without metadata injection', () => {
  const bytes = Uint8Array.from([97, 47, 32, 34, 92, 10, 9, 255]);
  assert.equal(quotedPath(bytes, 'a/'), '"a/a/ \\"\\\\\\012\\011\\377"');
  assert.equal(bytesHex(pathBytes(bytesHex(bytes))), bytesHex(bytes));
});
for (const value of ['', '/abs', 'x/', 'a//b', '.', '..', 'a/../b', 'a/.GiT/config', 'x\0x', `${'a/'.repeat(64)}a`]) {
  test(`unsafe path refuses: ${JSON.stringify(value)}`, () => assert.throws(() => pathBytes(p(value))));
}
test('duplicate and non-adjacent overlapping paths refuse, sorted independent paths are deterministic', async () => {
  await assert.rejects(buildPatch([change(), change()], 'sha1'), /Duplicate/);
  await assert.rejects(buildPatch([change('a','b','a'), change('a','b','a-'), change('a','b','a/b')], 'sha1'), /Overlapping/);
  const edits = [change('a', 'b', 'z'), change('c', 'd', 'a')];
  assert.deepEqual(await buildPatch(edits, 'sha1'), await buildPatch([...edits].reverse(), 'sha1'));
});
test('no-op removal cannot turn an empty change into a candidate', async () => {
  await assert.rejects(buildPatch([change('same', 'same')], 'sha1'), /No file changes/);
  const result = await buildPatch([change('same','same','noop'), change()], 'sha1');
  assert.equal(result.paths.length, 1);
});
test('unknown fields, unsupported modes, NUL content and invalid hash domains fail before hashing', async () => {
  let calls = 0; const crypto = { subtle: { digest() { calls++; throw new Error('must not hash'); } } };
  for (const edits of [[{ ...change(), force: true }], [{ ...change(), after: side('x', 0o120000) }],
    [{ ...change(), before: side('\0') }], [{ ...change(), before: undefined }],
    [{ path_hex: p('a'), before: null, after: null }], []]) {
    await assert.rejects(buildPatch(edits, 'sha1', { crypto }));
  }
  await assert.rejects(buildPatch([change()], 'sha512', { crypto })); assert.equal(calls, 0);
});
test('file/count/total/path byte bounds apply before owned copies and hashing', async () => {
  const file = new Uint8Array(EDIT_LIMITS.fileBytes + 1).fill(97);
  await assert.rejects(buildPatch([{ ...change(), after: { bytes: file, mode: 0o100644 } }], 'sha1'), /1 MiB/);
  await assert.rejects(buildPatch(Array.from({ length: 65 }, (_, i) => change('a','b',`f${i}`)), 'sha1'), /64/);
  await assert.rejects(buildPatch(Array.from({ length: 3 }, (_, i) => ({ path_hex: p(`f${i}`), before: { bytes: file.subarray(1), mode: 0o100644 }, after: { bytes: file.subarray(1), mode: 0o100755 } })), 'sha1'), /4 MiB/);
  assert.throws(() => pathBytes('61'.repeat(4097)));
});
test('line amplification is bounded independently of byte size', async () => {
  await assert.rejects(buildPatch([change('\n'.repeat(80_000), '\n'.repeat(80_001))], 'sha1'), /line budget/);
});
test('owned inputs are immutable across digest awaits', async () => {
  let release; const gate = new Promise(resolve => { release = resolve; }); let first = true;
  const crypto = { subtle: { async digest(...args) { if (first) { first = false; await gate; } return webcrypto.subtle.digest(...args); } } };
  const edit = change(); const wanted = await buildPatch([edit], 'sha1');
  const pending = buildPatch([edit], 'sha1', { crypto }); edit.before.bytes.fill(120); edit.after.bytes.fill(121); edit.path_hex = p('changed');
  release(); assert.deepEqual(await pending, wanted);
});
test('cancellation before and after hashing never returns a usable patch', async () => {
  const controller = new AbortController(); controller.abort(); await assert.rejects(buildPatch([change()], 'sha1', { signal: controller.signal }), { name: 'AbortError' });
  const late = new AbortController(); const crypto = { subtle: { async digest(...args) { const out = await webcrypto.subtle.digest(...args); late.abort(); return out; } } };
  await assert.rejects(buildPatch([change()], 'sha1', { signal: late.signal, crypto }), { name: 'AbortError' });
});
test('UTF-8 editing preserves BOM, CRLF and missing newline and rejects replacement decoding', () => {
  const value = '\uFEFFhello\r\nlast'; assert.equal(exactText(textBytes(value)), value);
  assert.throws(() => exactText(Uint8Array.of(255))); assert.throws(() => exactText(Uint8Array.of(0)));
  assert.throws(() => textBytes('\ud800')); assert.throws(() => textBytes('\0'));
  assert.throws(() => textBytes('é'.repeat(EDIT_LIMITS.fileBytes)));
});
test('object hashes use native kind/size/NUL framing', async () => {
  const bytes = b('hello\n'); assert.equal(await gitObjectId('blob', bytes, 'sha1'), 'ce013625030ba8dba906f756967f9e9ca394464a');
  await assert.rejects(gitObjectId('tree', bytes, 'sha1'));
});
