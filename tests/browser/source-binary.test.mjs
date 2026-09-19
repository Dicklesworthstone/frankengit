// Native-shaped HTTP doubles exercise the real source client and byte encoder.
// Actual Git application is a separate pinned non-production command.
import test from 'node:test';
import assert from 'node:assert/strict';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { fullFilePatch, fileBytes, normalizeEdits, FILE_LIMIT, PATCH_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, href, token, crypto, metadata, decodeUpload } from './source-edit-fixtures.mjs';
const binary = { allowBinary: true };
const side = (bytes, mode = 0o100644) => ({ bytes: Uint8Array.from(bytes), mode });
const row = (before, after, path = 'asset.bin') => ({ path_hex: Buffer.from(path).toString('hex'), before, after });
const all = Uint8Array.from({ length: 256 }, (_, n) => n);
export const binaryEdit = () => row(side([0, 255, 13, 10, 0, 1]), side([0, 254, 0, 10, 13], 0o100755));
async function connect(f) { const c = new SourceEditClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto }); await c.connect(token); return c; }
async function selected(f) { const c = await connect(f); await c.select('refs/heads/main', f.algorithm); return c; }
async function ready(f) { const c = await selected(f); await c.prepareEdits(f.edits, metadata); return c; }
const cases = [
  ['creation', row(null, side(all))], ['deletion', row(side(all), null)],
  ['replacement', binaryEdit()], ['mode-only', row(side(all), side(all, 0o100755))],
  ['binary to empty', row(side(all), side([]))], ['empty to binary', row(side([]), side(all))],
  ['binary to text', row(side(all), side(utf8.encode('text\r\n')))],
  ['text to binary', row(side(utf8.encode('text')), side(all))],
];
for (const algorithm of ['sha1', 'sha256']) {
  for (const [name, edit] of cases) test(`${algorithm}: ${name} retains exact byte payloads through preparation, inspection and publication`, async () => {
    const f = await fixture(algorithm, [edit], binary), c = await selected(f);
    if (edit.before) assert.deepEqual((await c.loadFile(edit.path_hex)).before.bytes, edit.before.bytes);
    f.inspection.comparison.entries[0].content = { type: 'binary', body_included: false,
      before_bytes: edit.before?.bytes.length ?? 0, after_bytes: edit.after?.bytes.length ?? 0 };
    await c.prepareEdits([edit], metadata);
    const prepare = f.calls.find(call => call.endpoint === 'source/prepare');
    assert.deepEqual(decodeUpload(prepare.options).payload, f.patch.bytes);
    assert(!Buffer.from(f.patch.bytes).includes('GIT binary patch'));
    assert.equal(c.candidate.inspection.binary_bodies_included, false);
    assert(!f.calls.some(call => call.endpoint === 'source/apply'));
    const pending = await c.stageApply(); assert.equal(pending.sent, false);
    assert.equal((await c.send()).outcome, 'committed');
    assert.equal(f.calls.at(-1).headers['idempotency-key'], pending.key);
  });
  test(`${algorithm}: binary publication survives a lost response and byte-identical original-key restore`, async () => {
    const f = await fixture(algorithm, [binaryEdit()], binary), c = await ready(f);
    await c.stageApply(); f.config.loseApply = true; await assert.rejects(c.send(), error => error.outcomeUnknown);
    const original = f.calls.at(-1), saved = c.exportReceipt(); assert(!saved.includes(token));
    c.disconnect(); assert(c.pending);
    const next = await connect(f), before = f.calls.length; await next.restoreReceipt(saved);
    assert.equal(f.calls.length, before); f.config.loseApply = false;
    await next.send(); assert.equal(f.calls.length, before + 1);
    assert.deepEqual(f.calls.at(-1).body, original.body);
    assert.equal(f.calls.at(-1).headers['idempotency-key'], original.headers['idempotency-key']);
  });
  test(`${algorithm}: binary file bytes are native-ID checked, not accepted because the header says binary`, async () => {
    const f = await fixture(algorithm, [binaryEdit()], binary), c = await selected(f);
    f.config.read = r => r.content_hex = r.content_hex.replace('ff', 'fe');
    await assert.rejects(c.loadFile(f.edits[0].path_hex)); assert.equal(c.candidate, null);
  });
}
test('shared text and initial-history encoder profiles remain explicitly NUL-refusing', () => {
  assert.throws(() => fileBytes(Uint8Array.of(0)));
  assert.throws(() => fullFilePatch([binaryEdit()]));
  assert.throws(() => normalizeEdits([binaryEdit()]));
  assert.deepEqual(fileBytes(all, true), all);
  for (const allowBinary of ['yes', 1, null, {}, []]) {
    assert.throws(() => fileBytes(all, allowBinary));
    assert.throws(() => fullFilePatch([binaryEdit()], { allowBinary }));
  }
  assert.throws(() => fullFilePatch([binaryEdit()], { force: true }));
});
test('binary opt-in does not change any non-NUL patch bytes', () => {
  for (const value of ['', '\n', 'before\r\n', '\ufffd', 'a\rb', '\ufefflast']) {
    const edits = [row(null, side(utf8.encode(value)))];
    assert.deepEqual(fullFilePatch(edits, binary).bytes, fullFilePatch(edits).bytes);
  }
});
test('binary literal hunks retain NUL, invalid UTF-8, CRLF and missing final newlines', () => {
  const patch = fullFilePatch([binaryEdit()], binary).bytes;
  assert(Buffer.from(patch).includes(Buffer.from('-\0\xff\r\n', 'latin1')));
  assert(Buffer.from(patch).includes(Buffer.from('+\0\xfe\0\n', 'latin1')));
  assert(Buffer.from(patch).includes(Buffer.from('\\ No newline at end of file\n')));
});
test('byte-preserving patches are independent of file ordering and caller mutation', () => {
  const a = binaryEdit(), b = row(null, side(all), Buffer.from([0x7a, 0xff]));
  const first = fullFilePatch([b, a], binary), second = fullFilePatch([a, b], binary);
  assert.deepEqual(first.bytes, second.bytes); a.before.bytes.fill(9); a.after.bytes.fill(8);
  assert.notDeepEqual(first.edits[0].before.bytes, a.before.bytes);
  assert.deepEqual(first.bytes, second.bytes);
});
test('maximum permitted many-line patch does not overflow the JavaScript argument stack', () => {
  const after = new Uint8Array(65535).fill(10); after[0] = 0;
  const edits = [row(side([0]), side(after))];
  const patch = fullFilePatch(edits, binary); assert(patch.bytes.length < PATCH_LIMIT);
  assert.equal(patch.edits[0].after.bytes.length, after.length);
});
test('binary file and aggregate limits still refuse before producing a candidate', () => {
  assert(fullFilePatch([row(null, side(new Uint8Array(FILE_LIMIT)))], binary).bytes.length < PATCH_LIMIT);
  for (const edits of [[row(null, side(new Uint8Array(FILE_LIMIT + 1)))],
    Array.from({ length: 5 }, (_, i) => row(null, side(new Uint8Array(FILE_LIMIT)), `asset${i}`)),
    [row(null, side(new Uint8Array(65537).fill(10)))],
    [row(null, side([0], 0o120000))], [row(side([0]), side([0]))],
    [row(null, side([0]), 'path\0bad')], [row(null, side([0]), '.git/object')],
    [row(null, side([0]), 'x'), row(null, side([1]), 'x/y')]]) {
    assert.throws(() => fullFilePatch(edits, binary));
  }
});
for (const [name, alter] of [
  ['byte length', r => r.total_bytes++], ['continued blob', r => r.next_offset = 1],
  ['wrong mode', r => r.kind = 'symlink'], ['snapshot', r => r.snapshot_token = `alg:1:${'8'.repeat(64)}`],
]) test(`binary load refuses ${name} without returning a file prefix`, async () => {
  const f = await fixture('sha1', [binaryEdit()], binary), c = await selected(f);
  f.config.read = alter; await assert.rejects(c.loadFile(f.edits[0].path_hex));
});
for (const [name, alter] of [
  ['changed content ID', r => r.comparison.entries[0].after.oid = 'e'.repeat(40)],
  ['extra changed path', r => r.comparison.entries.push(r.comparison.entries[0])],
  ['included binary body', r => { r.comparison.entries[0].content = { type: 'binary', body_included: true, before_bytes: 6, after_bytes: 5 }; }],
]) test(`binary inspection rejects ${name} before publication`, async () => {
  const f = await fixture('sha1', [binaryEdit()], binary), c = await selected(f);
  f.config.inspect = alter; await assert.rejects(c.prepareEdits(f.edits, metadata));
  assert.equal(c.candidate, null); await assert.rejects(c.stageApply());
});
test('binary inputs are captured before hashing, and cancellation discards a late inspected artifact', async () => {
  const edits = [binaryEdit()], f = await fixture('sha1', edits, binary), c = await selected(f);
  const preparing = c.prepareEdits(edits, metadata); edits[0].after.bytes.fill(99); await preparing;
  assert.deepEqual(decodeUpload(f.calls.find(call => call.endpoint === 'source/prepare').options).payload, f.patch.bytes);
  let release; f.config.inspect = () => new Promise(resolve => { release = resolve; });
  const next = c.prepareEdits([binaryEdit()], metadata);
  while (!release) await new Promise(setImmediate);
  c.disconnect(); release(); await assert.rejects(next); assert.equal(c.candidate, null);
});
test('binary outcomes remain unresolved until the original transaction is actually terminal', async () => {
  const f = await fixture('sha1', [binaryEdit()], binary), c = await ready(f); await c.stageApply();
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    f.config.outcome = state; assert.equal((await c.recover()).terminal, false); assert(c.pending);
    assert.equal(f.calls.at(-1).body, undefined);
  }
  f.config.outcome = 'committed'; assert.equal((await c.recover()).terminal, true); assert.equal(c.pending, null);
});
