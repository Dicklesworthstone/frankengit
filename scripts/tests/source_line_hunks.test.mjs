// Byte-level differential checks against installed Git, a test-only oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { buildPatch, MULTI_HUNK_PATCH_PROFILE as PROFILE, LINE_DIFF_LIMITS } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { changeFixture, hexPath } from './source_changes_fixture.mjs';
const input = (after, extra = {}) => ({ schema: 'frankengit-source-changes-v1', patch_profile: PROFILE, ...extra,
  changes: [{ path_hex: hexPath('file'), operation: 'replace', content_hex: Buffer.from(after).toString('hex') }] });
const side = (bytes, mode = 0o100644) => bytes === null ? null : { bytes: Buffer.from(bytes), mode };
const edits = (before, after, mode = 0o100644) => [{ path_hex: hexPath('file'), before: side(before), after: side(after, mode) }];
const encode = (before, after, format = 'sha1', options = {}) => buildPatch(edits(before, after), format, { crypto: webcrypto, patchProfile: PROFILE, ...options });
async function oracle(t, format) {
  const root = await mkdtemp(join(tmpdir(), 'fg-line-hunks-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_COUNT: '0', GIT_OPTIONAL_LOCKS: '0', LC_ALL: 'C' };
  const git = (args, bytes) => execFileSync('git', ['-C', root, ...args], { env, input: bytes, timeout: 15000, maxBuffer: 8 * 1024 * 1024 });
  git(['init', '--quiet', `--object-format=${format}`]);
  return (before, after, patch, mode = 0o100644, path = Buffer.from('file')) => {
    git(['read-tree', '--empty']);
    if (before !== null) {
      const id = git(['hash-object', '-w', '--stdin'], Buffer.from(before)).toString().trim();
      git(['update-index', '-z', '--index-info'], Buffer.concat([Buffer.from(`100644 ${id}\t`), path, Buffer.from([0])]));
    }
    const originalTree = git(['write-tree']).toString().trim();
    git(['apply', '--cached', '--binary', '--whitespace=nowarn', '-'], Buffer.from(patch));
    const expected = changeFixture(format, after === null ? [] : [{ path, bytes: after, mode }]);
    const result = git(['write-tree']).toString().trim(); assert.equal(result, expected.tree);
    if (after !== null) assert.deepEqual(git(['cat-file', 'blob', expected.files[0].id]), Buffer.from(after));
    git(['apply', '--cached', '--binary', '--reverse', '--whitespace=nowarn', '-'], Buffer.from(patch));
    assert.equal(git(['write-tree']).toString().trim(), originalTree);
    return result;
  };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: two distant one-line changes fit as two hunks where edge trimming exceeds one MiB`, async t => {
    const check = await oracle(t, format), before = Buffer.from('unchanged line\n'.repeat(65500)), after = Buffer.from(before);
    Buffer.from('different line').copy(after, 15 * 10); Buffer.from('different line').copy(after, 15 * 65480);
    const f = changeFixture(format, [{ path: 'file', bytes: before }]);
    await assert.rejects(buildSourceChanges(f.bytes, f.expected, input(after, { patch_profile: 'trim-common-lines-v1' })), /patch_budget/);
    const result = await buildSourceChanges(f.bytes, f.expected, input(after));
    assert.equal(result.manifest.effects[0].hunks, 2);
    assert.ok(result.bytes.length < 700, result.bytes.length);
    assert.equal((result.bytes.toString().match(/^@@ /gm) ?? []).length, 2);
    assert.equal(result.tree.afterTree, check(before, after, result.bytes));
    assert.deepEqual(await buildSourceChanges(f.bytes, f.expected, input(after)), result);
  });
  test(`${format}: hunk grouping coalesces six common lines but separates seven`, async t => {
    const check = await oracle(t, format);
    for (const gap of [0, 1, 5, 6, 7, 8, 20]) {
      const middle = 'same\n'.repeat(gap), before = `old\n${middle}before\n`, after = `new\n${middle}after\n`;
      const p = await encode(before, after, format);
      assert.equal(p.paths[0].hunks, gap > 6 ? 2 : 1, `gap=${gap}`); check(before, after, p.bytes);
    }
  });
  test(`${format}: insertions, removals, mode changes and shifted zero-line coordinates reverse exactly`, async t => {
    const check = await oracle(t, format), middle = 'keep\n'.repeat(20);
    const cases = [['', 'new\n'], ['old\n', ''], [null, 'created\n'], ['removed', null], [null, ''], ['', null],
      ['\n', ''], ['', '\n'], ['a\n', 'a'], ['a', 'a\n'], ['\na', '\nb'],
      [middle, `head\n${middle}tail\n`], [`head\n${middle}tail\n`, middle],
      [`a\n${middle}b`, `A\n${middle}B`], [`a\r\n${middle}b\r\n`, `A\r\n${middle}B\r\n`],
      [`same\n${middle}end\n`, `same\nINSERT\n${middle}END\n`],
      [`a\na\nb\na\nb\n`, `b\na\nb\na\na\n`]];
    for (const [before, after] of cases) {
      const p = await buildPatch(edits(before, after, 0o100755), format, { crypto: webcrypto, patchProfile: PROFILE });
      check(before, after, p.bytes, 0o100755);
    }
    const p = await buildPatch(edits('same', 'same', 0o100755), format, { crypto: webcrypto, patchProfile: PROFILE });
    assert.equal(p.paths[0].hunks, 0); check('same', 'same', p.bytes, 0o100755);
  });
  test(`${format}: arbitrary bytes, raw paths and explicit binary consent survive multi-hunk encoding`, async t => {
    const check = await oracle(t, format), path = Buffer.from([0xff, 34, 92, 9, 97]);
    const before = Buffer.concat([Buffer.from([0, 255, 10]), Buffer.from('same\n'.repeat(30)), Buffer.from(Array.from({ length: 256 }, (_, i) => i))]);
    const after = Buffer.from(before); after[1] = 254; after[after.length - 2] = 1;
    const raw = edits(before, after); raw[0].path_hex = path.toString('hex');
    await assert.rejects(buildPatch(raw, format, { crypto: webcrypto, patchProfile: PROFILE }), /NUL/);
    const p = await buildPatch(raw, format, { crypto: webcrypto, patchProfile: PROFILE, allowBinary: true });
    assert.equal(p.paths[0].hunks, 2); check(before, after, p.bytes, 0o100644, path);
  });
  test(`${format}: 64 seeded repeated-line edits agree with Git forward and reverse`, async t => {
    const check = await oracle(t, format); let seed = 0x6e62f30d;
    const random = n => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % n; };
    for (let trial = 0; trial < 64; trial++) {
      const a = Array.from({ length: 8 + random(40) }, () => ['a\n', 'b\n', '\n', 'c\r\n'][random(4)]), b = [...a];
      for (let op = 0; op < 4; op++) b.splice(random(b.length + 1), random(3), ...Array.from({ length: random(3) }, () => ['x\n', 'b\n', 'y\n'][random(3)]));
      let before = a.join(''), after = b.join('');
      if (trial % 3 === 0) before = before.replace(/\n$/, '');
      if (trial % 4 === 0) after = after.replace(/\n$/, '');
      if (before === after) after += 'different\n';
      const p = await encode(before, after, format); check(before, after, p.bytes);
    }
  });
}
// Independent quadratic reference is deliberately confined to tiny test inputs.
function referenceDistance(a, b) {
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const next = [i];
    for (let j = 1; j <= b.length; j++) next[j] = a[i - 1] === b[j - 1] ? previous[j - 1] : 1 + Math.min(previous[j], next[j - 1]);
    previous = next;
  }
  return previous[b.length];
}
test('every nonidentical pair of binary-alphabet sequences through length three matches the reference edit distance', async () => {
  const all = [[]]; for (let n = 1; n <= 3; n++) for (let bits = 0; bits < 2 ** n; bits++) all.push(Array.from({ length: n }, (_, at) => bits & (1 << at) ? 'a\n' : 'b\n'));
  for (const a of all) for (const b of all) {
    if (a.join('') === b.join('')) continue;
    const p = await encode(a.join(''), b.join(''));
    const rows = Buffer.from(p.bytes).toString().split('\n'); let edits = 0, inHunk = false;
    for (const row of rows) { if (row.startsWith('@@ ')) inHunk = true; else if (inHunk && /^[+-]/.test(row)) edits++; }
    assert.equal(edits, referenceDistance(a, b), JSON.stringify([a, b]));
  }
});
test('distance ceiling admits 128 full line replacements and refuses 129 without partial success', async () => {
  const pair = n => [Array.from({ length: n }, (_, i) => `a${i}\n`).join(''), Array.from({ length: n }, (_, i) => `b${i}\n`).join('')];
  const yes = await encode(...pair(128)); assert.equal(yes.paths[0].hunks, 1);
  await assert.rejects(encode(...pair(129)), { code: 'source_patch_diff_distance_limit' });
});
test('line-offset budget admits its exact total and refuses one additional line', async () => {
  const half = LINE_DIFF_LIMITS.maxLines / 2;
  const before = '\n'.repeat(half), after = 'x' + before;
  assert.equal((await encode(before, after)).paths[0].hunks, 1);
  await assert.rejects(encode(before, after + '\n'), { code: 'source_patch_diff_line_limit' });
});
test('byte-comparison work is bounded even for adversarial equal-length long lines', async () => {
  const a = 'x'.repeat(1998) + 'a\n', b = 'x'.repeat(1998) + 'b\n';
  await assert.rejects(encode(a.repeat(450), b.repeat(450)), { code: 'source_patch_diff_work_limit' });
  assert.equal((await encode(a.repeat(450), a.repeat(225) + b + a.repeat(224))).paths[0].hunks, 1);
});
test('event-loop cancellation interrupts line planning after input hashes have completed', async () => {
  const stop = new AbortController(); let hashes = 0, timer, aborted = false;
  const crypto = { subtle: { async digest(...args) {
    const result = await webcrypto.subtle.digest(...args);
    if (++hashes === 2) timer = setTimeout(() => { aborted = true; stop.abort(new Error('cancel during line diff')); }, 0);
    return result;
  } } };
  try {
    await assert.rejects(encode('a\n'.repeat(200000), 'x\n' + 'a\n'.repeat(199999), 'sha1', { crypto, signal: stop.signal }), /cancel during line diff/);
    assert.equal(hashes, 2); assert.equal(aborted, true);
  } finally { clearTimeout(timer); }
});
test('owned caller buffers and exact output-byte bounds remain enforced', async () => {
  const before = Buffer.from('old\n' + 'same\n'.repeat(20) + 'end\n'), after = Buffer.from('new\n' + 'same\n'.repeat(20) + 'END\n');
  const expected = await encode(before, after), e = edits(before, after), pending = buildPatch(e, 'sha1', { crypto: webcrypto, patchProfile: PROFILE });
  e[0].before.bytes.fill(0); e[0].after.bytes.fill(0); e[0].path_hex = 'bad';
  assert.deepEqual(await pending, expected);
  const f = changeFixture('sha1', [{ path: 'file', bytes: before }]), wanted = input(after);
  const draft = await buildSourceChanges(f.bytes, f.expected, wanted);
  assert.deepEqual(await buildSourceChanges(f.bytes, f.expected, wanted, { limits: { patchBytes: draft.bytes.length } }), draft);
  await assert.rejects(buildSourceChanges(f.bytes, f.expected, wanted, { limits: { patchBytes: draft.bytes.length - 1 } }), /patch_budget/);
  const previous = await buildSourceChanges(f.bytes, f.expected, { ...wanted, patch_profile: 'trim-common-lines-v1' });
  assert.equal(previous.tree.afterTree, draft.tree.afterTree); assert.notEqual(sha256(canonical(previous.manifest)), sha256(canonical(draft.manifest)));
});
test('shared hunk ceiling admits 4096 hunks across files and refuses a 4097th', async () => {
  const selected = extra => Array.from({ length: 64 }, (_, i) => {
    const count = 64 + Number(extra && i === 63);
    return { path_hex: hexPath(`f${i.toString().padStart(2, '0')}`),
      before: side(('a\n' + '\n'.repeat(7)).repeat(count)), after: side(('b\n' + '\n'.repeat(7)).repeat(count)) };
  });
  const p = await buildPatch(selected(false), 'sha1', { crypto: webcrypto, patchProfile: PROFILE });
  assert.equal(p.paths.reduce((total, row) => total + row.hunks, 0), LINE_DIFF_LIMITS.maxHunks);
  await assert.rejects(buildPatch(selected(true), 'sha1', { crypto: webcrypto, patchProfile: PROFILE }), { code: 'source_patch_diff_hunk_limit' });
});
