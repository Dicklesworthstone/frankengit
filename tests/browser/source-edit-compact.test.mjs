// Git is a test-only byte/tree oracle, never an implementation dependency.
// This exercises the real browser encoder, not native admission or a Rust node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { installIndex } from './git-index-fixture.mjs';
import { fullFilePatch, normalizeEdits, FILE_LIMIT, PATCH_LIMIT, INPUT_LIMIT, renameEdits } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';

const bytes = value => typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value);
const side = (value, mode = 0o100644) => value === null ? null : { bytes: bytes(value), mode };
const edit = (before, after, name = 'file') => ({ path_hex: Buffer.from(name).toString('hex'), before: side(before), after: side(after) });
const lines = n => Array.from({ length: n }, (_, i) => `line-${i}\n`);
const text = value => Buffer.from(value).toString();

function git(root, args, input) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  Object.assign(env, { GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' });
  const result = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.filemode=true', ...args], {
    cwd: root, env, input, timeout: 30_000, maxBuffer: 2 * 1024 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${args.join(' ')}\n${result.stderr}`);
  assert(!/offset [+-]?[1-9][0-9]* lines?/.test(String(result.stderr)), 'oracle must not relocate a hunk');
  return String(result.stdout).trim();
}
function install(root, edits, selected) {
  for (const row of edits) {
    const value = row[selected];
    if (value === null) continue;
    const path = Buffer.concat([Buffer.from(`${root}/`), Buffer.from(row.path_hex, 'hex')]);
    // The generated test paths only have ASCII directory components; the leaf
    // may contain non-UTF-8 bytes, whitespace, backslashes or quotes.
    const slash = path.lastIndexOf(47); mkdirSync(path.subarray(0, slash), { recursive: true });
    writeFileSync(path, value.bytes); chmodSync(path, value.mode & 0o777);
  }
  git(root, ['add', '--all']);
  return git(root, ['write-tree']);
}
function roundTrip(edits, algorithm, options = {}, indexOnly = false) {
  const root = mkdtempSync(join(tmpdir(), 'fgit-browser-patch-'));
  try {
    const actual = join(root, 'actual'), expected = join(root, 'expected');
    for (const path of [actual, expected]) { mkdirSync(path); git(path, ['init', '-q', `--object-format=${algorithm}`]); }
    const installSide = (root, side) => indexOnly
      ? installIndex((args, input) => git(root, args, input), edits, side)
      : install(root, edits, side);
    const beforeTree = installSide(actual, 'before'), afterTree = installSide(expected, 'after');
    const patch = fullFilePatch(edits, options);
    const target = indexOnly ? '--cached' : '--index';
    git(actual, ['apply', '--check', target, '--whitespace=nowarn', '-'], patch.bytes);
    git(actual, ['apply', '--verbose', target, '--whitespace=nowarn', '-'], patch.bytes);
    assert.equal(git(actual, ['write-tree']), afterTree, 'forward patch must produce the independently built complete tree');
    for (const row of edits) if (!indexOnly && row.after !== null) {
      const path = Buffer.concat([Buffer.from(`${actual}/`), Buffer.from(row.path_hex, 'hex')]);
      assert.deepEqual(new Uint8Array(readFileSync(path)), row.after.bytes);
    }
    git(actual, ['apply', '--reverse', '--verbose', target, '--whitespace=nowarn', '-'], patch.bytes);
    assert.equal(git(actual, ['write-tree']), beforeTree, 'reverse patch must restore the original complete tree');
    return patch;
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test('two full-size files with tiny edits fit without raising the encoded patch ceiling', () => {
  const before = bytes(`${'a'.repeat(63)}\n`.repeat(FILE_LIMIT / 64)), after = before.slice();
  after[FILE_LIMIT / 2] = 98;
  const edits = [edit(before, after, 'one'), edit(before, after, 'two')];
  assert.equal(edits.reduce((n, e) => n + e.before.bytes.length + e.after.bytes.length, 0), PATCH_LIMIT);
  const patch = fullFilePatch(edits);
  assert(patch.bytes.length < 2048, `small changes should not resend ${PATCH_LIMIT} bytes: ${patch.bytes.length}`);
  assert.deepEqual(patch.edits, edits);
  after.fill(0); edits[0].after.bytes.fill(0);
  assert.equal(patch.edits[0].after.bytes[FILE_LIMIT / 2], 98, 'complete verified effects remain detached');
});

test('trimmed hunk keeps exact line positions and three context lines', () => {
  const before = lines(30), after = before.slice(); after[15] = 'replacement\n';
  const patch = text(fullFilePatch([edit(before.join(''), after.join(''))]).bytes);
  assert(patch.includes('@@ -13,7 +13,7 @@\n'));
  assert(patch.includes(' line-12\n line-13\n line-14\n-line-15\n+replacement\n line-16\n line-17\n line-18\n'));
  assert(!patch.includes('line-0\n')); assert(!patch.includes('line-29\n'));
});

test('existing short-file patch bytes and no-newline markers stay unchanged', () => {
  assert.equal(text(fullFilePatch([edit('before\r\n', 'after')]).bytes),
    'diff --git "a/file" "b/file"\n--- "a/file"\n+++ "b/file"\n@@ -1,1 +1,1 @@\n-before\r\n+after\n\\ No newline at end of file\n');
});

test('compact encoding still refuses a large changed region and unsafe or unbounded input', () => {
  const large = bytes('a'.repeat(FILE_LIMIT)), other = bytes('b'.repeat(FILE_LIMIT));
  assert.throws(() => fullFilePatch([edit(large, other, 'one'), edit(large, other, 'two')]), /Encoded patch exceeds/);
  assert.throws(() => fullFilePatch([edit('', new Uint8Array(FILE_LIMIT + 1))]), /256 KiB/);
  assert.throws(() => fullFilePatch([edit('old', '\n'.repeat(65537))]), /line budget/);
  assert.throws(() => fullFilePatch([edit('old', '\0')]), /NUL/);
  assert.throws(() => fullFilePatch([edit('old', 'new', '../bad')]), /Unsafe/);
  assert.throws(() => fullFilePatch([edit('old', 'new', '.git/config')]), /Unsafe/);
  assert.throws(() => fullFilePatch([edit('old', 'new', 'a'), edit('old', 'new', 'a/b')]), /Overlapping/);
});

for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: full-size multi-file edits reproduce the complete intended trees`, () => {
    const before = bytes(`${'a'.repeat(63)}\n`.repeat(FILE_LIMIT / 64)), after = before.slice();
    after[FILE_LIMIT / 2] = 98;
    roundTrip([edit(before, after, 'one'), edit(before, after, 'two')], algorithm);
  });
  const original = lines(30);
  const cases = [
    ['middle replacement', edit(original.join(''), original.map((v, i) => i === 15 ? 'new\r\n' : v).join(''))],
    ['start insertion', edit(original.join(''), `new\n${original.join('')}`)],
    ['end insertion', edit(original.join(''), `${original.join('')}new\n`)],
    ['middle insertion', edit(original.join(''), [...original.slice(0, 15), 'new\n', ...original.slice(15)].join(''))],
    ['start deletion', edit(original.join(''), original.slice(1).join(''))],
    ['end deletion', edit(original.join(''), original.slice(0, -1).join(''))],
    ['middle deletion', edit(original.join(''), [...original.slice(0, 15), ...original.slice(16)].join(''))],
    ['add final newline', edit(original.join('').slice(0, -1), original.join(''))],
    ['remove final newline', edit(original.join(''), original.join('').slice(0, -1))],
    ['unchanged unterminated suffix', edit(`${original.join('')}tail`, `new\n${original.slice(1).join('')}tail`)],
    ['blank and CRLF lines', edit('\r\n'.repeat(40), `${'\r\n'.repeat(20)}\n${'\r\n'.repeat(20)}`)],
    ['new file', edit(null, original.join(''))],
    ['delete file', edit(original.join(''), null)],
    ['new empty file', edit(null, '')],
    ['delete empty file', edit('', null)],
    ['empty to nonempty', edit('', original.join(''))],
    ['nonempty to empty', edit(original.join(''), '')],
  ];
  for (const [name, row] of cases) test(`${algorithm}: ${name} preserves forward and reverse trees`, () => roundTrip([row], algorithm));

  for (const indexOnly of [false, true]) test(`${algorithm}: mode changes, ${indexOnly ? 'arbitrary byte names in Git objects' : 'host-representable names'}, binary opt-in and renames compose`, () => {
    const before = Buffer.concat([Buffer.from(original.join('')), Buffer.from([0, 255, 13, 10])]);
    const after = Buffer.from(before); after[65] ^= 1;
    const name = indexOnly ? Buffer.from([97, 32, 34, 92, 10, 255]) : Buffer.from('a "\\\né');
    const raw = edit(before, after, name); raw.after.mode = 0o100755;
    const mode = edit(original.join(''), original.join(''), 'script'); mode.after.mode = 0o100755;
    const moving = renameEdits(Buffer.from('old-name').toString('hex'), Buffer.from('new-name').toString('hex'), side('rename\n'));
    const rows = [...moving, mode, raw];
    const first = roundTrip(rows, algorithm, { allowBinary: true }, indexOnly);
    assert.deepEqual(first.bytes, fullFilePatch([...rows].reverse(), { allowBinary: true }).bytes);
    assert.deepEqual(first.edits.find(e => e.path_hex === raw.path_hex).after.bytes, new Uint8Array(after));
  });
}

// Independent position-exact application: unlike Git's general patch reader,
// this oracle cannot relocate a hunk or search for matching context elsewhere.
function records(input) {
  const result = [], buffer = Buffer.from(input); let start = 0;
  while (start < buffer.length) {
    const lf = buffer.indexOf(10, start), end = lf < 0 ? buffer.length : lf + 1;
    result.push(buffer.subarray(start, end)); start = end;
  }
  return result;
}
function applyAtDeclaredPositions(before, patch) {
  const source = records(before), encoded = records(patch), result = [];
  let cursor = 0, i = encoded.findIndex(row => row.subarray(0, 3).equals(Buffer.from('@@ ')));
  assert(i >= 0, 'a changed byte sequence must have a hunk');
  while (i < encoded.length) {
    const match = /^@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n$/.exec(String(encoded[i++]));
    assert(match, 'only counted exact hunks are expected');
    const [, a, b, c, d] = match.map(Number), oldCount = b, newCount = d;
    const oldStart = oldCount ? a - 1 : a, newStart = newCount ? c - 1 : c;
    assert(oldStart >= cursor && oldStart <= source.length, 'old ranges must be ordered and within the original');
    result.push(...source.slice(cursor, oldStart)); cursor = oldStart;
    assert.equal(newStart, result.length, 'new hunk coordinate must include all earlier insertions/deletions');
    let removed = 0, added = 0;
    while (removed < oldCount || added < newCount) {
      const row = encoded[i++]; assert(row, 'missing hunk row');
      const op = row[0]; assert([32, 43, 45].includes(op), 'invalid hunk operation');
      let value = row.subarray(1);
      if (encoded[i]?.equals(Buffer.from('\\ No newline at end of file\n'))) {
        assert.equal(value.at(-1), 10); value = value.subarray(0, -1); i += 1;
      }
      if (op !== 43) { assert.deepEqual(value, source[cursor++], 'context/deletion must match exact original bytes'); removed += 1; }
      if (op !== 45) { result.push(value); added += 1; }
      assert(removed <= oldCount && added <= newCount, 'hunk exceeded a declared count');
    }
  }
  result.push(...source.slice(cursor));
  return Buffer.concat(result);
}
function randomEdits(seed, count) {
  let state = seed >>> 0;
  const rand = maximum => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) % maximum; };
  const line = i => Buffer.from(['repeat\n', '\n', '\r\n', '\0\xff\n', `unique-${i}-${rand(1000)}\r\n`, '--- a/file\n', '\\ No newline at end of file\n'][rand(7)], 'latin1');
  const result = [];
  for (let sample = 0; sample < count; sample += 1) {
    const original = Array.from({ length: rand(150) }, (_, i) => line(i)), changed = original.slice();
    for (let j = 0, n = rand(80) + 1; j < n; j += 1) {
      const at = rand(changed.length + 1), operation = rand(3);
      changed.splice(at, operation === 0 ? 0 : rand(4) + 1, ...(operation === 1 ? [] : [line(j)]));
    }
    let before = Buffer.concat(original), after = Buffer.concat(changed);
    if (before.length && rand(3) === 0) before = before.subarray(0, -1);
    if (after.length && rand(3) === 0) after = after.subarray(0, -1);
    if (before.equals(after)) after = Buffer.concat([after, Buffer.from('changed\n')]);
    result.push(edit(before, after));
  }
  return result;
}

test('2,000 deterministic byte-level edit scripts apply only at their declared positions', () => {
  for (const row of randomEdits(0xf617cafe, 2000)) {
    const patch = fullFilePatch([row], { allowBinary: true });
    assert.deepEqual(applyAtDeclaredPositions(row.before.bytes, patch.bytes), Buffer.from(row.after.bytes));
    assert.deepEqual(patch.edits, [row]);
  }
});

for (const gap of [0, 1, 5, 6, 7, 8, 20]) test(`a ${gap}-line unchanged gap has nonoverlapping three-line context`, () => {
  const before = lines(70), after = before.slice(); after[10] = 'first\n'; after[11 + gap] = 'second\n';
  const row = edit(before.join(''), after.join('')), patch = fullFilePatch([row]);
  assert.equal((text(patch.bytes).match(/^@@ /gm) ?? []).length, gap <= 6 ? 1 : 2);
  assert.deepEqual(applyAtDeclaredPositions(row.before.bytes, patch.bytes), Buffer.from(row.after.bytes));
});

test('edit-distance exhaustion retains all changes rather than publishing a partial patch', () => {
  const before = lines(250), after = before.slice();
  for (let i = 5; i < 245; i += 2) after[i] = `replacement-${i}\n`;
  const row = edit(before.join(''), after.join('')), patch = fullFilePatch([row]);
  assert.equal((text(patch.bytes).match(/^@@ /gm) ?? []).length, 1, 'the exact middle is the bounded fallback');
  assert.deepEqual(applyAtDeclaredPositions(row.before.bytes, patch.bytes), Buffer.from(row.after.bytes));
});

test('the shared work bound preserves a long repeated middle when search cannot complete', () => {
  const before = Array.from({ length: 30000 }, (_, i) => `a${i % 2}\n`), after = before.slice();
  for (let i = 0; i < 100; i += 1) after[i * 299] = `b${i % 2}\n`;
  const row = edit(before.join(''), after.join('')), patch = fullFilePatch([row]);
  assert.deepEqual(applyAtDeclaredPositions(row.before.bytes, patch.bytes), Buffer.from(row.after.bytes));
  assert(patch.bytes.length <= PATCH_LIMIT);
});

for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: eight full-size files with distant edits fit one bounded patch`, () => {
    const before = bytes(`${'a'.repeat(63)}\n`.repeat(FILE_LIMIT / 64)), after = before.slice();
    after[4 * 64] = 98; after[FILE_LIMIT - 5 * 64] = 99;
    const rows = Array.from({ length: 8 }, (_, i) => edit(before, after, `file-${i}`));
    const patch = roundTrip(rows, algorithm);
    assert(patch.bytes.length < 12 * 1024);
    assert.equal((text(patch.bytes).match(/^@@ /gm) ?? []).length, 16);
    assert.throws(() => fullFilePatch([...rows, edit('a', 'b', 'over-budget')]), /retained byte/);
  });
  const corpus = randomEdits(0x6175eed, 20);
  for (const [index, row] of corpus.entries()) test(`${algorithm}: generated binary edit ${index} agrees with independent Git trees`, () => {
    roundTrip([row], algorithm, { allowBinary: true });
  });
}


test('retained-byte capacity is enforced independently of encoded bytes and input lines', () => {
  const before = bytes('a'.repeat(FILE_LIMIT)), after = before.slice(); after[0] = 98;
  const rows = Array.from({ length: 8 }, (_, i) => edit(before, after, `large-${i}`));
  assert.equal(rows.reduce((n, e) => n + e.before.bytes.length + e.after.bytes.length, 0), INPUT_LIMIT);
  assert.equal(normalizeEdits(rows).length, 8);
  assert.throws(() => normalizeEdits([...rows, edit(null, 'x', 'over-budget')]), /retained byte/);
  assert.throws(() => fullFilePatch(rows), /Encoded patch exceeds/);
});
