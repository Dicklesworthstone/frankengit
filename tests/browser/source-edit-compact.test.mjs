// Git is a test-only byte/tree oracle, never an implementation dependency.
// This exercises the real browser encoder, not native admission or a Rust node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fullFilePatch, FILE_LIMIT, PATCH_LIMIT, renameEdits } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';

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
function roundTrip(edits, algorithm, options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'fgit-browser-patch-'));
  try {
    const actual = join(root, 'actual'), expected = join(root, 'expected');
    for (const path of [actual, expected]) { mkdirSync(path); git(path, ['init', '-q', `--object-format=${algorithm}`]); }
    const beforeTree = install(actual, edits, 'before'), afterTree = install(expected, edits, 'after');
    const patch = fullFilePatch(edits, options);
    git(actual, ['apply', '--check', '--index', '--whitespace=nowarn', '-'], patch.bytes);
    git(actual, ['apply', '--verbose', '--index', '--whitespace=nowarn', '-'], patch.bytes);
    assert.equal(git(actual, ['write-tree']), afterTree, 'forward patch must produce the independently built complete tree');
    for (const row of edits) if (row.after !== null) {
      const path = Buffer.concat([Buffer.from(`${actual}/`), Buffer.from(row.path_hex, 'hex')]);
      assert.deepEqual(new Uint8Array(readFileSync(path)), row.after.bytes);
    }
    git(actual, ['apply', '--reverse', '--verbose', '--index', '--whitespace=nowarn', '-'], patch.bytes);
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

  test(`${algorithm}: mode changes, raw byte names, binary opt-in and renames compose`, () => {
    const before = Buffer.concat([Buffer.from(original.join('')), Buffer.from([0, 255, 13, 10])]);
    const after = Buffer.from(before); after[65] ^= 1;
    const raw = edit(before, after, Buffer.from([97, 32, 34, 92, 10, 255])); raw.after.mode = 0o100755;
    const mode = edit(original.join(''), original.join(''), 'script'); mode.after.mode = 0o100755;
    const moving = renameEdits(Buffer.from('old-name').toString('hex'), Buffer.from('new-name').toString('hex'), side('rename\n'));
    const rows = [...moving, mode, raw];
    const first = roundTrip(rows, algorithm, { allowBinary: true });
    assert.deepEqual(first.bytes, fullFilePatch([...rows].reverse(), { allowBinary: true }).bytes);
    assert.deepEqual(first.edits.find(e => e.path_hex === raw.path_hex).after.bytes, new Uint8Array(after));
  });
}
