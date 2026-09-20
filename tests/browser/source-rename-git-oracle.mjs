// Explicit NON-PRODUCTION interoperability lane. A pinned Git binary applies
// actual editor bytes in isolated indexes; this does not execute Rust admission.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { renameEdits, fullFilePatch } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';

const [git, expectedVersion, expectedHash] = process.argv.slice(2);
assert(git && isAbsolute(git) && expectedVersion && /^[0-9a-f]{64}$/.test(expectedHash ?? ''),
  'Usage: node source-rename-git-oracle.mjs /absolute/git "git version X" sha256-of-binary');
assert.equal(createHash('sha256').update(readFileSync(git)).digest('hex'), expectedHash, 'Pinned Git binary changed');
const root = mkdtempSync(join(tmpdir(), 'fg-source-rename-oracle-'));
const env = { PATH: process.env.PATH, HOME: root, XDG_CONFIG_HOME: root, GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' };
const run = (args, cwd, input) => execFileSync(git, ['-c', 'core.hooksPath=/dev/null', ...args],
  { cwd, env, input, stdio: ['pipe', 'pipe', 'pipe'], timeout: 10_000, maxBuffer: 4 * 1024 * 1024 });
const text = (args, cwd, input) => run(args, cwd, input).toString('utf8').trim();
const bytes = value => new Uint8Array(Buffer.from(value));
const side = (value, mode = 0o100644) => ({ bytes: bytes(value), mode });
const empty = side('');
const binary = Uint8Array.from({ length: 256 }, (_, i) => i);
const scenarios = [
  [side('same\r\n'), side('same\r\n')], [empty, empty],
  [side('before\n'), side('after\n')], [side('no final newline'), side('new\r\n')],
  [side(binary), side(binary, 0o100755)], [side([0, 255, 13, 10, 0]), side([254, 0, 10, 127])],
  [side([239, 187, 191, 13, 10]), empty], [empty, side([0, 255, 1], 0o100755)],
  [side('executable', 0o100755), side('ordinary')],
];
const pairs = [
  ['old.txt', 'new.txt'], ['src/old.txt', 'dst/new.txt'], [' old b/name ', 'next b/new b/name '],
  ['src/tab\told', 'dst/line\nnew'], ['back\\source', 'quoted"target'],
  [Buffer.from([115, 114, 99, 47, 255]), Buffer.from([100, 115, 116, 47, 254])],
  ['src/café', 'dst/项目'], ['src/trailing ', 'dst/ leading'],
].map(pair => pair.map(value => Buffer.from(value)));
const keep = { name: Buffer.from('untouched.bin'), ...side([0, 254, 10, 255]) };
let cases = 0, refusalCases = 0, checks = 0;
function verify(value, expected, message) { assert.deepEqual(value, expected, message); checks++; }
function object(cwd, algorithm, value) {
  const id = text(['hash-object', '-w', '--stdin'], cwd, value);
  const native = createHash(algorithm).update(`blob ${value.length}\0`).update(value).digest('hex');
  verify(id, native, 'Git blob identity'); return id;
}
function entry(cwd, name, id, mode) {
  run(['update-index', '-z', '--index-info'], cwd,
    Buffer.concat([Buffer.from(`${mode.toString(8)} ${id}\t`), name, Buffer.from([0])]));
}
function index(cwd) {
  const data = run(['ls-files', '--stage', '-z'], cwd), rows = []; let start = 0;
  for (let i = 0; i < data.length; i++) if (data[i] === 0) {
    const record = data.subarray(start, i), split = record.indexOf(9);
    assert(split > 0); const [mode, id, stage] = record.subarray(0, split).toString('ascii').split(' ');
    verify(stage, '0', 'no unmerged stage');
    rows.push({ name_hex: record.subarray(split + 1).toString('hex'), id, mode }); start = i + 1;
  }
  verify(start, data.length, 'complete index records'); return rows.sort((a, b) => a.name_hex.localeCompare(b.name_hex));
}
const expectedRows = entries => entries.map(e => ({ name_hex: e.name.toString('hex'), id: e.id,
  mode: e.mode.toString(8) })).sort((a, b) => a.name_hex.localeCompare(b.name_hex));
try {
  verify(text(['--version'], root), expectedVersion, 'Git version pin');
  for (const algorithm of ['sha1', 'sha256']) for (const [source, destination] of pairs) for (const [scenarioIndex, [before, after]] of scenarios.entries()) {
    const dir = join(root, `move-${cases}`); mkdirSync(dir); run(['init', '-q', '--bare', `--object-format=${algorithm}`], dir);
    const oldId = object(dir, algorithm, before.bytes), newId = object(dir, algorithm, after.bytes), keptId = object(dir, algorithm, keep.bytes);
    entry(dir, source, oldId, before.mode); entry(dir, keep.name, keptId, keep.mode);
    const original = text(['write-tree'], dir);
    const normalized = renameEdits(source.toString('hex'), destination.toString('hex'), before, after, { allowBinary: true });
    const patch = fullFilePatch(normalized, { allowBinary: true }).bytes;
    run(['apply', '--cached', '--binary', '--whitespace=nowarn', '-'], dir, patch);
    verify(index(dir), expectedRows([{ name: destination, id: newId, mode: after.mode }, { ...keep, id: keptId }]), 'both exact effects and untouched sibling');
    verify(run(['cat-file', 'blob', newId], dir), Buffer.from(after.bytes), 'resulting content remains exact');
    const actualTree = text(['write-tree'], dir);
    run(['read-tree', '--empty'], dir); entry(dir, destination, newId, after.mode); entry(dir, keep.name, keptId, keep.mode);
    verify(text(['write-tree'], dir), actualTree, 'complete expected tree, including directory removal');
    // Generate the exact inverse move; do not claim Git -R mode semantics.
    const reverse = fullFilePatch(renameEdits(destination.toString('hex'), source.toString('hex'),
      after, before, { allowBinary: true }), { allowBinary: true }).bytes;
    run(['apply', '--cached', '--binary', '--whitespace=nowarn', '-'], dir, reverse);
    verify(text(['write-tree'], dir), original, `inverse rename restores complete original tree: ${algorithm}/${source.toString('hex')}/${scenarioIndex}`);
    verify(index(dir), expectedRows([{ name: source, id: oldId, mode: before.mode }, { ...keep, id: keptId }]), 'reverse index bytes and modes');
    cases++;
    // An occupied destination is not an absent path, even with identical bytes.
    // This is Git interoperability evidence, not a native-server authority test.
    if (scenarioIndex === 0) {
      for (const content of [after.bytes, bytes('different existing content')]) {
        const occupied = object(dir, algorithm, content); entry(dir, destination, occupied, after.mode);
        const collidedTree = text(['write-tree'], dir);
        assert.throws(() => run(['apply', '--cached', '--binary', '--whitespace=nowarn', '-'], dir, patch)); checks++;
        verify(text(['write-tree'], dir), collidedTree, 'refusal cannot leave source deleted or a partial index');
        run(['read-tree', original], dir); refusalCases++;
      }
    }
  }
  console.log(JSON.stringify({ profile: 'source-editor-rename-local-git-oracle-v1', git_version: expectedVersion,
    git_sha256: expectedHash, object_formats: ['sha1', 'sha256'], forward_inverse_generated_patch_cases: cases,
    occupied_destination_refusal_cases: refusalCases, assertions_passed: checks, failed: 0,
    production_git_invocation: false, native_rust_executed: false, native_authority_tested: false, git_reverse_flag_claimed: false }, null, 2));
} finally { rmSync(root, { recursive: true, force: true }); }
