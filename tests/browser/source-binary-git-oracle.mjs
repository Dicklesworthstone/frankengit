// Explicitly NON-PRODUCTION: compare the actual browser encoder with pinned Git.
// No native Rust server or authority runs in this byte-format interoperability lane.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fullFilePatch } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
const [git, expectedVersion, expectedSha] = process.argv.slice(2);
assert(git?.startsWith('/') && expectedVersion && /^[0-9a-f]{64}$/.test(expectedSha ?? ''),
  'Usage: node source-binary-git-oracle.mjs /absolute/git "git version X" executable-sha256');
assert.equal(createHash('sha256').update(readFileSync(git)).digest('hex'), expectedSha);
const root = mkdtempSync(join(tmpdir(), 'fg-binary-byte-oracle-'));
const env = { PATH: process.env.PATH, HOME: root, XDG_CONFIG_HOME: root, GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' };
const run = (args, cwd, input) => execFileSync(git, args, { cwd, input, env, timeout: 10000,
  maxBuffer: 8 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] });
assert.equal(run(['--version'], root).toString().trim(), expectedVersion);
const side = (bytes, mode = 0o100644) => ({ bytes: Uint8Array.from(bytes), mode });
const all = Uint8Array.from({ length: 256 }, (_, i) => i), reversed = all.slice().reverse();
const control = Buffer.from('\0\ndiff --git a/wrong b/wrong\n\\ No newline at end of file\n@@ -0,0 +1 @@\r\n\0', 'latin1');
const cases = [
  ['create all byte values', null, side(all)], ['delete all byte values', side(all), null],
  ['replace byte sequence', side(all), side(reversed)], ['binary mode change', side(all), side(all, 0o100755)],
  ['empty to zero', side([]), side([0])], ['zero to empty', side([0]), side([])],
  ['create zero bytes', null, side([0, 0])], ['delete zero bytes', side([0, 0]), null],
  ['CRLF and unterminated lines', side([0, 255, 13, 10, 0]), side([0, 254, 0, 10, 13])],
  ['text to binary', side(Buffer.from('text\n')), side(all)], ['binary to text', side(all), side(Buffer.from('text'))],
  ['control-looking binary payload', side(all), side(control)],
];
const paths = ['asset.bin', ' space name ', 'directory/asset.bin', 'line\nname', 'quote"name', 'tab\tname', 'back\\slash',
  Buffer.from([0x66, 0xff])].map(value => Buffer.isBuffer(value) ? value : Buffer.from(value));
let passed = 0;
function verifySide(file, expected) {
  if (!expected) { assert.equal(existsSync(file), false); return; }
  assert.deepEqual(new Uint8Array(readFileSync(file)), expected.bytes);
  assert.equal(statSync(file).mode & 0o111, expected.mode === 0o100755 ? 0o111 : 0);
}
try {
  for (const format of ['sha1', 'sha256']) for (const path of paths) for (const [name, before, after] of cases) {
    const cwd = join(root, `case-${passed}`); mkdirSync(cwd); run(['init', '-q', `--object-format=${format}`], cwd);
    run(['config', 'core.autocrlf', 'false'], cwd); run(['config', 'core.fileMode', 'true'], cwd);
    const file = Buffer.concat([Buffer.from(cwd + '/'), path]);
    const slash = path.lastIndexOf(47); if (slash >= 0) mkdirSync(Buffer.concat([Buffer.from(cwd + '/'), path.subarray(0, slash)]), { recursive: true });
    if (before) writeFileSync(file, before.bytes, { mode: before.mode & 0o777 });
    const untouched = join(cwd, 'unselected.bin'); writeFileSync(untouched, all); run(['add', '--all'], cwd);
    const originalTree = run(['write-tree'], cwd).toString().trim();
    const patch = fullFilePatch([{ path_hex: path.toString('hex'), before, after }], { allowBinary: true }).bytes;
    assert(!Buffer.from(patch).includes('GIT binary patch'), name);
    run(['apply', '--check', '--index', '--whitespace=nowarn', '-'], cwd, patch);
    run(['apply', '--index', '--whitespace=nowarn', '-'], cwd, patch); verifySide(file, after);
    assert.deepEqual(new Uint8Array(readFileSync(untouched)), all);
    if (after) {
      const expectedId = createHash(format).update(Buffer.from(`blob ${after.bytes.length}\0`)).update(after.bytes).digest('hex');
      assert.equal(run(['hash-object', '--stdin'], cwd, after.bytes).toString().trim(), expectedId);
      assert.deepEqual(new Uint8Array(run(['cat-file', 'blob', expectedId], cwd)), after.bytes);
    }
    run(['apply', '--reverse', '--index', '--whitespace=nowarn', '-'], cwd, patch); verifySide(file, before);
    assert.equal(run(['write-tree'], cwd).toString().trim(), originalTree);
    passed++;
  }
  console.log(JSON.stringify({ profile: 'literal-binary-byte-patch-git-oracle-v1', git_version: expectedVersion,
    git_sha256: expectedSha, formats: ['sha1', 'sha256'], scenarios_per_format: cases.length * paths.length,
    cases: passed, passed, forward_and_reverse_application: true, production_git_invocation: false,
    native_rust_executed: false }, null, 2));
} finally { rmSync(root, { recursive: true, force: true }); }
