// Explicit NON-PRODUCTION differential lane. Require the exact operator-selected
// Git version and binary hash; all Git work is confined to disposable fixtures.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { fullFilePatch } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
const [git, expectedVersion, expectedHash] = process.argv.slice(2);
assert(git?.startsWith('/') && expectedVersion && /^[0-9a-f]{64}$/.test(expectedHash ?? ''), 'Usage: node source-edit-git-oracle.mjs /absolute/git "git version X" sha256-of-binary');
assert.equal(createHash('sha256').update(readFileSync(git)).digest('hex'), expectedHash, 'Pinned Git binary changed');
const root = mkdtempSync(join(tmpdir(), 'fg-source-authoring-oracle-'));
const env = { PATH: process.env.PATH, HOME: root, XDG_CONFIG_HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' };
const run = (args, cwd) => execFileSync(git, args, { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000 });
assert.equal(run(['--version'], root).trim(), expectedVersion);
const mode = 0o100644, executable = 0o100755;
const side = (text, m = mode) => ({ bytes: new Uint8Array(Buffer.from(text)), mode: m });
const scenarios = [
  [null, side('')], [side(''), null], [null, side('new\n')], [side('old\n'), null],
  [side('before\r\n'), side('after')], [side('before'), side('after\n')],
  [side('unchanged\r\n'), side('unchanged\r\n', executable)],
  [side(Buffer.from([255, 13, 10])), side(Buffer.from([254, 10]))],
];
const paths = ['file', 'with spaces ', 'a b/name', 'tab\tname', 'line\nname', 'quote"name', 'back\\slash', 'café', Buffer.from([120, 255])].map(v => Buffer.isBuffer(v) ? v : Buffer.from(v));
let cases = 0;
try {
 for (const algorithm of ['sha1', 'sha256']) for (const path of paths) for (const [before, after] of scenarios) {
  const dir = join(root, `case-${cases}`); mkdirSync(dir);
  run(['init', '-q', `--object-format=${algorithm}`], dir);
  run(['config', 'core.autocrlf', 'false'], dir); run(['config', 'core.fileMode', 'true'], dir);
  const file = Buffer.concat([Buffer.from(dir + '/'), path]), slash = path.lastIndexOf(47);
  if (slash >= 0) mkdirSync(Buffer.concat([Buffer.from(dir + '/'), path.subarray(0, slash)]), { recursive: true });
  if (before) writeFileSync(file, before.bytes, { mode: before.mode & 0o777 });
  run(['add', '--all'], dir);
  const patch = fullFilePatch([{ path_hex: path.toString('hex'), before, after }]).bytes;
  const patchPath = join(root, 'change.patch'); writeFileSync(patchPath, patch);
  run(['apply', '--index', '--whitespace=nowarn', patchPath], dir);
  if (after) {
   assert.deepEqual(new Uint8Array(readFileSync(file)), after.bytes);
   assert.equal(statSync(file).mode & 0o111, after.mode === executable ? 0o111 : 0);
  } else assert.equal(existsSync(file), false);
  cases += 1;
 }
 console.log(JSON.stringify({ profile: 'source-editor-exact-patch-local-oracle-v1', git_version: expectedVersion, git_sha256: expectedHash,
  object_formats: ['sha1','sha256'], cases, passed: cases, production_git_invocation: false, native_rust_conformance: false }));
} finally { rmSync(root, { recursive: true, force: true }); }
