// Non-production differential observations against the installed Git executable.
// No hosted/network access, user checkout, hook, filter, or global Git config.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { buildPatch, bytesHex, pathBytes } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
const raw = value => Buffer.isBuffer(value) ? value : Buffer.from(value);
const side = (bytes, mode = 0o100644) => ({ bytes: new Uint8Array(raw(bytes)), mode });
const edit = (path, before, after, beforeMode = 0o100644, afterMode = 0o100644) => ({
  path_hex: bytesHex(raw(path)), before: before === null ? null : side(before, beforeMode), after: after === null ? null : side(after, afterMode) });
const environment = root => ({ PATH: process.env.PATH, HOME: root, XDG_CONFIG_HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', LC_ALL: 'C' });
for (const algorithm of ['sha1', 'sha256']) test(`installed Git applies exact browser changes in ${algorithm} repositories`, async t => {
  const root = mkdtempSync(join(tmpdir(), 'fg-browser-patch-'));
  try {
    const git = (args, input) => execFileSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.filemode=true', ...args], { cwd: root, env: environment(root), input, stdio: ['pipe', 'pipe', 'pipe'] });
    t.diagnostic(git(['--version']).toString().trim()); git(['init', '-q', `--object-format=${algorithm}`]);
    const edits = [edit('normal', 'old\n', 'new\n'), edit('space name ', 'a\r\nb', 'c\r\nd'),
      edit('quote"tab\tback\\', 'hello', 'héllo'), edit(Buffer.from([110, 97, 109, 101, 255]), Buffer.from([255,10]), Buffer.from([254,10])),
      edit('new-empty', null, ''), edit('delete-empty', '', null), edit('new-exe', null, '#!/bin/sh\n', 0o100644, 0o100755),
      edit('delete', 'gone\nlast', null), edit('mode-only', 'unchanged', 'unchanged', 0o100644, 0o100755),
      edit('mode-content', 'before', 'after', 0o100755, 0o100644), edit('to-empty', 'old\n', ''), edit('from-empty', '', '\n')];
    // Deterministic varied final-newline and line-ending corpus, not random luck.
    for (let i = 0; i < 24; i++) edits.push(edit(`case-${i}`, `line ${i}${i % 3 ? '\n' : '\r\n'}tail${i % 2 ? '\n' : ''}`, `new ${i}${i % 2 ? '\r\n' : '\n'}end${i % 3 ? '' : '\n'}`));
    const file = e => Buffer.concat([Buffer.from(`${root}/`), pathBytes(e.path_hex)]);
    for (const e of edits) if (e.before) writeFileSync(file(e), e.before.bytes, { mode: e.before.mode & 0o777 });
    git(['add', '--all']);
    const patch = await buildPatch(edits, algorithm); git(['apply', '--check', '--index', '--whitespace=nowarn', '-'], patch.bytes);
    git(['apply', '--index', '--whitespace=nowarn', '-'], patch.bytes);
    for (const e of edits) {
      if (!e.after) assert.equal(existsSync(file(e)), false);
      else { assert.deepEqual(new Uint8Array(readFileSync(file(e))), e.after.bytes); assert.equal(statSync(file(e)).mode & 0o777, e.after.mode & 0o777); }
    }
    t.diagnostic(`${edits.length} exact file changes; bytes, existence and executable modes matched`);
    // Reverse application restores every original byte and mode, including empty files.
    git(['apply', '--index', '--reverse', '--whitespace=nowarn', '-'], patch.bytes);
    for (const e of edits) {
      if (!e.before) assert.equal(existsSync(file(e)), false);
      else { assert.deepEqual(new Uint8Array(readFileSync(file(e))), e.before.bytes); assert.equal(statSync(file(e)).mode & 0o777, e.before.mode & 0o777); }
    }
    assert.throws(() => git(['apply', '--index', '--reverse', '-'], patch.bytes), 'wrong-base application refuses');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
