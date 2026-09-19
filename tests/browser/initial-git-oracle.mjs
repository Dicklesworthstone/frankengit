// Explicit non-production interoperability check. Never imported by browser code.
// Run separately: node tests/browser/initial-git-oracle.mjs
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, webcrypto } from 'node:crypto';
import { initialPlan } from '../../crates/fgit-node/src/smart_http/server/browser/initial-plan.mjs';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
const git = '/usr/bin/git', expectedVersion = 'git version 2.47.3';
const version = execFileSync(git, ['--version'], { encoding: 'utf8' }).trim();
assert.equal(version, expectedVersion, 'This oracle lane must be explicitly repinned for another Git version.');
const root = mkdtempSync(join(tmpdir(), 'fg-initial-oracle-'));
const env = { PATH: '/usr/bin:/bin', HOME: root, XDG_CONFIG_HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_AUTHOR_NAME: 'Initial Author', GIT_AUTHOR_EMAIL: 'author@example.invalid', GIT_AUTHOR_DATE: '@1 +0000',
  GIT_COMMITTER_NAME: 'Initial Builder', GIT_COMMITTER_EMAIL: 'builder@example.invalid', GIT_COMMITTER_DATE: '@1 +0000', LC_ALL: 'C' };
let cases = 0;
try {
  for (const algorithm of ['sha1', 'sha256']) {
    const cwd = join(root, algorithm);
    const run = (args, input) => execFileSync(git, args, { cwd, env, input, maxBuffer: 4 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] });
    execFileSync(git, ['init', '--quiet', `--object-format=${algorithm}`, cwd], { env });
    const paths = [utf8.encode('a.c'), utf8.encode('a/b'), utf8.encode('a0'), utf8.encode('a-/b'), utf8.encode('a-/c'),
      utf8.encode('space b/name with spaces'), utf8.encode('tab\tquote"\\'), new Uint8Array([255,47,254]), utf8.encode('unicode/é'), utf8.encode('empty')];
    const contents = [new Uint8Array(), utf8.encode('line\n'), utf8.encode('line\r\n'), utf8.encode('unterminated'), new Uint8Array([255,10,254])];
    for (let shift = 0; shift < contents.length; shift++) {
      run(['read-tree', '--empty']);
      // Only the index is touched; --cached avoids checkout filename portability.
      const files = paths.map((path, i) => ({ path_hex: hex(path), bytes: contents[(i + shift) % contents.length], mode: i % 2 ? 0o100755 : 0o100644 }));
      const metadata = { author: 'Initial Author <author@example.invalid>', committer: 'Initial Builder <builder@example.invalid>', timestamp: 1, message: 'Exact initial history\n' };
      const plan = await initialPlan(files, metadata, algorithm, webcrypto);
      run(['apply', '--cached', '--whitespace=nowarn'], plan.patch);
      const tree = run(['write-tree']).toString().trim(); assert.equal(plan.tree, tree);
      const commit = run(['commit-tree', tree], metadata.message).toString().trim(); assert.equal(plan.commit, commit);
      assert.deepEqual(new Uint8Array(run(['cat-file', 'commit', commit])), plan.commitBody);
      assert.equal(run(['cat-file', '-p', commit]).toString().includes('\nparent '), false);
      const reversed = await initialPlan(files.reverse(), metadata, algorithm, webcrypto);
      assert.equal(reversed.commit, commit); assert.deepEqual(reversed.patch, plan.patch);
      for (const entry of plan.files) {
        const source = files.find(f => f.path_hex === entry.path_hex);
        assert.equal(run(['hash-object', '--stdin'], source.bytes).toString().trim(), entry.blob); cases++;
      }
      cases += 4;
    }
  }
  console.log(JSON.stringify({ passed: cases, version, binary_sha256: createHash('sha256').update(readFileSync(git)).digest('hex'),
    object_formats: ['sha1', 'sha256'], scope: 'Actual Git index application, tree/commit construction and blob identity; not native Rust execution.' }, null, 2));
} finally { rmSync(root, { recursive: true, force: true }); }
