// Explicit non-production oracle. No Git subprocess belongs in browser/runtime code.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { webcrypto, createHash } from 'node:crypto';
import { tagPlan } from '../../crates/fgit-node/src/smart_http/server/browser/tags-protocol.mjs';
const git = '/usr/bin/git', version = spawnSync(git, ['--version'], { encoding: 'utf8' }).stdout.trim();
assert.equal(version, 'git version 2.47.3', 'Run only with the declared non-production oracle');
const binarySha256 = createHash('sha256').update(readFileSync(git)).digest('hex');
const root = mkdtempSync(join(tmpdir(), 'fg-tag-oracle-'));
let checks = 0;
try {
  for (const algorithm of ['sha1', 'sha256']) {
    const cwd = join(root, algorithm);
    const env = { PATH: '/usr/bin:/bin', HOME: root, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_ATTR_NOSYSTEM: '1', GIT_CEILING_DIRECTORIES: root };
    function run(args, input, dir = cwd) {
      const r = spawnSync(git, ['--no-replace-objects', '-c', 'core.hooksPath=/dev/null', ...args], { cwd: dir, env, input, maxBuffer: 4 * 1024 * 1024, timeout: 10_000 });
      assert.equal(r.status, 0, r.stderr?.toString() || r.error?.message); return r.stdout;
    }
    run(['init', '--quiet', `--object-format=${algorithm}`, cwd], undefined, root);
    const blob = run(['hash-object', '-w', '--stdin'], Buffer.from([0, 255, 10])).toString().trim();
    const tree = run(['mktree'], '').toString().trim();
    const commit = run(['hash-object', '-w', '-t', 'commit', '--stdin'], `tree ${tree}\nauthor Oracle <oracle@example.invalid> 1700000000 +0000\ncommitter Oracle <oracle@example.invalid> 1700000000 +0000\n\nroot\n`).toString().trim();
    const inner = run(['mktag'], `object ${commit}\ntype commit\ntag inner\ntagger Oracle <oracle@example.invalid> 1700000000 +0000\n\ninner\n`).toString().trim();
    for (const [target_kind, target] of Object.entries({ blob, tree, commit, tag: inner })) {
      for (const [name, message] of [
        [Buffer.from('v1'), Buffer.from('release\n')], [Buffer.from('empty'), Buffer.alloc(0)],
        [Buffer.from([118, 255]), Buffer.from([255, 13, 10, 120])],
        [Buffer.from('release/nested'), Buffer.from('no final newline')],
        [Buffer.from('opaque'), Buffer.from('message\n-----BEGIN PGP SIGNATURE-----\nnot verified\n')],
      ]) {
        const fields = { object_format: algorithm, ref_hex: Buffer.concat([Buffer.from('refs/tags/'), name]).toString('hex'), target, target_kind,
          tagger: 'Oracle <oracle@example.invalid>', timestamp: 1700000000, message_hex: message.toString('hex') };
        const plan = await tagPlan('annotated', fields, webcrypto), body = Buffer.from(plan.body_hex, 'hex');
        const expected = Buffer.concat([Buffer.from(`object ${target}\ntype ${target_kind}\ntag `), name, Buffer.from('\ntagger Oracle <oracle@example.invalid> 1700000000 +0000\n\n'), message]);
        assert.deepEqual(body, expected); checks++;
        const id = run(['mktag'], body).toString().trim(); assert.equal(id, plan.new_object); checks++;
        assert.deepEqual(run(['cat-file', 'tag', id]), body); checks++;
        assert.equal(run(['rev-parse', `${id}^{}`]).toString().trim(), target_kind === 'tag' ? commit : target); checks++;
      }
    }
  }
  console.log(JSON.stringify({ oracle: 'explicit non-production Git', version, binary_sha256: binarySha256, checks, formats: ['sha1', 'sha256'], native_rust_executed: false }, null, 2));
} finally { rmSync(root, { recursive: true, force: true }); }
