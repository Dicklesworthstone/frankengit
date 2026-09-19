// Explicit non-production, pinned upstream Git lane. No product module invokes
// Git. This checks portable bytes/envelopes, not live native Rust admission.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { inspectBundle } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import { fixture, crypto, href, token, sha, hex } from './transfers-fixtures.mjs';
const executable = process.env.FGIT_TEST_GIT || 'git';
assert.equal(execFileSync(executable, ['--version'], { encoding: 'utf8' }).trim(), 'git version 2.47.3', 'Use the pinned non-production Git 2.47.3 oracle.');
const root = mkdtempSync(join(tmpdir(), 'fgit-transfer-oracle-'));
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
Object.assign(env, { HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null',
  GIT_ALLOW_PROTOCOL: 'file', GIT_TERMINAL_PROMPT: '0', GIT_AUTHOR_NAME: 'Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
  GIT_COMMITTER_NAME: 'Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
  GIT_AUTHOR_DATE: '2001-01-01T00:00:00+00:00', GIT_COMMITTER_DATE: '2001-01-01T00:00:00+00:00' });
let checks = 0;
const git = (cwd, args) => execFileSync(executable, ['-c', 'core.hooksPath=/dev/null', '-c', 'init.templateDir=', ...args], { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
try {
  for (const algorithm of ['sha1', 'sha256']) {
    const repo = join(root, algorithm); mkdirSync(repo);
    git(repo, ['init', '-b', 'main', `--object-format=${algorithm}`]);
    writeFileSync(join(repo, 'file.txt'), 'one\r\ntwo\n'); writeFileSync(join(repo, 'binary'), Uint8Array.of(0, 255, 13, 10, 1));
    git(repo, ['add', 'file.txt', 'binary']); git(repo, ['commit', '-m', 'first']); git(repo, ['branch', 'topic']);
    writeFileSync(join(repo, 'file.txt'), 'one\r\nchanged without final newline'); git(repo, ['commit', '-am', 'second']);
    git(repo, ['tag', '-a', 'v1', '-m', 'annotated tag']);
    const inputPath = join(root, `${algorithm}.bundle`); git(repo, ['bundle', 'create', inputPath, '--all']);
    const input = new Uint8Array(readFileSync(inputPath)), plan = await inspectBundle(input, crypto);
    assert.equal(plan.summary.object_format, algorithm); checks++;
    assert.equal(plan.summary.objects_verified, false); checks++;
    const expected = git(repo, ['for-each-ref', '--format=%(objectname) %(refname)']).toString().trim().split('\n')
      .map(line => { const at = line.indexOf(' '); return { object_id: line.slice(0, at), ref_hex: hex(line.slice(at + 1)) }; })
      .sort((a, b) => a.ref_hex < b.ref_hex ? -1 : 1);
    assert.deepEqual(plan.summary.refs, expected); checks++;
    assert.equal(plan.summary.advertised_head, git(repo, ['rev-parse', 'HEAD']).toString().trim()); checks++;
    const f = fixture(algorithm, input), client = new TransferClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl });
    await client.connect(token); await client.select(algorithm); await client.exportBundle();
    assert.equal(client.exported.sha256, sha(input)); checks++;
    const exported = client.exportBytes(); assert.deepEqual(exported, input); checks++;
    const outputPath = join(root, `${algorithm}-download.bundle`); writeFileSync(outputPath, exported);
    git(repo, ['bundle', 'verify', outputPath]); checks++;
    const mirror = join(root, `${algorithm}-mirror`); git(root, ['clone', '--mirror', outputPath, mirror]);
    git(mirror, ['fsck', '--full']); checks++;
    assert.deepEqual(git(mirror, ['show', 'refs/heads/main:binary']), Buffer.from([0, 255, 13, 10, 1])); checks++;
    assert.equal(git(mirror, ['rev-parse', 'refs/tags/v1']).toString(), git(repo, ['rev-parse', 'refs/tags/v1']).toString()); checks++;
    const corrupted = exported.slice(); corrupted[corrupted.length - 1] ^= 1;
    await assert.rejects(inspectBundle(corrupted, crypto)); checks++;
    // Reordering advertisements changes the artifact bytes, never their identities.
    const boundary = Buffer.from(input).indexOf('\n\n'), header = Buffer.from(input.subarray(0, boundary)).toString().split('\n');
    const controls = header.filter(row => row.startsWith('#') || row.startsWith('@'));
    const refs = header.filter(row => !row.startsWith('#') && !row.startsWith('@')).reverse();
    const reordered = new Uint8Array(Buffer.concat([Buffer.from([...controls, ...refs].join('\n') + '\n\n'), input.subarray(boundary + 2)]));
    assert.deepEqual((await inspectBundle(reordered, crypto)).summary.refs, expected); checks++;
  }
  console.log(`PASS ${checks} pinned Git 2.47.3 checks (SHA-1 and SHA-256): bundle envelopes, exact downloads, mirror clone, fsck, binary contents, tags, ordering and corruption refusal.`);
  console.log('HTTP is a double; native Rust-node admission and live browser deployment were not exercised.');
} finally { rmSync(root, { recursive: true, force: true }); }
