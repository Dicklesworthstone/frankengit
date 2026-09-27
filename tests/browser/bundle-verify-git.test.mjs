// Bounded interoperability observations against the installed Git binary, not
// the repository's pinned differential oracle and not native fg/server E2E.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { verifyGitBundleObjects, verifyGitBundle } from '../../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';
import { hash, webcrypto } from './bundle-verify-fixtures.mjs';

const gitVersion = execFileSync('git', ['--version'], { encoding: 'utf8' }).trim();
for (const format of ['sha1', 'sha256']) for (const ofs of [false, true]) {
  test(`${gitVersion}, ${format}, ${ofs ? 'OFS_DELTA' : 'REF_DELTA'}: real repository exports and independent object inventory`, async () => {
    const root = mkdtempSync(join(tmpdir(), 'fg-bundle-verify-'));
    const repo = join(root, 'repo'), home = join(root, 'home'); mkdirSync(repo); mkdirSync(home);
    const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_AUTHOR_NAME: 'Bundle fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Bundle fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      GIT_AUTHOR_DATE: '1700000000 +0000', GIT_COMMITTER_DATE: '1700000000 +0000', LC_ALL: 'C' };
    for (const key of Object.keys(env)) if (key.startsWith('GIT_') && !['GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'GIT_AUTHOR_DATE', 'GIT_COMMITTER_DATE'].includes(key)) delete env[key];
    const git = (args, input) => execFileSync('git', ['-C', repo, ...args], { env, input, maxBuffer: 20 * 1024 * 1024, timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] });
    try {
      git(['init', '--quiet', '--initial-branch=main', `--object-format=${format}`]);
      for (let revision = 0; revision < 18; revision++) {
        const lines = Array.from({ length: 500 }, (_, n) => `line ${n}: ${'common content '.repeat(4)}${n === revision ? `revision ${revision}` : 'stable'}\n`).join('');
        writeFileSync(join(repo, 'source.txt'), lines);
        writeFileSync(join(repo, 'binary.dat'), Buffer.from(Array.from({ length: 1024 }, (_, n) => (n * 31 + revision) % 256)));
        git(['add', '--', 'source.txt', 'binary.dat']); git(['commit', '--quiet', '-m', `revision ${revision}`]);
      }
      git(['tag', '-a', 'release', '-m', 'annotated tag']);
      const tip = git(['rev-parse', 'HEAD']).toString().trim(), tag = git(['rev-parse', 'refs/tags/release']).toString().trim();
      const pack = git(['pack-objects', '--stdout', '--revs', '--window=50', '--depth=20', ...(ofs ? ['--delta-base-offset'] : [])], Buffer.from(`${tip}\n${tag}\n`));
      const header = Buffer.from(`${format === 'sha1' ? '# v2 git bundle\n' : '# v3 git bundle\n@object-format=sha256\n'}${tip} refs/heads/main\n${tag} refs/tags/release\n\n`);
      const bundle = Buffer.concat([header, pack]);
      const report = await verifyGitBundleObjects(bundle, { cryptoImpl: webcrypto });
      assert.ok(report.delta_objects > 0, 'real oracle must actually emit deltas'); assert.ok(report.maximum_delta_depth > 0);
      const inventory = git(['rev-list', '--objects', tip, tag]).toString().trim().split('\n');
      assert.equal(report.pack_objects, inventory.length); assert.equal(report.sha256, hash(bundle, 'sha256').toString('hex'));
      const file = join(root, 'repository.bundle'); writeFileSync(file, bundle);
      git(['bundle', 'verify', file]);
      const cli = spawnSync(process.execPath, [resolve('scripts/verify_git_bundle.mjs'), file], { env: { ...env, PATH: home }, encoding: 'utf8', timeout: 15000 });
      assert.equal(cli.status, 0, cli.stderr);
      const closure = await verifyGitBundle(bundle, { cryptoImpl: webcrypto });
      assert.equal(closure.object_closure_verified, true); assert.equal(closure.reachable_objects, inventory.length);
      assert.equal(closure.unreachable_objects, 0); assert.deepEqual(JSON.parse(cli.stdout), closure);
      const anchored = spawnSync(process.execPath, [resolve('scripts/verify_git_bundle.mjs'), file,
        '--expect-format', format, '--expect-ref', `refs/heads/main=${tip}`,
        '--expect-ref', `refs/tags/release=${tag}`, '--exact-refs', '--expect-sha256', report.sha256],
      { env: { ...env, PATH: home }, encoding: 'utf8', timeout: 15000 });
      assert.equal(anchored.status, 0, anchored.stderr);
      const pinned = JSON.parse(anchored.stdout);
      assert.equal(pinned.caller_expectations_matched, true); assert.equal(pinned.expectations.ref_set, 'exact');
      assert.equal(pinned.expectations.sha256, report.sha256); assert.equal(pinned.reachable_objects, inventory.length);
      // Stock Git's ordinary bundle command supplies another independently
      // framed export, including HEAD, through the same production verifier.
      const stock = join(root, 'stock.bundle'); git(['bundle', 'create', stock, '--all']);
      assert.equal((await verifyGitBundleObjects(readFileSync(stock), { cryptoImpl: webcrypto })).pack_objects, inventory.length);
      // Remove a reachable blob but recompute a perfectly valid pack. The
      // object-only check passes; independent closure and an actual restore fail.
      const missing = inventory.find(line => line.endsWith(' source.txt')).split(' ')[0];
      const remaining = inventory.map(line => line.split(' ')[0]).filter(id => id !== missing).join('\n') + '\n';
      const incomplete = Buffer.concat([header, git(['pack-objects', '--stdout', '--window=50'], Buffer.from(remaining))]);
      assert.equal((await verifyGitBundleObjects(incomplete, { cryptoImpl: webcrypto })).objects_verified, true);
      writeFileSync(file, incomplete);
      const broken = spawnSync(process.execPath, [resolve('scripts/verify_git_bundle.mjs'), file], { env: { ...env, PATH: home }, encoding: 'utf8', timeout: 15000 });
      assert.equal(broken.status, 1); assert.equal(broken.stdout, '');
      assert.equal(JSON.parse(broken.stderr).error, 'missing_reachable_object');
      assert.equal(JSON.parse(broken.stderr).details.target_object, missing);
      const clone = spawnSync('git', ['clone', '--quiet', file, join(root, 'restore')], { env, encoding: 'utf8', timeout: 10000 });
      assert.notEqual(clone.status, 0, 'a real restore must not complete with the reachable blob absent');
      const corrupt = Buffer.from(bundle); corrupt[corrupt.length - 1] ^= 1; writeFileSync(file, corrupt);
      const refusal = spawnSync(process.execPath, [resolve('scripts/verify_git_bundle.mjs'), file], { env, encoding: 'utf8', timeout: 15000 });
      assert.equal(refusal.status, 1); assert.equal(refusal.stdout, ''); assert.equal(JSON.parse(refusal.stderr).error, 'pack_checksum_mismatch');
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}
