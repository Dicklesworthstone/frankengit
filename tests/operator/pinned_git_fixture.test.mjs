// Negative oracle-contract tests. The ambient "git" is an inert sentinel,
// never an upstream Git execution or a substitute source of Git behavior.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, chmod, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, delimiter } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

for (const [file, entrypoint] of [['pull_candidate_fixture.mjs', 'gitFixture'],
                                ['pull_resolution_fixture.mjs', 'conflictFixture']]) {
  test(`${entrypoint} refuses a missing verified oracle without invoking ambient Git`, async t => {
    const root = await mkdtemp(join(tmpdir(), 'fg-oracle-contract-'));
    await chmod(root, 0o700);
    t.after(() => rm(root, { recursive: true, force: true }));
    const fixtures = join(root, 'fixtures');
    await mkdir(fixtures, { mode: 0o700 });
    await writeFile(join(root, 'git'), '#!/bin/sh\necho UNPINNED_HOST_GIT_ATTEMPT >&2\nexit 73\n', { mode: 0o700 });
    const module = pathToFileURL(resolve('tests/operator', file)).href;
    const code = `try { const fixture = await import(${JSON.stringify(module)}); await fixture[${JSON.stringify(entrypoint)}](); }
      catch (error) { process.stderr.write(String(error) + '\\n'); process.exitCode = 7; }`;
    const env = { ...process.env, PATH: root + delimiter + process.env.PATH,
      FGIT_ORACLE_ROOT: join(root, 'missing-oracle'), TMPDIR: fixtures };
    delete env.FG_GIT_ORACLE;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', code],
      { env, encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 });
    assert.equal(child.error, undefined);
    assert.equal(child.signal, null);
    assert.equal(child.status, 7, child.stdout + child.stderr);
    assert.match(child.stderr, /FGIT_ORACLE_UNAVAILABLE/);
    assert.doesNotMatch(child.stderr, /UNPINNED_HOST_GIT_ATTEMPT/);
    assert.deepEqual(await readdir(fixtures), [], 'refused fixture must drain its owned temporary directory');
  });
}
