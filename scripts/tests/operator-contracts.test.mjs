// Controller fixtures: execute the actual suite, shared profile and Node tests
// in a miniature Git workspace. The executable handoff uses Node as a sentinel;
// these checks are not native forge, stock-Git compatibility or live API proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, writeFile, readFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runNativeProcess } from '../lib/native-process-owner.mjs';

const repository = fileURLToPath(new URL('../../', import.meta.url));
const suite = 'scripts/e2e/suites/operator/contract_tests.sh';
const runDirectory = 'receipt';

async function fixture(t, failOperator = false) {
  const root = await mkdtemp(join(tmpdir(), 'fg-operator-contract-fixture-'));
  let validated = false;
  t.after(async () => {
    if (validated) await rm(root, { recursive: true, force: true });
    else console.error(`Operator contract fixture retained: ${root}`);
  });
  for (const directory of ['scripts/e2e/suites/operator', 'scripts/lib', 'scripts/tests', 'tests/operator']) {
    await mkdir(join(root, directory), { recursive: true });
  }
  for (const path of [suite, 'scripts/verify_js.mjs', 'scripts/lib/native-process-owner.mjs']) {
    await copyFile(join(repository, path), join(root, path));
  }
  await writeFile(join(root, 'tests/node-version'), process.versions.node + '\n');
  const probe = (scope, extra = '') => `import test from 'node:test';import assert from 'node:assert/strict';import {writeFileSync} from 'node:fs';import vm from 'node:vm';test('${scope} fixture',()=>{${extra}assert.equal(process.env.FG_NATIVE_BIN,process.execPath);writeFileSync(new URL('../../${scope}-entered',import.meta.url),'executed');});\n`;
  await writeFile(join(root, 'tests/operator/probe.test.mjs'), probe('operator', failOperator ? "assert.fail('planted operator failure');" : ''));
  await writeFile(join(root, 'scripts/tests/probe.test.mjs'), probe('scripts', "assert.equal(typeof vm.SourceTextModule,'function');"));
  const environment = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_'))),
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
  for (const args of [['init', '-q'], ['add', 'scripts', 'tests'],
    ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'operator controller fixture']]) {
    execFileSync('/usr/bin/git', ['-c', 'core.hooksPath=/dev/null', '-C', root, ...args], {
      env: environment, timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'],
    });
  }
  return { root, complete() { validated = true; }, async run(node = process.execPath) {
    const result = await runNativeProcess('/usr/bin/env', [
      `FGE_LIB=${join(repository, 'scripts/e2e/lib.sh')}`,
      `FGE_RUN_DIR=${join(root, runDirectory)}`, 'FGE_SCRIPT_ID=operator-contract-fixture',
      `FGE_NODE=${node}`, `FG_BIN=${process.execPath}`, `TMPDIR=${root}`,
      '/bin/bash', join(root, suite),
    ], { timeoutMs: 30000, signal: t.signal, stdoutLimit: 2 * 1024 * 1024, stderrLimit: 2 * 1024 * 1024 });
    const records = (await readFile(join(root, runDirectory, 'e2e.ndjson'), 'utf8')).trim().split('\n').map(JSON.parse);
    return { ...result, records };
  } };
}

test('discovered operator suite executes both actual profile scopes and hands off the selected executable', { timeout: 45000 }, async t => {
  const f = await fixture(t), result = await f.run();
  assert.equal(result.code, 0, result.stderr.toString());
  assert.equal(result.signal, null);
  for (const scope of ['operator', 'scripts']) {
    assert.equal(await readFile(join(f.root, `${scope}-entered`), 'utf8'), 'executed');
    for (const suffix of ['001', '002']) {
      assert.equal(result.records.find(row => row.acceptance_id === `OPERATOR-CONTRACT-${scope}-${suffix}`)?.result.status, 'pass');
    }
  }
  assert.equal(result.records.at(-1).terminal.status, 'pass');
  f.complete();
});

test('planted operator assertion fails the suite while the unchanged script scope still executes', { timeout: 45000 }, async t => {
  const f = await fixture(t, true), result = await f.run();
  assert.notEqual(result.code, 0);
  assert.equal(await readFile(join(f.root, 'scripts-entered'), 'utf8'), 'executed');
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-operator-001')?.result.status, 'fail');
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-scripts-001')?.result.status, 'pass');
  assert.equal(result.records.at(-1).terminal.status, 'fail');
  f.complete();
});

test('an exit-zero command with no TAP cannot replace either test corpus', { timeout: 45000 }, async t => {
  const f = await fixture(t), result = await f.run('/usr/bin/true');
  assert.notEqual(result.code, 0);
  for (const scope of ['operator', 'scripts']) {
    await assert.rejects(access(join(f.root, `${scope}-entered`)), { code: 'ENOENT' });
    assert.equal(result.records.find(row => row.acceptance_id === `OPERATOR-CONTRACT-${scope}-002`)?.result.status, 'fail');
  }
  assert.equal(result.records.at(-1).terminal.status, 'fail');
  f.complete();
});
