// Controller fixtures: execute the actual suite, shared profile and Node tests
// in a miniature Git workspace. The executable handoff uses Node as a sentinel;
// these checks are not native forge, stock-Git compatibility or live API proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, writeFile, readFile, rm, access, unlink, readdir } from 'node:fs/promises';
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
  for (const directory of ['scripts/e2e/suites/operator', 'scripts/e2e/selftests', 'scripts/lib', 'scripts/tests', 'tests/operator']) {
    await mkdir(join(root, directory), { recursive: true });
  }
  for (const path of [suite, 'scripts/verify_js.mjs', 'scripts/lib/native-process-owner.mjs',
    'scripts/e2e/selftests/test_operator_command.py']) {
    await copyFile(join(repository, path), join(root, path));
  }
  // The ownership cases import shipped workflow helpers, which transitively
  // import workspace/native consumers. Copy the flat Python source surface so
  // adding a real consumer cannot silently invalidate this miniature fixture.
  // Only imported modules execute; the fixture's TAP corpora stay explicit.
  for (const entry of await readdir(join(repository, 'scripts/e2e'), { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.py')) {
      await copyFile(join(repository, 'scripts/e2e', entry.name), join(root, 'scripts/e2e', entry.name));
    }
  }
  // Controller-only stand-in: validate dispatch and executable/workdir handoff.
  // The actual repository suite separately runs the real native owner tests;
  // Node is deliberately the sentinel executable in this miniature workspace.
  await writeFile(join(root, 'scripts/e2e/selftests/test_http_service_owner.py'), `import json, os, unittest
from pathlib import Path
class DispatchFixtureTest(unittest.TestCase):
    def test_selected_executable_and_workdir_handoff(self):
        self.assertEqual(os.environ['FG_BIN'], os.environ['FG_OPERATOR_FIXTURE_NODE'])
        work = Path(os.environ['FGE_HTTP_OWNER_WORKDIR'])
        self.assertTrue(work.is_dir())
        root = Path(${JSON.stringify(root)})
        self.assertEqual(root.stat().st_mode & 0o077, 0)
        self.assertEqual(work, root / 'receipt/work/native-http-owner')
        Path(${JSON.stringify(join(root, 'native-owner-entered.json'))}).write_text(json.dumps({'kind':'dispatcher_fixture_only','fg_bin':os.environ['FG_BIN']}))
if __name__ == '__main__': unittest.main()
`);
  await writeFile(join(root, 'tests/node-version'), process.versions.node + '\n');
  const probe = (scope, extra = '') => `import test from 'node:test';import assert from 'node:assert/strict';import {writeFileSync} from 'node:fs';import vm from 'node:vm';test('${scope} fixture',()=>{${extra}assert.equal(process.env.FG_NATIVE_BIN,process.execPath);writeFileSync(new URL('${scope === 'supervisor' ? '../' : '../../'}${scope}-entered',import.meta.url),'executed');});\n`;
  await writeFile(join(root, 'tests/operator/probe.test.mjs'), probe('operator', failOperator ? "assert.fail('planted operator failure');" : ''));
  await writeFile(join(root, 'scripts/tests/probe.test.mjs'), probe('scripts', "assert.equal(typeof vm.SourceTextModule,'function');"));
  await writeFile(join(root, 'scripts/supervisor.test.mjs'), probe('supervisor', "assert.equal(typeof vm.SourceTextModule,'function');"));
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
      `FGE_NODE=${node}`, `FG_OPERATOR_FIXTURE_NODE=${process.execPath}`, `FG_BIN=${process.execPath}`, `TMPDIR=${root}`,
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
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-OWNER-001')?.result.status, 'pass');
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-HTTP-OWNER-001')?.result.status, 'pass');
  assert.deepEqual(JSON.parse(await readFile(join(f.root, 'native-owner-entered.json'), 'utf8')),
    { kind: 'dispatcher_fixture_only', fg_bin: process.execPath });
  for (const scope of ['operator', 'scripts']) {
    assert.equal(await readFile(join(f.root, `${scope}-entered`), 'utf8'), 'executed');
    for (const suffix of ['001', '002']) {
      assert.equal(result.records.find(row => row.acceptance_id === `OPERATOR-CONTRACT-${scope}-${suffix}`)?.result.status, 'pass');
    }
  }
  assert.equal(await readFile(join(f.root, 'supervisor-entered'), 'utf8'), 'executed');
  assert.equal(result.records.at(-1).terminal.status, 'pass');
  f.complete();
});

test('planted operator assertion fails the suite while the unchanged script scope still executes', { timeout: 45000 }, async t => {
  const f = await fixture(t, true), result = await f.run();
  assert.notEqual(result.code, 0);
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-OWNER-001')?.result.status, 'pass');
  assert.equal(await readFile(join(f.root, 'scripts-entered'), 'utf8'), 'executed');
  assert.equal(await readFile(join(f.root, 'supervisor-entered'), 'utf8'), 'executed');
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-operator-001')?.result.status, 'fail');
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-scripts-001')?.result.status, 'pass');
  assert.equal(result.records.at(-1).terminal.status, 'fail');
  assert.deepEqual([...result.records.at(-1).terminal.failed_ids].sort(),
    ['OPERATOR-CONTRACT-operator-001', 'OPERATOR-CONTRACT-operator-002']);
  f.complete();
});

test('an exit-zero command with no TAP cannot replace either test corpus', { timeout: 45000 }, async t => {
  const f = await fixture(t), emptyProfile = join(f.root, 'empty-profile-node');
  // Only the two profile commands return empty success. Runtime checks and
  // real ownership tests still execute Node, isolating the missing-TAP fault.
  await writeFile(emptyProfile, '#!/bin/sh\ncase "${1-}:${2-}" in\n' +
    '  */verify_js.mjs:operator|*/verify_js.mjs:scripts) exit 0 ;;\nesac\n' +
    'exec "$FG_OPERATOR_FIXTURE_NODE" "$@"\n', { mode: 0o700 });
  const result = await f.run(emptyProfile);
  assert.notEqual(result.code, 0);
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-OWNER-001')?.result.status, 'pass');
  for (const scope of ['operator', 'scripts']) {
    await assert.rejects(access(join(f.root, `${scope}-entered`)), { code: 'ENOENT' });
    assert.equal(result.records.find(row => row.acceptance_id === `OPERATOR-CONTRACT-${scope}-001`)?.result.status, 'pass');
    assert.equal(result.records.find(row => row.acceptance_id === `OPERATOR-CONTRACT-${scope}-002`)?.result.status, 'fail');
  }
  assert.equal(result.records.at(-1).terminal.status, 'fail');
  assert.deepEqual([...result.records.at(-1).terminal.failed_ids].sort(),
    ['OPERATOR-CONTRACT-operator-002', 'OPERATOR-CONTRACT-scripts-002']);
  f.complete();
});

test('missing ownership selftests fail only their gate while both module scopes still execute', { timeout: 45000 }, async t => {
  const f = await fixture(t);
  await unlink(join(f.root, 'scripts/e2e/selftests/test_operator_command.py'));
  const result = await f.run();
  assert.notEqual(result.code, 0);
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-OWNER-001')?.result.status, 'fail');
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-HTTP-OWNER-001')?.result.status, 'pass');
  for (const scope of ['operator', 'scripts']) {
    assert.equal(await readFile(join(f.root, `${scope}-entered`), 'utf8'), 'executed');
    for (const suffix of ['001', '002']) {
      assert.equal(result.records.find(row => row.acceptance_id === `OPERATOR-CONTRACT-${scope}-${suffix}`)?.result.status, 'pass');
    }
  }
  assert.equal(await readFile(join(f.root, 'supervisor-entered'), 'utf8'), 'executed');
  assert.equal(result.records.at(-1).terminal.status, 'fail');
  assert.deepEqual(result.records.at(-1).terminal.failed_ids, ['OPERATOR-CONTRACT-OWNER-001']);
  f.complete();
});

test('missing native HTTP ownership tests fail their gate while both profiles still run', { timeout: 45000 }, async t => {
  const f = await fixture(t);
  await unlink(join(f.root, 'scripts/e2e/selftests/test_http_service_owner.py'));
  const result = await f.run();
  assert.notEqual(result.code, 0);
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-OWNER-001')?.result.status, 'pass');
  assert.equal(result.records.find(row => row.acceptance_id === 'OPERATOR-CONTRACT-HTTP-OWNER-001')?.result.status, 'fail');
  for (const scope of ['operator', 'scripts']) {
    assert.equal(await readFile(join(f.root, `${scope}-entered`), 'utf8'), 'executed');
    for (const suffix of ['001', '002']) {
      assert.equal(result.records.find(row => row.acceptance_id === `OPERATOR-CONTRACT-${scope}-${suffix}`)?.result.status, 'pass');
    }
  }
  assert.equal(result.records.at(-1).terminal.status, 'fail');
  assert.deepEqual(result.records.at(-1).terminal.failed_ids, ['OPERATOR-CONTRACT-HTTP-OWNER-001']);
  f.complete();
});
