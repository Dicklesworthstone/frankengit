import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectDiscussionArchive } from '../../scripts/lib/forge-discussion-archive.mjs';
import { fixture, noRoot, token } from './discussion-archive-fixture.mjs';

const cli = fileURLToPath(new URL('../../scripts/archive_native_discussions.mjs', import.meta.url));
function exportArgs(f) {
  const o = f.options;
  return ['export', '--workdir', o.workdir, '--url', o.href, '--tenant', o.tenant,
    '--repository', o.repository, '--token-file', o.tokenFile, '--page-size', String(o.pageSize)];
}
const inspectArgs = (f, sha) => ['inspect', '--workdir', f.options.workdir, '--confirm', sha];
function run(args, { closedOutput = false, started = () => {} } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Discussion archive CLI did not settle')); }, 15000);
    if (closedOutput) child.stdout.destroy();
    else child.stdout.on('data', bytes => { stdout += bytes; if (stdout.length > 65536) child.kill('SIGKILL'); });
    child.stderr.on('data', bytes => { stderr += bytes; if (stderr.length > 65536) child.kill('SIGKILL'); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
    started(child);
  });
}
test('fresh CLI processes export and then inspect without the original token or server', async t => {
  const f = await fixture(t), exported = await run(exportArgs(f));
  assert.equal(exported.code, 0, exported.stderr); assert.equal(exported.stderr, '');
  const result = JSON.parse(exported.stdout);
  assert.deepEqual([result.discussions, result.events, result.pages], [2, 13, 15]);
  assert.equal(result.complete, true); assert.equal(result.restore_authority, false);
  await rm(f.options.tokenFile); f.server.closeAllConnections();
  await new Promise(resolve => f.server.close(resolve));
  const inspected = await run(inspectArgs(f, result.archive_sha256));
  assert.equal(inspected.code, 0, inspected.stderr); assert.equal(JSON.parse(inspected.stdout).network_accessed, false);
  assert.equal(f.calls.length, 15); assert.ok(!exported.stdout.includes(token));
});
test('CLI budget refusal exposes incomplete custody and cannot be inspected as a valid archive', async t => {
  const f = await fixture(t), result = await run([...exportArgs(f), '--max-requests', '1']);
  assert.equal(result.code, 3); assert.equal(result.stdout, ''); assert.equal(f.calls.length, 1);
  assert.equal(JSON.parse(result.stderr).archive_progress.complete, false); await noRoot(f.options);
  const names = await readdir(f.options.workdir);
  const inspected = await run(inspectArgs(f, '0'.repeat(64)));
  assert.equal(inspected.code, 2); assert.equal(f.calls.length, 1);
  assert.deepEqual(await readdir(f.options.workdir), names);
});
for (const extra of [['--max-events', '0'], ['--max-discussions', '4097'], ['--page-size', '1'],
  ['--confirm', '0'.repeat(64)], ['--unknown', 'true']]) {
  test(`CLI rejects duplicate, inapplicable or invalid ${extra.join(' ')} before HTTP`, async t => {
    const f = await fixture(t), result = await run([...exportArgs(f), ...extra]);
    assert.equal(result.code, 2); assert.equal(f.calls.length, 0);
    await assert.rejects(readdir(f.options.workdir), { code: 'ENOENT' });
  });
}
test('offline CLI refuses a wrong pin and rejects network or credential overrides', async t => {
  const f = await fixture(t); assert.equal((await run(exportArgs(f))).code, 0);
  const wrong = await run(inspectArgs(f, '0'.repeat(64)));
  assert.equal(wrong.code, 2); assert.match(wrong.stderr, /pin_mismatch/);
  const overridden = await run([...inspectArgs(f, '0'.repeat(64)), '--token-file', f.options.tokenFile]);
  assert.equal(overridden.code, 2); assert.equal(f.calls.length, 15);
});
for (const signal of ['SIGTERM', 'SIGINT']) test(`${signal} cancels the current response and publishes no root`, async t => {
  let child;
  const f = await fixture(t, { handle: async (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); child.kill(signal); return true;
  } });
  const result = await run(exportArgs(f), { started: value => { child = value; } });
  assert.equal(result.code, 3, result.stderr); assert.equal(result.signal, null); assert.equal(result.stdout, '');
  assert.equal(f.calls.length, 1); await noRoot(f.options);
});
test('SIGKILL retains a private unsealed prefix and a new process refuses offline inspection', async t => {
  let child;
  const f = await fixture(t, { handle: async (_req, res, calls) => {
    if (calls.length < 2) return false;
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); child.kill('SIGKILL'); return true;
  } });
  const result = await run(exportArgs(f), { started: value => { child = value; } });
  assert.equal(result.signal, 'SIGKILL'); assert.equal(f.calls.length, 2);
  assert.deepEqual(await readdir(f.options.workdir), ['page-000001.json']);
  const inspected = await run(inspectArgs(f, '0'.repeat(64)));
  assert.equal(inspected.code, 2); assert.equal(f.calls.length, 2);
});
test('a closed output pipe preserves the complete result and independent pin without recapturing', async t => {
  const f = await fixture(t), result = await run(exportArgs(f), { closedOutput: true });
  assert.equal(result.code, 4, result.stderr);
  const retained = JSON.parse(result.stderr).retained_result;
  assert.equal(retained.complete, true); assert.equal(f.calls.length, 15);
  assert.equal((await inspectDiscussionArchive({ workdir: f.options.workdir, confirm: retained.archive_sha256 })).complete, true);
  assert.ok((await readFile(join(f.options.workdir, 'archive.json'))).length > 0);
});
test('help explains complete capture and offline inspection without accessing a source', async () => {
  const result = await run(['--help']); assert.equal(result.code, 0);
  assert.match(JSON.parse(result.stdout).usage, /standalone discussion/);
  assert.match(JSON.parse(result.stdout).usage, /inspect/);
});
