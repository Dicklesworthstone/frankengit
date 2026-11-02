// Real archive CLI processes and production traversal against a response-schema
// peer. These tests do not stand in for a native Rust server campaign.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setupMilestones, tenant, repository } from './native_milestone_transfer_helper.mjs';
const archiveCli = fileURLToPath(new URL('../../scripts/archive_native_issues.mjs', import.meta.url));
const sourceFlags = f => ['--url', f.src.href, '--tenant', tenant, '--repository', repository, '--token-file', f.tokenFile];
function launch(t, script, args) {
  const child = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', text => { stdout += text; if (stdout.length > 4 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', text => { stderr += text; if (stderr.length > 4 * 1024 * 1024) child.kill('SIGKILL'); });
  const timer = setTimeout(() => child.kill('SIGKILL'), 20000);
  t.after(() => { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
  });
}
const decoded = (result, code = 0) => { assert.equal(result.code, code, result.stderr); return JSON.parse(result.stdout); };

test('archive CLI selects v2 explicitly and inspects both families with the source stopped', async t => {
  const f = await setupMilestones(t), workdir = join(f.root, 'cli-archive');
  const exported = decoded(await launch(t, archiveCli, ['export', '--include-milestones', ...sourceFlags(f),
    '--workdir', workdir, '--page-size', '1', '--max-milestones', '3']));
  assert.equal(exported.schema_version, 2); assert.equal(exported.milestones, 3);
  assert.equal(exported.issues, 4); assert.equal(exported.events, 21); assert.equal(exported.complete, true);
  await f.src.close();
  const inspected = decoded(await launch(t, archiveCli, ['inspect', '--workdir', workdir, '--confirm', exported.archive_sha256]));
  assert.equal(inspected.schema_version, 2); assert.equal(inspected.milestones, 3);
  assert.equal(inspected.network_accessed, false); assert.equal(inspected.local_read_only, true);
});

test('archive profile flags reject duplicate, inspect-only and missing-profile combinations before I/O', async t => {
  const f = await setupMilestones(t), start = f.src.calls.length;
  const args = ['export', ...sourceFlags(f), '--workdir', join(f.root, 'invalid')];
  for (const flags of [['--include-milestones', '--include-milestones'], ['--include-milestones', 'true'],
    ['--max-milestones', '2'], ['--include-milestones', '--max-milestones', '0']]) {
    const result = await launch(t, archiveCli, [...args, ...flags]);
    assert.equal(result.code, 2, result.stderr); assert.equal(result.stdout, '');
  }
  const inspect = await launch(t, archiveCli, ['inspect', '--workdir', f.archiveDir,
    '--confirm', f.archive.archive_sha256, '--include-milestones']);
  assert.equal(inspect.code, 2, inspect.stderr); assert.equal(f.src.calls.length, start);
  await assert.rejects(readdir(join(f.root, 'invalid')), { code: 'ENOENT' });
});

