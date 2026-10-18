// Full CLI and all production operator imports, with a loopback response-schema
// peer rather than Rust fg. No importer, inspector, client or filesystem stubs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main, writeOutput } from '../../scripts/migrate_native_issues.mjs';
import { inspectNativeIssueMigration } from '../../scripts/lib/native-issue-migration.mjs';
import { setup, peer, fixtureIssues, destinationTenant as tenant, destinationRepository as repository } from './native_issue_transfer_helper.mjs';
const cli = fileURLToPath(new URL('../../scripts/migrate_native_issues.mjs', import.meta.url));
function launch(t, args, timeout = 15000) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', part => { stdout += part; if (stdout.length > 8 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', part => { stderr += part; if (stderr.length > 8 * 1024 * 1024) child.kill('SIGKILL'); });
  const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
  t.after(() => { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
  });
  return { child, done };
}
const row = result => JSON.parse(result.stdout);
const errors = result => JSON.parse(result.stderr);
function output() {
  let text = ''; const stream = new Writable({ write(bytes, _encoding, done) { text += bytes; done(); } });
  return { stream, get text() { return text; } };
}
function brokenOutput() { return new Writable({ write(_bytes, _encoding, done) { done(Object.assign(new Error('closed consumer'), { code: 'EPIPE' })); } }); }
async function fixture(t, count = 3, options = {}) {
  const f = await setup(t, fixtureIssues(count));
  const dest = await peer({ tenantId: tenant, repositoryId: repository, ...options }); t.after(() => dest.close());
  const tokenFile = join(f.root, 'native-token'); await writeFile(tokenFile, dest.token, { mode: 0o600 });
  const workdir = join(f.root, 'migration');
  const flags = ['--workdir', workdir, '--url', dest.href, '--tenant', tenant, '--repository', repository, '--token-file', tokenFile];
  const prepare = ['prepare', ...flags, '--archive', f.archiveDir, '--archive-sha256', f.archive.archive_sha256, '--offset', '1000'];
  return { ...f, dest, workdir, tokenFile, flags, prepare };
}
async function prepared(t, options) {
  const f = await fixture(t, 3, options), result = await launch(t, f.prepare).done;
  assert.equal(result.code, 0, result.stderr);
  return { ...f, plan: row(result), phase: name => [name, ...f.flags, '--confirm', row(result).plan_sha256] };
}
test('real CLI prepare -> inspect -> budget stop -> resumed run -> status owns full lifecycle', async t => {
  const f = await prepared(t);
  assert.equal(f.dest.calls.length, 0); assert.equal(f.plan.steps, 5);
  let result = await launch(t, f.phase('inspect')).done;
  assert.equal(result.code, 0, result.stderr); assert.equal(row(result).network_accessed, false);
  await rm(f.archiveDir, { recursive: true }); await f.src.close();
  result = await launch(t, [...f.phase('run'), '--max-mutations', '1']).done;
  assert.equal(result.code, 3, result.stderr); assert.equal(row(result).mutation_calls, 1);
  const request = await readFile(join(f.workdir, 'batch-000001/step-000000.request.json'));
  result = await launch(t, f.phase('run')).done;
  assert.equal(result.code, 0, result.stderr); assert.equal(row(result).mutation_calls, 4);
  result = await launch(t, f.phase('status')).done;
  assert.equal(result.code, 0, result.stderr); assert.equal(row(result).mutation_calls, 0);
  assert.equal(row(result).committed_observed, 5);
  assert.deepEqual(await readFile(join(f.workdir, 'batch-000001/step-000000.request.json')), request);
  assert.equal(f.dest.calls.filter(c => /\/(open|comment|close)$/.test(c.path)).length, 5);
});
test('CLI refuses incompatible flags, duplicate options and noncanonical bounds before preparation', async t => {
  const f = await fixture(t);
  for (const args of [[...f.prepare, '--retry-unresolved'], [...f.prepare, '--offset', '2'],
    [...f.prepare, '--max-steps', '01'], [...f.prepare, '--max-steps', '10001'],
    ['status', ...f.flags, '--confirm', 'a'.repeat(64), '--max-mutations', '1'], ['prepare', '--__proto__', 'x']]) {
    const result = await launch(t, args).done;
    assert.equal(result.code, 2, result.stderr); assert.equal(result.stdout, '');
  }
  assert.equal((await readdir(f.root)).includes('migration'), false); assert.equal(f.dest.calls.length, 0);
});
test('CLI independent source pin refuses before request preparation', async t => {
  const f = await fixture(t), args = [...f.prepare]; args[args.indexOf('--archive-sha256') + 1] = '0'.repeat(64);
  const result = await launch(t, args).done;
  assert.equal(result.code, 2); assert.match(errors(result).message, /pin_mismatch/);
  assert.equal((await readdir(f.root)).includes('migration'), false); assert.equal(f.dest.calls.length, 0);
});
test('CLI canonical collision returns refusal, not successful import or a new request identity', async t => {
  const rows = fixtureIssues(1); rows[0].number = 1001;
  const f = await prepared(t, { rows });
  const result = await launch(t, f.phase('run')).done;
  assert.equal(result.code, 1, result.stderr); assert.equal(row(result).stop_reason, 'terminal_refusal');
  assert.equal(f.dest.source.has(1002), false);
  const again = await launch(t, [...f.phase('run'), '--retry-unresolved']).done;
  assert.equal(again.code, 1); assert.equal(row(again).mutation_calls, 0);
});
for (const signal of ['SIGTERM', 'SIGINT']) test(`CLI ${signal} aborts active outcome read and drains without starting a mutation`, async t => {
  let entered; const ready = new Promise(resolve => { entered = resolve; }); let armed = true, closed = false;
  const f = await prepared(t, { fault({ call, res }) {
    if (armed && call.path.endsWith('/outcomes')) { res.once('close', () => { closed = true; }); entered(); return true; }
  } });
  const running = launch(t, f.phase('run'));
  await Promise.race([ready, running.done.then(result => { throw new Error(`exited before read: ${result.stderr}`); })]);
  running.child.kill(signal);
  const result = await running.done;
  assert.equal(result.code, 3, result.stderr); assert.equal(result.signal, null);
  assert.equal(errors(result).migration_progress.committed_observed, 0); assert.equal(f.dest.decisions.size, 0);
  assert.equal(closed, true);
  assert.ok(!(await readdir(f.workdir)).includes('migration.sender.lock'));
  assert.ok(!(await readdir(join(f.workdir, 'batch-000001'))).includes('sender.lock'));
  armed = false;
  assert.equal((await launch(t, f.phase('run')).done).code, 0);
});
test('SIGKILL after a synced dispatch start retains sender locks and forbids automatic replay', async t => {
  let entered; const ready = new Promise(resolve => { entered = resolve; }); let armed = true;
  const f = await prepared(t, { fault({ call }) {
    if (armed && call.path.endsWith('/open')) { entered(); return true; }
  } });
  const running = launch(t, f.phase('run'));
  await Promise.race([ready, running.done.then(result => { throw new Error(result.stderr); })]);
  const request = await readFile(join(f.workdir, 'batch-000001/step-000000.request.json'));
  running.child.kill('SIGKILL'); const killed = await running.done; assert.equal(killed.signal, 'SIGKILL'); armed = false;
  assert.ok((await readdir(f.workdir)).includes('migration.sender.lock'));
  assert.ok((await readdir(join(f.workdir, 'batch-000001'))).includes('sender.lock'));
  const status = await launch(t, f.phase('status')).done;
  assert.equal(status.code, 3, status.stderr); assert.equal(row(status).owner_present, true);
  assert.equal(row(status).stop_reason, 'unresolved_original_request');
  const blocked = await launch(t, [...f.phase('run'), '--retry-unresolved']).done;
  assert.equal(blocked.code, 2, blocked.stderr); assert.match(errors(blocked).message, /sender_lock_retained/);
  assert.equal(f.dest.calls.filter(c => c.path.endsWith('/open')).length, 1);
  assert.deepEqual(await readFile(join(f.workdir, 'batch-000001/step-000000.request.json')), request);
});
test('CLI whole-operation deadline cancels a held outcome read without resetting its allowance', async t => {
  const f = await prepared(t, { fault({ call }) { if (call.path.endsWith('/outcomes')) return true; } });
  const start = performance.now(), result = await launch(t, [...f.phase('run'), '--timeout-ms', '400']).done;
  assert.equal(result.code, 3, result.stderr); assert.ok(performance.now() - start < 5000);
  assert.equal(f.dest.decisions.size, 0); assert.ok(!(await readdir(f.workdir)).includes('migration.sender.lock'));
});
test('output loss after preparation preserves the exact published plan and exits nonzero', async t => {
  const f = await fixture(t), stderr = output();
  const code = await main(f.prepare, { stdout: brokenOutput(), stderr: stderr.stream });
  assert.equal(code, 4);
  const diagnostic = JSON.parse(stderr.text), p = diagnostic.retained_operation;
  assert.equal(p.type, 'native_issue_migration_prepared'); assert.equal(f.dest.calls.length, 0);
  assert.equal((await inspectNativeIssueMigration({ workdir: f.workdir, href: f.dest.href, tenant, repository,
    tokenFile: f.tokenFile, confirm: p.plan_sha256 })).steps, 5);
});
test('output loss after committed migration preserves the result and never resubmits', async t => {
  const f = await prepared(t), stderr = output();
  const code = await main(f.phase('run'), { stdout: brokenOutput(), stderr: stderr.stream });
  assert.equal(code, 4); assert.equal(JSON.parse(stderr.text).retained_operation.complete, true);
  const again = await launch(t, f.phase('run')).done;
  assert.equal(again.code, 0); assert.equal(row(again).mutation_calls, 0); assert.equal(f.dest.decisions.size, 5);
});
test('terminal output is bounded and controls are escaped without changing decoded text', async () => {
  const stdout = output(), original = 'control\u202e\u009b text';
  await writeOutput(stdout.stream, { original });
  assert.ok(!stdout.text.includes('\u202e')); assert.deepEqual(JSON.parse(stdout.text), { original });
  await assert.rejects(writeOutput(stdout.stream, { oversized: 'x'.repeat(4 * 1024 * 1024) }), /output limit/);
});
