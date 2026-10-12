// Actual CLI subprocesses, process death, private files and Ed25519 approvals.
// These bytes are not native fg archives; no engine or hardware-crash claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { watch } from 'node:fs';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { runJobCommand, jobArguments } from '../repository_backup_job.mjs';
import { initializeRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { jobFixture, DATA } from './repository-backup-job-fixture.mjs';

const SCRIPT = fileURLToPath(new URL('../repository_backup_job.mjs', import.meta.url));
function args(f, operation, intent, options = {}) {
  const max = options.maximumBytes ?? DATA.length;
  const values = [operation, '--trusted-local', '--trust-key', f.trustKey,
    ...Object.entries(f.policy).flatMap(([k, v]) => [`--${k.replaceAll('_', '-')}`, v]),
    '--max-archive-bytes', String(max), '--max-total-read-bytes', String(options.maximumTotalBytes ?? max * (1 + 4 * f.destinations.length)),
    '--timeout-secs', '20'];
  if (operation === 'seal') values.push('--job-directory', f.jobDirectory, '--candidate', f.source.input, f.source.approval,
    ...f.destinations.flatMap(p => ['--replica-directory', p]));
  else values.push('--intent', intent);
  if (options.witness) values.push('--witness', options.witness);
  if (options.progress) values.push('--progress-json');
  return values;
}
function launch(t, argv, onProgress = () => {}) {
  const child = spawn(process.execPath, [SCRIPT, ...argv], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', pending = '';
  const timer = setTimeout(() => child.kill('SIGKILL'), 25000);
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, out, err }); });
  });
  child.stdout.on('data', bytes => { out += bytes; if (out.length > 4 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', bytes => {
    err += bytes; pending += bytes;
    if (err.length > 4 * 1024 * 1024) child.kill('SIGKILL');
    let newline;
    while ((newline = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, newline); pending = pending.slice(newline + 1);
      let message; try { message = JSON.parse(line); } catch { continue; }
      onProgress(message, child);
    }
  });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await done; });
  return { child, done };
}
async function command(t, argv) { return launch(t, argv).done; }
async function sealed(t, f, options = {}) {
  const r = await command(t, args(f, 'seal', null, options)); assert.equal(r.code, 0, r.err); return JSON.parse(r.out);
}
const lastError = result => JSON.parse(result.err.trim().split('\n').at(-1));

for (const format of ['sha1', 'sha256']) test(`${format}: CLI seals and runs the exact saved intent`, async t => {
  const f = await jobFixture(t, format), job = await sealed(t, f);
  for (const path of f.destinations) assert.deepEqual(await readdir(path), []);
  const r = await command(t, args(f, 'run', job.intent)); assert.equal(r.code, 0, r.err);
  const report = JSON.parse(r.out); assert.equal(report.state, 'complete'); assert.equal(report.job.job_id, job.job_id);
  for (const row of report.result.completed_replicas) assert.deepEqual(await readFile(row.receipt.candidate.input), DATA);
});

test('CLI help performs no job operation', async t => {
  const r = await command(t, ['--help']); assert.equal(r.code, 0); assert.match(r.out, /^Usage:/); assert.equal(r.err, '');
});

test('CLI requires explicit trusted-local consent', async t => {
  const f = await jobFixture(t), r = await command(t, args(f, 'seal').filter(v => v !== '--trusted-local'));
  assert.equal(r.code, 1); assert.equal(lastError(r).code, 'backup_job_trusted_local_required'); assert.deepEqual(await readdir(f.jobDirectory), []);
});

test('CLI rejects source and destination overrides on run before any job read', () => {
  const base = ['run', '--trusted-local', '--intent', '/not-read', '--trust-key', '/not-read'];
  for (const extras of [['--candidate', '/a', '/b'], ['--replica-directory', '/a']]) assert.throws(() => jobArguments([...base, ...extras]), { code: 'backup_job_inapplicable_option' });
  assert.throws(() => jobArguments(['unknown']), { code: 'backup_job_operation' });
});

test('CLI grammar bounds are enforced without filesystem access', () => {
  for (const argv of [[], Array(351).fill('x'), ['run', '--bogus'], ['run', '--intent'], ['run', '--trusted-local', '--trusted-local'],
    ['run', '--max-archive-bytes', '0'], ['run', '--timeout-secs', '3601'], ['run', '--max-total-read-bytes', '999999999999999999'], ['run', '\0']]) {
    assert.throws(() => jobArguments(argv));
  }
});

test('CLI exact retry uses copies after original archive and control disappear', async t => {
  const f = await jobFixture(t), job = await sealed(t, f), first = await command(t, args(f, 'run', job.intent));
  assert.equal(first.code, 0, first.err); const original = JSON.parse(first.out);
  const inode = await lstat(original.result.completed_replicas[0].receipt.candidate.input, { bigint: true });
  await unlink(f.source.input); await unlink(f.source.approval);
  const second = await command(t, args(f, 'run', job.intent)); assert.equal(second.code, 0, second.err);
  const resumed = JSON.parse(second.out); assert.equal(resumed.job.job_id, original.job.job_id);
  assert.equal((await lstat(resumed.result.completed_replicas[0].receipt.candidate.input, { bigint: true })).ino, inode.ino);
});

test('SIGKILL after a completed replica permits exact CLI restart without original source', async t => {
  const f = await jobFixture(t, 'sha256', 16), job = await sealed(t, f); let killed = false, first;
  const proc = launch(t, args(f, 'run', job.intent, { progress: true }), (event, child) => {
    if (!killed && event.phase === 'replica_complete') { first = event.candidate; killed = true; child.kill('SIGKILL'); }
  });
  const interrupted = await proc.done; assert.equal(killed, true); assert.equal(interrupted.signal, 'SIGKILL');
  assert(first); const before = await lstat(first.input, { bigint: true });
  await unlink(f.source.input); await unlink(f.source.approval);
  const resumed = await command(t, args(f, 'run', job.intent)); assert.equal(resumed.code, 0, resumed.err);
  assert.equal(JSON.parse(resumed.out).result.completed_replicas.length, 16);
  assert.equal((await lstat(first.input, { bigint: true })).ino, before.ino);
});

test('SIGTERM drains with partial receipts and resumes after original loss', async t => {
  const f = await jobFixture(t, 'sha256', 16), job = await sealed(t, f); let stopped = false;
  const proc = launch(t, args(f, 'run', job.intent, { progress: true }), (event, child) => {
    if (!stopped && event.phase === 'replica_complete') { stopped = true; child.kill('SIGTERM'); }
  });
  const interrupted = await proc.done; assert.equal(stopped, true); assert.equal(interrupted.code, 1, interrupted.out);
  const error = lastError(interrupted); assert.equal(error.code, 'backup_cancelled'); assert(error.replenishment.completed_replicas.length >= 1);
  await unlink(f.source.input); await unlink(f.source.approval);
  const resumed = await command(t, args(f, 'run', job.intent)); assert.equal(resumed.code, 0, resumed.err);
});

test('kill during streaming preserves private scratch and exact restart never claims or deletes it', async t => {
  const f = await jobFixture(t), data = Buffer.alloc(8 * 1024 * 1024 + 19, 0x37);
  f.source = await f.sign('large', data); const job = await sealed(t, f, { maximumBytes: data.length });
  let killed = false, scratch;
  const proc = launch(t, args(f, 'run', job.intent, { maximumBytes: data.length }));
  const watcher = watch(f.destinations[0], async (_event, name) => {
    if (killed || !name?.startsWith('.fg-backup-replica-')) return;
    const path = join(f.destinations[0], name);
    let stat; try { stat = await lstat(path); } catch { return; }
    if (!killed && stat.size > 0 && stat.size < data.length) { scratch = path; killed = true; proc.child.kill('SIGKILL'); }
  });
  t.after(() => watcher.close());
  const interrupted = await proc.done; watcher.close(); assert.equal(killed, true); assert.equal(interrupted.signal, 'SIGKILL');
  const before = await lstat(scratch, { bigint: true }); assert.equal(before.mode & 0o777n, 0o600n);
  const resumed = await command(t, args(f, 'run', job.intent, { maximumBytes: data.length })); assert.equal(resumed.code, 0, resumed.err);
  assert.equal((await lstat(scratch, { bigint: true })).ino, before.ino);
  for (const row of JSON.parse(resumed.out).result.completed_replicas) assert.deepEqual(await readFile(row.receipt.candidate.input), data);
});

test('bounded CLI progress emits only durable milestones', async t => {
  const f = await jobFixture(t, 'sha256', 3), job = await sealed(t, f);
  const r = await command(t, args(f, 'run', job.intent, { progress: true })); assert.equal(r.code, 0, r.err);
  const events = r.err.trim().split('\n').map(line => JSON.parse(line)); assert.equal(events.length, 4);
  assert.deepEqual(events.map(e => e.phase), ['checkpoint_pinned', 'replica_complete', 'replica_complete', 'replica_complete']);
});

test('broken real stdout pipe preserves a sealed intent receipt on stderr', async t => {
  const f = await jobFixture(t), proc = launch(t, args(f, 'seal')); proc.child.stdout.destroy();
  const r = await proc.done; assert.equal(r.code, 1); const error = lastError(r);
  assert.equal(error.completed_result.state, 'sealed');
  const resumed = await command(t, args(f, 'run', error.completed_result.intent)); assert.equal(resumed.code, 0, resumed.err);
});

test('failed final result delivery retains confirmed job completion', async t => {
  const f = await jobFixture(t), job = await sealed(t, f), output = { write(_text, cb) { const e = new Error('pipe'); e.code = 'EPIPE'; cb(e); } };
  await assert.rejects(runJobCommand(args(f, 'run', job.intent), output), error =>
    error.code === 'EPIPE' && error.completed_result?.state === 'complete' && error.completed_result.result.all_destinations_verified);
});

test('CLI cannot drop a witness bound at seal time', async t => {
  const f = await jobFixture(t), witness = join(f.root, 'witness');
  await initializeRepositoryBackupWitness(witness, f.trustKey, f.policy);
  const job = await sealed(t, f, { witness });
  const missing = await command(t, args(f, 'run', job.intent)); assert.equal(missing.code, 1); assert.equal(lastError(missing).code, 'backup_job_witness_required');
  const allowed = await command(t, args(f, 'run', job.intent, { witness })); assert.equal(allowed.code, 0, allowed.err);
});

test('killed witnessed CLI keeps the lease blocking and cannot resume unwitnessed', async t => {
  const f = await jobFixture(t, 'sha256', 16), witness = join(f.root, 'witness');
  await initializeRepositoryBackupWitness(witness, f.trustKey, f.policy);
  const job = await sealed(t, f, { witness }); let killed = false;
  const proc = launch(t, args(f, 'run', job.intent, { witness, progress: true }), (event, child) => {
    if (!killed && event.phase === 'replica_complete') { killed = true; child.kill('SIGKILL'); }
  });
  assert.equal((await proc.done).signal, 'SIGKILL'); assert.equal(killed, true);
  await lstat(join(witness, '.witness-lock'));
  const blocked = await command(t, args(f, 'run', job.intent, { witness })); assert.equal(lastError(blocked).code, 'backup_witness_locked');
  const bypass = await command(t, args(f, 'run', job.intent)); assert.equal(lastError(bypass).code, 'backup_job_witness_required');
  await lstat(join(witness, '.witness-lock'));
});

test('CLI insufficient budget refuses before any output, while exact budget works', async t => {
  const f = await jobFixture(t), job = await sealed(t, f);
  const low = await command(t, args(f, 'run', job.intent, { maximumTotalBytes: DATA.length * 9 - 1 }));
  assert.equal(lastError(low).code, 'backup_replenishment_read_budget'); for (const path of f.destinations) assert.deepEqual(await readdir(path), []);
  const exact = await command(t, args(f, 'run', job.intent, { maximumTotalBytes: DATA.length * 9 })); assert.equal(exact.code, 0, exact.err);
});
