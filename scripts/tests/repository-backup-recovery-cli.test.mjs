// Actual command/HTTPS/files/process integration. Native-schema peer is labelled
// in backup-recovery-fixture; it is not fg or native repository acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile, lstat, unlink, chmod, rm, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { runRecoveryCommand, recoveryArguments } from '../recover_repository_backup.mjs';
import { recoveryFixture, DATA } from './backup-recovery-fixture.mjs';

const CLI = fileURLToPath(new URL('../recover_repository_backup.mjs', import.meta.url));
const missing = path => assert.rejects(lstat(path), { code: 'ENOENT' });
function args(f, operation = 'restore', extra = []) {
  const o = f.options;
  return [operation, '--cache-directory', o.cacheDirectory, '--approval', o.approval, '--trust-key', o.trustKey,
    '--witness', o.witness, '--fg', o.fg, '--trusted-local', '--verification-instance', o.verificationInstance,
    ...Object.entries(o.policy).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v]),
    '--max-archive-bytes', String(DATA.length), '--max-acquisition-bytes', String(DATA.length * 4),
    '--sources', f.sourceFile, '--ca-file', f.caFile,
    ...(operation === 'restore' ? ['--destination', o.destination, '--destination-instance', o.destinationInstance, '--approval-record', o.approvalRecord] : []), ...extra];
}
function launch(t, argv, brokenOutput = false) {
  const child = spawn(process.execPath, [CLI, ...argv], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  if (brokenOutput) child.stdout.destroy(); else child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await done; });
  return { child, done, stderr: () => stderr };
}
const lines = text => text.trim().split('\n').filter(Boolean).map(JSON.parse);
async function waitFor(check, maximum = 5000) {
  const until = Date.now() + maximum;
  while (!await check()) { assert(Date.now() < until, 'bounded event wait'); await delay(10); }
}
async function off(f) { await missing(join(f.witness, '.witness-lock')); }
function privateReport(text) { assert(!text.includes('capability-do-not-log')); }
function omit(argv, key) { const at = argv.indexOf(key); if (at >= 0) argv.splice(at, 2); return argv; }

for (const format of ['sha1', 'sha256']) test(`actual remote recovery CLI and offline native exact resume (${format})`, async t => {
  const f = await recoveryFixture(t, format), first = await launch(t, args(f, 'restore', ['--progress-json'])).done;
  assert.equal(first.code, 0, first.stderr); const result = JSON.parse(first.stdout);
  assert.equal(result.state, 'complete'); assert.equal(result.acquisition.mode, 'downloaded');
  const markers = lines(first.stderr); assert.equal(markers.length, 6);
  assert.deepEqual(markers.map(m => m.phase), ['checkpoint_pinned', 'acquisition_complete', 'authenticated', 'preflight_verified', 'approval_recorded', 'restore_starting']);
  assert(markers.every(m => m.checkpoint.approval_sha256 === result.checkpoint.approval_sha256));
  const inode = (await lstat(result.candidate.input)).ino; await unlink(f.sourceFile); await unlink(f.caFile); await unlink(f.local);
  const next = omit(omit(args(f, 'restore', ['--resume', '--checkpoint', result.checkpoint.approval_sha256, result.checkpoint.trusted_key_id]), '--sources'), '--ca-file');
  const retry = await launch(t, next).done; assert.equal(retry.code, 0, retry.stderr);
  const resumed = JSON.parse(retry.stdout); assert.equal(resumed.acquisition.mode, 'cached'); assert.equal(resumed.native.native.already_published, true);
  assert.equal(f.requests.length, 1); assert.equal((await lstat(resumed.candidate.input)).ino, inode);
  assert.deepEqual(resumed.checkpoint, result.checkpoint); await off(f); privateReport(first.stdout + first.stderr + retry.stdout);
});

test('native verify command does not create a restore root or an approval record', async t => {
  const f = await recoveryFixture(t), done = await launch(t, args(f, 'verify')).done;
  assert.equal(done.code, 0, done.stderr); assert.equal(JSON.parse(done.stdout).native.native.type, 'repository_source_backup_verify');
  await missing(f.options.destination); await missing(f.options.approvalRecord); assert.equal((await f.events()).length, 1);
});

test('lost native reply returns original pins and resume calls only the original native intent', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'lose_restore_response' });
  const failed = await launch(t, args(f)).done; assert.equal(failed.code, 1); assert.equal(failed.stdout, '');
  const error = lines(failed.stderr).at(-1); assert.equal(error.state, 'restore_attempted_unknown'); assert(error.recovery.acquisition);
  const pin = error.recovery.checkpoint; await unlink(f.sourceFile);
  const retry = await launch(t, omit(args(f, 'restore', ['--resume', '--checkpoint', pin.approval_sha256, pin.trusted_key_id]), '--sources')).done;
  assert.equal(retry.code, 0, retry.stderr); assert.equal(JSON.parse(retry.stdout).native.native.already_published, true);
  assert.equal(f.requests.length, 1); assert.deepEqual((await f.events()).filter(e => e.operation === 'restore').map(e => e.resume), [false, true]);
});

test('wrong independent destination on resume refuses before another native subprocess', async t => {
  const f = await recoveryFixture(t), done = await launch(t, args(f)).done; assert.equal(done.code, 0, done.stderr);
  const { checkpoint } = JSON.parse(done.stdout), next = args(f, 'restore', ['--resume', '--checkpoint', checkpoint.approval_sha256, checkpoint.trusted_key_id]);
  next[next.indexOf('--destination') + 1] = join(f.root, 'other-destination');
  const refused = await launch(t, next).done; assert.equal(refused.code, 1);
  assert.equal(lines(refused.stderr).at(-1).code, 'backup_restore_approval_record_mismatch');
  assert.equal((await f.events()).length, 2); assert.equal(f.requests.length, 1); await missing(join(f.root, 'other-destination'));
});

test('private URL-file ownership is enforced on cache miss', async t => {
  const f = await recoveryFixture(t); await chmod(f.sourceFile, 0o644);
  const done = await launch(t, args(f)).done; assert.equal(done.code, 1);
  assert.equal(lines(done.stderr).at(-1).code, 'backup_private_owner_required');
  assert.equal(f.requests.length, 0); assert.equal((await f.events()).length, 0); await off(f);
});

test('malformed private source JSON cannot leak its signed URL into diagnostics', async t => {
  const f = await recoveryFixture(t); await writeFile(f.sourceFile, '["' + f.url + '"');
  const done = await launch(t, args(f)).done; assert.equal(done.code, 1);
  assert.equal(lines(done.stderr).at(-1).code, 'backup_recovery_invalid_sources'); privateReport(done.stderr);
  assert.equal(f.requests.length, 0); assert.equal((await f.events()).length, 0);
});

test('invalid native/options grammar refuses without consulting source or native paths', async t => {
  const f = await recoveryFixture(t);
  for (const changes of [['--resume'], ['--insecure'], ['--timeout-secs', '0'], ['--checkpoint', 'invalid', 'invalid'], ['--trusted-local']]) {
    const done = await launch(t, args(f, 'restore', changes)).done; assert.equal(done.code, 1);
    assert.equal(done.stdout, ''); assert(lines(done.stderr).at(-1).code.startsWith('backup_'));
  }
  assert.equal(f.requests.length, 0); assert.equal((await f.events()).length, 0);
  assert.throws(() => recoveryArguments(['verify', ...Array(81).fill('--option')]));
});

test('SIGTERM drains a held native restore before releasing its witness', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'hold_restore' });
  const run = launch(t, args(f, 'restore', ['--progress-json']));
  await waitFor(async () => (await f.events()).some(e => e.operation === 'restore'));
  await lstat(join(f.witness, '.witness-lock')); run.child.kill('SIGTERM');
  const done = await run.done; assert.equal(done.code, 1, done.stderr);
  const error = lines(done.stderr).at(-1); assert.equal(error.code, 'native_import_cancelled'); assert.equal(error.state, 'restore_attempted_unknown');
  const events = await f.events(); assert(events.some(e => e.stopped === 'restore'));
  for (const event of events.filter(e => e.operation)) assert.throws(() => process.kill(event.pid, 0), { code: 'ESRCH' });
  await off(f); assert(error.recovery.acquisition); privateReport(done.stderr);
});

test('SIGTERM drains a silent download and never invokes native restoration', async t => {
  const f = await recoveryFixture(t); f.setHandler((_, res) => { res.writeHead(200); res.write(DATA.subarray(0, 8)); });
  const run = launch(t, args(f)); await waitFor(() => f.requests.length > 0); run.child.kill('SIGTERM');
  const done = await run.done; assert.equal(done.code, 1, done.stderr); assert.equal(lines(done.stderr).at(-1).code, 'backup_cancelled');
  assert.equal((await f.events()).length, 0); await missing(f.options.destination); await off(f);
  await waitFor(() => f.sockets.size === 0); assert.deepEqual(await readdir(f.destination), []);
});

test('SIGKILL during download retains a blocking witness and does not authorize automatic restart', async t => {
  const f = await recoveryFixture(t); f.setHandler((_, res) => { res.writeHead(200); res.write(DATA.subarray(0, 8)); });
  const run = launch(t, args(f)); await waitFor(() => f.requests.length > 0); run.child.kill('SIGKILL');
  const killed = await run.done; assert.equal(killed.signal, 'SIGKILL'); await lstat(join(f.witness, '.witness-lock'));
  const again = await launch(t, args(f)).done; assert.equal(again.code, 1);
  assert.equal(lines(again.stderr).at(-1).code, 'backup_witness_locked'); assert.equal(f.requests.length, 1);
  assert.equal((await f.events()).length, 0); await missing(f.options.destination);
});

test('actually closed stdout preserves completed native publication with exit 4', async t => {
  const f = await recoveryFixture(t), done = await launch(t, args(f), true).done;
  assert.equal(done.code, 4, done.stderr); const error = lines(done.stderr).at(-1);
  assert.equal(error.state, 'complete'); assert.equal(error.completed_result.native.native.reopened_and_verified, true);
  assert.equal(error.completed_result.native.state, 'complete'); await lstat(f.options.destination); await off(f);
  assert.equal((await f.events()).filter(e => e.operation === 'restore').length, 1);
});

test('late witness cleanup failure retains the completed native result, not rollback', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'move_witness_lock' });
  const done = await launch(t, args(f)).done; assert.equal(done.code, 4, done.stderr);
  const error = lines(done.stderr).at(-1); assert.equal(error.completed_result.state, 'complete');
  assert.equal(error.completed_result.native.native.reopened_and_verified, true); await lstat(f.options.destination);
  assert.equal(error.recovery.native.state, 'complete'); await lstat(join(f.witness, '.moved-test-lock'));
});

test('late native approval cleanup failure retains the validated native receipt with exit 4', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'fail_approval_cleanup' });
  const done = await launch(t, args(f)).done; assert.equal(done.code, 4, done.stderr);
  const error = lines(done.stderr).at(-1); assert.equal(error.code, 'backup_native_approval_cleanup_failed');
  assert.equal(error.native_receipt.type, 'repository_source_backup_restore'); assert.equal(error.native_receipt.reopened_and_verified, true);
  assert.equal(error.state, 'complete'); await off(f); await lstat(f.options.destination);
  // This extra directory was created by our fixture invocation and intentionally
  // retained by the operator, not user data. Test cleanup does not weaken production.
  assert(error.approval_scratch.includes('fg-backup-native-approval-'));
  t.after(() => rm(error.approval_scratch, { recursive: true, force: true }));
});

test('whole-operation deadline also bounds native work after HTTPS acquisition', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'hold_verify' });
  f.setHandler((_, res) => { setTimeout(() => res.end(DATA), 300); });
  const start = Date.now(), done = await launch(t, args(f, 'verify', ['--timeout-secs', '1'])).done;
  assert.equal(done.code, 1, done.stderr); assert.equal(lines(done.stderr).at(-1).code, 'native_import_deadline');
  assert(Date.now() - start < 4000); assert((await f.events()).some(e => e.stopped === 'verify')); await off(f);
});

test('failed progress delivery stops before download and preserves the original pin', async t => {
  const f = await recoveryFixture(t);
  await assert.rejects(runRecoveryCommand(args(f, 'restore', ['--progress-json']), { write() { throw new Error('unexpected result'); } },
    { write(_text, callback) { const error = new Error('closed progress'); error.code = 'EPIPE'; callback(error); } }), error => {
    assert.equal(error.code, 'EPIPE'); assert(error.recovery.checkpoint.approval_sha256); assert.equal(error.state, 'not_started'); return true;
  });
  assert.equal(f.requests.length, 0); assert.equal((await f.events()).length, 0); await off(f);
});

test('a complete verify cache permits native restore without reading the now-invalid source file', async t => {
  const f = await recoveryFixture(t), cached = await launch(t, args(f, 'verify')).done; assert.equal(cached.code, 0, cached.stderr);
  await writeFile(f.sourceFile, 'not valid JSON or a trusted source'); await chmod(f.sourceFile, 0o644);
  const restored = await launch(t, args(f)).done; assert.equal(restored.code, 0, restored.stderr);
  assert.equal(JSON.parse(restored.stdout).acquisition.mode, 'cached'); assert.equal(f.requests.length, 1);
});

test('the help command is usable without native binary, source or witness', async t => {
  const done = await launch(t, ['--help']).done; assert.equal(done.code, 0); assert(done.stdout.includes('--checkpoint'));
  assert(done.stdout.includes('Exit 4')); assert.equal(done.stderr, '');
});
