// Actual CLI processes over private files and an explicitly labelled native-schema peer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile, unlink, lstat, readdir, chmod } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { recoveryArguments } from '../recover_repository_backup.mjs';
import { recoveryFixture, DATA } from './backup-recovery-fixture.mjs';

const CLI = fileURLToPath(new URL('../recover_repository_backup.mjs', import.meta.url));
function common(f, operation = 'verify') {
  const o = f.options;
  return [operation, '--cache-directory', o.cacheDirectory, '--trust-key', o.trustKey,
    '--witness', o.witness, '--fg', o.fg, '--trusted-local', '--verification-instance', o.verificationInstance,
    ...Object.entries(o.policy).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v]),
    '--max-archive-bytes', String(DATA.length), '--max-acquisition-bytes', String(DATA.length * 4),
    ...(operation === 'restore' ? ['--destination', o.destination, '--destination-instance', o.destinationInstance,
      '--approval-record', o.approvalRecord] : [])];
}
function launch(t, argv, broken = false) {
  const child = spawn(process.execPath, [CLI, ...argv], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  if (broken) child.stdout.destroy(); else child.stdout.on('data', b => { stdout += b; });
  child.stderr.on('data', b => { stderr += b; });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await done; });
  return { child, done };
}
const lines = text => text.trim().split('\n').filter(Boolean).map(JSON.parse);
async function waitFor(check) {
  const until = Date.now() + 10000;
  while (!await check()) { assert(Date.now() < until, 'bounded child event wait'); await delay(10); }
}
for (const format of ['sha1', 'sha256']) test(`${format}: local CLI restore and offline exact resume`, async t => {
  const f = await recoveryFixture(t, format); await chmod(f.local, 0o444);
  const done = await launch(t, [...common(f, 'restore'), '--approval', f.approval, '--input', f.local, '--progress-json']).done;
  assert.equal(done.code, 0, done.stderr);
  const result = JSON.parse(done.stdout); assert.equal(result.acquisition.mode, 'local');
  assert.equal(result.native.native.signature_verified, true);
  assert.equal(lines(done.stderr).length, 6);
  const inode = (await lstat(result.candidate.input)).ino; await unlink(f.local);
  const resumed = await launch(t, [...common(f, 'restore'), '--approval', f.approval, '--resume',
    '--checkpoint', result.checkpoint.approval_sha256, result.checkpoint.trusted_key_id]).done;
  assert.equal(resumed.code, 0, resumed.stderr);
  const next = JSON.parse(resumed.stdout);
  assert.equal(next.acquisition.mode, 'cached'); assert.equal(next.native.native.already_published, true);
  assert.equal((await lstat(next.candidate.input)).ino, inode); assert.deepEqual(f.requests, []);
});
test('grouped local and unavailable HTTPS candidates retain highest-checkpoint semantics', async t => {
  const f = await recoveryFixture(t), low = join(f.root, 'low.approval');
  await writeFile(low, (await f.sign(DATA, { head_generation: '1' })).envelope);
  await f.sign(DATA, { head_generation: '2' });
  const argv = [...common(f), '--candidate', low, '--sources', join(f.root, 'absent', 'urls'),
    '--candidate', f.approval, '--input', f.local];
  const options = recoveryArguments(argv).options;
  assert.equal(options.candidates.length, 2);
  assert.deepEqual(options.candidates[1].localInputs, [f.local]);
  const done = await launch(t, argv).done; assert.equal(done.code, 0, done.stderr);
  const result = JSON.parse(done.stdout);
  assert.equal(result.checkpoint_selection.selected_index, 1); assert.equal(String(result.native.native.head_generation), '2');
  assert.equal(result.acquisition.mode, 'local'); assert.deepEqual(f.requests, []);
});
test('repeated local CLI inputs fail over within the same signed artifact', async t => {
  const f = await recoveryFixture(t), bad = join(f.root, 'a-bad');
  await writeFile(bad, Buffer.alloc(DATA.length, 0));
  const done = await launch(t, [...common(f), '--approval', f.approval, '--input', bad, '--input', f.local]).done;
  assert.equal(done.code, 0, done.stderr);
  const result = JSON.parse(done.stdout); assert.equal(result.acquisition.receipt.source.input, f.local);
  assert.equal(result.acquisition.receipt.streaming.total_payload_bytes_read, String(4 * DATA.length));
  assert.deepEqual(f.requests, []);
});
test('all-corrupt local CLI reports incomplete acquisition and bounded replica diagnostics', async t => {
  const f = await recoveryFixture(t), bad = join(f.root, 'a-bad'); await writeFile(bad, Buffer.alloc(DATA.length, 0));
  const done = await launch(t, [...common(f), '--approval', f.approval, '--input', bad]).done;
  assert.equal(done.code, 1); assert.equal(done.stdout, '');
  const report = lines(done.stderr).at(-1);
  assert.equal(report.local_acquisition.replica_attempts.length, 1);
  assert.equal(report.recovery.acquisition, null); assert.equal(report.completed_result, null);
  assert.deepEqual(await f.events(), []); assert.deepEqual(f.requests, []);
  assert.deepEqual(await readdir(f.destination), []);
});
test('mixed local/network/fragment CLI mechanisms refuse before any acquisition', async t => {
  const f = await recoveryFixture(t);
  for (const extra of [['--sources', f.sourceFile], ['--ca-file', f.caFile], ['--repair-catalog', 'catalog', '--repair-replica', f.local]]) {
    const done = await launch(t, [...common(f), '--approval', f.approval, '--input', f.local, ...extra]).done;
    assert.equal(done.code, 1); assert.equal(lines(done.stderr).at(-1).code, 'backup_recovery_mixed_acquisition');
  }
  assert.deepEqual(await f.events(), []); assert.deepEqual(f.requests, []);
});
test('local CLI lost native response resumes the same original intent without media', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'lose_restore_response' });
  const failed = await launch(t, [...common(f, 'restore'), '--approval', f.approval, '--input', f.local]).done;
  assert.equal(failed.code, 1); const report = lines(failed.stderr).at(-1), pin = report.recovery.checkpoint;
  assert.equal(report.state, 'restore_attempted_unknown'); assert.equal(report.recovery.acquisition.mode, 'local');
  await unlink(f.local);
  const next = await launch(t, [...common(f, 'restore'), '--approval', f.approval, '--resume',
    '--checkpoint', pin.approval_sha256, pin.trusted_key_id]).done;
  assert.equal(next.code, 0, next.stderr); assert.equal(JSON.parse(next.stdout).native.native.already_published, true);
  assert.deepEqual((await f.events()).filter(e => e.operation === 'restore').map(e => e.resume), [false, true]);
  assert.deepEqual(f.requests, []);
});
test('SIGTERM during native work after local acquisition drains before releasing witness', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'hold_verify' });
  const run = launch(t, [...common(f), '--approval', f.approval, '--input', f.local]);
  await waitFor(async () => (await f.events()).some(e => e.operation === 'verify'));
  await lstat(join(f.witness, '.witness-lock')); run.child.kill('SIGTERM');
  const done = await run.done; assert.equal(done.code, 1, done.stderr);
  assert((await f.events()).some(e => e.stopped === 'verify'));
  await assert.rejects(lstat(join(f.witness, '.witness-lock')), { code: 'ENOENT' });
  const report = lines(done.stderr).at(-1); assert.equal(report.recovery.acquisition.mode, 'local');
  assert.deepEqual(f.requests, []);
});
test('broken stdout retains native completion after local restore with exit 4', async t => {
  const f = await recoveryFixture(t);
  const done = await launch(t, [...common(f, 'restore'), '--approval', f.approval, '--input', f.local], true).done;
  assert.equal(done.code, 4, done.stderr); const report = lines(done.stderr).at(-1);
  assert.equal(report.completed_result.native.state, 'complete');
  assert.equal(report.completed_result.acquisition.mode, 'local');
  assert.deepEqual((await f.events()).map(e => e.operation), ['verify', 'restore']); assert.deepEqual(f.requests, []);
});
test('local CLI counts, duplicate paths and candidate ownership are bounded before I/O', async t => {
  const f = await recoveryFixture(t);
  assert.throws(() => recoveryArguments([...common(f), '--approval', f.approval,
    ...Array.from({ length: 65 }, (_, i) => ['--input', join(f.root, String(i))]).flat()]), { code: 'backup_candidate_limit' });
  assert.throws(() => recoveryArguments([...common(f), '--approval', f.approval, '--input', f.local, '--input', f.local]),
    { code: 'backup_duplicate_candidate' });
  assert.throws(() => recoveryArguments([...common(f), '--input', f.local, '--candidate', f.approval]),
    { code: 'backup_recovery_mixed_candidates' });
  const parsed = recoveryArguments([...common(f), '--candidate', f.approval,
    ...Array.from({ length: 64 }, (_, i) => ['--input', join(f.root, String(i))]).flat()]);
  assert.equal(parsed.options.candidates[0].localInputs.length, 64); assert.deepEqual(await f.events(), []);
});
