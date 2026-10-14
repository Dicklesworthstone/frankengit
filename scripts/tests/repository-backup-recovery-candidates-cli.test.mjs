// Actual CLI processes and HTTPS; the native peer is a labelled schema fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFile, readFile, lstat, unlink, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { recoveryArguments } from '../recover_repository_backup.mjs';
import { recoveryFixture, DATA } from './backup-recovery-fixture.mjs';
const CLI = fileURLToPath(new URL('../recover_repository_backup.mjs', import.meta.url));
const lines = text => text.trim().split('\n').filter(Boolean).map(JSON.parse);
const missing = path => assert.rejects(lstat(path), { code: 'ENOENT' });
function args(f, operation = 'verify') {
  const o = f.options;
  return [operation, '--cache-directory', o.cacheDirectory, '--trust-key', o.trustKey,
    '--witness', o.witness, '--fg', o.fg, '--trusted-local', '--verification-instance', o.verificationInstance,
    ...Object.entries(o.policy).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v]),
    '--max-archive-bytes', String(DATA.length), '--max-acquisition-bytes', String(DATA.length * 4),
    ...(operation === 'restore' ? ['--destination', o.destination, '--destination-instance', o.destinationInstance, '--approval-record', o.approvalRecord] : [])];
}
async function approval(f, name, generation, data = DATA) {
  const signed = await f.sign(data, { head_generation: generation }), path = join(f.root, name + '.approval');
  await writeFile(path, signed.envelope); return path;
}
const remote = (f, path) => ['--candidate', path, '--sources', f.sourceFile, '--ca-file', f.caFile];
function launch(t, argv, broken = false) {
  const child = spawn(process.execPath, [CLI, ...argv], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  if (broken) child.stdout.destroy(); else child.stdout.on('data', b => { stdout += b; });
  child.stderr.on('data', b => { stderr += b; });
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await done; });
  return { child, done };
}
async function waitFor(check) {
  const until = Date.now() + 5000;
  while (!await check()) { assert(Date.now() < until, 'bounded peer wait'); await delay(10); }
}
const noEffects = async f => { assert.deepEqual(f.requests, []); assert.deepEqual(await f.events(), []); assert.deepEqual(await readdir(f.destination), []); };

for (const format of ['sha1', 'sha256']) test(`${format}: real grouped command selects highest approval and preserves redacted progress`, async t => {
  const f = await recoveryFixture(t, format), low = await approval(f, 'old', '9007199254740992'), high = await approval(f, 'new', '9007199254740993');
  const d = await launch(t, [...args(f), '--candidate', low, '--sources', join(f.root, 'absent', 'urls'), ...remote(f, high), '--progress-json']).done;
  assert.equal(d.code, 0, d.stderr); const r = JSON.parse(d.stdout);
  assert.equal(r.checkpoint_selection.selected_index, 1); assert.equal(r.checkpoint_selection.selected.head_generation, '9007199254740993');
  assert.equal(r.checkpoint_selection.candidates.length, 2); assert.equal(r.acquisition.mode, 'downloaded');
  assert.equal(f.requests.length, 1); assert.equal((await f.events()).length, 1);
  assert(!JSON.stringify(r).includes('capability-do-not-log')); assert(!d.stderr.includes('capability-do-not-log'));
  assert(lines(d.stderr).every(x => x.checkpoint.approval_sha256 === r.checkpoint.approval_sha256));
  await missing(f.options.destination); await missing(f.options.approvalRecord);
});
test('group parser permits independent HTTPS and repair plans without cross-group option inheritance', async t => {
  const f = await recoveryFixture(t), first = f.approval, second = join(f.root, 'second');
  const parsed = recoveryArguments([...args(f), ...remote(f, first), '--candidate', second,
    '--repair-catalog', '/catalog', '--repair-replica', '/b', '--repair-replica', '/a']).options;
  assert.equal(parsed.candidates[0].sourceFile, f.sourceFile); assert.equal(parsed.candidates[0].repairCatalog, undefined);
  assert.equal(parsed.candidates[1].sourceFile, undefined); assert.deepEqual(parsed.candidates[1].repairReplicas, ['/a', '/b']);
  assert(Object.isFrozen(parsed.candidates)); assert(Object.isFrozen(parsed.candidates[1].repairReplicas)); await noEffects(f);
});
test('invalid groups, duplicate options and mixed singleton intake refuse before I/O', async t => {
  const f = await recoveryFixture(t), base = args(f);
  const invalid = [
    ['--candidate'], ['--candidate', f.approval, '--sources', f.sourceFile, '--sources', f.sourceFile],
    [...remote(f, f.approval), '--repair-catalog', '/c', '--repair-replica', '/r'],
    ['--approval', f.approval, ...remote(f, f.approval)],
    ['--sources', f.sourceFile, ...remote(f, f.approval)],
    ['--candidate', f.approval, '--repair-catalog', '/c'],
    ['--candidate', f.approval, '--tenant-id', f.options.policy.tenant_id],
    ...[['--candidate', f.approval, '--unknown'], Array(65).fill(['--candidate', f.approval]).flat()],
  ];
  for (const flags of invalid) assert.throws(() => recoveryArguments([...base, ...flags]));
  const d = await launch(t, [...base, ...invalid[1]]).done; assert.equal(d.code, 1); assert.equal(d.stdout, ''); await noEffects(f);
});
test('64 fully described candidate groups fit the command grammar', async t => {
  const f = await recoveryFixture(t), argv = [...args(f), ...Array(64).fill(remote(f, f.approval)).flat()];
  const parsed = recoveryArguments(argv).options; assert.equal(parsed.candidates.length, 64);
  assert.throws(() => recoveryArguments([...argv, ...Array(1025).fill('--progress-json')]), { code: 'backup_recovery_argument_limit' });
  const d = await launch(t, argv).done; assert.equal(d.code, 0, d.stderr); assert.equal(JSON.parse(d.stdout).checkpoint_selection.candidates.length, 64);
  assert.equal(f.requests.length, 1);
});
test('missing higher source blocks lower recovery across fresh command invocations', async t => {
  const f = await recoveryFixture(t), low = await approval(f, 'old', '1'), high = await approval(f, 'new', '2', Buffer.alloc(DATA.length, 0x42));
  const failed = await launch(t, [...args(f), ...remote(f, low), '--candidate', high, '--sources', join(f.root, 'missing')]).done;
  assert.equal(failed.code, 1); assert.equal(lines(failed.stderr).at(-1).recovery.checkpoint_selection.selected.approval, high);
  const again = await launch(t, [...args(f), ...remote(f, low)]).done;
  assert.equal(again.code, 1); assert.equal(lines(again.stderr).at(-1).code, 'backup_below_witness'); await noEffects(f);
});
test('invalid lower signature refuses despite healthy highest archive', async t => {
  const f = await recoveryFixture(t), low = await approval(f, 'old', '1'), high = await approval(f, 'new', '2');
  const bad = JSON.parse(await readFile(low)); bad.signatures[0].sig = Buffer.alloc(64).toString('base64'); await writeFile(low, JSON.stringify(bad));
  const d = await launch(t, [...args(f), ...remote(f, high), ...remote(f, low)]).done;
  assert.equal(d.code, 1); assert.equal(lines(d.stderr).at(-1).code, 'backup_invalid_signature'); await noEffects(f);
});
test('highest conflicting statements survive omission on the next command', async t => {
  const f = await recoveryFixture(t), a = await approval(f, 'a', '2'), b = await approval(f, 'b', '2', Buffer.alloc(DATA.length, 0x42));
  const d = await launch(t, [...args(f), ...remote(f, a), ...remote(f, b)]).done;
  assert.equal(d.code, 1); assert.equal(lines(d.stderr).at(-1).code, 'backup_checkpoint_ambiguous');
  const again = await launch(t, [...args(f), ...remote(f, a)]).done;
  assert.equal(again.code, 1); assert.equal(lines(again.stderr).at(-1).code, 'backup_witness_checkpoint_ambiguous'); await noEffects(f);
});
test('lost response resumes from cache with reordered equivalent approvals and no URL files', async t => {
  const f = await recoveryFixture(t), a = await approval(f, 'a', '2'), b = join(f.root, 'b.approval');
  await writeFile(b, JSON.stringify(JSON.parse(await readFile(a)), null, 2)); await f.configure({ mode: 'lose_restore_response' });
  const d = await launch(t, [...args(f, 'restore'), ...remote(f, a), '--candidate', b]).done;
  assert.equal(d.code, 1); const e = lines(d.stderr).at(-1), pin = e.recovery.checkpoint;
  assert.equal(e.state, 'restore_attempted_unknown'); assert.equal(e.recovery.checkpoint_selection.selected_index, 0);
  const inode = (await lstat(e.recovery.candidate.input)).ino; await unlink(f.sourceFile); await unlink(f.caFile); await unlink(f.local);
  const retry = await launch(t, [...args(f, 'restore'), '--candidate', b, '--candidate', a,
    '--resume', '--checkpoint', pin.approval_sha256, pin.trusted_key_id]).done;
  assert.equal(retry.code, 0, retry.stderr); const r = JSON.parse(retry.stdout);
  assert.equal(r.checkpoint_selection.selected_index, 1); assert.equal(r.acquisition.mode, 'cached');
  assert.equal(r.native.native.already_published, true); assert.equal((await lstat(r.candidate.input)).ino, inode); assert.equal(f.requests.length, 1);
});
test('native refusal does not execute another candidate plan', async t => {
  const f = await recoveryFixture(t), low = await approval(f, 'old', '1'), high = await approval(f, 'new', '2');
  await f.configure({ mode: 'refuse_verify' }); const d = await launch(t, [...args(f), ...remote(f, low), ...remote(f, high)]).done;
  assert.equal(d.code, 1); const e = lines(d.stderr).at(-1); assert.equal(e.code, 'backup_native_refused');
  assert.equal(e.recovery.checkpoint_selection.selected.approval, high); assert.equal((await f.events()).length, 1); assert.equal(f.requests.length, 1);
});
test('SIGTERM during selected native work drains before releasing witness', async t => {
  const f = await recoveryFixture(t), a = await approval(f, 'a', '2'); await f.configure({ mode: 'hold_restore' });
  const active = launch(t, [...args(f, 'restore'), ...remote(f, a)]); await waitFor(async () => (await f.events()).some(e => e.operation === 'restore'));
  active.child.kill('SIGTERM'); const d = await active.done;
  assert.equal(d.code, 1); assert.equal(lines(d.stderr).at(-1).state, 'restore_attempted_unknown');
  assert((await f.events()).some(e => e.stopped === 'restore')); await missing(join(f.witness, '.witness-lock'));
});
test('broken stdout retains native completion and the selected checkpoint-set report', async t => {
  const f = await recoveryFixture(t), a = await approval(f, 'a', '2');
  const d = await launch(t, [...args(f, 'restore'), ...remote(f, a)], true).done;
  assert.equal(d.code, 4, d.stderr); const e = lines(d.stderr).at(-1);
  assert.equal(e.completed_result.native.state, 'complete'); assert.equal(e.completed_result.checkpoint_selection.selected.approval, a);
  assert.equal((await f.events()).length, 2); await lstat(f.options.destination);
});
test('explicit checkpoint cannot select an older approval through the command', async t => {
  const f = await recoveryFixture(t), a = await approval(f, 'a', '1');
  const first = await launch(t, [...args(f), ...remote(f, a)]).done; assert.equal(first.code, 0, first.stderr);
  const pin = JSON.parse(first.stdout).checkpoint, b = await approval(f, 'b', '2');
  const d = await launch(t, [...args(f), ...remote(f, a), ...remote(f, b), '--checkpoint', pin.approval_sha256, pin.trusted_key_id]).done;
  assert.equal(d.code, 1); assert.equal(lines(d.stderr).at(-1).code, 'backup_recovery_checkpoint_mismatch');
  assert.equal(f.requests.length, 1); assert.equal((await f.events()).length, 1);
});
