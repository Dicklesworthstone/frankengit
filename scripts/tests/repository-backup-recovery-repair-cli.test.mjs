// Actual recovery CLI/processes over damaged files. Native peer is explicitly NOT fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFile, readFile, unlink, lstat, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { catalogRepositoryBackupChunks, BACKUP_CHUNK_BYTES as C } from '../lib/repository-backup-chunks.mjs';
import { recoveryFixture, digest } from './backup-recovery-fixture.mjs';
import { recoveryArguments, recoveryErrorReport } from '../recover_repository_backup.mjs';
const CLI = fileURLToPath(new URL('../recover_repository_backup.mjs', import.meta.url));
const DATA = Buffer.concat([Buffer.alloc(C, 0x51), Buffer.alloc(C, 0x52)]);
const lines = text => text.trim().split('\n').filter(Boolean).map(JSON.parse);
const missing = path => assert.rejects(lstat(path), { code: 'ENOENT' });
async function fixture(t, format = 'sha256') {
  const f = await recoveryFixture(t, format); await f.sign(DATA);
  const catalog = join(f.root, 'catalog'), a = join(f.root, 'a'), b = join(f.root, 'b');
  await catalogRepositoryBackupChunks({ input: f.local, output: catalog, approval: f.approval, trustKey: f.trustKey,
    policy: f.options.policy, maximumBytes: DATA.length });
  const first = Buffer.from(DATA), second = Buffer.from(DATA); first[0] ^= 1; second[C] ^= 1;
  await writeFile(a, first); await writeFile(b, second); await unlink(f.local);
  function args(operation = 'verify', extra = [], repair = true) {
    const o = f.options;
    return [operation, '--cache-directory', o.cacheDirectory, '--approval', o.approval, '--trust-key', o.trustKey,
      '--witness', o.witness, '--fg', o.fg, '--trusted-local', '--verification-instance', o.verificationInstance,
      ...Object.entries(o.policy).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v]),
      '--max-archive-bytes', String(DATA.length), '--max-acquisition-bytes', String(DATA.length * 4 + C),
      ...(repair ? ['--repair-catalog', catalog, '--repair-replica', b, '--repair-replica', a] : []),
      ...(operation === 'restore' ? ['--destination', o.destination, '--destination-instance', o.destinationInstance, '--approval-record', o.approvalRecord] : []),
      ...extra];
  }
  return { ...f, catalog, a, b, first, second, args };
}
function launch(t, args, broken = false) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  if (broken) child.stdout.destroy(); else child.stdout.on('data', b => { stdout += b; });
  child.stderr.on('data', b => { stderr += b; });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await done; });
  return { child, done };
}
async function partial(root, done) {
  let exited = false; done.then(() => { exited = true; });
  const until = Date.now() + 10000;
  while (Date.now() < until && !exited) {
    for (const name of await readdir(root)) {
      if (!name.startsWith('.fg-backup-chunks-')) continue;
      try { const stat = await lstat(join(root, name)); if (stat.size > 0 && stat.size < DATA.length) return name; }
      catch (e) { if (e.code !== 'ENOENT') throw e; }
    }
    await delay(2);
  }
  assert.fail('no in-progress reconstruction within bounded wait');
}
for (const format of ['sha1', 'sha256']) test(`${format}: CLI reconstructs, restores and resumes with no fragment or network inputs`, async t => {
  const f = await fixture(t, format);
  const first = await launch(t, f.args('restore', ['--progress-json'])).done;
  assert.equal(first.code, 0, first.stderr);
  const r = JSON.parse(first.stdout); assert.equal(r.acquisition.mode, 'reconstructed');
  assert.equal(r.native.native.signature_verified, true); assert.equal(r.native.native.object_format, format);
  assert.deepEqual(lines(first.stderr).map(e => e.phase), ['checkpoint_pinned', 'reconstruction_complete', 'acquisition_complete',
    'authenticated', 'preflight_verified', 'approval_recorded', 'restore_starting']);
  const before = await lstat(r.candidate.input);
  await unlink(f.a); await unlink(f.b); await unlink(f.catalog); await unlink(f.sourceFile); await unlink(f.caFile);
  const retry = await launch(t, f.args('restore', ['--resume', '--checkpoint', r.checkpoint.approval_sha256, r.checkpoint.trusted_key_id], false)).done;
  assert.equal(retry.code, 0, retry.stderr); const resumed = JSON.parse(retry.stdout);
  assert.equal(resumed.acquisition.mode, 'cached'); assert.equal(resumed.native.native.already_published, true);
  assert.equal((await lstat(r.candidate.input)).ino, before.ino); assert.deepEqual(f.requests, []);
  assert.deepEqual(await readFile(r.candidate.input), DATA);
});
test('CLI unrecoverable-range diagnostics retain checkpoint and source evidence without native work', async t => {
  const f = await fixture(t); await writeFile(f.b, f.first);
  const r = await launch(t, f.args()).done; assert.equal(r.code, 1); assert.equal(r.stdout, '');
  const e = lines(r.stderr).at(-1); assert.equal(e.code, 'backup_chunk_unrecoverable');
  assert.equal(e.reconstruction_chunk_index, 0); assert.equal(e.reconstruction_replicas.length, 2);
  assert(e.recovery.checkpoint); assert.equal(e.exit_code, 1); assert.deepEqual(await f.events(), []);
  assert.deepEqual(await readdir(f.destination), []);
});
test('closed stdout after reconstructed native restore preserves completion as exit 4', async t => {
  const f = await fixture(t), r = await launch(t, f.args('restore'), true).done;
  assert.equal(r.code, 4, r.stderr); const e = lines(r.stderr).at(-1);
  assert.equal(e.completed_result.native.state, 'complete');
  assert.equal(e.completed_result.acquisition.mode, 'reconstructed');
  assert.deepEqual(await readFile(e.completed_result.candidate.input), DATA);
  assert.deepEqual((await f.events()).map(e => e.operation), ['verify', 'restore']);
});
test('SIGTERM during actual reconstruction drains quarantine and leaves a usable explicit retry', async t => {
  const f = await fixture(t), run = launch(t, f.args());
  await partial(f.destination, run.done); run.child.kill('SIGTERM'); const r = await run.done;
  assert.equal(r.code, 1, r.stderr); assert.deepEqual(await f.events(), []);
  assert.deepEqual(await readdir(f.destination), []); await missing(join(f.witness, '.witness-lock'));
  const retry = await launch(t, f.args()).done; assert.equal(retry.code, 0, retry.stderr);
});
test('SIGKILL during reconstruction retains the witness lease and never trusts abandoned fragments', async t => {
  const f = await fixture(t), run = launch(t, f.args());
  await partial(f.destination, run.done); run.child.kill('SIGKILL'); const r = await run.done;
  assert.equal(r.signal, 'SIGKILL'); await lstat(join(f.witness, '.witness-lock'));
  const names = await readdir(f.destination); assert(names.some(n => n.startsWith('.fg-backup-chunks-')));
  assert(!names.some(n => n.startsWith('archive-sha256-'))); assert.deepEqual(await f.events(), []);
  const snapshot = await Promise.all(names.map(async n => [n, digest(await readFile(join(f.destination, n)))]));
  const retry = await launch(t, f.args()).done; assert.equal(retry.code, 1);
  assert.equal(lines(retry.stderr).at(-1).code, 'backup_witness_locked');
  assert.deepEqual(await Promise.all(names.map(async n => [n, digest(await readFile(join(f.destination, n)))])), snapshot);
});
test('all 64 explicit fragment paths fit the bounded CLI and excess paths refuse', async t => {
  const f = await fixture(t), extra = Array.from({ length: 62 }, (_, i) => ['--repair-replica', join(f.root, `0-missing-${i}`)]).flat();
  const ok = await launch(t, f.args('verify', extra)).done; assert.equal(ok.code, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).acquisition.reconstruction.replicas.length, 64);
  assert.throws(() => recoveryArguments(f.args('verify', [...extra, '--repair-replica', join(f.root, 'excess')])), { code: 'backup_chunk_replica_limit' });
});
for (const option of ['--sources', '--ca-file']) test(`CLI refuses mixed ${option} and fragment acquisition before effects`, async t => {
  const f = await fixture(t), r = await launch(t, f.args('verify', [option, f.sourceFile])).done;
  assert.equal(r.code, 1); assert.equal(lines(r.stderr).at(-1).code, 'backup_recovery_mixed_acquisition');
  assert.deepEqual(await readdir(f.destination), []); assert.deepEqual(await f.events(), []);
});
test('duplicate catalog, incomplete replica flag and sparse source arrays refuse before work', async t => {
  const f = await fixture(t);
  assert.throws(() => recoveryArguments(f.args('verify', ['--repair-catalog', f.catalog])), { code: 'backup_duplicate_option' });
  assert.throws(() => recoveryArguments(f.args('verify', ['--repair-replica'])), { code: 'backup_missing_option_value' });
  assert.throws(() => recoveryArguments(f.args('verify', ['--repair-replica', f.a])), { code: 'backup_chunk_replica_limit' });
  assert.deepEqual(await readdir(f.destination), []);
});
test('reconstruction completion by itself never becomes a native-completion exit code', () => {
  const e = recoveryErrorReport({ code: 'EIO', state: 'complete', completed_result: { type: 'repository_backup_reconstructed', state: 'complete' },
    recovery: { reconstruction: { state: 'complete' }, native: null } });
  assert.equal(e.exit_code, 1);
});
test('help exposes explicit reconstruction and unchanged native trust boundary', async t => {
  const r = await launch(t, ['--help']).done; assert.equal(r.code, 0);
  assert(r.stdout.includes('--repair-catalog')); assert(r.stdout.includes('--repair-replica'));
  assert(r.stdout.includes('ORIGINAL signed archive')); assert(r.stdout.includes('native'));
});
