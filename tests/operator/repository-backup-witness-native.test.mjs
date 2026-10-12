import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, access, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { signRepositoryBackupFile } from '../../scripts/lib/repository-backup-approval.mjs';
import { initializeRepositoryBackupWitness, withRepositoryBackupWitness } from '../../scripts/lib/repository-backup-witness.mjs';
import { selectedRepositoryBackupOptions, runSelectedRepositoryBackup } from '../../scripts/lib/repository-backup-selected.mjs';
import { selectionArguments } from '../../scripts/select_repository_backup_native.mjs';
import { importJson } from '../../scripts/lib/native-import-process.mjs';

// The full production JS operator and its real child lifecycle are exercised.
// The child is the existing EXPLICITLY FAKE native protocol peer. The optional
// FG_NATIVE_BIN campaign is the only native Rust/archive execution target here.
const peer = pathToFileURL(resolve('tests/operator/fixtures/repository-backup-fake.mjs')).href;
const code = expected => error => error.code === expected;
async function exists(path) { try { await access(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
async function until(fn) { for (let i = 0; i < 300; i++) { if (await fn()) return; await new Promise(r => setTimeout(r, 10)); } throw Error('test observation timeout'); }
async function fixture(t, object_format = 'sha1') {
  const root = await mkdtemp(join(tmpdir(), 'fg-witness-native-')); t.after(() => rm(root, { recursive: true, force: true }));
  const keys = generateKeyPairSync('ed25519'), key = join(root, 'public.pem'), witness = join(root, 'witness');
  const privatePem = Buffer.from(keys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await writeFile(key, keys.publicKey.export({ type: 'spki', format: 'pem' }));
  const policy = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16), object_format, minimum_head_generation: '1' };
  await initializeRepositoryBackupWitness(witness, key, policy);
  const calls = join(root, 'calls'), config = join(root, 'config'), fg = join(root, 'fg-peer');
  await writeFile(config, JSON.stringify({ log: calls, mode: 'normal' }));
  await writeFile(fg, `#!${process.execPath}\nimport { fakeRepositoryBackup } from ${JSON.stringify(peer)}; await fakeRepositoryBackup(${JSON.stringify(config)});\n`, { mode: 0o700 });
  const base = { operation: 'restore', fg, witness, trustKey: key, policy, trustedLocal: true, verificationInstance: '1001',
    destinationInstance: '1002', destination: join(root, 'restored'), approvalRecord: join(root, 'approval-record') };
  async function candidate(name, generation) {
    const input = join(root, name), approval = input + '.dsse';
    const data = { ...policy, head_generation: generation }; delete data.minimum_head_generation;
    await writeFile(input, JSON.stringify(data)); const signed = await signRepositoryBackupFile(input, privatePem, data);
    await writeFile(approval, signed.envelope); return { input, approval };
  }
  const select = rows => runSelectedRepositoryBackup({ operation: 'select', candidates: rows, witness, trustKey: key, policy });
  const run = async (rows, extra = {}) => {
    try { return await runSelectedRepositoryBackup({ ...base, candidates: rows, ...extra }); }
    catch (error) {
      for (const path of [error.verification_scratch, error.approval_scratch]) if (path) t.after(() => rm(path, { recursive: true, force: true }));
      throw error;
    }
  };
  return { root, witness, key, policy, base, candidate, select, run,
    mode: mode => writeFile(config, JSON.stringify({ log: calls, mode })),
    calls: async () => await exists(calls) ? (await readFile(calls, 'utf8')).trim().split('\n').map(JSON.parse) : [] };
}
for (const format of ['sha1', 'sha256']) test(`${format}: witnessed recovery preserves native signed verification and exact resume`, async t => {
  const f = await fixture(t, format), a = await f.candidate('a', '2'), b = await f.candidate('b', '3');
  const result = await f.run([b, a]); assert.equal(result.state, 'complete');
  assert.equal(result.selection.recovery_witness.highest_observed_generation, '3');
  assert.equal(result.result.native.signature_verified, true); assert.equal(result.result.approval_effect_time_enforced, true);
  assert.equal(result.result.complete_capsule_restored, false);
  assert.deepEqual((await f.calls()).map(c => c.args[1]), ['verify', 'restore']);
  assert.equal(await exists(join(f.witness, '.witness-lock')), false);
  const record = await readFile(f.base.approvalRecord);
  const resumed = await f.run([b], { resume: true }); assert.equal(resumed.result.native.already_published, true);
  assert.deepEqual(await readFile(f.base.approvalRecord), record);
});
test('a retained higher observation prevents even native preflight for lower restore and resume', async t => {
  const f = await fixture(t), a = await f.candidate('a', '2'), b = await f.candidate('b', '3'); await f.select([b]);
  for (const resume of [false, true]) await assert.rejects(f.run([a], { resume }), error => {
    assert.equal(error.code, 'backup_below_witness'); assert.equal(error.state, resume ? 'existing_unknown' : 'not_started'); return true;
  });
  assert.equal((await f.calls()).length, 0); assert.equal(await exists(f.base.destination), false);
  assert.equal((await f.run([b])).state, 'complete');
});
test('lost native reply retains witness and original intent, and recovers only by explicit same-checkpoint resume', async t => {
  const f = await fixture(t), a = await f.candidate('a', '2'); await f.mode('restore-lost-reply');
  await assert.rejects(f.run([a]), error => { assert.equal(error.state, 'restore_attempted_unknown'); return true; });
  assert.equal((await withRepositoryBackupWitness(f.witness, f.key, f.policy, {}, w => w.snapshot())).highest_observed_generation, '2');
  await f.mode('normal'); assert.equal((await f.run([a], { resume: true })).result.native.already_published, true);
});
test('lease remains held while a real restore child runs and releases only after cancellation drains it', async t => {
  const f = await fixture(t), a = await f.candidate('a', '2'), controller = new AbortController(); await f.mode('restore-wait');
  const pending = f.run([a], { signal: controller.signal });
  const refused = assert.rejects(pending, error => { assert.equal(error.state, 'restore_attempted_unknown'); return true; });
  const marker = join(f.base.destination, 'started'); await until(() => exists(marker)); const pid = Number(await readFile(marker, 'utf8'));
  await assert.rejects(f.select([a]), code('backup_witness_locked')); assert.equal((await f.calls()).length, 2);
  controller.abort(); await refused;
  assert.throws(() => process.kill(pid, 0), code('ESRCH'));
  assert.equal(await exists(join(f.witness, '.witness-lock')), false);
  await f.mode('normal'); assert.equal((await f.run([a], { resume: true })).state, 'complete');
});
test('native receipt disagreement cannot become successful witnessed recovery', async t => {
  const f = await fixture(t), a = await f.candidate('a', '2'); await f.mode('restore-bad-report');
  await assert.rejects(f.run([a]), error => { assert.equal(error.code, 'backup_native_receipt_mismatch'); assert.equal(error.state, 'restore_attempted_unknown'); return true; });
  assert.equal(await exists(join(f.base.destination, 'authority-visible')), true);
  await f.mode('normal'); assert.equal((await f.run([a], { resume: true })).state, 'complete');
});
test('witness cleanup failure preserves a confirmed native result instead of suggesting rollback', async t => {
  const f = await fixture(t), a = await f.candidate('a', '2');
  await assert.rejects(f.run([a], { onProgress: async event => {
    if (event.phase === 'restore_starting') await unlink(join(f.witness, '.witness-lock'));
  } }), error => {
    assert.equal(error.state, 'complete'); assert.equal(error.completed_result.result.native.reopened_and_verified, true); return true;
  });
  assert.equal(await exists(join(f.base.destination, 'authority-visible')), true);
});
test('unwitnessed legacy selection remains explicitly read-only and supplied-set-only', async t => {
  const f = await fixture(t), a = await f.candidate('a', '2'), b = await f.candidate('b', '3'); await f.select([b]);
  const report = await runSelectedRepositoryBackup({ operation: 'select', candidates: [a], trustKey: f.key, policy: f.policy });
  assert.equal(report.read_only, true); assert.equal(report.recovery_witness, undefined);
  assert.equal(report.highest_retained_generation_enforced, undefined); assert.equal(report.newest_checkpoint_verified, false);
});
test('witness path collisions and duplicate flags refuse before source/native I/O', async t => {
  const f = await fixture(t), a = await f.candidate('a', '2');
  for (const witness of [a.input, a.approval, f.key, f.base.destination, join(f.base.destination, 'witness'), f.root]) {
    assert.throws(() => selectedRepositoryBackupOptions({ ...f.base, candidates: [a], witness }), code('backup_witness_separate_path_required'));
  }
  assert.throws(() => selectionArguments(['select', '--witness', f.witness, '--witness', f.witness]), code('backup_duplicate_option'));
  assert.equal((await f.calls()).length, 0);
});
test('the actual selection CLI carries the lease through signed restore and emits restart refusals', async t => {
  const f = await fixture(t), a = await f.candidate('a', '2'), b = await f.candidate('b', '3');
  const common = ['--witness', f.witness, '--trust-key', f.key, '--fg', f.base.fg, '--trusted-local',
    '--verification-instance', f.base.verificationInstance, '--destination-instance', f.base.destinationInstance,
    '--destination', f.base.destination, '--approval-record', f.base.approvalRecord,
    ...Object.entries(f.policy).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v])];
  const run = row => spawnSync(process.execPath, [resolve('scripts/select_repository_backup_native.mjs'), 'restore',
    ...common, '--candidate', row.input, row.approval], { encoding: 'utf8', timeout: 10000 });
  const good = run(b); assert.equal(good.status, 0, good.stderr); assert.equal(JSON.parse(good.stdout).result.native.signature_verified, true);
  const bad = run(a); assert.equal(bad.status, 1); const error = JSON.parse(bad.stderr);
  assert.equal(error.code, 'backup_below_witness'); assert.equal(error.witness.highest_observed_generation, '3');
  assert.equal((await f.calls()).length, 2);
});
test('actual fg witnessed source recovery and same-approval resume', { skip: !process.env.FG_NATIVE_BIN && 'FG_NATIVE_BIN unavailable; no Rust/archive execution claim' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'fg-witness-real-')); t.after(() => rm(root, { recursive: true, force: true }));
  const fg = resolve(process.env.FG_NATIVE_BIN), source = join(root, 'source'), archive = join(root, 'archive');
  const tenant = '11'.repeat(16), repository = '22'.repeat(16);
  const execute = args => { const result = spawnSync(fg, args, { encoding: 'utf8', timeout: 300000 }); assert.equal(result.status, 0, result.stderr); return result.stdout; };
  execute(['init', source, tenant, repository]);
  const exported = importJson(Buffer.from(execute(['backup', 'export', source, archive, tenant, repository, '--trusted-local'])));
  const data = Object.fromEntries(['tenant_id', 'repository_id', 'incarnation_id', 'object_format'].map(k => [k, exported[k]]));
  const policy = { ...data, minimum_head_generation: String(exported.head_generation) }, keys = generateKeyPairSync('ed25519');
  const key = join(root, 'public.pem'), approval = join(root, 'approval'), witness = join(root, 'witness');
  await writeFile(key, keys.publicKey.export({ format: 'pem', type: 'spki' }));
  const signed = await signRepositoryBackupFile(archive, Buffer.from(keys.privateKey.export({ format: 'pem', type: 'pkcs8' })), { ...data, head_generation: policy.minimum_head_generation });
  await writeFile(approval, signed.envelope); await initializeRepositoryBackupWitness(witness, key, policy);
  const options = { operation: 'restore', fg, witness, trustKey: key, policy, candidates: [{ input: archive, approval }], trustedLocal: true,
    verificationInstance: '9990001', destinationInstance: '9990002', destination: join(root, 'restored'), approvalRecord: join(root, 'record') };
  const first = await runSelectedRepositoryBackup(options), retry = await runSelectedRepositoryBackup({ ...options, resume: true });
  assert.equal(first.result.native.signature_verified, true); assert.equal(retry.result.native.already_published, true);
  assert.deepEqual(first.result.native.approval, retry.result.native.approval);
  execute(['doctor', options.destination, tenant, repository]);
});

for (const format of ['sha1', 'sha256']) test(`${format}: replica work budget never enlarges the signed native archive ceiling`, async t => {
  const f = await fixture(t, format), a = await f.candidate('a', '2');
  const bytes = await readFile(a.input), b = { input: join(f.root, 'b'), approval: join(f.root, 'b.dsse') };
  await writeFile(b.input, bytes); await writeFile(b.approval, await readFile(a.approval));
  await writeFile(a.input, Buffer.alloc(bytes.length, 0));
  await assert.rejects(f.run([a, b], { maximumBytes: bytes.length }), code('backup_replica_read_budget'));
  assert.equal((await f.calls()).length, 0);
  const result = await f.run([a, b], { maximumBytes: bytes.length, maximumReplicaBytes: 2 * bytes.length });
  assert.equal(result.state, 'complete'); assert.equal(result.selection.selected.input, b.input);
  assert.equal(result.selection.streaming.total_payload_bytes_read, String(2 * bytes.length));
  assert.equal(result.result.native.signature_verified, true);
  for (const call of await f.calls()) {
    assert.equal(call.args[call.args.indexOf('--max-archive-bytes') + 1], String(bytes.length));
    assert.equal(call.args.includes('--max-replica-bytes'), false);
    assert.equal(call.args[2], b.input);
  }
  assert.equal((await f.run([b], { maximumBytes: bytes.length, resume: true })).result.native.already_published, true);
});
test('the selection command validates independent replica budgets and forwards no native budget override', async t => {
  const f = await fixture(t), a = await f.candidate('a', '2');
  const args = ['select', '--candidate', a.input, a.approval, '--trust-key', f.key, '--witness', f.witness,
    ...Object.entries(f.policy).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v])];
  for (const value of ['0', '01', '-1', '1.1', '70368744177665']) assert.throws(() => selectionArguments([...args, '--max-replica-bytes', value]));
  const checked = selectionArguments([...args, '--max-archive-bytes', '1024', '--max-replica-bytes', '70368744177664']);
  assert.equal(checked.maximumReplicaBytes, 70368744177664); assert.equal(checked.maximumBytes, 1024);
  const result = spawnSync(process.execPath, [resolve('scripts/select_repository_backup_native.mjs'), ...args,
    '--max-replica-bytes', '1024'], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).streaming.replica_payload_byte_budget, '1024');
  assert.equal((await f.calls()).length, 0);
});
test('a parent-directory alias cannot place native restore state inside the independent witness', async t => {
  const { symlink } = await import('node:fs/promises');
  const f = await fixture(t), a = await f.candidate('a', '2'), alias = join(f.root, 'alias');
  await symlink(f.witness, alias);
  await assert.rejects(f.run([a], { destination: join(alias, 'restored') }), code('backup_witness_separate_path_required'));
  assert.equal((await f.calls()).length, 0);
  assert.equal(await exists(join(f.witness, 'restored')), false);
  assert.equal((await f.run([a])).state, 'complete');
});
test('aliased inputs cannot make the witness the only copy of the selected archive', async t => {
  const { symlink } = await import('node:fs/promises');
  const f = await fixture(t), a = await f.candidate('a', '2'), alias = join(f.root, 'alias');
  await writeFile(join(f.witness, 'archive'), await readFile(a.input)); await symlink(f.witness, alias);
  await assert.rejects(f.run([{ input: join(alias, 'archive'), approval: a.approval }]), code('backup_witness_separate_path_required'));
  assert.equal((await f.calls()).length, 0); assert.equal(await exists(f.base.destination), false);
  assert.equal((await f.run([a])).state, 'complete');
});
test('changing a parent alias at submission cannot introduce a witness overlap after preflight', async t => {
  const { mkdir, symlink } = await import('node:fs/promises');
  const f = await fixture(t), a = await f.candidate('a', '2'), outside = join(f.root, 'outside'), alias = join(f.root, 'alias');
  await mkdir(outside, { mode: 0o700 }); await symlink(outside, alias);
  await assert.rejects(f.run([a], { destination: join(alias, 'restored'), onProgress: async event => {
    if (event.phase === 'restore_starting') { await unlink(alias); await symlink(f.witness, alias); }
  } }), code('backup_witness_separate_path_required'));
  assert.deepEqual((await f.calls()).map(call => call.args[1]), ['verify']);
  assert.equal(await exists(join(f.witness, 'restored')), false);
  assert.equal(await exists(join(outside, 'restored')), false);
  assert.equal(await exists(join(f.witness, '.witness-lock')), false);
});
test('canonical path separation never opens a missing lower-generation archive or its parents', async t => {
  const f = await fixture(t), low = await f.candidate('low', '1'), high = await f.candidate('high', '2');
  const missing = { input: join(f.root, 'missing-parent', 'lower-archive'), approval: low.approval };
  const result = await f.run([missing, high]);
  assert.equal(result.state, 'complete'); assert.equal(result.selection.selected.input, high.input);
  assert.equal((await f.calls()).every(call => call.args[2] === high.input), true);
});
