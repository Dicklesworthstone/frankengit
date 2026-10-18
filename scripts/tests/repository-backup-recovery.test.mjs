import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, lstat, unlink, symlink, rename, chmod, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { recoverRepositoryBackup, repositoryBackupRecoveryOptions } from '../lib/repository-backup-recovery.mjs';
import { withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { recoveryFixture, DATA, digest } from './backup-recovery-fixture.mjs';

const code = expected => error => { assert.equal(error.code, expected); return true; };
const missing = path => assert.rejects(lstat(path), { code: 'ENOENT' });
async function unlocked(f) { await missing(join(f.witness, '.witness-lock')); }
async function noEffects(f) { assert.equal((await f.events()).length, 0); await missing(f.options.destination); }
async function noSockets(f) { for (let i = 0; i < 100 && f.sockets.size; i++) await delay(5); assert.equal(f.sockets.size, 0); }
function privateReport(value) { assert(!JSON.stringify(value).includes('capability-do-not-log')); }

for (const format of ['sha1', 'sha256']) test(`HTTPS acquisition -> signed native preflight/restore under one lease (${format})`, async t => {
  const f = await recoveryFixture(t, format), stages = new Set();
  const result = await recoverRepositoryBackup({ ...f.options, async onProgress(e) {
    stages.add(e.stage); await lstat(join(f.witness, '.witness-lock'));
    if (e.phase === 'acquisition_complete') await noSockets(f);
  } });
  assert.equal(result.state, 'complete'); assert.equal(result.acquisition.mode, 'downloaded');
  assert.equal(result.native.native.signature_verified, true);
  assert.equal(String(result.native.native.head_generation), '9007199254740993');
  assert.equal(result.native.native.object_format, format); assert.equal(result.complete_capsule_restored, false);
  assert.deepEqual([...stages].sort(), ['download', 'native', 'recovery']);
  assert.deepEqual((await f.events()).map(e => e.operation), ['verify', 'restore']);
  assert.deepEqual(await readFile(result.candidate.input), DATA);
  assert.equal(result.recovery_witness.highest_observed_generation, '9007199254740993');
  assert.equal(result.highest_retained_generation_enforced, true); privateReport(result); await unlocked(f);
});

test('verify invokes native verification only and leaves no restored repository', async t => {
  const f = await recoveryFixture(t), result = await recoverRepositoryBackup(f.verifyOptions());
  assert.equal(result.native.type, 'approved_repository_backup_verify');
  assert.deepEqual((await f.events()).map(e => e.operation), ['verify']); await missing(f.options.destination); await unlocked(f);
});

test('lost restore response resumes from authenticated cache with no URLs or second network fetch', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'lose_restore_response' });
  let error;
  try { await recoverRepositoryBackup(f.options); } catch (e) { error = e; }
  assert.equal(error.code, 'backup_native_refused'); assert.equal(error.state, 'restore_attempted_unknown');
  const before = await lstat(error.recovery.candidate.input), recorded = await readFile(f.options.approvalRecord);
  assert.equal(error.recovery.acquisition.mode, 'downloaded'); assert.equal(f.requests.length, 1); await unlocked(f);
  await unlink(f.sourceFile); await unlink(f.caFile); await unlink(f.local);
  const result = await recoverRepositoryBackup({ ...f.options, resume: true, checkpoint: error.recovery.checkpoint });
  assert.equal(result.acquisition.mode, 'cached'); assert.equal(result.native.native.already_published, true);
  assert.equal(result.native.native.resume_requested, true); assert.equal(f.requests.length, 1);
  assert.equal((await lstat(result.candidate.input)).ino, before.ino);
  assert.deepEqual(await readFile(f.options.approvalRecord), recorded);
  assert.deepEqual((await f.events()).map(e => e.operation), ['verify', 'restore', 'verify', 'restore']); await unlocked(f);
});

test('acquisition completion followed by cancellation preserves cached bytes for offline verification', async t => {
  const f = await recoveryFixture(t), controller = new AbortController(); let pin;
  await assert.rejects(recoverRepositoryBackup({ ...f.options, signal: controller.signal, onProgress(e) {
    if (e.phase === 'acquisition_complete') { pin = e.checkpoint; controller.abort(); }
  } }), error => { assert.equal(error.code, 'backup_cancelled'); assert(error.recovery.acquisition); return true; });
  await noEffects(f); await unlocked(f); await unlink(f.sourceFile);
  const { sourceFile, caFile, ...verify } = f.verifyOptions();
  const result = await recoverRepositoryBackup({ ...verify, checkpoint: pin });
  assert.equal(result.acquisition.mode, 'cached'); assert.equal(f.requests.length, 1);
});

for (const phase of ['verify', 'restore']) test(`native ${phase} mismatch is fatal; there is no mirror/native retry`, async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: `wrong_digest_${phase}` });
  await assert.rejects(recoverRepositoryBackup(f.options), code('backup_native_receipt_mismatch'));
  assert.equal(f.requests.length, 1); assert.equal((await f.events()).length, phase === 'verify' ? 1 : 2);
  if (phase === 'verify') { await missing(f.options.destination); await missing(f.options.approvalRecord); }
  await unlocked(f);
});

test('restore/preflight count disagreement retains uncertainty and never retries publication', async t => {
  const f = await recoveryFixture(t); await f.configure({ mode: 'wrong_restore_counts' });
  await assert.rejects(recoverRepositoryBackup(f.options), error => {
    assert.equal(error.code, 'backup_restore_preflight_mismatch'); assert.equal(error.state, 'restore_attempted_unknown'); return true;
  });
  assert.equal((await f.events()).length, 2); await lstat(f.options.destination); await unlocked(f);
});

test('cached corrupt bytes refuse without using a healthy remote copy or modifying cache', async t => {
  const f = await recoveryFixture(t), first = await recoverRepositoryBackup(f.verifyOptions());
  const wrong = Buffer.alloc(DATA.length, 0x44); await writeFile(first.candidate.input, wrong);
  await assert.rejects(recoverRepositoryBackup(f.options), code('backup_artifact_mismatch'));
  assert.equal(f.requests.length, 1); assert.deepEqual(await readFile(first.candidate.input), wrong);
  assert.equal((await f.events()).length, 1); await missing(f.options.destination); await unlocked(f);
});

test('cached archive can complete its absent exact approval without network', async t => {
  const f = await recoveryFixture(t), first = await recoverRepositoryBackup(f.verifyOptions());
  await unlink(first.candidate.approval); await unlink(f.sourceFile);
  const result = await recoverRepositoryBackup(f.options);
  assert.equal(result.acquisition.mode, 'cached'); assert.equal(f.requests.length, 1);
  assert.deepEqual(await readFile(result.candidate.approval), await readFile(f.approval));
});

test('changed signed checkpoint at acquisition handoff cannot reach the native peer', async t => {
  const f = await recoveryFixture(t);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, async onProgress(e) {
    if (e.phase === 'acquisition_complete') await writeFile(e.candidate.approval, (await f.sign(DATA, { head_generation: '9007199254740994' })).envelope);
  } }), code('backup_selected_approval_changed'));
  await noEffects(f); await unlocked(f);
});

test('byte mutation at native boundary is reauthenticated rather than trusted from acquisition', async t => {
  const f = await recoveryFixture(t);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, async onProgress(e) {
    if (e.phase === 'acquisition_complete') await writeFile(e.candidate.input, Buffer.alloc(DATA.length, 0x21));
  } }), code('backup_artifact_mismatch')); await noEffects(f);
});

test('unavailable newer signed observation constrains later lower requests', async t => {
  const f = await recoveryFixture(t), old = await readFile(f.approval);
  await f.sign(DATA, { head_generation: '18446744073709551615' }); f.setHandler((_, res) => { res.writeHead(404); res.end(); });
  await assert.rejects(recoverRepositoryBackup(f.options), code('backup_download_no_source'));
  await writeFile(f.approval, old); f.setHandler((_, res) => res.end(DATA));
  await assert.rejects(recoverRepositoryBackup(f.options), code('backup_below_witness'));
  assert.equal(f.requests.length, 1); await noEffects(f); await unlocked(f);
});

for (const failure of ['expired', 'oversized']) test(`${failure} higher evidence is retained before acquisition`, async t => {
  const f = await recoveryFixture(t), old = await readFile(f.approval);
  const metadata = failure === 'expired' ? { issued_at: '2026-01-01T00:00:00Z', expires_at: '2026-01-02T00:00:00Z' } : {};
  await f.sign(DATA, { ...metadata, head_generation: '9007199254740994' });
  await assert.rejects(recoverRepositoryBackup({ ...f.options, ...(failure === 'oversized' ? { maximumBytes: 1 } : {}) }),
    code(failure === 'expired' ? 'backup_approval_expired' : 'backup_selected_archive_limit'));
  await writeFile(f.approval, old); await assert.rejects(recoverRepositoryBackup(f.options), code('backup_below_witness'));
  assert.equal(f.requests.length, 0); await noEffects(f); await unlocked(f);
});

test('invalid signatures never become retained observations or open a socket', async t => {
  const f = await recoveryFixture(t), original = await readFile(f.approval), state = await readFile(join(f.witness, 'witness.json'));
  const envelope = JSON.parse(original), signature = Buffer.from(envelope.signatures[0].sig, 'base64'); signature[0] ^= 1;
  envelope.signatures[0].sig = signature.toString('base64'); await writeFile(f.approval, JSON.stringify(envelope));
  await assert.rejects(recoverRepositoryBackup(f.options), code('backup_invalid_signature'));
  assert.deepEqual(await readFile(join(f.witness, 'witness.json')), state); assert.equal(f.requests.length, 0); await noEffects(f);
});

test('complete native grammar and explicit resume pins are checked before file or network work', async t => {
  const f = await recoveryFixture(t);
  for (const change of [{ trustedLocal: false }, { verificationInstance: '0' }, { destinationInstance: '01' },
    { fg: 'fg' }, { resume: true }, { operation: 'inspect' }, { now: Date.now() }, { native: () => {} }, { maximumAcquisitionBytes: 0 }]) {
    assert.throws(() => repositoryBackupRecoveryOptions({ ...f.options, ...change }));
  }
  assert.equal(f.requests.length, 0); await noEffects(f); assert.deepEqual(await readdir(f.destination), []);
});

for (const field of ['destination', 'approvalRecord', 'sourceFile', 'trustKey']) test(`physical witness alias in ${field} refuses before effects`, async t => {
  const f = await recoveryFixture(t), alias = join(f.root, 'alias'); await symlink(f.witness, alias);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, [field]: join(alias, 'target') }), code('backup_recovery_separate_paths_required'));
  assert.equal(f.requests.length, 0); await noEffects(f);
});

test('destination parent retargeting at the native boundary refuses before native execution', async t => {
  const f = await recoveryFixture(t), one = join(f.root, 'one'), two = join(f.root, 'two'), alias = join(f.root, 'alias');
  await mkdir(one, { mode: 0o700 }); await mkdir(two, { mode: 0o700 }); await symlink(one, alias);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, destination: join(alias, 'repository'), async onProgress(e) {
    if (e.phase === 'acquisition_complete') { await unlink(alias); await symlink(two, alias); }
  } }), code('backup_recovery_path_changed')); await noEffects(f); await unlocked(f);
});

test('cache directory replacement is detected even when its pathname remains the same', async t => {
  const f = await recoveryFixture(t);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, async onProgress(e) {
    if (e.phase === 'acquisition_complete') { await rename(f.destination, f.destination + '.old'); await mkdir(f.destination, { mode: 0o700 }); }
  } }), code('backup_recovery_cache_changed')); await noEffects(f); await unlocked(f);
});

test('a competing operation cannot acquire the witness during native preflight or restore', async t => {
  const f = await recoveryFixture(t), observed = [];
  await recoverRepositoryBackup({ ...f.options, async onProgress(e) {
    if (e.stage === 'native') {
      await assert.rejects(withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, {}, async () => {}), code('backup_witness_locked'));
      observed.push(e.phase);
    }
  } });
  assert(observed.includes('preflight_verified')); assert(observed.includes('restore_starting')); await unlocked(f);
});

test('shared acquisition budget is exact and too-small work refuses before connecting', async t => {
  const f = await recoveryFixture(t);
  await assert.rejects(recoverRepositoryBackup({ ...f.options, maximumAcquisitionBytes: 4 * DATA.length - 1 }), code('backup_download_read_budget'));
  assert.equal(f.requests.length, 0); await noEffects(f);
  const r = await recoverRepositoryBackup(f.verifyOptions()); assert.equal(r.acquisition.receipt.streaming.total_payload_bytes_read, String(4 * DATA.length));
  const cached = await recoverRepositoryBackup({ ...f.verifyOptions(), maximumAcquisitionBytes: 2 * DATA.length });
  assert.equal(cached.acquisition.receipt.streaming.total_payload_bytes_read, String(2 * DATA.length));
});

test('caller changes to paths/policy cannot retarget an in-flight restore', async t => {
  const f = await recoveryFixture(t), raw = { ...f.options, policy: { ...f.options.policy } };
  const pending = recoverRepositoryBackup(raw); raw.destination = '/wrong'; raw.policy.repository_id = 'f'.repeat(32);
  const result = await pending; assert.equal(result.native.destination, f.options.destination);
  assert.equal(result.native.authentication.statement.repository_id, f.options.policy.repository_id);
});

test('native child cancellation drains before witness release and retains ambiguous restore state', async t => {
  const f = await recoveryFixture(t), controller = new AbortController(); await f.configure({ mode: 'hold_restore' });
  const timer = setInterval(async () => { if ((await f.events()).some(e => e.operation === 'restore')) controller.abort(); }, 10);
  try { await assert.rejects(recoverRepositoryBackup({ ...f.options, signal: controller.signal }), error => {
    assert.equal(error.code, 'native_import_cancelled'); assert.equal(error.state, 'restore_attempted_unknown'); assert(error.recovery.acquisition); return true;
  }); } finally { clearInterval(timer); }
  const events = await f.events(); assert(events.some(e => e.stopped === 'restore'));
  for (const e of events.filter(e => e.operation)) assert.throws(() => process.kill(e.pid, 0), { code: 'ESRCH' });
  await unlocked(f);
});

test('native expiry is not bypassed by cache reuse', async t => {
  const f = await recoveryFixture(t); await recoverRepositoryBackup(f.verifyOptions());
  await f.sign(DATA, { issued_at: '2026-01-01T00:00:00Z', expires_at: '2026-01-02T00:00:00Z', head_generation: '9007199254740994' });
  await assert.rejects(recoverRepositoryBackup(f.options), code('backup_approval_expired'));
  assert.equal(f.requests.length, 1); assert.equal((await f.events()).length, 1); await unlocked(f);
});

test('missing cache without a source descriptor fails without a native command', async t => {
  const f = await recoveryFixture(t), { sourceFile, ...options } = f.options;
  await assert.rejects(recoverRepositoryBackup(options), code('backup_recovery_sources_required'));
  await noEffects(f); await unlocked(f);
});
