import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm, lstat, access, chmod, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { signRepositoryBackupFile } from '../../scripts/lib/repository-backup-approval.mjs';
import { runApprovedRepositoryBackup, repositoryBackupOptions } from '../../scripts/lib/repository-backup-native.mjs';
import { nativeBackupArguments } from '../../scripts/restore_repository_backup_native.mjs';
import { importJson } from '../../scripts/lib/native-import-process.mjs';
const helper = pathToFileURL(resolve('tests/operator/fixtures/repository-backup-fake.mjs')).href;
const code = value => error => error.code === value;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function exists(path) { try { await access(path); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
async function until(check) { for (let n = 0; n < 300; n++) { if (await check()) return; await sleep(10); } throw Error('test wait exceeded'); }
function pair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privatePem: Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' })), publicPem: Buffer.from(publicKey.export({ type: 'spki', format: 'pem' })) };
}
async function fixture(t, format = 'sha1') {
  const root = await mkdtemp(join(tmpdir(), 'fg-signed-native-test-')), keys = pair();
  t.after(() => rm(root, { recursive: true, force: true }));
  const data = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16),
    object_format: format, head_generation: '18446744073709551615' };
  const input = join(root, 'archive'), approval = join(root, 'approval'), trustKey = join(root, 'public.pem'), fg = join(root, 'fake-fg');
  const configPath = join(root, 'config'), log = join(root, 'calls');
  await writeFile(input, JSON.stringify(data)); await writeFile(trustKey, keys.publicPem);
  const signed = await signRepositoryBackupFile(input, keys.privatePem, data); await writeFile(approval, signed.envelope);
  let config = { log, mode: 'normal' }; await writeFile(configPath, JSON.stringify(config));
  await writeFile(fg, `#!${process.execPath}\nimport { fakeRepositoryBackup } from ${JSON.stringify(helper)};\nawait fakeRepositoryBackup(${JSON.stringify(configPath)});\n`, { mode: 0o700 });
  const policy = { ...data, minimum_head_generation: data.head_generation }; delete policy.head_generation;
  const options = { operation: 'restore', fg, input, approval, trustKey, policy, trustedLocal: true,
    verificationInstance: '9007199254740993', destinationInstance: '9223372036854775807',
    destination: join(root, 'restored'), approvalRecord: join(root, 'record') };
  return { root, data, keys, options, async mode(extra) { config = { ...config, ...extra }; await writeFile(configPath, JSON.stringify(config)); },
    async calls() { return await exists(log) ? (await readFile(log, 'utf8')).trim().split('\n').map(JSON.parse) : []; },
    async run(overrides = {}) {
      try { return await runApprovedRepositoryBackup({ ...options, ...overrides }); }
      catch (error) { if (error.verification_scratch) t.after(() => rm(error.verification_scratch, { recursive: true, force: true })); throw error; }
    } };
}
for (const format of ['sha1', 'sha256']) {
  test(`signed ${format} archive verifies before native restore, then resumes the exact approval`, async t => {
    const f = await fixture(t, format), result = await f.run();
    assert.equal(result.state, 'complete'); assert.equal(result.native.signature_verified, false);
    assert.equal(result.authentication.signature_verified, true); assert.equal(result.signed_identity_matched_native, true);
    assert.equal(result.native.head_generation, f.data.head_generation); assert.equal(result.native.destination_instance, '9223372036854775807');
    assert.equal(result.approval_effect_time_enforced, false); assert.equal(result.complete_capsule_restored, false);
    assert.ok(await exists(join(f.options.destination, 'authority-visible')));
    assert.equal((await lstat(f.options.approvalRecord)).mode & 0o777, 0o600);
    const calls = await f.calls(); assert.deepEqual(calls.map(c => c.args.slice(0, 2)), [['backup', 'verify'], ['backup', 'restore']]);
    for (const call of calls) {
      assert.ok(call.args.includes('--expected-sha256')); assert.ok(call.args.includes(result.authentication.statement.artifact.sha256));
      assert.ok(!call.args.includes(f.options.approval)); assert.ok(!call.args.includes(f.options.trustKey));
    }
    const record = await readFile(f.options.approvalRecord), resumed = await f.run({ resume: true });
    assert.equal(resumed.native.already_published, true); assert.equal(resumed.native.resume_requested, true);
    assert.deepEqual(await readFile(f.options.approvalRecord), record);
  });
}
test('verify-only operation never creates a restore record or destination', async t => {
  const f = await fixture(t), result = await f.run({ operation: 'verify', destination: undefined, destinationInstance: undefined, approvalRecord: undefined });
  assert.equal(result.destination_changed, false); assert.equal(result.native.authority_import_verified, true);
  assert.equal(result.native.destination_authority_published, false); assert.equal((await f.calls()).length, 1);
  assert.ok(!await exists(f.options.destination)); assert.ok(!await exists(f.options.approvalRecord));
});
for (const [mismatch, wrong] of [['tenant_id', '99'.repeat(16)], ['repository_id', '99'.repeat(16)], ['incarnation_id', '99'.repeat(16)],
  ['object_format', 'sha256'], ['head_generation', 1], ['archive_bytes', 1], ['sha256', '0'.repeat(64)], ['signature_verified', true],
  ['object_graph_verified', false], ['authority_import_verified', false], ['destination_authority_published', true], ['verification_instance', 12]]) {
  test(`native ${mismatch} disagreement refuses before ANY restore call`, async t => {
    const f = await fixture(t); await f.mode({ mismatch, wrong });
    await assert.rejects(f.run());
    assert.deepEqual((await f.calls()).map(c => c.args[1]), ['verify']);
    assert.ok(!await exists(f.options.destination)); assert.ok(!await exists(f.options.approvalRecord));
  });
}
test('wrong signer, identity, floor and artifact refuse before even native verification', async t => {
  const f = await fixture(t), original = await readFile(f.options.trustKey);
  await writeFile(f.options.trustKey, pair().publicPem); await assert.rejects(f.run(), code('backup_untrusted_signer'));
  await writeFile(f.options.trustKey, original);
  await assert.rejects(f.run({ policy: { ...f.options.policy, incarnation_id: '55'.repeat(16) } }), code('backup_approval_identity_mismatch'));
  await writeFile(f.options.input, 'changed'); await assert.rejects(f.run(), code('backup_artifact_mismatch'));
  assert.equal((await f.calls()).length, 0); assert.ok(!await exists(f.options.destination));
});
test('a changed path after approved preflight cannot become permission for changed bytes', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ onProgress: async event => { if (event.phase === 'preflight_verified') await writeFile(f.options.input, 'replaced after preflight'); } }), error => {
    assert.equal(error.state, 'restore_attempted_unknown'); return error.code === 'backup_native_refused';
  });
  assert.deepEqual((await f.calls()).map(c => c.args[1]), ['verify', 'restore']);
  assert.ok(await exists(f.options.approvalRecord)); assert.ok(!await exists(f.options.destination));
});
test('approval expiry during preflight prevents restore submission', async t => {
  const f = await fixture(t), expires = Math.floor(Date.now() / 1000) * 1000 + 2000;
  const signed = await signRepositoryBackupFile(f.options.input, f.keys.privatePem, { ...f.data, expires_at: new Date(expires).toISOString().replace('.000Z', 'Z') });
  await writeFile(f.options.approval, signed.envelope);
  await assert.rejects(f.run({ onProgress: async event => { if (event.phase === 'preflight_verified') await sleep(Math.max(0, expires - Date.now() + 10)); } }), code('backup_approval_expired'));
  assert.equal((await f.calls()).length, 1); assert.ok(!await exists(f.options.destination)); assert.ok(!await exists(f.options.approvalRecord));
});
test('resume cannot change the retained trust policy, destination instance or signer', async t => {
  const f = await fixture(t); await f.run(); const before = (await f.calls()).length;
  await assert.rejects(f.run({ resume: true, policy: { ...f.options.policy, minimum_head_generation: '1' } }), code('backup_restore_approval_record_mismatch'));
  await assert.rejects(f.run({ resume: true, destinationInstance: '3' }), code('backup_restore_approval_record_mismatch'));
  const keys = pair(), original = JSON.parse(await readFile(f.options.approval)), statement = JSON.parse(Buffer.from(original.payload, 'base64'));
  const signed = await signRepositoryBackupFile(f.options.input, keys.privatePem, Object.fromEntries(Object.entries(statement).filter(([k]) => !['type', 'artifact', 'scope'].includes(k))));
  await writeFile(f.options.approval, signed.envelope); await writeFile(f.options.trustKey, keys.publicPem);
  await assert.rejects(f.run({ resume: true }), code('backup_restore_approval_record_mismatch'));
  assert.equal((await f.calls()).length, before);
});
test('missing approvals and tampered records cannot downgrade a resume', async t => {
  const f = await fixture(t); await f.run(); const record = await readFile(f.options.approvalRecord);
  await writeFile(f.options.approvalRecord, '{}'); await assert.rejects(f.run({ resume: true }), code('backup_restore_approval_record_mismatch'));
  await writeFile(f.options.approvalRecord, record); await rm(f.options.approval);
  await assert.rejects(f.run({ resume: true }), error => { assert.equal(error.state, 'existing_unknown'); return true; });
  assert.ok(await exists(join(f.options.destination, 'authority-visible')));
});
test('a lost native reply remains unknown, retains approval, and recovers only through explicit native resume', async t => {
  const f = await fixture(t); await f.mode({ mode: 'restore-lost-reply' });
  await assert.rejects(f.run(), error => { assert.equal(error.state, 'restore_attempted_unknown'); return true; });
  assert.ok(await exists(join(f.options.destination, 'authority-visible'))); assert.ok(await exists(f.options.approvalRecord));
  await f.mode({ mode: 'normal' }); await assert.rejects(f.run(), code('backup_existing_path'));
  const result = await f.run({ resume: true }); assert.equal(result.native.already_published, true);
  assert.equal((await f.calls()).filter(c => c.args[1] === 'restore').length, 2);
});
test('cancellation terminates and reaps a real child without removing potentially published state', async t => {
  const f = await fixture(t); await f.mode({ mode: 'restore-wait' }); const controller = new AbortController();
  const pending = f.run({ signal: controller.signal }), rejection = assert.rejects(pending, error => { assert.equal(error.state, 'restore_attempted_unknown'); return true; });
  const marker = join(f.options.destination, 'started'); await until(() => exists(marker)); const pid = Number(await readFile(marker, 'utf8'));
  controller.abort(); await rejection;
  assert.throws(() => process.kill(pid, 0), error => error.code === 'ESRCH');
  assert.ok(await exists(join(f.options.destination, 'authority-visible'))); assert.ok(await exists(f.options.approvalRecord));
});
for (const mode of ['verify-refuse', 'verify-flood', 'duplicate-report']) {
  test(`${mode} retains diagnostic scratch and never falls back or restores`, async t => {
    const f = await fixture(t); await f.mode({ mode });
    await assert.rejects(f.run(), error => { assert.ok(error.verification_scratch); return true; });
    assert.equal((await f.calls()).length, 1); assert.ok(!await exists(f.options.destination));
  });
}
test('record mutation at the final observer is detected before native submission', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ onProgress: async event => { if (event.phase === 'restore_starting') await writeFile(f.options.approvalRecord, '{}'); } }), code('backup_restore_approval_record_mismatch'));
  assert.equal((await f.calls()).length, 1); assert.ok(!await exists(f.options.destination));
});
test('malformed post-restore receipt never claims rollback or complete restoration', async t => {
  const f = await fixture(t); await f.mode({ mode: 'restore-bad-report' });
  await assert.rejects(f.run(), error => { assert.equal(error.state, 'restore_attempted_unknown'); return error.code === 'backup_native_receipt_mismatch'; });
  assert.ok(await exists(join(f.options.destination, 'authority-visible')));
});
test('pre-cancellation, invalid limits, relative executables and inapplicable flags refuse before I/O', async t => {
  const f = await fixture(t), controller = new AbortController(); controller.abort();
  await assert.rejects(f.run({ signal: controller.signal }), code('backup_cancelled'));
  for (const extra of [{ fg: 'fg' }, { timeoutMs: 0 }, { maximumBytes: 0 }, { trustedLocal: false },
    { verificationInstance: '9223372036854775808' }, { destinationInstance: '01' }, { approvalRecord: join(f.options.destination, 'record') }]) {
    assert.throws(() => repositoryBackupOptions({ ...f.options, ...extra }));
  }
  for (const args of [[], ['verify'], ['restore', 'x', '--force'], ['verify', 'x', '--trusted-local', '--trusted-local']]) assert.throws(() => nativeBackupArguments(args));
  assert.equal((await f.calls()).length, 0);
});
test('real command processes compose signing, native preflight and restore without Rust test substitution claims', async t => {
  const f = await fixture(t), script = resolve('scripts/restore_repository_backup_native.mjs');
  const args = ['restore', f.options.input, '--fg', f.options.fg, '--approval', f.options.approval, '--trust-key', f.options.trustKey,
    '--tenant-id', f.data.tenant_id, '--repository-id', f.data.repository_id, '--incarnation-id', f.data.incarnation_id, '--object-format', f.data.object_format,
    '--minimum-head-generation', f.data.head_generation, '--verification-instance', f.options.verificationInstance,
    '--destination', f.options.destination, '--destination-instance', f.options.destinationInstance, '--approval-record', f.options.approvalRecord, '--trusted-local'];
  const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr); assert.equal(JSON.parse(result.stdout).state, 'complete');
  const resume = spawnSync(process.execPath, [script, ...args, '--resume'], { encoding: 'utf8' });
  assert.equal(resume.status, 0, resume.stderr); assert.equal(JSON.parse(resume.stdout).native.already_published, true);
});
test('whole-operation deadline charges preflight time rather than granting restore a fresh budget', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ timeoutMs: 500, onProgress: async event => { if (event.phase === 'preflight_verified') await sleep(510); } }), code('backup_deadline'));
  assert.ok(!await exists(f.options.destination)); assert.equal((await f.calls()).length, 1);
});

test('actual fg exports, authenticates and restores a native authority archive', { skip: !process.env.FG_NATIVE_BIN && 'FG_NATIVE_BIN not supplied; no native Rust execution claim' }, async t => {
  const fg = resolve(process.env.FG_NATIVE_BIN), root = await mkdtemp(join(tmpdir(), 'fg-backup-real-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const tenant = '11'.repeat(16), repository = '22'.repeat(16), source = join(root, 'source'), archive = join(root, 'source.fgit');
  const run = args => { const r = spawnSync(fg, args, { encoding: 'utf8', timeout: 300000, maxBuffer: 65536 }); assert.equal(r.status, 0, r.stderr); return r.stdout; };
  run(['init', source, tenant, repository]);
  const exported = importJson(Buffer.from(run(['backup', 'export', source, archive, tenant, repository, '--trusted-local'])));
  const data = Object.fromEntries(['tenant_id', 'repository_id', 'incarnation_id', 'object_format'].map(k => [k, exported[k]]));
  data.head_generation = String(exported.head_generation); const keys = pair(), approval = join(root, 'approval'), trustKey = join(root, 'public');
  const signed = await signRepositoryBackupFile(archive, keys.privatePem, data); await writeFile(approval, signed.envelope); await writeFile(trustKey, keys.publicPem);
  const policy = { ...data, minimum_head_generation: data.head_generation }; delete policy.head_generation;
  const result = await runApprovedRepositoryBackup({ operation: 'restore', fg, input: archive, approval, trustKey, policy, trustedLocal: true,
    verificationInstance: '900000001', destinationInstance: '900000002', destination: join(root, 'restored'), approvalRecord: join(root, 'record') });
  assert.equal(result.native.reopened_and_verified, true);
  run(['doctor', join(root, 'restored'), tenant, repository]);
});

test('lost CLI stdout after confirmed restore retains complete state and the original record', async t => {
  const f = await fixture(t), args = ['restore', f.options.input, '--fg', f.options.fg, '--approval', f.options.approval, '--trust-key', f.options.trustKey,
    '--tenant-id', f.data.tenant_id, '--repository-id', f.data.repository_id, '--incarnation-id', f.data.incarnation_id, '--object-format', f.data.object_format,
    '--minimum-head-generation', f.data.head_generation, '--verification-instance', f.options.verificationInstance,
    '--destination', f.options.destination, '--destination-instance', f.options.destinationInstance, '--approval-record', f.options.approvalRecord, '--trusted-local'];
  const child = spawn(process.execPath, [resolve('scripts/restore_repository_backup_native.mjs'), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.destroy(); let diagnostic = ''; child.stderr.setEncoding('utf8'); child.stderr.on('data', s => { diagnostic += s; });
  const exit = await new Promise((resolve, reject) => { child.on('error', reject); child.on('close', resolve); });
  assert.equal(exit, 1); assert.equal(JSON.parse(diagnostic).state, 'complete');
  assert.ok(await exists(join(f.options.destination, 'authority-visible'))); assert.ok(await exists(f.options.approvalRecord));
});
