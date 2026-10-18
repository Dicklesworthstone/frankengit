import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtemp, readFile, writeFile, chmod, rm, stat, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { signRepositoryBackupFile } from '../../scripts/lib/repository-backup-approval.mjs';
import { repositoryBackupOptions, runApprovedRepositoryBackup } from '../../scripts/lib/repository-backup-native.mjs';
import { selectedRepositoryBackupOptions, runSelectedRepositoryBackup } from '../../scripts/lib/repository-backup-selected.mjs';
import { selectionArguments, runSelectionCommand } from '../../scripts/select_repository_backup_native.mjs';

// Real signatures, files and children; unchanged DELIBERATELY FAKE native
// contract adapter. Opaque JSON artifacts are NOT native repository archives.
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const instant = ms => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');
const fake = new URL('./fixtures/repository-backup-fake.mjs', import.meta.url).href;
const command = new URL('../../scripts/select_repository_backup_native.mjs', import.meta.url).pathname;
const code = value => e => e.code === value;
async function fixture(t, format = 'sha256') {
  const root = await mkdtemp(join(tmpdir(), 'fg-selected-native-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const pair = generateKeyPairSync('ed25519');
  const secret = Buffer.from(pair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  const publicPem = Buffer.from(pair.publicKey.export({ format: 'pem', type: 'spki' }));
  const trustKey = join(root, 'public'), log = join(root, 'calls'), configPath = join(root, 'config');
  const fg = join(root, 'explicit-fake-fg.mjs');
  await writeFile(trustKey, publicPem);
  await writeFile(fg, `#!${process.execPath}\nimport { fakeRepositoryBackup } from ${JSON.stringify(fake)};\nawait fakeRepositoryBackup(${JSON.stringify(configPath)});\n`); await chmod(fg, 0o700);
  const configure = value => writeFile(configPath, JSON.stringify({ log, ...value })); await configure({});
  const policy = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16), object_format: format, minimum_head_generation: '1' };
  const native = { operation: 'verify', fg, trustKey, policy, verificationInstance: '9001', trustedLocal: true };
  const restore = { operation: 'restore', destination: join(root, 'destination'), destinationInstance: '9002', approvalRecord: join(root, 'record') };
  async function candidate(name, generation, extra = {}) {
    const input = join(root, name), approval = input + '.approval';
    const data = { ...policy, head_generation: generation, issued_at: instant(Date.now() - 60000), ...extra };
    delete data.minimum_head_generation;
    await writeFile(input, JSON.stringify(data));
    await writeFile(approval, (await signRepositoryBackupFile(input, secret, data)).envelope);
    return { input, approval };
  }
  async function run(rows, extra = {}) {
    try { return await runSelectedRepositoryBackup({ ...native, candidates: rows, ...extra }); }
    catch (error) {
      if (error.verification_scratch) t.after(() => rm(error.verification_scratch, { recursive: true, force: true }));
      throw error;
    }
  }
  async function calls() { try { return (await readFile(log, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); } catch (e) { if (e.code === 'ENOENT') return []; throw e; } }
  const args = (op, rows) => [op, ...rows.flatMap(row => ['--candidate', row.input, row.approval]), '--trust-key', trustKey,
    ...Object.entries(policy).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v]),
    ...(op === 'select' ? [] : ['--fg', fg, '--trusted-local', '--verification-instance', native.verificationInstance]),
    ...(op !== 'restore' ? [] : ['--destination', restore.destination, '--destination-instance', restore.destinationInstance, '--approval-record', restore.approvalRecord])];
  return { root, secret, publicPem, native, restore, trustKey, candidate, run, calls, configure, args };
}
const missing = path => assert.rejects(stat(path), code('ENOENT'));

for (const format of ['sha1', 'sha256']) test(`selected ${format} checkpoint uses native verify and restore once, with the original floor`, async t => {
  const f = await fixture(t, format), a = await f.candidate('low', '9'), b = await f.candidate('high', '10');
  const report = await f.run([a, b], f.restore);
  assert.equal(report.state, 'complete'); assert.equal(report.selection.selected.input, b.input);
  assert.equal(report.result.authentication.statement.head_generation, '10');
  assert.equal(report.result.authentication.policy.minimum_head_generation, '1');
  const calls = await f.calls(); assert.deepEqual(calls.map(c => c.args[1]), ['verify', 'restore']);
  for (const c of calls) { assert.equal(c.args[2], b.input); assert.ok(!c.args.includes(f.trustKey)); assert.ok(!c.args.includes(b.approval)); }
  assert.equal(await readFile(join(f.restore.destination, 'authority-visible'), 'utf8'), report.selection.authentication.statement.artifact.sha256);
  assert.equal(report.selection.native_content_verified, false);
  assert.equal(report.result.approval_effect_time_enforced, false);
  const record = JSON.parse(await readFile(f.restore.approvalRecord));
  assert.equal(record.statement.head_generation, '10'); assert.equal(record.policy.minimum_head_generation, '1');
});

test('full-width selected generations also survive the native receipt boundary', async t => {
  const f = await fixture(t), a = await f.candidate('a', '18446744073709551614'), b = await f.candidate('b', '18446744073709551615');
  const report = await f.run([a, b], { ...f.restore, policy: { ...f.native.policy, minimum_head_generation: '18446744073709551615' } });
  assert.equal(report.selection.selected.input, b.input);
  assert.equal(report.result.native.head_generation, '18446744073709551615');
  assert.equal(report.result.authentication.policy.minimum_head_generation, '18446744073709551615');
});

test('read-only selection and real CLI do not start a native process', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10'), b = await f.candidate('b', '11');
  const selected = spawnSync(process.execPath, [command, ...f.args('select', [a, b])], { encoding: 'utf8' });
  assert.equal(selected.status, 0, selected.stderr);
  const report = JSON.parse(selected.stdout); assert.equal(report.selected.input, b.input);
  assert.equal(report.newest_checkpoint_verified, false); assert.deepEqual(await f.calls(), []);
  const verified = spawnSync(process.execPath, [command, ...f.args('verify', [b, a])], { encoding: 'utf8' });
  assert.equal(verified.status, 0, verified.stderr); assert.equal(JSON.parse(verified.stdout).state, 'complete');
  assert.equal((await f.calls()).length, 1);
});

for (const defect of ['approval', 'key-and-approval', 'archive']) test(`selected ${defect} substitution between selection and native work refuses`, async t => {
  const f = await fixture(t), a = await f.candidate('low', '9'), b = await f.candidate('high', '10');
  const original = await readFile(b.approval);
  await assert.rejects(f.run([a, b], { ...f.restore, async onProgress(event) {
    if (event.phase !== 'selection_complete') return;
    if (defect === 'approval') {
      // A fully valid LOWER artifact and its real approval at the chosen paths.
      // Ordinary reauthentication alone would silently change the checkpoint.
      await writeFile(b.approval, await readFile(a.approval));
      await writeFile(b.input, await readFile(a.input));
    }
    if (defect === 'archive') await writeFile(b.input, await readFile(a.input));
    if (defect === 'key-and-approval') {
      const other = generateKeyPairSync('ed25519');
      await writeFile(f.trustKey, other.publicKey.export({ format: 'pem', type: 'spki' }));
      const data = JSON.parse(await readFile(b.input));
      await writeFile(b.approval, (await signRepositoryBackupFile(b.input, Buffer.from(other.privateKey.export({ format: 'pem', type: 'pkcs8' })), data)).envelope);
    }
  } }), code(defect === 'archive' ? 'backup_artifact_mismatch' : 'backup_selected_approval_changed'));
  assert.deepEqual(await f.calls(), []); await missing(f.restore.destination); await missing(f.restore.approvalRecord);
  await writeFile(f.trustKey, f.publicPem); await writeFile(b.approval, original);
  assert.equal((await f.run([a])).state, 'complete');
});

test('checkpoint pins narrow authentication and are copied, never used as trust keys', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10');
  const checkpoint = { approval_sha256: sha256(await readFile(a.approval)), trusted_key_id: 'sha256:' + '0'.repeat(64) };
  await assert.rejects(runApprovedRepositoryBackup({ ...f.native, ...a, checkpoint }), code('backup_selected_signer_changed'));
  assert.deepEqual(await f.calls(), []);
  const opts = repositoryBackupOptions({ ...f.native, ...a, checkpoint }); checkpoint.approval_sha256 = '0'.repeat(64);
  assert.notEqual(opts.checkpoint.approval_sha256, checkpoint.approval_sha256); assert.ok(Object.isFrozen(opts.checkpoint));
  assert.equal((await runApprovedRepositoryBackup({ ...f.native, ...a })).state, 'complete');
});

for (const defect of ['missing', 'expired', 'ambiguous']) test(`${defect} higher candidate never launches an older native restore`, async t => {
  const f = await fixture(t), a = await f.candidate('low', '9'), b = await f.candidate('high', '10');
  const rows = [a, b];
  if (defect === 'missing') await unlink(b.input);
  if (defect === 'ambiguous') rows.push(await f.candidate('other', '10', { issued_at: instant(Date.now() - 120000) }));
  if (defect === 'expired') {
    const data = JSON.parse(await readFile(b.input)); data.expires_at = instant(Date.now() + 60000);
    await writeFile(b.approval, (await signRepositoryBackupFile(b.input, f.secret, data)).envelope);
    const clock = Date.now(); t.mock.method(Date, 'now', () => clock + 120000);
  }
  await assert.rejects(f.run(rows, f.restore)); assert.deepEqual(await f.calls(), []);
  await missing(f.restore.destination); await missing(f.restore.approvalRecord);
  assert.equal((await f.run([a])).state, 'complete');
});

for (const mode of ['verify-refuse', 'verify-flood', 'duplicate-report']) test(`native ${mode} retains refusal without fallback or destination publication`, async t => {
  const f = await fixture(t), a = await f.candidate('low', '9'), b = await f.candidate('high', '10');
  await f.configure({ mode }); await assert.rejects(f.run([a, b], f.restore));
  const calls = await f.calls(); assert.equal(calls.length, 1); assert.equal(calls[0].args[2], b.input);
  await missing(f.restore.destination); await missing(f.restore.approvalRecord);
  await f.configure({}); assert.equal((await f.run([a, b])).state, 'complete');
});

test('native generation mismatch cannot be blessed by valid selection signatures', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10');
  await f.configure({ mismatch: 'head_generation', wrong: 9 });
  await assert.rejects(f.run([a], f.restore), code('backup_native_receipt_mismatch'));
  await missing(f.restore.destination); await missing(f.restore.approvalRecord);
  await f.configure({}); assert.equal((await f.run([a])).state, 'complete');
});

test('lost restore response retains the record and resumes only the same signed checkpoint', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10'); await f.configure({ mode: 'restore-lost-reply' });
  await assert.rejects(f.run([a], f.restore), e => e.state === 'restore_attempted_unknown');
  const record = await readFile(f.restore.approvalRecord); assert.ok((await stat(f.restore.destination)).isDirectory());
  await f.configure({}); const resumed = await f.run([a], { ...f.restore, resume: true });
  assert.equal(resumed.state, 'complete'); assert.equal(resumed.result.native.already_published, true);
  assert.deepEqual(await readFile(f.restore.approvalRecord), record);
  const b = await f.candidate('b', '11'), before = (await f.calls()).length;
  await assert.rejects(f.run([a, b], { ...f.restore, resume: true }), code('backup_restore_approval_record_mismatch'));
  assert.equal((await f.calls()).length, before); assert.deepEqual(await readFile(f.restore.approvalRecord), record);
});

test('resume refuses changed external floor even when the same highest artifact remains valid', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10');
  const policy = { ...f.native.policy, minimum_head_generation: '9' };
  await f.run([a], { ...f.restore, policy }); const before = (await f.calls()).length;
  await assert.rejects(f.run([a], { ...f.restore, resume: true }), code('backup_restore_approval_record_mismatch'));
  assert.equal((await f.calls()).length, before);
  assert.equal((await f.run([a], { ...f.restore, policy, resume: true })).state, 'complete');
});

test('one timeout and cancellation cover selection before native submission', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10'), controller = new AbortController();
  await assert.rejects(f.run([a], { ...f.restore, signal: controller.signal, onProgress(e) { if (e.phase === 'selection_complete') controller.abort(); } }), code('backup_cancelled'));
  await assert.rejects(f.run([a], { ...f.restore, timeoutMs: 10, async onProgress() { await new Promise(r => setTimeout(r, 25)); } }), code('backup_deadline'));
  assert.deepEqual(await f.calls(), []); await missing(f.restore.destination);
});

test('cancellation reaps native child and preserves unknown publication and exact resume', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10'), controller = new AbortController();
  await f.configure({ mode: 'restore-wait' });
  let pid, polling = false;
  const poll = setInterval(async () => {
    if (polling || controller.signal.aborted) return; polling = true;
    try { pid = Number(await readFile(join(f.restore.destination, 'started'), 'utf8')); controller.abort(); } catch {} finally { polling = false; }
  }, 10);
  const safety = setTimeout(() => controller.abort(), 3000);
  try { await assert.rejects(f.run([a], { ...f.restore, signal: controller.signal }), e => e.state === 'restore_attempted_unknown'); }
  finally { clearInterval(poll); clearTimeout(safety); }
  assert.ok(pid); assert.throws(() => process.kill(pid, 0), code('ESRCH'));
  await f.configure({}); assert.equal((await f.run([a], { ...f.restore, resume: true })).state, 'complete');
});

test('existing candidate files remain byte-exact and destination is never overwritten', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10'); await writeFile(f.restore.destination, 'keep');
  await assert.rejects(f.run([a], f.restore), code('backup_existing_path'));
  assert.equal(await readFile(f.restore.destination, 'utf8'), 'keep'); assert.deepEqual(await f.calls(), []);
});

test('grammar and checkpoint validation refuse before file I/O; no force or fallback flags', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10');
  for (const extra of [ ['--candidate', 'missing'], ['--force'], ['--fallback'], ['--trust-key', 'other'], ['--timeout-secs', '01'], ['--max-archive-bytes', '0'], ['--resume'] ]) {
    assert.throws(() => selectionArguments([...f.args('select', [a]), ...extra]));
  }
  for (const checkpoint of [null, {}, { approval_sha256: '0'.repeat(64), trusted_key_id: 'sha256:' + 'a'.repeat(64), authority: true },
    { approval_sha256: 'x'.repeat(64), trusted_key_id: 'sha256:' + 'a'.repeat(64) }]) {
    assert.throws(() => repositoryBackupOptions({ ...f.native, ...a, checkpoint }), code('backup_invalid_checkpoint'));
  }
  assert.throws(() => selectedRepositoryBackupOptions({ ...f.native, candidates: [a], input: a.input }));
  assert.throws(() => selectedRepositoryBackupOptions({ ...f.native, ...f.restore, candidates: [a], approvalRecord: a.approval }));
  assert.deepEqual(await f.calls(), []);
  assert.equal(selectionArguments(f.args('verify', [a])).operation, 'verify');
});

test('wrapper snapshots candidates, policy and native options before yielding', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10');
  const raw = { ...f.native, candidates: [{ ...a }], policy: { ...f.native.policy } };
  const pending = runSelectedRepositoryBackup(raw); raw.fg = '/not-a-program'; raw.policy.minimum_head_generation = '999'; raw.candidates[0].input = '/not-a-file';
  assert.equal((await pending).state, 'complete');
});

test('output failure after confirmed restore retains complete knowledge and permits exact resume', async t => {
  const f = await fixture(t), a = await f.candidate('a', '10');
  const output = { write(_text, callback) { const e = new Error('broken output'); e.code = 'EPIPE'; callback(e); } };
  await assert.rejects(runSelectionCommand(f.args('restore', [a]), output), e => {
    assert.equal(e.state, 'complete'); assert.equal(e.completed_result.result.native.reopened_and_verified, true); return e.code === 'EPIPE';
  });
  assert.equal((await f.run([a], { ...f.restore, resume: true })).state, 'complete');
});
