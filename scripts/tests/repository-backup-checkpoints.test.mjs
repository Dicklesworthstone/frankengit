// Real signatures and private files; checkpoint selection does not read payloads.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, unlink, copyFile } from 'node:fs/promises';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { selectRepositoryBackupApprovals as select } from '../lib/repository-backup-checkpoints.mjs';
import { initializeRepositoryBackupWitness, withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';

const NOW = Date.parse('2026-10-14T12:00:00Z');
const ID = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16), object_format: 'sha256' };
const sha = value => createHash('sha256').update(value).digest('hex');
const code = value => error => error.code === value;
async function fixture(t, format = 'sha256') {
  const root = await mkdtemp(join(tmpdir(), 'fg-checkpoints-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const pair = generateKeyPairSync('ed25519'), key = join(root, 'public.pem');
  await writeFile(key, pair.publicKey.export({ format: 'pem', type: 'spki' }));
  const policy = { ...ID, object_format: format, minimum_head_generation: '1' };
  const witness = join(root, 'witness'); await initializeRepositoryBackupWitness(witness, key, policy, { now: NOW });
  async function approval(name, generation, changes = {}) {
    const body = join(root, name + '.body'), path = join(root, name + '.approval');
    await writeFile(body, changes.body ?? 'opaque ' + generation);
    const signed = await signRepositoryBackupFile(body, Buffer.from(pair.privateKey.export({ format: 'pem', type: 'pkcs8' })),
      { ...ID, object_format: format, head_generation: generation, issued_at: '2026-10-14T11:00:00Z', ...changes.meta },
      { now: changes.now ?? NOW });
    await writeFile(path, signed.envelope); await unlink(body); // no payload remains to select or hash
    return path;
  }
  const run = (rows, options = {}, expected = policy) => select(rows, key, expected, { now: NOW, ...options });
  const owned = (rows, options = {}) => withRepositoryBackupWitness(witness, key, policy, { now: NOW },
    w => select(rows, key, policy, { now: NOW, ...options }, w));
  return { root, key, policy, witness, approval, run, owned };
}
for (const format of ['sha1', 'sha256']) test(`${format}: choose full-width highest approval without any archive file`, async t => {
  const f = await fixture(t, format), a = await f.approval('a', '9007199254740992'), b = await f.approval('b', '18446744073709551615');
  for (const rows of [[a, b], [b, a]]) {
    const selected = await f.run(rows);
    assert.equal(selected.report.selected.approval, b);
    assert.equal(selected.checkCurrent().statement.head_generation, '18446744073709551615');
    assert.equal(selected.report.payloads_read, false); assert.equal(selected.report.native_content_verified, false);
    assert.equal(selected.report.newest_checkpoint_verified, false); assert.equal(selected.report.candidate_set_completeness_verified, false);
  }
});
for (const defect of ['expired', 'future', 'oversized', 'below-floor']) test(`${defect}: the highest signed checkpoint refuses instead of choosing older`, async t => {
  const f = await fixture(t), low = await f.approval('low', '1');
  const opts = defect === 'expired' ? { meta: { expires_at: '2026-10-14T11:30:00Z' }, now: NOW - 3600000 }
    : defect === 'future' ? { meta: { issued_at: '2026-10-14T13:00:00Z' }, now: NOW + 3600000 }
    : defect === 'oversized' ? { body: Buffer.alloc(1000) } : {};
  const high = await f.approval('high', '2', opts);
  const expectedCode = { expired: 'backup_approval_expired', future: 'backup_approval_in_future', oversized: 'backup_selected_archive_limit', 'below-floor': 'backup_approval_below_floor' }[defect];
  await assert.rejects(f.run([low, high], { maximumBytes: 100 }, { ...f.policy, minimum_head_generation: defect === 'below-floor' ? '3' : '1' }), code(expectedCode));
});
for (const difference of ['body', 'expiry']) test(`same-generation ${difference} conflict refuses even with identical artifact identities`, async t => {
  const f = await fixture(t), a = await f.approval('a', '2'), b = await f.approval('b', '2', difference === 'body'
    ? { body: 'different source bytes' } : { meta: { expires_at: '2026-10-14T13:00:00Z' } });
  await assert.rejects(f.run([a, b]), code('backup_checkpoint_ambiguous'));
});
test('identical statements keep the selected copy\'s exact envelope-byte pin', async t => {
  const f = await fixture(t), a = await f.approval('a', '2'), b = join(f.root, 'b.approval');
  await writeFile(b, JSON.stringify(JSON.parse(await readFile(a)), null, 2));
  const selected = await f.run([b, a, b]);
  assert.deepEqual(selected.report.highest_indices, [0, 1, 2]);
  assert.equal(selected.report.checkpoint.approval_sha256, sha(await readFile(b)));
  assert.notEqual(selected.report.checkpoint.approval_sha256, sha(await readFile(a)));
  assert.equal(selected.report.candidates[0].statement_sha256, selected.report.candidates[1].statement_sha256);
});
test('invalid lower approval cannot be hidden by a valid higher approval', async t => {
  const f = await fixture(t), high = await f.approval('high', '2'), bad = join(f.root, 'bad'); await writeFile(bad, '{}');
  await assert.rejects(f.run([high, bad]), code('backup_invalid_envelope'));
});
test('missing approval is fatal rather than availability-based selection', async t => {
  const f = await fixture(t), a = await f.approval('a', '2');
  await assert.rejects(f.run([a, join(f.root, 'missing')]), code('ENOENT'));
});
test('an expired observation remains constraining across an owned restart', async t => {
  const f = await fixture(t), low = await f.approval('low', '1');
  const high = await f.approval('high', '2', { meta: { expires_at: '2026-10-14T11:30:00Z' }, now: NOW - 3600000 });
  await assert.rejects(f.owned([low, high]), code('backup_approval_expired'));
  await assert.rejects(f.owned([low]), code('backup_below_witness'));
});
test('retained conflicts block omission of one candidate on the next run', async t => {
  const f = await fixture(t), a = await f.approval('a', '2'), b = await f.approval('b', '2', { body: 'conflict' });
  await assert.rejects(f.owned([a, b]), code('backup_checkpoint_ambiguous'));
  await assert.rejects(f.owned([a]), code('backup_witness_checkpoint_ambiguous'));
  assert.equal((await f.owned([await f.approval('new', '3')])).report.selected.head_generation, '3');
});
test('a bad signature cannot ratchet the retained floor', async t => {
  const f = await fixture(t), a = await f.approval('a', '1'), b = await f.approval('b', '2');
  const envelope = JSON.parse(await readFile(b)); envelope.signatures[0].sig = Buffer.alloc(64).toString('base64'); await writeFile(b, JSON.stringify(envelope));
  await assert.rejects(f.owned([b]), code('backup_invalid_signature'));
  assert.equal((await f.owned([a])).report.selected.head_generation, '1');
});
test('later malformed input preserves the previously authenticated higher observation', async t => {
  const f = await fixture(t), a = await f.approval('a', '2'), low = await f.approval('low', '1'), bad = join(f.root, 'bad');
  await writeFile(bad, '{}'); await assert.rejects(f.owned([a, bad]), code('backup_invalid_envelope'));
  await assert.rejects(f.owned([low]), code('backup_below_witness'));
});
test('intake snapshots the complete path set and independent policy before observers', async t => {
  const f = await fixture(t), a = await f.approval('a', '1'), b = await f.approval('b', '2');
  const rows = [a, b], policy = { ...f.policy };
  const selected = await f.run(rows, { onProgress() { rows[1] = join(f.root, 'missing'); policy.minimum_head_generation = '3'; } }, policy);
  assert.equal(selected.report.selected.approval, b); assert.equal(selected.report.authentication.policy.minimum_head_generation, '1');
  assert.throws(() => { selected.report.candidates[0].approval = 'changed'; }, TypeError);
  assert.throws(() => { selected.inspected.length = 0; }, TypeError);
});
test('all 64 bounded approval reads are accepted, 65 refuse before opening any file', async t => {
  const f = await fixture(t), a = await f.approval('a', '1');
  assert.equal((await f.run(Array(64).fill(a))).report.candidates.length, 64);
  await assert.rejects(select(Array(65).fill('/absent'), '/absent-key', f.policy), code('backup_candidate_limit'));
  await assert.rejects(f.run([]), code('backup_candidate_limit'));
});
test('invalid path and options fail before key I/O', async t => {
  const f = await fixture(t);
  await assert.rejects(select(['bad\0path'], '/absent-key', f.policy), code('backup_invalid_path'));
  await assert.rejects(select(['/absent'], '/absent-key', f.policy, { unknown: true }), code('backup_invalid_options'));
});
test('cancellation after an authenticated observation does not forget it', async t => {
  const f = await fixture(t), a = await f.approval('a', '2'), low = await f.approval('low', '1'), controller = new AbortController();
  await assert.rejects(f.owned([a], { signal: controller.signal, onProgress() { controller.abort(); } }), code('backup_cancelled'));
  await assert.rejects(f.owned([low]), code('backup_below_witness'));
});
test('observer failure is fatal, never interpreted as a missing replica', async t => {
  const f = await fixture(t), a = await f.approval('a', '1'), original = Object.assign(Error('observer'), { code: 'ENOENT' });
  await assert.rejects(f.run([a], { onProgress() { throw original; } }), error => error === original);
});
test('the deadline spans every approval and observer', async t => {
  const f = await fixture(t), a = await f.approval('a', '1');
  await assert.rejects(f.run([a], { timeoutMs: 100, async onProgress() { await delay(120); } }), code('backup_deadline'));
});
test('a changed key file cannot select a second trust domain during intake', async t => {
  const f = await fixture(t), a = await f.approval('a', '1'), b = await f.approval('b', '2');
  const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'pem', type: 'spki' });
  const result = await f.run([a, b], { onProgress() { return writeFile(f.key, other); } });
  assert.equal(result.report.selected.approval, b);
  await assert.rejects(f.run([b]), code('backup_untrusted_signer'));
});
test('namespace mismatch and invalid external floor refuse independently signed input', async t => {
  const f = await fixture(t), a = await f.approval('a', '1');
  await assert.rejects(f.run([a], {}, { ...f.policy, repository_id: '44'.repeat(16) }), code('backup_approval_identity_mismatch'));
  await assert.rejects(f.run([a], {}, { ...f.policy, minimum_head_generation: '9007199254740993' }), code('backup_approval_below_floor'));
});
