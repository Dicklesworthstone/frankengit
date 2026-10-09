import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, unlink, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { inspectRepositoryBackupApproval, verifyRepositoryBackupApproval, signRepositoryBackupFile } from '../../scripts/lib/repository-backup-approval.mjs';
import { selectRepositoryBackup, repositoryBackupCandidates, MAX_BACKUP_CANDIDATES } from '../../scripts/lib/repository-backup-selection.mjs';

// Actual signatures and filesystem reads over opaque test artifacts. These are
// NOT native fg archives, nor evidence of native graph/authority verification.
const NOW = Date.parse('2026-10-08T12:00:00Z');
const ISSUED = '2026-10-08T11:00:00Z', EXPIRED = '2026-10-08T11:30:00Z';
const POLICY = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16),
  object_format: 'sha256', minimum_head_generation: '1' };
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const SECRET = Buffer.from(privateKey.export({ format: 'pem', type: 'pkcs8' }));
const PUBLIC = Buffer.from(publicKey.export({ format: 'pem', type: 'spki' }));
const sha256 = b => createHash('sha256').update(b).digest('hex');
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-selection-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const key = join(root, 'public.pem'); await writeFile(key, PUBLIC);
  async function candidate(name, generation, options = {}) {
    const input = join(root, name), approval = input + '.approval';
    await writeFile(input, options.bytes ?? Buffer.from('opaque archive ' + generation));
    const declarations = { ...POLICY, head_generation: generation, issued_at: ISSUED, ...options.declarations };
    delete declarations.minimum_head_generation;
    const signed = await signRepositoryBackupFile(input, options.key ?? SECRET, declarations,
      { now: options.signingTime ?? NOW, maximumBytes: 20 * 1024 * 1024 });
    await writeFile(approval, signed.envelope);
    return { input, approval };
  }
  const select = (rows, policy = POLICY, options = {}) => selectRepositoryBackup(rows, key, policy, { now: NOW, ...options });
  return { root, key, candidate, select };
}
const refuses = (promise, code) => assert.rejects(promise, e => e.code === code, code);

test('signature inspection cannot be mistaken for a currently usable approval', async t => {
  const f = await fixture(t), row = await f.candidate('old', '10', { declarations: { expires_at: EXPIRED }, signingTime: NOW - 3600000 });
  const encoded = await readFile(row.approval);
  const inspected = await inspectRepositoryBackupApproval(encoded, PUBLIC, POLICY, { now: NOW });
  assert.equal(inspected.authentication, undefined);
  assert.equal(inspected.checkpoint.signature_verified, true);
  assert.equal(inspected.checkpoint.approval_validity_checked, false);
  assert.throws(() => inspected.checkCurrent(), { code: 'backup_approval_expired' });
  await refuses(verifyRepositoryBackupApproval(encoded, PUBLIC, POLICY, { now: NOW }), 'backup_approval_expired');
  const good = await f.candidate('good', '10');
  assert.equal((await verifyRepositoryBackupApproval(await readFile(good.approval), PUBLIC, POLICY, { now: NOW })).authentication.signature_verified, true);
});

test('highest full-width signed generation wins, not input order or filenames', async t => {
  const f = await fixture(t);
  const a = await f.candidate('looks-newest-9999', '9007199254740992');
  const b = await f.candidate('looks-old', '9007199254740993');
  const c = await f.candidate('middle', '10');
  const first = (await f.select([a, b, c])).report;
  const second = (await f.select([c, b, a])).report;
  assert.deepEqual(first, second);
  assert.equal(first.selected.input, b.input);
  assert.equal(first.selected.head_generation, '9007199254740993');
  assert.equal(first.checkpoint.approval_sha256, sha256(await readFile(b.approval)));
  for (const field of ['native_content_verified', 'newest_checkpoint_verified', 'candidate_set_completeness_verified']) assert.equal(first[field], false);
  assert.equal(first.read_only, true);
  assert.equal(first.authentication.native_content_verified, false);
});

test('u64 maximum generation and independent floor stay lossless', async t => {
  const f = await fixture(t), a = await f.candidate('old', '18446744073709551614'), b = await f.candidate('new', '18446744073709551615');
  assert.equal((await f.select([a, b], { ...POLICY, minimum_head_generation: '18446744073709551615' })).report.selected.input, b.input);
  await refuses(f.select([a], { ...POLICY, minimum_head_generation: '18446744073709551615' }), 'backup_approval_below_floor');
});

for (const defect of ['missing', 'corrupt', 'expired', 'future', 'oversized']) test(`a ${defect} highest checkpoint never falls back to a usable lower one`, async t => {
  const f = await fixture(t), low = await f.candidate('low', '9');
  let options = {};
  if (defect === 'expired') options = { declarations: { expires_at: EXPIRED }, signingTime: NOW - 3600000 };
  if (defect === 'future') options = { declarations: { issued_at: '2026-10-08T13:00:00Z' }, signingTime: NOW + 3600000 };
  if (defect === 'oversized') options = { bytes: Buffer.alloc(200000, 1) };
  const high = await f.candidate('high', '10', options);
  if (defect === 'missing') await unlink(high.input);
  if (defect === 'corrupt') await writeFile(high.input, 'opaque archive XX');
  const code = { missing: 'ENOENT', corrupt: 'backup_artifact_mismatch', expired: 'backup_approval_expired',
    future: 'backup_approval_in_future', oversized: 'backup_selected_archive_limit' }[defect];
  await refuses(f.select([low, high], POLICY, { maximumBytes: 100000 }), code);
  assert.equal((await f.select([low], POLICY, { maximumBytes: 100000 })).report.selected.input, low.input);
});

test('lower expired and missing artifacts do not prevent a valid higher checkpoint', async t => {
  const f = await fixture(t), low = await f.candidate('low', '9', { declarations: { expires_at: EXPIRED }, signingTime: NOW - 3600000 });
  const high = await f.candidate('high', '10'); await unlink(low.input);
  const result = await f.select([low, high], { ...POLICY, minimum_head_generation: '10' });
  assert.equal(result.report.selected.input, high.input);
  assert.equal(result.report.candidates.length, 2);
});

test('two distinct signed statements at highest generation require operator choice', async t => {
  const f = await fixture(t), a = await f.candidate('a', '12'), b = await f.candidate('b', '12', { bytes: Buffer.from('other') });
  const low = await f.candidate('low', '11'); await unlink(a.input); await unlink(b.input);
  await refuses(f.select([a, low, b]), 'backup_checkpoint_ambiguous');
  await refuses(f.select([b, low, a]), 'backup_checkpoint_ambiguous');
  assert.equal((await f.select([low])).report.selected.head_generation, '11');
});

test('different approvals for identical artifact/generation remain explicit ambiguity', async t => {
  const f = await fixture(t), a = await f.candidate('a', '12'), b = await f.candidate('b', '12', { declarations: { issued_at: '2026-10-08T11:01:00Z' } });
  assert.equal(sha256(await readFile(a.input)), sha256(await readFile(b.input)));
  await refuses(f.select([a, b]), 'backup_checkpoint_ambiguous');
});

test('identical signed replicas collapse deterministically without hiding their count', async t => {
  const f = await fixture(t), a = await f.candidate('a', '12'), b = await f.candidate('b', '12');
  assert.deepEqual(await readFile(a.approval), await readFile(b.approval));
  const result = (await f.select([b, a])).report;
  assert.equal(result.selected.input, a.input); assert.equal(result.identical_statement_candidates, 2);
  assert.equal(Object.isFrozen(result), true); assert.equal(Object.isFrozen(result.selected), true);
  assert.throws(() => { result.authentication.statement.artifact.sha256 = '0'.repeat(64); }, TypeError);
});

test('conflicts below a unique higher checkpoint do not pick a lower generation', async t => {
  const f = await fixture(t), a = await f.candidate('a', '12'), b = await f.candidate('b', '12', { bytes: Buffer.from('other') }), c = await f.candidate('c', '13');
  await unlink(a.input); await unlink(b.input);
  assert.equal((await f.select([a, b, c])).report.selected.input, c.input);
});

for (const defect of ['signature', 'identity', 'key', 'symlink']) test(`a supplied ${defect} defect refuses the set rather than silently omitting a candidate`, async t => {
  const f = await fixture(t), good = await f.candidate('good', '12'), bad = await f.candidate('bad', '11',
    defect === 'identity' ? { declarations: { repository_id: '44'.repeat(16) } } : {});
  if (defect === 'signature') {
    const envelope = JSON.parse(await readFile(bad.approval));
    const sig = Buffer.from(envelope.signatures[0].sig, 'base64'); sig[0] ^= 1;
    envelope.signatures[0].sig = sig.toString('base64'); await writeFile(bad.approval, JSON.stringify(envelope));
  }
  if (defect === 'key') {
    const other = generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' });
    const data = { ...POLICY, head_generation: '11', issued_at: ISSUED }; delete data.minimum_head_generation;
    await writeFile(bad.approval, (await signRepositoryBackupFile(bad.input, Buffer.from(other), data, { now: NOW })).envelope);
  }
  if (defect === 'symlink') { await unlink(bad.approval); await symlink(good.approval, bad.approval); }
  await assert.rejects(f.select([good, bad]));
  assert.equal((await f.select([good])).report.selected.input, good.input);
});

test('mutable descriptors, policy and option clock are captured before any await', async t => {
  const f = await fixture(t), a = await f.candidate('a', '12');
  const rows = [{ ...a }], policy = { ...POLICY }, options = { now: NOW };
  const pending = selectRepositoryBackup(rows, f.key, policy, options);
  rows[0].input = '/missing'; rows.push({ input: '/unknown', approval: '/unknown' });
  policy.minimum_head_generation = '999'; policy.repository_id = 'ff'.repeat(16); options.now = NOW + 1e9;
  assert.equal((await pending).report.selected.input, a.input);
});

test('descriptors refuse excess, duplicates, relative aliases and unknown fields before I/O', async () => {
  for (const value of [[], null, new Array(MAX_BACKUP_CANDIDATES + 1).fill({ input: 'a', approval: 'b' }),
    [{ input: 'a', approval: 'b', rank: 99 }], [{ input: '', approval: 'b' }],
    [{ input: 'a', approval: 'b' }, { input: './a', approval: './b' }]]) {
    await assert.rejects(selectRepositoryBackup(value, '/missing', POLICY));
  }
  assert.equal(repositoryBackupCandidates([{ input: 'a', approval: 'b' }]).length, 1);
});

test('one deadline and cancellation span the complete approval set and artifact', async t => {
  const f = await fixture(t), a = await f.candidate('a', '12'), controller = new AbortController();
  await refuses(f.select([a], POLICY, { signal: controller.signal, onProgress() { controller.abort(); } }), 'backup_cancelled');
  await refuses(f.select([a], POLICY, { timeoutMs: 10, async onProgress() { await new Promise(r => setTimeout(r, 25)); } }), 'backup_deadline');
  assert.equal((await f.select([a])).report.selected.input, a.input);
});

test('expiry is checked again after selection progress and during downstream use', async t => {
  const f = await fixture(t), a = await f.candidate('a', '12', { declarations: { expires_at: '2026-10-08T12:01:00Z' } });
  let clock = NOW; t.mock.method(Date, 'now', () => clock);
  await refuses(selectRepositoryBackup([a], f.key, POLICY, { onProgress(e) { if (e.phase === 'checkpoint_selected') clock += 120000; } }), 'backup_approval_expired');
  clock = NOW; const selected = await selectRepositoryBackup([a], f.key, POLICY);
  selected.checkCurrent(); clock += 120000;
  assert.throws(() => selected.checkCurrent(), { code: 'backup_approval_expired' });
});

test('mutating the winning source during hashing refuses, never returns the lower file', async t => {
  const f = await fixture(t), a = await f.candidate('a', '12', { bytes: Buffer.alloc(200000, 1) }), b = await f.candidate('b', '11');
  let changed = false;
  await assert.rejects(f.select([a, b], POLICY, { async onProgress(event) {
    if (event.bytes_read && !changed) { changed = true; await writeFile(a.input, Buffer.alloc(200000, 2)); }
  } }));
  assert.equal(changed, true);
  assert.equal((await f.select([b])).report.selected.input, b.input);
});

test('streamed selection handles over-16-MiB sources without enlarging read buffers', async t => {
  const f = await fixture(t), a = await f.candidate('a', '12', { bytes: Buffer.alloc(17 * 1024 * 1024, 7) });
  const { report } = await f.select([a]);
  assert.equal(report.authentication.statement.artifact.bytes, String(17 * 1024 * 1024));
  assert.equal(report.streaming.maximum_read_bytes, 65536);
  assert.equal(report.streaming.read_calls, 272);
});
