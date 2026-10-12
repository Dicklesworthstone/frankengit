// Real filesystem/Ed25519 operator scrubbing. Payloads are not native fg archives.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile, readFile, copyFile, unlink, symlink, link, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { scrubRepositoryBackups, selectRepositoryBackup } from '../lib/repository-backup-selection.mjs';

const NOW = Date.parse('2026-10-12T12:00:00Z');
const ID = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: 'sha256' };
const POLICY = { ...ID, minimum_head_generation: '1' };
const DATA = Buffer.alloc(131089, 0x61);
const code = expected => e => { assert.equal(e.code, expected); return true; };
async function fixture(t, identity = ID) {
  const root = await mkdtemp(join(tmpdir(), 'fg-backup-scrub-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const keys = generateKeyPairSync('ed25519'), key = join(root, 'trusted.pem');
  const privatePem = keys.privateKey.export({ format: 'pem', type: 'pkcs8' });
  await writeFile(key, keys.publicKey.export({ format: 'pem', type: 'spki' }), { mode: 0o600 });
  const policy = { ...identity, minimum_head_generation: '1' };
  async function signed(name, generation = '7', bytes = DATA, overrides = {}) {
    const input = join(root, `${name}.archive`), approval = join(root, `${name}.approval`);
    await writeFile(input, bytes, { mode: 0o600 });
    const { envelope } = await signRepositoryBackupFile(input, Buffer.from(privatePem), {
      ...identity, head_generation: generation, issued_at: '2026-10-12T11:00:00Z',
      expires_at: '2026-10-13T12:00:00Z', ...overrides,
    }, { now: NOW });
    await writeFile(approval, envelope, { mode: 0o600 }); return { input, approval };
  }
  async function replica(name, source, pretty = false) {
    const row = { input: join(root, `${name}.archive`), approval: join(root, `${name}.approval`) };
    await copyFile(source.input, row.input);
    const encoded = await readFile(source.approval);
    await writeFile(row.approval, pretty ? JSON.stringify(JSON.parse(encoded), null, 2) : encoded);
    return row;
  }
  const scrub = (rows, options = {}, expected = policy, witness = null) => scrubRepositoryBackups(rows, key, expected,
    { now: NOW, maximumBytes: DATA.length, maximumReplicaBytes: DATA.length * 8, ...options }, witness);
  return { root, key, policy, signed, replica, scrub };
}
const outcomes = report => report.replica_attempts.map(row => row.code);

test('healthy first copy cannot hide corruption and missing later copies', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a), c = await f.replica('c', a);
  await writeFile(b.input, Buffer.alloc(DATA.length, 0x62)); await unlink(c.input);
  const selected = await selectRepositoryBackup([a, b, c], f.key, f.policy, { now: NOW });
  assert.equal(selected.report.replica_attempts.length, 1); // Selection is not a scrub.
  const { report } = await f.scrub([c, a, b]);
  assert.deepEqual(outcomes(report), [null, 'backup_artifact_mismatch', 'ENOENT']);
  assert.equal(report.scrub_complete, true); assert.equal(report.all_replicas_authenticated, false);
  assert.equal(report.authenticated_candidates, 1); assert.equal(report.unavailable_candidates, 2);
  assert.equal(report.streaming.total_payload_bytes_read, String(2 * DATA.length));
});

for (const format of ['sha1', 'sha256']) test(`all authentic replicas checked in ${format} namespace`, async t => {
  const f = await fixture(t, { ...ID, object_format: format }), a = await f.signed('a'), b = await f.replica('b', a, true);
  const result = await f.scrub([b, a]); const r = result.report; result.checkCurrent();
  assert.equal(r.type, 'repository_backup_scrub'); assert.equal(r.schema_version, 1);
  assert.equal(r.all_replicas_authenticated, true); assert.equal(r.distinct_authenticated_files, 2);
  assert.equal(r.streaming.total_payload_read_calls, 6); assert.equal(r.streaming.maximum_read_bytes, 65536);
  assert.notEqual(r.candidates[0].approval_sha256, r.candidates[1].approval_sha256);
  for (const flag of ['native_content_verified', 'newest_checkpoint_verified', 'candidate_set_completeness_verified',
    'failure_domain_independence_verified', 'simultaneous_availability_verified']) assert.equal(r[flag], false);
});

test('all unavailable is complete degraded evidence, never an older healthy fallback', async t => {
  const f = await fixture(t), a = await f.signed('a', '9'), b = await f.replica('b', a), old = await f.signed('old', '8');
  await unlink(a.input); await unlink(b.input); let reads = 0;
  const { report } = await f.scrub([a, old, b], { onProgress(e) { if ('bytes_read' in e) reads++; } });
  assert.equal(report.head_generation, '9'); assert.equal(report.authenticated_candidates, 0);
  assert.equal(report.distinct_authenticated_files, 0); assert.equal(report.unavailable_candidates, 2);
  assert.equal(report.lower_checkpoint_candidates_not_scrubbed, 1); assert.equal(report.scrub_complete, true);
  assert.equal(reads, 0);
});

test('full u64 maximum chooses the real higher generation before payload I/O', async t => {
  const f = await fixture(t), low = await f.signed('0-low', '18446744073709551614'), high = await f.signed('high', '18446744073709551615');
  await unlink(low.input);
  const { report } = await f.scrub([low, high]);
  assert.equal(report.head_generation, '18446744073709551615'); assert.deepEqual(outcomes(report), [null]);
});

test('duplicate file paths with distinct envelopes never inflate distinct file count', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a, true);
  b.input = a.input; const { report } = await f.scrub([a, b]);
  assert.equal(report.authenticated_candidates, 2); assert.equal(report.distinct_authenticated_files, 1);
  assert.deepEqual(report.replica_attempts[0].file_identity, report.replica_attempts[1].file_identity);
});

test('hard-linked paths and parent-directory aliases count one verified inode', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await unlink(b.input); await link(a.input, b.input);
  const alias = join(f.root, 'alias'); await symlink(f.root, alias);
  const c = { input: join(alias, 'a.archive'), approval: join(alias, 'a.approval') };
  const { report } = await f.scrub([b, c, a]);
  assert.equal(report.authenticated_candidates, 3); assert.equal(report.distinct_authenticated_files, 1);
});

test('candidate order does not change scrub ordering or inventory commitment', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  assert.deepEqual((await f.scrub([a, b])).report, (await f.scrub([b, a])).report);
});

test('all approvals must authenticate before even the first healthy archive opens', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  const envelope = JSON.parse(await readFile(b.approval)); envelope.signatures[0].sig = Buffer.alloc(64).toString('base64');
  await writeFile(b.approval, JSON.stringify(envelope)); let reads = 0;
  await assert.rejects(f.scrub([a, b], { onProgress(e) { if ('bytes_read' in e) reads++; } }), code('backup_invalid_signature'));
  assert.equal(reads, 0);
});

test('a missing approval is fatal, not a merely unavailable byte replica', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a); await unlink(b.approval);
  await assert.rejects(f.scrub([a, b]), e => { assert.equal(e.code, 'ENOENT'); assert.notEqual(e.scrub_complete, true); return true; });
});

test('equal-generation signed conflicts refuse without artifact reads', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.signed('b', '7', Buffer.from('other'));
  let reads = 0;
  await assert.rejects(f.scrub([a, b], { onProgress(e) { if ('bytes_read' in e) reads++; } }), code('backup_checkpoint_ambiguous'));
  assert.equal(reads, 0);
});

test('expired higher approval blocks the older healthy checkpoint', async t => {
  const f = await fixture(t), a = await f.signed('a', '8', DATA, { expires_at: '2026-10-12T13:00:00Z' });
  const old = await f.signed('old', '7'); await unlink(a.input);
  await assert.rejects(f.scrub([old, a], { now: Date.parse('2026-10-12T14:00:00Z') }), code('backup_approval_expired'));
});

test('independent floor and namespace cannot be weakened by scrub', async t => {
  const f = await fixture(t), a = await f.signed('a');
  await assert.rejects(f.scrub([a], {}, { ...POLICY, minimum_head_generation: '8' }), code('backup_approval_below_floor'));
  await assert.rejects(f.scrub([a], {}, { ...POLICY, repository_id: '9'.repeat(32) }), code('backup_approval_identity_mismatch'));
});

test('exact 2N payload budget completes two copies; 2N-1 is explicitly incomplete', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  assert.equal((await f.scrub([a, b], { maximumReplicaBytes: DATA.length * 2 })).report.all_replicas_authenticated, true);
  await assert.rejects(f.scrub([a, b], { maximumReplicaBytes: DATA.length * 2 - 1 }), e => {
    assert.equal(e.code, 'backup_replica_read_budget'); assert.equal(e.scrub_complete, false);
    assert.equal(e.replica_attempts.length, 1); assert.equal(e.replica_bytes_read, String(DATA.length));
    assert.equal(e.active_replica.input, b.input); return true;
  });
});

test('large aggregate ceiling never widens the independent archive ceiling', async t => {
  const f = await fixture(t), a = await f.signed('a');
  await assert.rejects(f.scrub([a], { maximumBytes: DATA.length - 1 }), code('backup_selected_archive_limit'));
});

test('oversized and short replacements are unavailable without exceeding signed work', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a), c = await f.replica('c', a);
  await writeFile(a.input, Buffer.alloc(DATA.length + 1)); await writeFile(b.input, Buffer.from('short'));
  const { report } = await f.scrub([a, b, c]);
  assert.deepEqual(outcomes(report), ['backup_file_size_or_type', 'backup_artifact_mismatch', null]);
  assert.equal(report.streaming.total_payload_bytes_read, String(DATA.length + 5));
});

test('final-component symlinks and directories refuse without blocking other checks', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a), c = await f.replica('c', a);
  await unlink(a.input); await symlink(c.input, a.input); await unlink(b.input); await mkdir(b.input);
  const { report } = await f.scrub([a, b, c]);
  assert.deepEqual(outcomes(report), ['ELOOP', 'backup_file_size_or_type', null]);
  assert.equal(report.distinct_authenticated_files, 1);
});

test('replacement during an open scan cannot supply successful identity evidence', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a); let changed = false;
  const { report } = await f.scrub([a, b], { async onProgress(e) {
    if ('bytes_read' in e && !changed) { changed = true; await unlink(a.input); await writeFile(a.input, DATA); }
  } });
  assert.deepEqual(outcomes(report), ['backup_file_changed', null]);
  assert.equal(report.replica_attempts[0].file_identity, null);
});

test('caller mutation after invocation cannot change snapshotted candidates or policy', async t => {
  const f = await fixture(t), a = await f.signed('a'), rows = [{ ...a }], policy = { ...POLICY };
  const pending = f.scrub(rows, {}, policy); rows[0].input = '/missing'; rows.length = 0; policy.repository_id = '9'.repeat(32);
  assert.equal((await pending).report.replica_attempts[0].input, a.input);
});

test('cancellation between replicas preserves partial evidence and never reports complete', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a), c = new AbortController();
  await assert.rejects(f.scrub([a, b], { signal: c.signal, onProgress(e) { if (e.phase === 'replica_scrubbed') c.abort(); } }), e => {
    assert.equal(e.code, 'backup_cancelled'); assert.equal(e.scrub_complete, false);
    assert.equal(e.replica_attempts.length, 1); return true;
  });
});

test('deadline during payload work does not reset for the next replica', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await assert.rejects(f.scrub([a, b], { timeoutMs: 100, async onProgress(e) { if ('bytes_read' in e) await delay(120); } }), e => {
    assert.equal(e.code, 'backup_deadline'); assert.equal(e.scrub_complete, false);
    assert.equal(e.replica_attempts.length, 0); assert.equal(e.replica_bytes_read, '65536'); return true;
  });
});

for (const phase of ['payload', 'replica_scrubbed', 'replica_unavailable']) test(`observer ENOENT in ${phase} is fatal, not a replica failure`, async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  if (phase === 'replica_unavailable') await unlink(a.input);
  const failure = Object.assign(new Error('observer failure'), { code: 'ENOENT' });
  await assert.rejects(f.scrub([a, b], { onProgress(e) {
    if (phase === 'payload' ? 'bytes_read' in e : e.phase === phase) throw failure;
  } }), e => { assert.equal(e, failure); assert.equal(e.scrub_complete, false); return true; });
});

test('reports and nested attempt/identity evidence are immutable', async t => {
  const f = await fixture(t), a = await f.signed('a'); const { report } = await f.scrub([a]);
  for (const x of [report, report.candidates, report.replica_attempts, report.replica_attempts[0],
    report.replica_attempts[0].file_identity, report.authentication, report.streaming]) assert.equal(Object.isFrozen(x), true);
});

test('invalid arguments and pre-cancellation refuse before any file I/O', async t => {
  const f = await fixture(t), a = await f.signed('a'), c = new AbortController(); c.abort();
  await assert.rejects(f.scrub([a], { signal: c.signal }), code('backup_cancelled'));
  for (const v of [0, -1, 1.5, 2 ** 47, NaN]) await assert.rejects(f.scrub([a], { maximumReplicaBytes: v }), code('backup_invalid_options'));
  await assert.rejects(f.scrub([a, a]), code('backup_duplicate_candidate'));
  await assert.rejects(f.scrub([a], { unexpected: true }), code('backup_invalid_options'));
});
