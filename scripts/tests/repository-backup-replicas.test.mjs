// Real-file/Ed25519 tests of operator replica selection, not native fg recovery.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile, readFile, copyFile, unlink, symlink, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { selectRepositoryBackup } from '../lib/repository-backup-selection.mjs';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';

const NOW = Date.parse('2026-10-11T12:00:00Z');
const ID = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
  incarnation_id: '3'.repeat(32), object_format: 'sha256' };
const POLICY = { ...ID, minimum_head_generation: '1' };
const DATA = Buffer.alloc(131089, 0x61);
const digest = value => createHash('sha256').update(value).digest('hex');

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-backup-replicas-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  const key = join(root, 'trusted.pem');
  await writeFile(key, publicKey.export({ format: 'pem', type: 'spki' }), { mode: 0o600 });
  async function signed(name, generation = '7', bytes = DATA, declarations = {}, signingNow = NOW) {
    const input = join(root, `${name}.archive`), approval = join(root, `${name}.approval`);
    await writeFile(input, bytes, { mode: 0o600 });
    const result = await signRepositoryBackupFile(input, Buffer.from(privatePem), {
      ...ID, head_generation: generation, issued_at: '2026-10-11T11:00:00Z',
      expires_at: '2026-10-12T12:00:00Z', ...declarations,
    }, { now: signingNow });
    await writeFile(approval, result.envelope, { mode: 0o600 });
    return { input, approval };
  }
  async function replica(name, source, pretty = false) {
    const input = join(root, `${name}.archive`), approval = join(root, `${name}.approval`);
    await copyFile(source.input, input);
    const encoded = await readFile(source.approval);
    await writeFile(approval, pretty ? JSON.stringify(JSON.parse(encoded), null, 2) + '\n' : encoded, { mode: 0o600 });
    return { input, approval };
  }
  function select(rows, options = {}, policy = POLICY) {
    return selectRepositoryBackup(rows, key, policy, { now: NOW, maximumBytes: DATA.length * 4, ...options });
  }
  return { root, key, signed, replica, select };
}
const hasCode = code => error => { assert.equal(error.code, code); return true; };
const codes = result => result.report.replica_attempts.map(attempt => attempt.code);

test('missing first replica selects an identical signed checkpoint, not an older backup', async t => {
  const f = await fixture(t), a = await f.signed('a', '9007199254740993');
  const b = await f.replica('b', a), lower = await f.signed('0-lower', '9007199254740992');
  await unlink(a.input); await unlink(lower.input);
  const result = await f.select([b, lower, a]);
  assert.equal(result.report.selected.input, b.input);
  assert.equal(result.report.selected.head_generation, '9007199254740993');
  assert.deepEqual(codes(result), ['ENOENT', null]);
  assert.equal(result.report.identical_statement_candidates, 2);
  assert.equal(result.report.candidates.length, 3);
  assert.equal(result.report.streaming.total_payload_bytes_read, String(DATA.length));
  assert.equal(result.report.native_content_verified, false);
  assert.equal(result.report.newest_checkpoint_verified, false);
  assert.equal(result.report.candidate_set_completeness_verified, false);
});

test('corrupt first replica is rejected by its signed digest before healthy alias selection', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await writeFile(a.input, Buffer.alloc(DATA.length, 0x62));
  const result = await f.select([a, b]);
  assert.equal(result.report.selected.input, b.input);
  assert.deepEqual(codes(result), ['backup_artifact_mismatch', null]);
  assert.equal(result.report.streaming.total_payload_bytes_read, String(DATA.length * 2));
  assert.equal(result.report.streaming.total_payload_read_calls, Math.ceil(DATA.length / 65536) * 2);
});

test('one healthy candidate preserves the existing receipt and explicit non-claims', async t => {
  const f = await fixture(t), a = await f.signed('a'), result = await f.select([a]);
  assert.equal(result.report.schema_version, 1);
  assert.equal(result.report.selected.input, a.input);
  assert.equal(result.report.highest_supplied_generation_selected, true);
  assert.equal(result.report.selected_artifact_authenticated, true);
  assert.equal(result.report.read_only, true);
  assert.equal(result.report.authentication.complete_capsule_verified, false);
  assert.equal(result.report.streaming.maximum_read_bytes, 65536);
  assert.equal(result.report.streaming.read_calls, Math.ceil(DATA.length / 65536));
  result.checkCurrent();
});

test('all newest replicas unavailable refuses rather than reading a healthy lower generation', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  const lower = await f.signed('0-lower', '6');
  await unlink(a.input); await unlink(b.input);
  let payloadReads = 0;
  await assert.rejects(f.select([lower, a, b], { onProgress(event) { if ('bytes_read' in event) payloadReads++; } }), error => {
    assert.equal(error.code, 'ENOENT');
    assert.deepEqual(error.replica_attempts.map(attempt => attempt.input), [a.input, b.input]);
    assert.equal(error.selected_head_generation, '7');
    return true;
  });
  assert.equal(payloadReads, 0);
});

test('conflicting highest signed statements refuse before opening any artifact', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.signed('b', '7', Buffer.from('different archive'));
  await unlink(a.input); await unlink(b.input);
  await assert.rejects(f.select([a, b]), hasCode('backup_checkpoint_ambiguous'));
});

test('same bytes and generation but different approval lifetime are not replicas', async t => {
  const f = await fixture(t), a = await f.signed('a');
  const b = await f.signed('b', '7', DATA, { expires_at: '2026-10-13T12:00:00Z' });
  await assert.rejects(f.select([a, b]), hasCode('backup_checkpoint_ambiguous'));
});

test('expired highest checkpoint blocks both its replicas and a valid older backup', async t => {
  const f = await fixture(t), a = await f.signed('a', '8', DATA, { expires_at: '2026-10-11T13:00:00Z' });
  const b = await f.replica('b', a), old = await f.signed('old', '7');
  await unlink(a.input);
  await assert.rejects(f.select([old, a, b], { now: Date.parse('2026-10-11T14:00:00Z') }), hasCode('backup_approval_expired'));
});

test('minimum-generation floor is not relaxed by replica availability', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await unlink(a.input);
  await assert.rejects(f.select([a, b], {}, { ...POLICY, minimum_head_generation: '8' }), hasCode('backup_approval_below_floor'));
});

test('missing approval is fatal even when another copy has a healthy archive', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await unlink(a.approval);
  let payloadReads = 0;
  await assert.rejects(f.select([a, b], { onProgress(e) { if ('bytes_read' in e) payloadReads++; } }), hasCode('ENOENT'));
  assert.equal(payloadReads, 0);
});

test('a tampered signature cannot be skipped as an unavailable replica', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  const envelope = JSON.parse(await readFile(a.approval));
  envelope.signatures[0].sig = Buffer.alloc(64).toString('base64');
  await writeFile(a.approval, JSON.stringify(envelope));
  await assert.rejects(f.select([a, b]), hasCode('backup_invalid_signature'));
});

test('aggregate replica read budget refuses before starting a second full archive', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await writeFile(a.input, Buffer.alloc(DATA.length, 0x62));
  let reads = 0;
  await assert.rejects(f.select([a, b], { maximumBytes: DATA.length, onProgress(e) { if ('bytes_read' in e) reads++; } }), error => {
    assert.equal(error.code, 'backup_replica_read_budget');
    assert.equal(error.replica_bytes_read, String(DATA.length));
    assert.equal(error.replica_attempts.length, 1);
    return true;
  });
  assert.equal(reads, Math.ceil(DATA.length / 65536));
});

test('exact aggregate budget permits one corrupt and one healthy full read', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await writeFile(a.input, Buffer.alloc(DATA.length, 0x62));
  const result = await f.select([a, b], { maximumBytes: DATA.length * 2 });
  assert.equal(result.report.selected.input, b.input);
  assert.equal(result.report.streaming.total_payload_bytes_read, String(DATA.length * 2));
});

test('an oversized replaced replica is refused before reading beyond its signed size', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await writeFile(a.input, Buffer.alloc(DATA.length * 2));
  const result = await f.select([a, b], { maximumBytes: DATA.length });
  assert.deepEqual(codes(result), ['backup_file_size_or_type', null]);
  assert.equal(result.report.replica_attempts[0].bytes_read, '0');
  assert.equal(result.report.streaming.total_payload_bytes_read, String(DATA.length));
});

test('a missing replica consumes no payload budget needed by the healthy replica', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await unlink(a.input);
  const result = await f.select([a, b], { maximumBytes: DATA.length });
  assert.equal(result.report.selected.input, b.input);
});

test('symlink and directory replicas are never followed or treated as authenticated data', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a), c = await f.replica('c', a);
  await unlink(a.input); await symlink(c.input, a.input);
  await unlink(b.input); await mkdir(b.input);
  const result = await f.select([a, b, c]);
  assert.deepEqual(codes(result), ['ELOOP', 'backup_file_size_or_type', null]);
  assert.equal(result.report.selected.input, c.input);
});

test('a changed open replica cannot supply a successful receipt', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  let changed = false;
  const result = await f.select([a, b], { async onProgress(event) {
    if ('bytes_read' in event && !changed) { changed = true; await unlink(a.input); }
  } });
  assert.equal(result.report.selected.input, b.input);
  assert.deepEqual(codes(result), ['ENOENT', null]);
});

test('cancellation between replicas stops before reading another copy', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a), abort = new AbortController();
  await unlink(a.input);
  let reads = 0;
  await assert.rejects(f.select([a, b], { signal: abort.signal, onProgress(e) {
    if (e.phase === 'replica_unavailable') abort.abort();
    if ('bytes_read' in e) reads++;
  } }), hasCode('backup_cancelled'));
  assert.equal(reads, 0);
});

test('expiry between replicas is not interpreted as path unavailability', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await unlink(a.input); let clock = NOW;
  t.mock.method(Date, 'now', () => clock);
  await assert.rejects(f.select([a, b], { now: undefined, onProgress(e) {
    if (e.phase === 'replica_unavailable') clock = Date.parse('2026-10-13T12:00:00Z');
  } }), hasCode('backup_approval_expired'));
});

test('deadline expiry between replicas is fatal, with no native or fallback work', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  await unlink(a.input);
  let waitedBetweenReplicas = false;
  await assert.rejects(f.select([a, b], { timeoutMs: 1000, async onProgress(e) {
    if (e.phase === 'replica_unavailable') { waitedBetweenReplicas = true; await delay(1100); }
  } }), hasCode('backup_deadline'));
  assert.equal(waitedBetweenReplicas, true);
});

test('observer errors with filesystem-like codes propagate unchanged and do not trigger failover', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  const sentinel = Object.assign(new Error('observer failure'), { code: 'ENOENT' });
  let callbacks = 0;
  await assert.rejects(f.select([a, b], { onProgress(e) {
    if ('bytes_read' in e) { callbacks++; throw sentinel; }
  } }), error => error === sentinel);
  assert.equal(callbacks, 1);
});

test('unknown operational errors remain fatal rather than broad catch-and-retry', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  a.input = join(f.root, 'a'.repeat(300));
  await assert.rejects(f.select([a, b]), hasCode('ENAMETOOLONG'));
});

test('the chosen replica carries its own exact approval-byte pin', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a, true);
  await unlink(a.input);
  const result = await f.select([a, b]);
  assert.equal(result.report.selected.approval, b.approval);
  assert.equal(result.report.checkpoint.approval_sha256, digest(await readFile(b.approval)));
  assert.notEqual(result.report.checkpoint.approval_sha256, digest(await readFile(a.approval)));
});

test('permuting candidate inputs preserves selection order and candidate-set identity', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a), c = await f.replica('c', a);
  await unlink(a.input);
  const first = await f.select([c, a, b]), second = await f.select([b, c, a]);
  assert.deepEqual(first.report, second.report);
  assert.equal(first.report.selected.input, b.input);
  assert.equal(first.report.replica_attempts.length, 2);
});

test('replica receipts are frozen and later cancellation invalidates checkCurrent', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a), abort = new AbortController();
  await unlink(a.input);
  const result = await f.select([a, b], { signal: abort.signal });
  assert.equal(Object.isFrozen(result.report.replica_attempts), true);
  assert.equal(Object.isFrozen(result.report.replica_attempts[0]), true);
  assert.equal(Object.isFrozen(result.report.streaming), true);
  assert.throws(() => { result.report.replica_attempts[0].input = b.input; }, TypeError);
  abort.abort(); assert.throws(() => result.checkCurrent(), hasCode('backup_cancelled'));
});

// These drive the checked-in CLI with its real import closure, signature checks,
// parser, selection orchestration, stdout/stderr, and exit status. No fg binary,
// fake native verifier, repository authority, or external Git engine is involved.
const execFileAsync = promisify(execFile);
const CLI = fileURLToPath(new URL('../select_repository_backup_native.mjs', import.meta.url));
async function cli(args) {
  try {
    const result = await execFileAsync(process.execPath, [CLI, ...args], { timeout: 5000, maxBuffer: 1024 * 1024 });
    return { code: 0, ...result };
  } catch (error) {
    if (typeof error.code !== 'number') throw error;
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}
function cliArgs(f, candidates, maximumBytes = DATA.length * 4) {
  return ['select', ...candidates.flatMap(row => ['--candidate', row.input, row.approval]),
    '--trust-key', f.key, '--tenant-id', ID.tenant_id, '--repository-id', ID.repository_id,
    '--incarnation-id', ID.incarnation_id, '--object-format', ID.object_format,
    '--minimum-head-generation', '1', '--max-archive-bytes', String(maximumBytes)];
}
async function currentSigned(f, name, generation = '7') {
  const now = Date.now();
  return f.signed(name, generation, DATA, {
    issued_at: new Date(Math.floor(now / 1000) * 1000).toISOString().replace('.000Z', 'Z'),
    expires_at: null,
  }, now);
}

test('CLI select succeeds through a missing-replica failover and returns the selected approval pin', async t => {
  const f = await fixture(t), a = await currentSigned(f, 'a'), b = await f.replica('b', a, true);
  await unlink(a.input);
  const result = await cli(cliArgs(f, [a, b]));
  assert.equal(result.code, 0, result.stderr); assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  assert.equal(report.type, 'repository_backup_selection');
  assert.equal(report.selected.input, b.input);
  assert.equal(report.checkpoint.approval_sha256, digest(await readFile(b.approval)));
  assert.equal(report.native_content_verified, false);
});

test('CLI reports every failed highest-checkpoint replica without falling back to an older one', async t => {
  const f = await fixture(t), a = await currentSigned(f, 'a'), b = await f.replica('b', a);
  const lower = await currentSigned(f, '0-lower', '6');
  await unlink(a.input); await unlink(b.input);
  const result = await cli(cliArgs(f, [a, lower, b]));
  assert.equal(result.code, 1); assert.equal(result.stdout, '');
  const report = JSON.parse(result.stderr);
  assert.equal(report.code, 'ENOENT'); assert.equal(report.state, 'not_started');
  assert.equal(report.selected_head_generation, '7');
  assert.equal(report.replica_bytes_read, '0');
  assert.deepEqual(report.replica_attempts.map(row => row.input), [a.input, b.input]);
});

test('CLI retains consumed-byte and replica evidence when the shared read budget is exhausted', async t => {
  const f = await fixture(t), a = await currentSigned(f, 'a'), b = await f.replica('b', a);
  await writeFile(a.input, Buffer.alloc(DATA.length, 0x62));
  const result = await cli(cliArgs(f, [a, b], DATA.length));
  assert.equal(result.code, 1); assert.equal(result.stdout, '');
  const report = JSON.parse(result.stderr);
  assert.equal(report.code, 'backup_replica_read_budget');
  assert.equal(report.replica_bytes_read, String(DATA.length));
  assert.equal(report.replica_attempts.length, 1);
  assert.equal(report.replica_attempts[0].code, 'backup_artifact_mismatch');
});

test('CLI help states shared replica budget and retains the no-older-checkpoint boundary', async () => {
  const result = await cli(['--help']);
  assert.equal(result.code, 0); assert.equal(result.stderr, '');
  assert.match(result.stdout, /shared across replica attempts/);
  assert.match(result.stdout, /EXACT SAME signed statement/);
  assert.match(result.stdout, /never falls back to an older archive/);
});
