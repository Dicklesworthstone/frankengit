// Actual CLI processes, persisted witness, signatures and files; no native fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, readdir, lstat, unlink, rm, symlink, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { selectRepositoryBackup } from '../lib/repository-backup-selection.mjs';
import { initializeRepositoryBackupWitness, withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { runReplenishmentCommand, replenishmentArguments } from '../replenish_repository_backups.mjs';

const CLI = fileURLToPath(new URL('../replenish_repository_backups.mjs', import.meta.url));
const sha = data => createHash('sha256').update(data).digest('hex');
const instant = ms => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');
async function fixture(t, format = 'sha256', bytes = Buffer.alloc(65559, 97)) {
  const root = await mkdtemp(join(tmpdir(), 'fg-replenish-cli-')); t.after(() => rm(root, { recursive: true, force: true }));
  const id = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: format };
  const policy = { ...id, minimum_head_generation: '1' }, trust = join(root, 'trust.pem'), witness = join(root, 'witness');
  const pair = generateKeyPairSync('ed25519'), pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  await writeFile(trust, pair.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  const signed = async (name, generation = '5', data = bytes) => {
    const input = join(root, name + '.backup'), approval = join(root, name + '.approval');
    await writeFile(input, data, { mode: 0o600 });
    const result = await signRepositoryBackupFile(input, Buffer.from(pem), { ...id, head_generation: generation,
      issued_at: instant(Date.now() - 60000), expires_at: instant(Date.now() + 3600000) });
    await writeFile(approval, result.envelope, { mode: 0o600 }); return { input, approval };
  };
  const row = await signed('source'), dirs = [join(root, 'a-copy'), join(root, 'b-copy')];
  for (const d of dirs) await mkdir(d, { mode: 0o700 });
  const policyArgs = ['--trust-key', trust, '--tenant-id', id.tenant_id, '--repository-id', id.repository_id,
    '--incarnation-id', id.incarnation_id, '--object-format', format, '--minimum-head-generation', '1',
    '--max-archive-bytes', String(bytes.length), '--max-total-read-bytes', String(9 * bytes.length)];
  const args = [...policyArgs, '--candidate', row.input, row.approval, ...dirs.flatMap(d => ['--replica-directory', d])];
  const envelope = await readFile(row.approval), checkpoint = { approval_sha256: sha(envelope), trusted_key_id: JSON.parse(envelope).signatures[0].keyid };
  const init = () => initializeRepositoryBackupWitness(witness, trust, policy);
  return { root, id, policy, trust, witness, row, dirs, bytes, args, policyArgs, signed, init, checkpoint };
}
async function command(args, onLine = null) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', buffered = '', callbackError;
  const timeout = setTimeout(() => child.kill('SIGKILL'), 15000);
  const closed = new Promise((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  });
  child.stdout.on('data', data => { stdout += data; if (stdout.length > 2 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', data => {
    stderr += data; buffered += data;
    if (stderr.length > 2 * 1024 * 1024) child.kill('SIGKILL');
    while (buffered.includes('\n')) {
      const at = buffered.indexOf('\n'), line = buffered.slice(0, at); buffered = buffered.slice(at + 1);
      try { if (onLine) onLine(JSON.parse(line), child); }
      catch (error) { callbackError = error; child.kill('SIGKILL'); }
    }
  });
  try {
    const outcome = await closed;
    if (callbackError) throw callbackError;
    return { ...outcome, stdout, stderr,
      result: stdout.trim() && outcome.code === 0 ? JSON.parse(stdout) : null,
      error: outcome.code === 1 && stderr.trim() ? JSON.parse(stderr.trim().split('\n').at(-1)) : null };
  } finally { clearTimeout(timeout); if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await closed; } }
}
async function empty(f) { for (const d of f.dirs) assert.deepEqual(await readdir(d), []); }
const output = { write(text, done) { done(); } };

for (const format of ['sha1', 'sha256']) test(`${format}: real command publishes selectable copies and exact restart reuses them`, async t => {
  const f = await fixture(t, format), first = await command(f.args);
  assert.equal(first.code, 0, first.stderr); assert.equal(first.stderr, '');
  assert.equal(first.result.final_scrub.distinct_authenticated_files, 2);
  const paths = first.result.completed_replicas.map(r => r.receipt.candidate);
  const inode = (await lstat(paths[0].input)).ino;
  const again = await command([...f.args, '--checkpoint', first.result.checkpoint.approval_sha256, first.result.checkpoint.trusted_key_id]);
  assert.equal(again.code, 0, again.stderr); assert.equal((await lstat(paths[0].input)).ino, inode);
  assert(again.result.completed_replicas.every(r => r.receipt.disposition.archive === 'reused'));
  await unlink(f.row.input); await unlink(f.row.approval);
  const selected = await selectRepositoryBackup(paths, f.trust, f.policy, { maximumBytes: f.bytes.length * 2 });
  assert.deepEqual(selected.report.checkpoint, first.result.checkpoint);
});

test('CLI witnesses survive restart and prevent omission of an unavailable newer checkpoint', async t => {
  const f = await fixture(t); await f.init(); const high = await f.signed('high', '18446744073709551615'); await unlink(high.input);
  const failed = await command([...f.args, '--candidate', high.input, high.approval, '--witness', f.witness]);
  assert.equal(failed.code, 1); assert.equal(failed.error.code, 'ENOENT');
  const older = await command([...f.args, '--witness', f.witness]);
  assert.equal(older.code, 1); assert.equal(older.error.code, 'backup_below_witness'); await empty(f);
  await assert.rejects(lstat(join(f.witness, '.witness-lock')), { code: 'ENOENT' });
});

test('witnessed successful copying holds and releases the real exclusive lease', async t => {
  const f = await fixture(t); await f.init(); let seen = 0;
  const result = await command([...f.args, '--witness', f.witness, '--progress-json'], row => { if (row.phase === 'replica_complete') seen++; });
  assert.equal(result.code, 0, result.stderr); assert.equal(seen, 2);
  assert.equal(result.result.recovery_witness.highest_observed_generation, '5');
  assert.equal(result.result.highest_retained_generation_enforced, true);
  await assert.rejects(lstat(join(f.witness, '.witness-lock')), { code: 'ENOENT' });
});

test('persisted equal-generation conflicts remain blocking on later commands', async t => {
  const f = await fixture(t); await f.init(); const fork = await f.signed('fork', '5', Buffer.alloc(f.bytes.length, 98));
  const a = await command([...f.args, '--candidate', fork.input, fork.approval, '--witness', f.witness]);
  assert.equal(a.error.code, 'backup_checkpoint_ambiguous');
  const b = await command([...f.args, '--witness', f.witness]);
  assert.equal(b.error.code, 'backup_witness_checkpoint_ambiguous'); await empty(f);
});

test('a real killed CLI preserves a completed copy for exact restart', async t => {
  const f = await fixture(t, 'sha256', Buffer.alloc(8 * 1024 * 1024, 97)); let first, checkpoint;
  const killed = await command([...f.args, '--progress-json'], (row, child) => {
    if (row.phase === 'checkpoint_pinned') checkpoint = row.checkpoint;
    if (row.phase === 'replica_complete' && !first) { first = row.candidate; child.kill('SIGKILL'); }
  });
  assert.equal(killed.signal, 'SIGKILL'); assert(first); assert.deepEqual(checkpoint, f.checkpoint);
  const inode = (await lstat(first.input)).ino;
  const resumed = await command([...f.args, '--checkpoint', checkpoint.approval_sha256, checkpoint.trusted_key_id]);
  assert.equal(resumed.code, 0, resumed.stderr); assert.equal((await lstat(first.input)).ino, inode);
  assert.equal(resumed.result.final_scrub.distinct_authenticated_files, 2);
});

test('a killed witnessed CLI leaves a blocking lease, without reset or lock stealing', async t => {
  const f = await fixture(t, 'sha256', Buffer.alloc(8 * 1024 * 1024, 97)); await f.init(); let first;
  const killed = await command([...f.args, '--witness', f.witness, '--progress-json'], (row, child) => {
    if (row.phase === 'replica_complete' && !first) { first = row.candidate; child.kill('SIGKILL'); }
  });
  assert.equal(killed.signal, 'SIGKILL'); assert(first);
  const lock = await readFile(join(f.witness, '.witness-lock'));
  const again = await command([...f.args, '--witness', f.witness]);
  assert.equal(again.error.code, 'backup_witness_locked');
  assert.deepEqual(await readFile(join(f.witness, '.witness-lock')), lock);
  assert.deepEqual(await readFile(first.input), f.bytes);
});

test('conflicting destination failure carries previous completed copies over the CLI error protocol', async t => {
  const f = await fixture(t);
  await writeFile(join(f.dirs[1], `archive-sha256-${sha(f.bytes)}.fgbackup`), Buffer.alloc(f.bytes.length, 98), { mode: 0o600 });
  const result = await command(f.args);
  assert.equal(result.code, 1); assert.equal(result.error.code, 'backup_replica_digest_mismatch');
  assert.equal(result.error.replenishment.completed_replicas.length, 1);
  assert.deepEqual(result.error.replenishment.checkpoint, f.checkpoint);
  assert.equal(result.error.replenishment.all_destinations_verified, false);
});

test('too-small whole-job budget refuses before publication through the real CLI', async t => {
  const f = await fixture(t), args = [...f.args]; args[args.indexOf('--max-total-read-bytes') + 1] = String(9 * f.bytes.length - 1);
  const result = await command(args); assert.equal(result.error.code, 'backup_replenishment_read_budget'); await empty(f);
});

test('the progress stream is bounded to checkpoint and completed-destination milestones', async t => {
  const f = await fixture(t), result = await command([...f.args, '--progress-json']);
  assert.equal(result.code, 0); const lines = result.stderr.trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 3); assert.deepEqual(lines.map(r => r.phase), ['checkpoint_pinned', 'replica_complete', 'replica_complete']);
});

test('failed stdout delivery preserves the completed group receipt and releases witness', async t => {
  const f = await fixture(t); await f.init();
  await assert.rejects(runReplenishmentCommand([...f.args, '--witness', f.witness], { write(text, done) {
    done(Object.assign(new Error('closed pipe'), { code: 'EPIPE' }));
  } }), error => { assert.equal(error.code, 'EPIPE'); assert.equal(error.completed_result.state, 'complete');
    assert.equal(error.completed_result.completed_replicas.length, 2); return true; });
  await assert.rejects(lstat(join(f.witness, '.witness-lock')), { code: 'ENOENT' });
});

test('failed progress delivery refuses before target publication but preserves observed checkpoint', async t => {
  const f = await fixture(t); await f.init();
  await assert.rejects(runReplenishmentCommand([...f.args, '--witness', f.witness, '--progress-json'], output, undefined,
    { write(text, done) { done(Object.assign(new Error('closed progress'), { code: 'EPIPE' })); } }), { code: 'EPIPE' });
  await empty(f);
  const state = await withRepositoryBackupWitness(f.witness, f.trust, f.policy, {}, w => w.snapshot());
  assert.equal(state.highest_observed_generation, '5');
});

test('missing or corrupt witness state is never initialized by replenishment', async t => {
  const f = await fixture(t); const absent = await command([...f.args, '--witness', f.witness]); assert.equal(absent.error.code, 'ENOENT');
  await f.init(); await writeFile(join(f.witness, 'witness.json'), '{bad json');
  const bad = await command([...f.args, '--witness', f.witness]); assert.equal(bad.error.code, 'backup_witness_invalid_state'); await empty(f);
});

test('an aliased destination cannot become part of the independently retained witness', async t => {
  const f = await fixture(t); await f.init(); const inside = join(f.witness, 'copy'), alias = join(f.root, 'alias');
  await mkdir(inside, { mode: 0o700 }); await symlink(f.witness, alias);
  const args = [...f.args]; args[args.lastIndexOf('--replica-directory') + 1] = join(alias, 'copy');
  const result = await command([...args, '--witness', f.witness]);
  assert.equal(result.error.code, 'backup_witness_separate_path_required'); assert.deepEqual(await readdir(inside), []); await empty(f);
});

test('an aliased selected source cannot live inside the retained witness', async t => {
  const f = await fixture(t); await f.init(); const alias = join(f.root, 'alias'); await symlink(f.witness, alias);
  await copyFile(f.row.input, join(f.witness, 'source.backup')); await copyFile(f.row.approval, join(f.witness, 'source.approval'));
  const args = [...f.args], i = args.indexOf('--candidate'); args[i + 1] = join(alias, 'source.backup'); args[i + 2] = join(alias, 'source.approval');
  const result = await command([...args, '--witness', f.witness]); assert.equal(result.error.code, 'backup_witness_separate_path_required'); await empty(f);
});

test('an aliased trust key cannot be learned from the retained witness directory', async t => {
  const f = await fixture(t); await f.init(); const alias = join(f.root, 'alias'); await symlink(f.witness, alias);
  await copyFile(f.trust, join(f.witness, 'trust.pem')); const args = [...f.args]; args[args.indexOf('--trust-key') + 1] = join(alias, 'trust.pem');
  const result = await command([...args, '--witness', f.witness]); assert.equal(result.error.code, 'backup_witness_separate_path_required'); await empty(f);
});

test('parser refuses malformed pins, duplicate singleton flags and native mutation options', async t => {
  const f = await fixture(t);
  for (const extra of [['--fg', '/bin/false'], ['--trust-key', f.trust], ['--checkpoint', '0'.repeat(64)], ['--progress-json', '--progress-json'], ['--max-archive-bytes', '-1']]) {
    assert.throws(() => replenishmentArguments([...f.args, ...extra]));
  }
  for (const args of [null, Array(351).fill('x'), ['x'.repeat(8193)]]) assert.throws(() => replenishmentArguments(args));
  await empty(f);
});

test('a pre-cancelled command makes no target or witness change', async t => {
  const f = await fixture(t); await f.init(); const before = await readFile(join(f.witness, 'witness.json')), c = new AbortController(); c.abort();
  await assert.rejects(runReplenishmentCommand([...f.args, '--witness', f.witness], output, c.signal), { code: 'backup_cancelled' });
  assert.deepEqual(await readFile(join(f.witness, 'witness.json')), before); await empty(f);
});

test('SIGTERM drains a real witnessed CLI and leaves completed copies resumable', async t => {
  const f = await fixture(t, 'sha256', Buffer.alloc(8 * 1024 * 1024, 97)); await f.init(); let first;
  const cancelled = await command([...f.args, '--witness', f.witness, '--progress-json'], (row, child) => {
    if (row.phase === 'replica_complete' && !first) { first = row.candidate; child.kill('SIGTERM'); }
  });
  assert.equal(cancelled.code, 1, cancelled.stderr); assert.equal(cancelled.signal, null);
  assert.equal(cancelled.error.code, 'backup_cancelled');
  assert(cancelled.error.replenishment.completed_replicas.length >= 1);
  await assert.rejects(lstat(join(f.witness, '.witness-lock')), { code: 'ENOENT' });
  const inode = (await lstat(first.input)).ino;
  const result = await command([...f.args, '--witness', f.witness, '--checkpoint', f.checkpoint.approval_sha256, f.checkpoint.trusted_key_id]);
  assert.equal(result.code, 0, result.stderr); assert.equal((await lstat(first.input)).ino, inode);
});
