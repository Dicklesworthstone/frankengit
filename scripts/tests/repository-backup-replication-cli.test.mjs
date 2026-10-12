// Actual Node CLI subprocesses and process-kill/restart at real I/O boundaries.
// SIGKILL is process-crash evidence only, not hardware/power-loss simulation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, readdir, lstat, rm, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { replicateRepositoryBackup } from '../lib/repository-backup-replication.mjs';
import { replicationArguments, runReplicationCommand } from '../replicate_repository_backup_native.mjs';

const CLI = fileURLToPath(new URL('../replicate_repository_backup_native.mjs', import.meta.url));
const SELECT = fileURLToPath(new URL('../select_repository_backup_native.mjs', import.meta.url));
const MODULE = new URL('../lib/repository-backup-replication.mjs', import.meta.url).href;
const exec = promisify(execFile), DATA = Buffer.alloc(196633, 0x70);
const ID = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: 'sha256' };
const POLICY = { ...ID, minimum_head_generation: '1' };
const instant = n => new Date(Math.floor(n / 1000) * 1000).toISOString().replace('.000Z', 'Z');
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-replica-cli-')); t.after(() => rm(root, { recursive: true, force: true }));
  const destination = join(root, 'copies'); await mkdir(destination, { mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync('ed25519'), trustKey = join(root, 'trust.pem');
  await writeFile(trustKey, publicKey.export({ format: 'pem', type: 'spki' }), { mode: 0o600 });
  const row = { input: join(root, 'original.backup'), approval: join(root, 'original.dsse') };
  await writeFile(row.input, DATA, { mode: 0o600 });
  const signed = await signRepositoryBackupFile(row.input, Buffer.from(privateKey.export({ format: 'pem', type: 'pkcs8' })), {
    ...ID, head_generation: '18446744073709551614', issued_at: instant(Date.now() - 60000), expires_at: instant(Date.now() + 86400000),
  });
  await writeFile(row.approval, signed.envelope, { mode: 0o600 });
  const policyArgs = ['--trust-key', trustKey, '--tenant-id', ID.tenant_id, '--repository-id', ID.repository_id,
    '--incarnation-id', ID.incarnation_id, '--object-format', ID.object_format, '--minimum-head-generation', '1'];
  const args = ['--candidate', row.input, row.approval, ...policyArgs, '--replica-directory', destination,
    '--max-archive-bytes', String(DATA.length), '--max-total-read-bytes', String(DATA.length * 4)];
  const options = { candidates: [row], trustKey, policy: POLICY, destination, maximumBytes: DATA.length };
  return { root, row, destination, args, options, policyArgs, signed };
}
async function cli(args, executable = CLI) {
  try { const { stdout, stderr } = await exec(process.execPath, [executable, ...args], { timeout: 10000, maxBuffer: 1024 * 1024 }); return { code: 0, stdout, stderr }; }
  catch (error) { return { code: error.code, stdout: error.stdout, stderr: error.stderr }; }
}
async function killedAt(t, f, phase) {
  // The test observer stops exactly at a named production boundary so the
  // parent can kill/reap the process rather than throwing a simulated error.
  const code = `import { replicateRepositoryBackup } from ${JSON.stringify(MODULE)};
    const opts = JSON.parse(process.argv[1]);
    await replicateRepositoryBackup({ ...opts, onProgress: async event => {
      if (event.phase === ${JSON.stringify(phase)}) {
        process.send({ phase: event.phase }); await new Promise(() => {});
      }
    }});`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code, JSON.stringify(f.options)],
    { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  let diagnostics = ''; child.stderr.on('data', chunk => { diagnostics += chunk; });
  const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await closed; });
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('crash boundary timeout: ' + diagnostics)); }, 5000);
    child.once('error', error => { clearTimeout(timeout); reject(error); });
    child.once('exit', () => { clearTimeout(timeout); reject(new Error('child exited before crash boundary: ' + diagnostics)); });
    child.once('message', message => { clearTimeout(timeout); assert.equal(message.phase, phase); resolve(); });
  });
  assert(child.kill('SIGKILL'));
  const status = await closed; assert.equal(status.signal, 'SIGKILL');
}

test('CLI publishes a candidate that the actual selector consumes after source removal', async t => {
  const f = await fixture(t), run = await cli(f.args);
  assert.equal(run.code, 0, run.stderr); assert.equal(run.stderr, '');
  const result = JSON.parse(run.stdout); assert.equal(result.state, 'complete');
  await unlink(f.row.input); await unlink(f.row.approval);
  const selection = await cli(['select', '--candidate', result.candidate.input, result.candidate.approval, ...f.policyArgs], SELECT);
  assert.equal(selection.code, 0, selection.stderr);
  const report = JSON.parse(selection.stdout);
  assert.equal(report.selected.head_generation, '18446744073709551614');
  assert.equal(report.native_content_verified, false); assert.equal(report.selected_artifact_authenticated, true);
  assert.deepEqual(await readFile(result.candidate.input), DATA);
  assert.deepEqual(await readFile(result.candidate.approval), f.signed.envelope);
});

test('a second independent CLI process resumes the identical signed copy', async t => {
  const f = await fixture(t), first = await cli(f.args); assert.equal(first.code, 0, first.stderr);
  const initial = JSON.parse(first.stdout), inode = (await lstat(initial.candidate.input, { bigint: true })).ino;
  const second = await cli(f.args); assert.equal(second.code, 0, second.stderr);
  const resumed = JSON.parse(second.stdout);
  assert.deepEqual(resumed.disposition, { archive: 'reused', approval: 'reused' });
  assert.equal((await lstat(resumed.candidate.input, { bigint: true })).ino, inode);
});

test('SIGKILL after archive durability resumes through the real CLI without rewriting the body', async t => {
  const f = await fixture(t); await killedAt(t, f, 'archive_durable');
  const names = await readdir(f.destination);
  assert.equal(names.filter(n => n.endsWith('.approval.json')).length, 0);
  const body = names.find(n => n.endsWith('.fgbackup')); assert(body);
  const before = await lstat(join(f.destination, body), { bigint: true });
  const resumed = await cli(f.args); assert.equal(resumed.code, 0, resumed.stderr);
  const result = JSON.parse(resumed.stdout);
  assert.deepEqual(result.disposition, { archive: 'reused', approval: 'created' });
  assert.equal((await lstat(result.candidate.input, { bigint: true })).ino, before.ino);
});

test('SIGKILL during streaming exposes no approval and a later CLI preserves the orphan', async t => {
  const f = await fixture(t); await killedAt(t, f, 'copy_archive');
  const names = await readdir(f.destination); assert.equal(names.length, 1);
  const orphan = names[0]; assert.match(orphan, /^\.fg-backup-replica-/);
  const before = await lstat(join(f.destination, orphan), { bigint: true });
  const resumed = await cli(f.args); assert.equal(resumed.code, 0, resumed.stderr);
  const result = JSON.parse(resumed.stdout); assert.equal(result.state, 'complete');
  assert.equal((await lstat(join(f.destination, orphan), { bigint: true })).ino, before.ino);
  assert.deepEqual(await readFile(result.candidate.input), DATA);
});

test('CLI refuses insufficient total work budget with no output candidate or staged files', async t => {
  const f = await fixture(t), args = f.args.slice(); args[args.indexOf('--max-total-read-bytes') + 1] = String(DATA.length * 3 - 1);
  const run = await cli(args); assert.equal(run.code, 1); assert.equal(run.stdout, '');
  const error = JSON.parse(run.stderr); assert.equal(error.code, 'backup_replication_read_budget');
  assert.equal(error.publication_state, 'not_started'); assert.deepEqual(await readdir(f.destination), []);
});

test('CLI keeps conflicting output files and reports its refusal', async t => {
  const f = await fixture(t), first = await replicateRepositoryBackup(f.options);
  await writeFile(first.candidate.input, Buffer.alloc(DATA.length, 0x62));
  const run = await cli(f.args); assert.equal(run.code, 1);
  const error = JSON.parse(run.stderr);
  assert.equal(error.code, 'backup_replica_digest_mismatch'); assert.equal(error.publication_state, 'approval_visible');
  assert.deepEqual(error.replica, first.candidate);
  assert.deepEqual(await readFile(first.candidate.input), Buffer.alloc(DATA.length, 0x62));
});

test('CLI help states durability, scope, and independently retained trust requirements', async () => {
  const run = await cli(['--help']); assert.equal(run.code, 0); assert.equal(run.stderr, '');
  assert.match(run.stdout, /Independently retained/); assert.match(run.stdout, /create-only/);
  assert.match(run.stdout, /NOT native validation/); assert.match(run.stdout, /never select an older/);
});

test('native options and signing or unsigned bypass options are not accepted', async t => {
  const f = await fixture(t);
  for (const extra of [['--resume'], ['--fg', '/fake-fg'], ['--unsigned'], ['--private-key', '/fake-key']]) {
    assert.throws(() => replicationArguments([...f.args, ...extra]));
  }
  assert.throws(() => replicationArguments([...f.args, '--replica-directory', f.destination]), { code: 'backup_duplicate_option' });
  assert.deepEqual(await readdir(f.destination), []);
});

test('output failure preserves the completed publication receipt and never implies rollback', async t => {
  const f = await fixture(t), broken = new Error('broken result pipe'); broken.code = 'EPIPE';
  const output = { write(_text, callback) { callback(broken); } };
  await assert.rejects(runReplicationCommand(f.args, output), error => {
    assert.equal(error, broken); assert.equal(error.publication_state, 'complete');
    assert.equal(error.completed_result.state, 'complete'); assert.deepEqual(error.replica, error.completed_result.candidate); return true;
  });
  const resumed = await cli(f.args); assert.equal(resumed.code, 0, resumed.stderr);
  assert.deepEqual(JSON.parse(resumed.stdout).disposition, { archive: 'reused', approval: 'reused' });
});


for (const enoughBudget of [true, false]) {
  test(`CLI full-size corrupt-replica failover ${enoughBudget ? 'fits the exact total budget' : 'refuses one byte below the required budget'}`, async t => {
    const f = await fixture(t);
    const input = join(f.root, 'z-healthy.backup'), approval = join(f.root, 'z-healthy.dsse');
    await writeFile(input, DATA, { mode: 0o600 });
    await writeFile(approval, f.signed.envelope, { mode: 0o600 });
    await writeFile(f.row.input, Buffer.alloc(DATA.length, 0x62));
    const args = [...f.args, '--candidate', input, approval];
    args[args.indexOf('--max-total-read-bytes') + 1] = String(DATA.length * 4 - (enoughBudget ? 0 : 1));
    const run = await cli(args);
    if (enoughBudget) {
      assert.equal(run.code, 0, run.stderr); assert.equal(run.stderr, '');
      const result = JSON.parse(run.stdout);
      assert.equal(result.source.input, input); assert.equal(result.state, 'complete');
      assert.equal(result.streaming.total_payload_bytes_read, String(DATA.length * 4));
      assert.deepEqual(await readFile(result.candidate.input), DATA);
    } else {
      assert.equal(run.code, 1); assert.equal(run.stdout, '');
      const error = JSON.parse(run.stderr);
      assert.equal(error.code, 'backup_replication_read_budget');
      assert.equal(error.publication_state, 'not_started');
      assert.deepEqual(await readdir(f.destination), []);
    }
  });
}
