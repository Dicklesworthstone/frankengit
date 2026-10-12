// Real TLS, signed approvals, persistent witness files and actual CLI processes.
// Payloads are opaque operator bytes, not native fg archive/authority evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile, readdir, lstat, symlink, unlink, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { downloadRepositoryBackupWithWitness as download } from '../lib/repository-backup-download-witness.mjs';
import { initializeRepositoryBackupWitness as initialize, withRepositoryBackupWitness as withWitness } from '../lib/repository-backup-witness.mjs';
import { runDownloadCommand } from '../download_repository_backup.mjs';
import { tlsFixture, DATA, NOW } from './backup-download-fixture.mjs';

const code = expected => error => { assert.equal(error.code, expected); return true; };
async function fixture(t) {
  const f = await tlsFixture(t), witness = join(f.root, 'retained');
  await initialize(witness, f.trustKey, f.options.policy, { now: NOW });
  return { ...f, witness, options: { ...f.options, witness }, original: await readFile(f.approval) };
}
const state = async f => JSON.parse(await readFile(join(f.witness, 'witness.json')));
const observe = (f, bytes) => withWitness(f.witness, f.trustKey, f.options.policy, { now: NOW }, w => w.observe(bytes));
const released = async f => assert(!((await readdir(f.witness)).includes('.witness-lock')));
async function noSockets(f) { for (let n = 0; n < 100 && f.sockets.size; n++) await delay(5); assert.equal(f.sockets.size, 0); }

for (const object_format of ['sha1', 'sha256']) test(`witness lease spans real HTTPS and publication (${object_format})`, async t => {
  const f = await tlsFixture(t), witness = join(f.root, 'retained'), policy = { ...f.options.policy, object_format };
  await f.sign(DATA, { object_format }); await initialize(witness, f.trustKey, policy, { now: NOW });
  const phases = new Set();
  const result = await download({ ...f.options, witness, policy, async onProgress(event) {
    if (['source_started', 'publication'].includes(event.phase) && !phases.has(event.phase)) {
      phases.add(event.phase);
      await assert.rejects(withWitness(witness, f.trustKey, policy, { now: NOW }, () => assert.fail('second owner')), code('backup_witness_locked'));
    }
  } });
  assert.equal(result.state, 'complete'); assert.equal(result.highest_retained_generation_enforced, true);
  assert.equal(result.recovery_witness.highest_observed_generation, '9007199254740993');
  assert.deepEqual(await readFile(result.candidate.input), DATA); assert.equal(phases.size, 2);
  await released({ witness }); await noSockets(f);
});

test('unavailable newer download constrains later invocation before network access', async t => {
  const f = await fixture(t); f.setHandler((_, res) => { res.writeHead(404); res.end(); });
  await f.sign(DATA, { head_generation: '18446744073709551615' });
  await assert.rejects(download(f.options), code('backup_download_no_source')); await released(f);
  const retained = await state(f); assert.equal(retained.observations.length, 1);
  await writeFile(f.approval, f.original); f.requests.length = 0;
  await assert.rejects(download(f.options), code('backup_below_witness')); assert.equal(f.requests.length, 0);
  assert.deepEqual(await state(f), retained); await released(f);
});

for (const failure of ['expired', 'oversized', 'future']) test(`${failure} signed higher evidence is retained before refusal`, async t => {
  const f = await fixture(t);
  const extra = failure === 'expired' ? { expires_at: '2026-10-12T11:30:00Z' }
    : failure === 'future' ? { issued_at: '2026-10-12T13:00:00Z' } : {};
  await f.sign(DATA, { head_generation: '9007199254740994', ...extra }, failure === 'future' ? NOW + 7200000 : NOW - 3600000);
  await assert.rejects(download({ ...f.options, ...(failure === 'oversized' ? { maximumBytes: 1 } : {}) }));
  assert.equal(f.requests.length, 0); assert.equal((await state(f)).observations.length, 1);
  await writeFile(f.approval, f.original);
  await assert.rejects(download(f.options), code('backup_below_witness')); await released(f);
});

test('conflicting signed statements persist across failed download and retry', async t => {
  const f = await fixture(t); await observe(f, f.original);
  await f.sign(Buffer.alloc(DATA.length, 9));
  await assert.rejects(download(f.options), code('backup_witness_checkpoint_ambiguous'));
  assert.equal((await state(f)).observations.length, 2); assert.equal(f.requests.length, 0);
  await writeFile(f.approval, f.original);
  await assert.rejects(download(f.options), code('backup_witness_checkpoint_ambiguous')); await released(f);
});

test('invalid signatures never become retained observations', async t => {
  const f = await fixture(t), original = await state(f), envelope = JSON.parse(f.original);
  const signature = Buffer.from(envelope.signatures[0].sig, 'base64'); signature[0] ^= 1;
  envelope.signatures[0].sig = signature.toString('base64'); await writeFile(f.approval, JSON.stringify(envelope));
  await assert.rejects(download(f.options), code('backup_invalid_signature'));
  assert.deepEqual(await state(f), original); assert.equal(f.requests.length, 0); await released(f);
});

test('explicit original intent pin cannot be widened by witness observation', async t => {
  const f = await fixture(t);
  await assert.rejects(download({ ...f.options, checkpoint: { approval_sha256: '0'.repeat(64), trusted_key_id: f.signed.trusted_key_id } }), code('backup_download_checkpoint_mismatch'));
  assert.equal(f.requests.length, 0); assert.equal((await state(f)).observations.length, 1); await released(f);
});

test('post-observation approval substitution cannot retarget the publisher', async t => {
  const f = await fixture(t);
  await assert.rejects(download({ ...f.options, async onProgress(event) {
    if (event.phase === 'download_verified') await f.sign(DATA, { head_generation: '9007199254740994' });
  } }), code('backup_replication_checkpoint_mismatch'));
  assert.deepEqual(await readdir(f.destination), []); await released(f); await noSockets(f);
});

test('cancellation drains network before releasing witness and preserves observation', async t => {
  const f = await fixture(t), controller = new AbortController();
  await assert.rejects(download({ ...f.options, signal: controller.signal, onProgress(event) {
    if (event.phase === 'download') controller.abort();
  } }), code('backup_cancelled'));
  await released(f); await noSockets(f); assert.equal((await state(f)).observations.length, 1);
  assert.deepEqual(await readdir(f.destination), []);
});

test('deadline on a silent TLS peer releases ownership without forgetting checkpoint', async t => {
  const f = await fixture(t); f.setHandler(() => {});
  await assert.rejects(download({ ...f.options, timeoutMs: 200 }), code('backup_deadline'));
  await released(f); await noSockets(f); assert.equal((await state(f)).observations.length, 1);
});

for (const failure of ['missing', 'corrupt', 'locked']) test(`${failure} witness never falls back to unwitnessed acquisition`, async t => {
  const f = await fixture(t);
  if (failure === 'missing') await unlink(join(f.witness, 'witness.json'));
  else if (failure === 'corrupt') await writeFile(join(f.witness, 'witness.json'), 'garbage');
  else await writeFile(join(f.witness, '.witness-lock'), 'held', { mode: 0o600 });
  await assert.rejects(download(f.options)); assert.equal(f.requests.length, 0); assert.deepEqual(await readdir(f.destination), []);
});

test('physical parent aliases cannot place downloaded data inside witness', async t => {
  const f = await fixture(t), alias = join(f.root, 'alias'); await symlink(f.witness, alias);
  const destination = join(alias, 'nested'); await mkdir(destination, { mode: 0o700 });
  await assert.rejects(download({ ...f.options, destination }), code('backup_witness_separate_path_required'));
  assert.equal(f.requests.length, 0); assert.deepEqual(await readdir(destination), []); await released(f);
});

test('private URL control files must also stay outside the witness', async t => {
  const f = await fixture(t), alias = join(f.root, 'alias'); await symlink(f.witness, alias);
  const sourceFile = join(alias, 'urls.json'); await writeFile(sourceFile, JSON.stringify([f.url]), { mode: 0o600 });
  await assert.rejects(download({ ...f.options, sourceFile }), code('backup_witness_separate_path_required'));
  assert.equal(f.requests.length, 0); await released(f);
});

test('observer path substitution is refused before opening a network socket', async t => {
  const f = await fixture(t), control = join(f.root, 'control'); await mkdir(control);
  const caFile = join(control, 'tls.pem'); await writeFile(caFile, await readFile(f.caFile));
  await assert.rejects(download({ ...f.options, caFile, async onProgress(event) {
    if (event.phase === 'checkpoint_pinned') {
      await unlink(caFile); await symlink(join(f.witness, 'witness.json'), caFile);
    }
  } }), code('backup_witness_separate_path_required'));
  assert.equal(f.requests.length, 0); await released(f);
});

test('exact retry retains published inode and witness statement', async t => {
  const f = await fixture(t), a = await download(f.options), inode = (await lstat(a.candidate.input)).ino;
  const b = await download({ ...f.options, checkpoint: a.checkpoint });
  assert.equal((await lstat(b.candidate.input)).ino, inode); assert.deepEqual(a.recovery_witness, b.recovery_witness);
  await released(f);
});

const CLI = fileURLToPath(new URL('../download_repository_backup.mjs', import.meta.url));
async function cliFixture(t) {
  const f = await fixture(t), sourceFile = join(f.root, 'urls.json');
  await writeFile(sourceFile, JSON.stringify([f.url]), { mode: 0o600 });
  await f.sign(DATA, { issued_at: new Date(Math.floor(Date.now() / 1000) * 1000 - 1000).toISOString().replace('.000Z', 'Z'), expires_at: null }, Date.now());
  const p = f.options.policy, args = ['--sources', sourceFile, '--approval', f.approval, '--trust-key', f.trustKey,
    '--ca-file', f.caFile, '--replica-directory', f.destination, '--witness', f.witness,
    '--tenant-id', p.tenant_id, '--repository-id', p.repository_id, '--incarnation-id', p.incarnation_id,
    '--object-format', p.object_format, '--minimum-head-generation', '1', '--timeout-secs', '5'];
  return { ...f, args };
}
function launch(t, args) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; child.stdout.on('data', b => { out += b; }); child.stderr.on('data', b => { err += b; });
  const exit = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, out, err })); });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await exit; });
  return { child, exit };
}

test('actual CLI integrates witness and preserves completion on failed result delivery', async t => {
  const f = await cliFixture(t), first = await launch(t, f.args).exit;
  assert.equal(first.code, 0, first.err); const result = JSON.parse(first.out); assert(result.highest_retained_generation_enforced);
  const failure = Object.assign(new Error('output closed'), { code: 'EPIPE' });
  await assert.rejects(runDownloadCommand(f.args, { write(_, cb) { cb(failure); } }), error => {
    assert.equal(error, failure); assert(error.completed_result.recovery_witness); return true;
  }); await released(f);
});

test('killed CLI retains witness lease and restart refuses without any new network request', async t => {
  const f = await cliFixture(t); f.setHandler((_, res) => { res.writeHead(200); res.write(DATA.subarray(0, 70000)); });
  const owner = launch(t, f.args); let partial = false;
  for (let n = 0; n < 200 && !partial; n++) {
    for (const path of await readdir(f.destination)) if (path.endsWith('.tmp') && (await lstat(join(f.destination, path))).size > 0) partial = true;
    if (!partial) await delay(5);
  }
  assert(partial); owner.child.kill('SIGKILL'); assert.equal((await owner.exit).signal, 'SIGKILL');
  const count = f.requests.length, retry = await launch(t, f.args).exit;
  assert.equal(retry.code, 1); assert.equal(JSON.parse(retry.err).code, 'backup_witness_locked');
  assert.equal(f.requests.length, count); assert((await readdir(f.witness)).includes('.witness-lock'));
});

test('a stronger retained floor cannot be weakened on a later acquisition', async t => {
  const f = await fixture(t);
  await withWitness(f.witness, f.trustKey, { ...f.options.policy, minimum_head_generation: '2' }, { now: NOW }, () => {});
  await assert.rejects(download(f.options), code('backup_witness_floor_regression'));
  assert.equal(f.requests.length, 0); await released(f);
});

test('post-publication witness cleanup failure preserves the completed download receipt', async t => {
  const f = await fixture(t); let changed = false;
  await assert.rejects(download({ ...f.options, async onProgress(event) {
    if (!changed && event.phase === 'publication' && event.event.phase === 'archive_durable') {
      changed = true; await unlink(join(f.witness, '.witness-lock'));
      await writeFile(join(f.witness, '.witness-lock'), 'replacement-owner', { mode: 0o600 });
    }
  } }), asyncError => {
    assert.equal(asyncError.code, 'backup_witness_lock_changed'); assert.equal(asyncError.download_state, 'complete');
    assert.equal(asyncError.completed_result.state, 'complete'); assert(asyncError.completed_result.recovery_witness);
    return true;
  });
  assert(changed); assert.equal(await readFile(join(f.witness, '.witness-lock'), 'utf8'), 'replacement-owner');
  assert.equal((await readdir(f.destination)).filter(path => path.endsWith('.approval.json')).length, 1);
});
