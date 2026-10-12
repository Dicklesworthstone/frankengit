// Real Node CLI, POSIX files, Ed25519 and persisted witness; no native fg peer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtemp, writeFile, readFile, copyFile, unlink, link, symlink, rm, lstat, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { initializeRepositoryBackupWitness, withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { scrubArguments, runRepositoryBackupScrub, runScrubCommand } from '../scrub_repository_backups.mjs';

const CLI = fileURLToPath(new URL('../scrub_repository_backups.mjs', import.meta.url));
const ID = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: 'sha256' };
const POLICY = { ...ID, minimum_head_generation: '1' }, DATA = Buffer.alloc(65539, 0x43);
const hash = b => createHash('sha256').update(b).digest('hex');
const code = expected => e => { assert.equal(e.code, expected); return true; };
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-scrub-cli-')); t.after(() => rm(root, { recursive: true, force: true }));
  const keys = generateKeyPairSync('ed25519'), key = join(root, 'trust.pem'), witness = join(root, 'witness');
  const privatePem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  await writeFile(key, keys.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  async function signed(name, generation = '7', bytes = DATA, overrides = {}) {
    const row = { input: join(root, `${name}.archive`), approval: join(root, `${name}.approval`) };
    await writeFile(row.input, bytes, { mode: 0o600 });
    const result = await signRepositoryBackupFile(row.input, Buffer.from(privatePem), {
      ...ID, head_generation: generation, ...overrides,
    });
    await writeFile(row.approval, result.envelope, { mode: 0o600 }); return row;
  }
  async function replica(name, src) {
    const row = { input: join(root, `${name}.archive`), approval: join(root, `${name}.approval`) };
    await copyFile(src.input, row.input); await copyFile(src.approval, row.approval); return row;
  }
  const args = (rows, extra = []) => [...rows.flatMap(r => ['--candidate', r.input, r.approval]), '--trust-key', key,
    ...Object.entries(POLICY).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v]),
    '--max-archive-bytes', String(DATA.length), ...extra];
  async function command(rows, extra = []) {
    try { const r = await promisify(execFile)(process.execPath, [CLI, ...args(rows, extra)], { timeout: 10000, maxBuffer: 2 * 1024 ** 2 }); return { ...r, code: 0 }; }
    catch (e) { if (typeof e.code !== 'number') throw e; return { code: e.code, stdout: e.stdout, stderr: e.stderr }; }
  }
  const options = (rows, extra = {}) => ({ candidates: rows, trustKey: key, policy: POLICY, maximumBytes: DATA.length,
    maximumReplicaBytes: DATA.length * 8, ...extra });
  return { root, key, witness, signed, replica, args, command, options,
    init: () => initializeRepositoryBackupWitness(witness, key, POLICY) };
}

test('real CLI reports every healthy file and exact read accounting', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  const r = await f.command([b, a], ['--max-replica-bytes', String(DATA.length * 2), '--minimum-distinct-files', '2']);
  assert.equal(r.code, 0); assert.equal(r.stderr, ''); const v = JSON.parse(r.stdout);
  assert.equal(v.healthy, true); assert.equal(v.scrub_complete, true); assert.equal(v.distinct_authenticated_files, 2);
  assert.equal(v.streaming.total_payload_bytes_read, String(DATA.length * 2));
});

test('real CLI exits 2 for later-copy corruption and includes the complete health report', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a); await writeFile(b.input, Buffer.alloc(DATA.length));
  const r = await f.command([a, b], ['--max-replica-bytes', String(DATA.length * 2)]);
  assert.equal(r.code, 2); assert.equal(r.stderr, ''); const v = JSON.parse(r.stdout);
  assert.equal(v.healthy, false); assert.equal(v.scrub_complete, true); assert.equal(v.unavailable_candidates, 1);
  assert.equal(v.replica_attempts[1].code, 'backup_artifact_mismatch');
});

test('minimum-distinct-file health check cannot be satisfied with hard links', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a); await unlink(b.input); await link(a.input, b.input);
  const r = await f.command([a, b], ['--max-replica-bytes', String(DATA.length * 2), '--minimum-distinct-files', '2']);
  assert.equal(r.code, 2); const v = JSON.parse(r.stdout);
  assert.equal(v.all_replicas_authenticated, true); assert.equal(v.authenticated_candidates, 2);
  assert.equal(v.distinct_authenticated_files, 1); assert.equal(v.healthy, false);
});

test('real CLI incomplete budget is exit 1 with partial evidence, not degraded completion', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.replica('b', a);
  const r = await f.command([a, b], ['--max-replica-bytes', String(DATA.length * 2 - 1)]);
  assert.equal(r.code, 1); assert.equal(r.stdout, ''); const e = JSON.parse(r.stderr);
  assert.equal(e.code, 'backup_replica_read_budget'); assert.equal(e.scrub_complete, false);
  assert.equal(e.replica_attempts.length, 1); assert.equal(e.replica_bytes_read, String(DATA.length));
});

test('zero available highest copies is degraded exit 2, not an older checkpoint fallback', async t => {
  const f = await fixture(t), a = await f.signed('a', '8'), old = await f.signed('old', '7'); await unlink(a.input);
  const r = await f.command([a, old]); assert.equal(r.code, 2);
  const v = JSON.parse(r.stdout); assert.equal(v.head_generation, '8'); assert.equal(v.distinct_authenticated_files, 0);
});

test('CLI rejects side-effect options and malformed policy before I/O', async t => {
  const f = await fixture(t), a = await f.signed('a');
  for (const args of [['--fg', '/missing'], ['--resume'], ['--destination', '/missing'], ['--repair'], ['--sign-key', '/missing'],
    ['--minimum-distinct-files', '0'], ['--minimum-distinct-files', '65'], ['--max-replica-bytes', '0']]) {
    assert.throws(() => scrubArguments(f.args([a], args)));
  }
  assert.throws(() => scrubArguments(f.args([a], ['--trust-key', '/missing'])), code('backup_duplicate_option'));
  assert.throws(() => scrubArguments(f.args([a], ['--witness'])), code('backup_missing_option_value'));
});

test('unwitnessed scrub changes neither archive/control bytes nor directory entries', async t => {
  const f = await fixture(t), a = await f.signed('a');
  const before = await Promise.all([readFile(a.input), readFile(a.approval), readdir(f.root), lstat(a.input, { bigint: true })]);
  assert.equal((await f.command([a])).code, 0);
  assert.equal(hash(await readFile(a.input)), hash(before[0])); assert.deepEqual(await readFile(a.approval), before[1]);
  assert.deepEqual(await readdir(f.root), before[2]); const after = await lstat(a.input, { bigint: true });
  for (const field of ['ino', 'size', 'mode', 'mtimeNs', 'ctimeNs']) assert.equal(after[field], before[3][field]);
});

test('witness retains unavailable newer evidence across real CLI restarts', async t => {
  const f = await fixture(t), high = await f.signed('high', '9007199254740993'), old = await f.signed('old', '9007199254740992');
  await f.init(); await unlink(high.input);
  const first = await f.command([high, old], ['--witness', f.witness]); assert.equal(first.code, 2);
  assert.equal(JSON.parse(first.stdout).recovery_witness.highest_observed_generation, '9007199254740993');
  const second = await f.command([old], ['--witness', f.witness]); assert.equal(second.code, 1);
  assert.equal(JSON.parse(second.stderr).code, 'backup_below_witness');
  assert.equal((await readdir(f.witness)).includes('.witness-lock'), false);
});

test('witness persists signed conflicts even if a later run omits the conflicting candidate', async t => {
  const f = await fixture(t), a = await f.signed('a'), b = await f.signed('b', '7', Buffer.from('conflict')); await f.init();
  assert.equal(JSON.parse((await f.command([a, b], ['--witness', f.witness])).stderr).code, 'backup_checkpoint_ambiguous');
  assert.equal(JSON.parse((await f.command([a], ['--witness', f.witness])).stderr).code, 'backup_witness_checkpoint_ambiguous');
});

test('strict floor retained by witness cannot be weakened on a later scrub', async t => {
  const f = await fixture(t), a = await f.signed('a', '9'); await f.init();
  await runRepositoryBackupScrub(f.options([a], { witness: f.witness, policy: { ...POLICY, minimum_head_generation: '9' } }));
  await assert.rejects(runRepositoryBackupScrub(f.options([a], { witness: f.witness })), code('backup_witness_floor_regression'));
});

test('expired signed newer evidence is retained before refusal', async t => {
  const f = await fixture(t), now = Date.now(), old = await f.signed('old', '7'), high = await f.signed('high', '8', DATA, {
    issued_at: new Date(now - 10000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expires_at: new Date(now + 60000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  });
  await f.init();
  await assert.rejects(runRepositoryBackupScrub(f.options([high], { witness: f.witness, now: now + 120000 })), code('backup_approval_expired'));
  await assert.rejects(runRepositoryBackupScrub(f.options([old], { witness: f.witness })), code('backup_below_witness'));
});

test('signature tampering is fatal and cannot become retained high-water evidence', async t => {
  const f = await fixture(t), a = await f.signed('a', '9'); await f.init();
  const before = await readFile(join(f.witness, 'witness.json')), e = JSON.parse(await readFile(a.approval));
  e.signatures[0].sig = Buffer.alloc(64).toString('base64'); await writeFile(a.approval, JSON.stringify(e));
  await assert.rejects(runRepositoryBackupScrub(f.options([a], { witness: f.witness })), code('backup_invalid_signature'));
  assert.deepEqual(await readFile(join(f.witness, 'witness.json')), before);
});

test('missing or corrupt witnesses never bootstrap during scrub', async t => {
  const f = await fixture(t), a = await f.signed('a');
  await assert.rejects(runRepositoryBackupScrub(f.options([a], { witness: f.witness })), code('ENOENT'));
  await f.init(); await writeFile(join(f.witness, 'witness.json'), 'broken');
  await assert.rejects(runRepositoryBackupScrub(f.options([a], { witness: f.witness })), code('backup_witness_invalid_state'));
  assert.equal(await readFile(join(f.witness, 'witness.json'), 'utf8'), 'broken');
});

test('physical aliases cannot put archive sources inside the independent witness', async t => {
  const f = await fixture(t), a = await f.signed('a'); await f.init();
  const before = await readFile(join(f.witness, 'witness.json'));
  await copyFile(a.input, join(f.witness, 'hidden.archive')); const alias = join(f.root, 'alias'); await symlink(f.witness, alias);
  await assert.rejects(runRepositoryBackupScrub(f.options([{ input: join(alias, 'hidden.archive'), approval: a.approval }], { witness: f.witness })), code('backup_witness_separate_path_required'));
  assert.deepEqual(await readFile(join(f.witness, 'witness.json')), before);
});

test('missing ancestors of an old archive do not force lower-checkpoint reads', async t => {
  const f = await fixture(t), a = await f.signed('a', '9'), old = await f.signed('old', '8'); await f.init();
  old.input = join(f.root, 'missing', 'ancestors', 'old.archive');
  const r = await runRepositoryBackupScrub(f.options([a, old], { witness: f.witness }));
  assert.equal(r.healthy, true); assert.equal(r.lower_checkpoint_candidates_not_scrubbed, 1);
});

test('the existing witness lease excludes concurrent scrub owners', async t => {
  const f = await fixture(t), a = await f.signed('a'); await f.init();
  await withRepositoryBackupWitness(f.witness, f.key, POLICY, {}, async () => {
    const r = await f.command([a], ['--witness', f.witness]);
    assert.equal(r.code, 1); assert.equal(JSON.parse(r.stderr).code, 'backup_witness_locked');
  });
  assert.equal((await f.command([a], ['--witness', f.witness])).code, 0);
});

test('cancelled scrub drains its witness lease but retains the newer observation', async t => {
  const f = await fixture(t), high = await f.signed('high', '9'), old = await f.signed('old', '8'); await f.init();
  const c = new AbortController();
  await assert.rejects(runRepositoryBackupScrub(f.options([high], { witness: f.witness, signal: c.signal,
    onProgress(e) { if ('bytes_read' in e) c.abort(); } })), code('backup_cancelled'));
  assert.equal((await readdir(f.witness)).includes('.witness-lock'), false);
  await assert.rejects(runRepositoryBackupScrub(f.options([old], { witness: f.witness })), code('backup_below_witness'));
});

test('killed scrub owner leaves a blocking witness lease; no automatic lock stealing', { timeout: 15000 }, async t => {
  const f = await fixture(t), a = await f.signed('a'); await f.init();
  const source = `import {runRepositoryBackupScrub} from ${JSON.stringify(pathToFileURL(CLI).href)};
    await runRepositoryBackupScrub({...JSON.parse(process.argv[1]), async onProgress(e) {
      if(e.phase === 'checkpoint_selected') { process.stdout.write('READY\\n'); await new Promise(() => {}); }
    }});`;
  // An owned timer keeps this intentionally paused test process alive until killed.
  const child = spawn(process.execPath, ['--input-type=module', '-e', 'setInterval(()=>{},1000);\n' + source,
    JSON.stringify(f.options([a], { witness: f.witness }))], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  let stderr = ''; child.stderr.on('data', b => { stderr += b; });
  const closed = once(child, 'close');
  const ready = await Promise.race([once(child.stdout, 'data'), closed.then(() => { throw new Error(stderr || 'child exited before witness'); })]);
  assert.match(String(ready[0]), /READY/); child.kill('SIGKILL'); await closed;
  const r = await f.command([a], ['--witness', f.witness]); assert.equal(r.code, 1);
  assert.equal(JSON.parse(r.stderr).code, 'backup_witness_locked');
  const state = JSON.parse(await readFile(join(f.witness, 'witness.json'))); assert.equal(state.observations.length, 1);
});

test('broken output retains complete report and does not keep or reset a witness lease', async t => {
  const f = await fixture(t), a = await f.signed('a'); await f.init();
  const pipe = Object.assign(new Error('pipe'), { code: 'EPIPE' });
  await assert.rejects(runScrubCommand(f.args([a], ['--witness', f.witness]), { write(_text, callback) { callback(pipe); } }), e => {
    assert.equal(e, pipe); assert.equal(e.completed_result.scrub_complete, true); assert.equal(e.completed_result.healthy, true); return true;
  });
  assert.equal((await f.command([a], ['--witness', f.witness])).code, 0);
});

test('CLI help describes distinct files, degraded exits and native non-claims', async () => {
  const { stdout } = await promisify(execFile)(process.execPath, [CLI, '--help']);
  for (const text of ['Exit 2', 'NOT native', '--minimum-distinct-files', '--witness']) assert.ok(stdout.includes(text));
});
