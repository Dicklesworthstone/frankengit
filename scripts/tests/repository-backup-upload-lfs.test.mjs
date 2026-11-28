// Actual TLS, Ed25519 authentication, files and a reaped child protocol peer.
// The peer models native semantics over opaque fixture bytes; it is NOT fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, unlink, link, symlink, rm, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tlsFixture, ID } from './backup-download-fixture.mjs';
import { uploadRepositoryBackup, repositoryBackupUploadOptions, repositoryBackupUploadTarget } from '../lib/repository-backup-upload.mjs';
import { repositoryBackupUploadJobOptions } from '../lib/repository-backup-upload-job.mjs';
import { uploadArguments, runUploadCommand } from '../upload_repository_backup.mjs';

const LFS = Buffer.alloc(65553, 0x61), sha = bytes => createHash('sha256').update(bytes).digest('hex');
const approvalModule = new URL('../lib/repository-backup-approval.mjs', import.meta.url).href;
const nativeApprovalModule = new URL('../lib/repository-backup-native-approval.mjs', import.meta.url).href;
const CLI = fileURLToPath(new URL('../upload_repository_backup.mjs', import.meta.url));

async function fixture(t, format = 'sha256') {
  const f = await tlsFixture(t), objects = new Map(), events = [], races = new Map(), retainedScratch = new Set();
  t.after(async () => { for (const path of retainedScratch) await rm(path, { recursive: true, force: true }); });
  const policy = { ...ID, object_format: format, minimum_head_generation: '1' };
  const bytes = Buffer.from(JSON.stringify({ ...ID, object_format: format, TEST_ONLY_EXPECTED_COMPANION: sha(LFS) }));
  await f.sign(bytes, { object_format: format, head_generation: '7', issued_at: '2026-01-01T00:00:00Z', expires_at: null });
  const envelope = await readFile(f.approval), lfsArchive = join(f.root, 'source.fglf');
  const fg = join(f.root, 'native-protocol-peer.mjs'), config = join(f.root, 'peer.json'), log = join(f.root, 'calls');
  await writeFile(lfsArchive, LFS, { mode: 0o600 }); await writeFile(config, '{}', { mode: 0o600 });
  await writeFile(fg, `#!${process.execPath}
import { readFile, appendFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { authenticateRepositoryBackupFile } from ${JSON.stringify(approvalModule)};
import { nativeBackupApprovalBinding } from ${JSON.stringify(nativeApprovalModule)};
const args = process.argv.slice(2), flags = {}, config = JSON.parse(await readFile(${JSON.stringify(config)}));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
await appendFile(${JSON.stringify(log)}, JSON.stringify(args) + '\\n');
if (args[0] !== 'backup' || args[1] !== 'verify') process.exit(80);
for (let i = 4; i < args.length; i++) {
  const flag = args[i]; if (Object.hasOwn(flags, flag)) process.exit(81);
  flags[flag] = flag === '--trusted-local' ? true : args[++i];
}
const policy = Object.fromEntries(['tenant_id','repository_id','incarnation_id','object_format','minimum_head_generation']
  .map(key => [key, flags['--' + key.replaceAll('_', '-')]]));
const envelope = await readFile(flags['--approval']), key = await readFile(flags['--trust-key']);
const { authentication } = await authenticateRepositoryBackupFile(args[2], envelope, key, policy);
const statement = authentication.statement, source = JSON.parse(await readFile(args[2]));
const lfs = await readFile(flags['--lfs-archive']);
if (hash(lfs) !== flags['--expected-lfs-sha256'] || hash(lfs) !== source.TEST_ONLY_EXPECTED_COMPANION || config.wrongPair) process.exit(82);
if (config.retain) { await mkdir(args[3]); await writeFile(join(args[3], 'UNKNOWN_NATIVE_WORK'), 'retained'); process.exit(83); }
if (config.stall) await new Promise(resolve => setTimeout(resolve, 60000));
const result = { type: 'repository_source_backup_verify', schema_version: 1,
  ...Object.fromEntries(['tenant_id','repository_id','incarnation_id','object_format'].map(key => [key, statement[key]])),
  sha256: statement.artifact.sha256, head_generation: Number(statement.head_generation), objects: 2, references: 1,
  payload_bytes: 1, complete: true, scope: 'authority_and_selected_git_objects', object_graph_verified: true,
  original_payload_commitments_verified: true, node_closed: true, signature_verified: true, routing_published: false,
  archive_bytes: Number(statement.artifact.bytes), transport_version: 1, retained_outcome_checkpoint_verified: false,
  retained_outcome_checkpoint_root: null, retained_outcome_objects: 0, retained_outcome_payload_bytes: 0,
  local_edges: 1, external_gitlinks: 0, verification_instance: Number(flags['--verification-instance']),
  authority_import_verified: true, git_payloads_written: false, destination_authority_published: false,
  scratch_removed: true, destination_readback_verified: false, newest_checkpoint_verified: false, external_artifacts_verified: false,
  approval: { type: 'repository_backup_approval_authentication', signature_verified: true,
    ...nativeBackupApprovalBinding(envelope, key, policy), minimum_head_generation: policy.minimum_head_generation,
    statement, newest_checkpoint_verified: false, complete_capsule_verified: false },
  lfs_companion: { sha256: hash(lfs), bytes: lfs.length, objects: 1, payload_bytes: lfs.length - 16, exact_snapshot: true },
  lfs_payloads_verified: true };
if (config.badReceipt) result.lfs_companion.exact_snapshot = false;
process.stdout.write(JSON.stringify(result) + '\\n');
`, { mode: 0o700 });
  let intercept;
  f.server.on('checkContinue', (req, res) => {
    const path = new URL(req.url, f.url).pathname;
    if (races.has(path)) {
      objects.set(path, races.get(path)); races.delete(path); events.push({ method: req.method, path, headers: req.headers });
      assert.equal(req.headers['if-none-match'], '*'); res.writeHead(412, { 'content-length': 0 }); res.end();
    } else { res.writeContinue(); f.server.emit('request', req, res); }
  });
  f.setHandler(async (req, res) => {
    const path = new URL(req.url, f.url).pathname; events.push({ method: req.method, path, headers: req.headers });
    if (intercept && await intercept(req, res, path)) return;
    if (req.method === 'GET') {
      const value = objects.get(path); res.writeHead(value ? 200 : 404, { 'content-length': value?.length ?? 0 }); res.end(value); return;
    }
    assert.equal(req.method, 'PUT'); assert.equal(req.headers['if-none-match'], '*');
    if (objects.has(path)) { res.writeHead(412, { 'content-length': 0 }); res.end(); return; }
    try { const chunks = []; for await (const chunk of req) chunks.push(chunk);
      objects.set(path, Buffer.concat(chunks)); res.writeHead(201, { 'content-length': 0 }); res.end(); }
    catch { res.destroy(); }
  });
  const origin = new URL(f.url).origin;
  const target = Object.fromEntries(['archive', 'lfs', 'approval'].map(kind => [kind, {
    get: `${origin}/${kind}?SECRET-CAPABILITY=GET`, put: `${origin}/${kind}?SECRET-CAPABILITY=PUT` }]));
  const options = { input: f.local, approval: f.approval, trustKey: f.trustKey, caFile: f.caFile, policy,
    target, lfsArchive, expectedLfsSha256: sha(LFS), fg, verificationInstance: '992', trustedLocal: true,
    maximumBytes: LFS.length, maximumTotalBytes: 3 * (bytes.length + LFS.length), timeoutMs: 10000 };
  async function calls() { try { return (await readFile(log, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; } }
  async function run(extra) { try { return await uploadRepositoryBackup({ ...options, ...extra }); }
    catch (error) { if (error.verification_scratch) retainedScratch.add(error.verification_scratch); throw error; } }
  const targetFile = join(f.root, 'capabilities.json'); await writeFile(targetFile, JSON.stringify(target), { mode: 0o600 });
  const args = ['--input', f.local, '--approval', f.approval, '--trust-key', f.trustKey, '--target', targetFile,
    '--ca-file', f.caFile, '--lfs-archive', lfsArchive, '--expected-lfs-sha256', sha(LFS), '--fg', fg,
    '--verification-instance', '992', '--trusted-local',
    ...Object.entries(policy).flatMap(([key, value]) => ['--' + key.replaceAll('_', '-'), value]),
    '--max-archive-bytes', String(LFS.length), '--max-total-bytes', String(options.maximumTotalBytes), '--timeout-secs', '10'];
  return { ...f, options, run, calls, bytes, envelope, objects, events, args, targetFile,
    intercept(fn) { intercept = fn; }, race(kind, bytes) { races.set('/' + kind, bytes); },
    mode: value => writeFile(config, JSON.stringify(value)) };
}
const puts = f => f.events.filter(event => event.method === 'PUT').map(event => event.path);
async function refusal(promise, expected) {
  let error; try { await promise; } catch (caught) { error = caught; }
  assert.ok(error, 'operation must refuse'); if (expected) assert.equal(error.code, expected);
  assert(!JSON.stringify(error).includes('SECRET-CAPABILITY')); return error;
}

for (const format of ['sha1', 'sha256']) test(`paired upload verifies native relation then reads back both before approval (${format})`, async t => {
  const f = await fixture(t, format), phases = [];
  const result = await f.run({ async onProgress(event) {
    phases.push(event.phase);
    if (event.phase === 'native_verified') assert.equal(f.events.length, 0);
    if (event.phase === 'lfs_verified') assert.equal(f.objects.has('/approval'), false);
  } });
  assert.deepEqual(f.objects.get('/archive'), f.bytes); assert.deepEqual(f.objects.get('/lfs'), LFS);
  assert.deepEqual(f.objects.get('/approval'), f.envelope);
  assert.deepEqual(f.events.map(event => event.method + ' ' + event.path), ['GET /approval', 'GET /archive', 'GET /lfs',
    'GET /approval', 'PUT /archive', 'GET /archive', 'GET /approval', 'PUT /lfs', 'GET /lfs', 'PUT /approval', 'GET /approval']);
  assert.equal(result.state, 'complete'); assert.equal(result.streaming.requests, 11); assert.equal(phases.length, 7);
  assert.equal(result.streaming.total_payload_bytes, String(3 * (f.bytes.length + LFS.length)));
  assert.equal(result.streaming.native_preflight_metered, false); assert.equal(result.native_content_verified, true);
  assert.equal(result.lfs_companion_signed, false); assert.equal(result.lfs_verified_before_approval_put, true);
  assert.equal(result.lfs_verified_before_acknowledgement, true); assert.equal(result.remote_physical_durability_verified, false);
  assert.deepEqual(result.lfs_companion, { sha256: sha(LFS), bytes: String(LFS.length), objects: '1', payload_bytes: String(LFS.length - 16), exact_snapshot: true });
  const calls = await f.calls(); assert.equal(calls.length, 1); assert.equal(calls[0][2], f.local);
  assert.equal(calls[0][calls[0].indexOf('--lfs-archive') + 1], f.options.lfsArchive);
  assert.equal(calls[0][calls[0].indexOf('--expected-lfs-sha256') + 1], sha(LFS));
  for (const event of f.events) assert.equal(event.headers['user-agent'], 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)');
  assert(!JSON.stringify(result).includes('SECRET-CAPABILITY'));
});

test('exact paired retry authenticates all three objects without another PUT or a historical ordering claim', async t => {
  const f = await fixture(t), first = await f.run(); f.events.length = 0;
  const second = await f.run({ checkpoint: first.checkpoint });
  assert.deepEqual(second.disposition, { archive: 'reused', approval: 'reused', lfs: 'reused' }); assert.deepEqual(puts(f), []);
  assert.equal(second.streaming.requests, 4); assert.equal(second.streaming.total_payload_bytes, String(2 * (f.bytes.length + LFS.length)));
  assert.equal(second.lfs_verified_before_approval_put, false); assert.equal(second.lfs_verified_before_acknowledgement, true);
  assert.equal((await f.calls()).length, 2);
});

for (const kind of ['archive', 'lfs']) test(`preexisting approval with missing ${kind} refuses every PUT`, async t => {
  const f = await fixture(t); f.objects.set('/approval', f.envelope);
  f.objects.set(kind === 'archive' ? '/lfs' : '/archive', kind === 'archive' ? LFS : f.bytes);
  await refusal(f.run(), 'backup_upload_missing_dependency'); assert.deepEqual(puts(f), []);
});
for (const kind of ['archive', 'lfs']) test(`approval appearing immediately before missing ${kind} PUT is not permission to repair it`, async t => {
  const f = await fixture(t); await refusal(f.run({ onProgress(event) {
    if (event.phase === kind + '_put_started') f.objects.set('/approval', f.envelope);
  } }), 'backup_upload_missing_dependency');
  assert.equal(f.objects.has('/' + kind), false);
  assert.deepEqual(puts(f), kind === 'archive' ? [] : ['/archive']);
});
for (const kind of ['archive', 'lfs', 'approval']) test(`existing corrupt paired ${kind} refuses every PUT`, async t => {
  const f = await fixture(t), expected = { archive: f.bytes, lfs: LFS, approval: f.envelope };
  f.objects.set('/' + kind, Buffer.alloc(expected[kind].length, 7));
  await refusal(f.run(), 'backup_upload_digest'); assert.deepEqual(puts(f), []);
});
test('unadvertised source-only work resumes with companion and approval publication', async t => {
  const f = await fixture(t); f.objects.set('/archive', f.bytes); const result = await f.run();
  assert.deepEqual(puts(f), ['/lfs', '/approval']); assert.equal(result.disposition.archive, 'reused');
});
for (const exact of [true, false]) test(`conditional companion winner is ${exact ? 'verified exactly' : 'refused without approval'}`, async t => {
  const f = await fixture(t); f.race('lfs', exact ? LFS : Buffer.alloc(LFS.length, 2));
  if (exact) assert.equal((await f.run()).disposition.lfs, 'concurrent_exact');
  else { await refusal(f.run(), 'backup_upload_digest'); assert.equal(f.objects.has('/approval'), false); }
  assert.equal(puts(f).filter(path => path === '/lfs').length, 1);
});
test('lost companion PUT response stays uncertain and only an explicit retry reads it back', async t => {
  const f = await fixture(t); let lose = true;
  f.intercept(async (req, res, path) => {
    if (lose && req.method === 'PUT' && path === '/lfs') {
      lose = false; const chunks = []; for await (const chunk of req) chunks.push(chunk);
      f.objects.set(path, Buffer.concat(chunks)); req.socket.destroy(); return true;
    }
  });
  const error = await refusal(f.run(), 'backup_upload_transport'); assert.equal(error.publication_state, 'lfs_put_unknown');
  assert.equal(f.objects.has('/approval'), false); f.events.length = 0;
  assert.equal((await f.run({ checkpoint: error.checkpoint })).state, 'complete'); assert.deepEqual(puts(f), ['/approval']);
});
test('false companion PUT success cannot publish approval', async t => {
  const f = await fixture(t); f.intercept(async (req, res, path) => {
    if (req.method === 'PUT' && path === '/lfs') { for await (const _ of req) {} res.writeHead(201, { 'content-length': 0 }); res.end(); return true; }
  });
  await refusal(f.run(), 'backup_upload_missing_readback'); assert.equal(f.objects.has('/approval'), false);
});
for (const kind of ['missing', 'digest', 'wrong-pair', 'bad-receipt']) test(`local ${kind} pair cannot reach HTTPS or downgrade to source-only`, async t => {
  const f = await fixture(t);
  if (kind === 'missing') await unlink(f.options.lfsArchive);
  else if (kind === 'digest') await writeFile(f.options.lfsArchive, Buffer.alloc(LFS.length, 2));
  else await f.mode(kind === 'wrong-pair' ? { wrongPair: true } : { badReceipt: true });
  await refusal(f.run()); assert.equal(f.events.length, 0);
});
test('native unknown scratch is retained and reported without any remote write', async t => {
  const f = await fixture(t); await f.mode({ retain: true }); const error = await refusal(f.run());
  assert.ok(error.verification_scratch); assert((await lstat(error.verification_scratch)).isDirectory());
  assert.equal(f.events.length, 0);
});
for (const kind of ['source', 'lfs']) test(`${kind} substitution after native verification cannot reach HTTPS`, async t => {
  const f = await fixture(t); await refusal(f.run({ async onProgress(event) {
    if (event.phase === 'native_verified') await writeFile(kind === 'source' ? f.local : f.options.lfsArchive,
      Buffer.alloc(kind === 'source' ? f.bytes.length : LFS.length, 3));
  } }), kind === 'source' ? 'backup_upload_source_changed' : 'backup_upload_lfs_changed');
  assert.equal(f.events.length, 0);
});
test('companion substitution after its readback cannot publish approval', async t => {
  const f = await fixture(t); await refusal(f.run({ async onProgress(event) {
    if (event.phase === 'lfs_verified') await writeFile(f.options.lfsArchive, Buffer.alloc(LFS.length, 3));
  } }), 'backup_upload_lfs_changed'); assert.equal(f.objects.has('/approval'), false);
});
test('3(N+L)-1 refuses before native verification or networking', async t => {
  const f = await fixture(t); await refusal(f.run({ maximumTotalBytes: f.options.maximumTotalBytes - 1 }), 'backup_upload_budget');
  assert.equal(f.events.length, 0); assert.deepEqual(await f.calls(), []);
});
test('the independent companion size limit is not enlarged by the aggregate budget', async t => {
  const f = await fixture(t); await refusal(f.run({ maximumBytes: LFS.length - 1 }), 'backup_lfs_archive_size_or_type');
  assert.equal(f.events.length, 0); assert.deepEqual(await f.calls(), []);
});
test('cancellation after both body readbacks retains unadvertised reusable work', async t => {
  const f = await fixture(t), stop = new AbortController();
  await refusal(f.run({ signal: stop.signal, onProgress(event) { if (event.phase === 'lfs_verified') stop.abort(); } }), 'backup_cancelled');
  assert.deepEqual(f.objects.get('/archive'), f.bytes); assert.deepEqual(f.objects.get('/lfs'), LFS); assert.equal(f.objects.has('/approval'), false);
  f.events.length = 0; await f.run(); assert.deepEqual(puts(f), ['/approval']);
});
test('native preflight consumes the original deadline and is reaped before any network', async t => {
  const f = await fixture(t); await f.mode({ stall: true });
  await refusal(f.run({ timeoutMs: 300 })); assert.equal(f.events.length, 0);
});
test('abort during companion GET drains the peer and prevents all PUTs', async t => {
  const f = await fixture(t), stop = new AbortController(); let closed;
  f.intercept((req, res, path) => { if (req.method === 'GET' && path === '/lfs') {
    closed = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('peer did not close')), 2000);
      req.socket.once('close', () => { clearTimeout(timer); resolve(); });
    });
    stop.abort(); return true;
  } });
  await refusal(f.run({ signal: stop.signal }), 'backup_cancelled'); await closed; assert.deepEqual(puts(f), []);
});
test('hardlink, symlink and exact input aliases refuse before native/network work', async t => {
  const f = await fixture(t), alias = join(f.root, 'alias');
  await link(f.local, alias); await refusal(f.run({ lfsArchive: alias }), 'backup_lfs_separate_path_required'); await unlink(alias);
  await symlink(f.options.lfsArchive, alias); await refusal(f.run({ lfsArchive: alias }));
  assert.throws(() => repositoryBackupUploadOptions({ ...f.options, lfsArchive: f.local }), { code: 'backup_lfs_separate_path_required' });
  assert.equal(f.events.length, 0); assert.deepEqual(await f.calls(), []);
});
test('paired target identities are distinct and v1 job target grammar remains source-only', async t => {
  const f = await fixture(t);
  assert.throws(() => repositoryBackupUploadTarget(f.options.target), { code: 'backup_upload_target' });
  for (const kind of ['archive', 'approval']) assert.throws(() => repositoryBackupUploadOptions({ ...f.options,
    target: { ...f.options.target, lfs: f.options.target[kind] } }), { code: 'backup_upload_target_mismatch' });
  assert.throws(() => repositoryBackupUploadOptions({ ...f.options,
    target: { ...f.options.target, lfs: { get: f.options.target.lfs.get, put: f.options.target.archive.put } } }), { code: 'backup_upload_target_mismatch' });
  assert.throws(() => repositoryBackupUploadOptions({ ...f.options, lfsArchive: undefined }), { code: 'backup_lfs_pair_required' });
  assert.throws(() => repositoryBackupUploadOptions({ ...f.options, trustedLocal: undefined }), { code: 'backup_explicit_local_operation_required' });
  const job = { trustedLocal: true, jobDirectory: join(f.root, 'job'), input: f.local, approval: f.approval,
    trustKey: f.trustKey, policy: f.options.policy, targets: [{ target: f.options.target, caFile: f.caFile }] };
  assert.throws(() => repositoryBackupUploadJobOptions(job, 'seal'), { code: 'backup_upload_target' });
  const sourceOnly = { archive: f.options.target.archive, approval: f.options.target.approval };
  assert.deepEqual(repositoryBackupUploadJobOptions({ ...job, targets: [{ target: sourceOnly }] }, 'seal').targets[0].target, sourceOnly);
});
test('paired CLI grammar keeps all companion, trust and native requirements explicit', async t => {
  const f = await fixture(t), parsed = uploadArguments(f.args); assert.equal(parsed.expectedLfsSha256, sha(LFS));
  assert.equal(parsed.lfsArchive, f.options.lfsArchive); assert.equal(parsed.trustedLocal, true);
  for (const flag of ['--expected-lfs-sha256', '--lfs-archive', '--fg', '--verification-instance', '--trusted-local']) {
    const args = f.args.slice(), at = args.indexOf(flag); args.splice(at, flag === '--trusted-local' ? 1 : 2);
    assert.throws(() => uploadArguments(args));
  }
});
test('actual CLI publishes the exact pair and redacts all signed URL capabilities', async t => {
  const f = await fixture(t), child = spawn(process.execPath, [CLI, ...f.args, '--progress-json'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 131072) child.kill('SIGKILL'); });
  child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 131072) child.kill('SIGKILL'); });
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
  const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await done; });
  let result; try { result = await done; } finally { clearTimeout(timer); }
  assert.equal(result.code, 0, stderr); const receipt = JSON.parse(stdout);
  assert.equal(receipt.lfs_companion.sha256, sha(LFS)); assert.equal(receipt.native_content_verified, true);
  assert.equal(stderr.trim().split('\n').length, 7); assert(!(stdout + stderr).includes('SECRET-CAPABILITY'));
});
test('failed paired final output reports the completed three-object publication', async t => {
  const f = await fixture(t), broken = { write(text, callback) { callback(Object.assign(new Error('closed'), { code: 'EPIPE' })); } };
  const error = await refusal(runUploadCommand(f.args, broken), 'EPIPE');
  assert.equal(error.publication_state, 'complete'); assert.equal(error.completed_result.lfs_companion.sha256, sha(LFS));
  assert.deepEqual(f.objects.get('/approval'), f.envelope);
});
