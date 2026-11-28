// Actual HTTPS, Ed25519, file custody and process ownership. The native-schema
// peer models pair identity over opaque JSON; it is NOT a Rust/FGLF verifier.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, lstat, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { downloadRepositoryBackup, repositoryBackupDownloadOptions } from '../lib/repository-backup-download.mjs';
import { downloadRepositoryBackupWithWitness } from '../lib/repository-backup-download-witness.mjs';
import { initializeRepositoryBackupWitness, withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { downloadArguments } from '../download_repository_backup.mjs';
import { runNativeProcess } from '../lib/native-process-owner.mjs';
import { tlsFixture, digest } from './backup-download-fixture.mjs';

const LFS = Buffer.alloc(65553, 0x61);
const CLI = fileURLToPath(new URL('../download_repository_backup.mjs', import.meta.url));
const absent = path => assert.rejects(lstat(path), { code: 'ENOENT' });
const code = expected => error => { assert.equal(error.code, expected); return true; };
async function fixture(t, format = 'sha256') {
  const f = await tlsFixture(t), retained = new Set();
  const source = Buffer.from(JSON.stringify({ TEST_ONLY_EXPECTED_COMPANION: digest(LFS), object_format: format }));
  const signed = await f.sign(source, { object_format: format, head_generation: '7',
    issued_at: '2026-01-01T00:00:00Z', expires_at: null }, Date.now());
  const fg = join(f.root, 'native-peer.mjs'), config = join(f.root, 'peer-config.json'), log = join(f.root, 'native-calls');
  const descendantPid = join(f.root, 'descendant-pid');
  await writeFile(config, '{}', { mode: 0o600 });
  const lfsUrl = f.url.replace('/backup', '/lfs');
  f.setHandler((req, res) => res.end(req.url.startsWith('/lfs') ? LFS : source));
  await writeFile(fg, `#!${process.execPath}
import { readFile, appendFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { authenticateRepositoryBackupFile } from ${JSON.stringify(new URL('../lib/repository-backup-approval.mjs', import.meta.url).href)};
import { nativeBackupApprovalBinding } from ${JSON.stringify(new URL('../lib/repository-backup-native-approval.mjs', import.meta.url).href)};
const args = process.argv.slice(2), flags = {}, mode = JSON.parse(await readFile(${JSON.stringify(config)}));
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
if (hash(lfs) !== flags['--expected-lfs-sha256'] || hash(lfs) !== source.TEST_ONLY_EXPECTED_COMPANION) process.exit(82);
if (mode.descendant) {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  child.unref(); await writeFile(${JSON.stringify(descendantPid)}, String(child.pid)); process.exit(0);
}
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
  lfs_companion: { sha256: hash(lfs), bytes: lfs.length, objects: 1, payload_bytes: lfs.length - 16, exact_snapshot: !mode.badReceipt },
  lfs_payloads_verified: true };
process.stdout.write(JSON.stringify(result) + '\\n');
`, { mode: 0o700 });
  const { now, ...base } = f.options;
  const options = { ...base, policy: { ...base.policy, object_format: format }, lfsSources: [lfsUrl],
    expectedLfsSha256: digest(LFS), expectedLfsBytes: String(LFS.length), fg, trustedLocal: true,
    verificationInstance: '992', timeoutMs: 10000 };
  const remember = error => {
    for (const path of [error.verification_scratch, error.approval_scratch, error.retained_download]) if (path) retained.add(path);
    return error;
  };
  const run = async extra => { try { return await downloadRepositoryBackup({ ...options, ...extra }); }
    catch (error) { throw remember(error); } };
  t.after(async () => { for (const path of retained) await rm(path, { recursive: true, force: true }); });
  const calls = async () => { try { return (await readFile(log, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; } };
  const noQuarantine = async () => assert.deepEqual((await readdir(f.root)).filter(name => name.startsWith('.fg-backup-download-pair-')), []);
  const noSockets = async () => { for (let i = 0; i < 50 && f.sockets.size; i++) await delay(5); assert.equal(f.sockets.size, 0); };
  return { ...f, source, signed, fg, lfsUrl, options, run, calls, noQuarantine, noSockets, descendantPid, remember,
    needed: 4 * source.length + 3 * LFS.length,
    mode: value => writeFile(config, JSON.stringify(value)),
    paths: { input: join(f.destination, `archive-sha256-${digest(source)}.fgbackup`),
      approval: join(f.destination, `checkpoint-sha256-${digest(signed.envelope)}.approval.json`),
      lfs: join(f.destination, `lfs-sha256-${digest(LFS)}.fglf`) } };
}
const redacted = value => {
  const text = JSON.stringify(value); assert.ok(!text.includes('capability-do-not-log')); assert.ok(!text.includes('127.0.0.1'));
};

for (const format of ['sha1', 'sha256']) test(`${format}: HTTPS pair is natively verified before either destination body or approval`, async t => {
  const f = await fixture(t, format);
  const result = await f.run({ maximumTotalBytes: f.needed, maximumRequests: 2, async onProgress(event) {
    if (event.phase === 'component_verified' || (event.phase === 'publication' && event.event.phase === 'native_verified')) {
      assert.deepEqual(await readdir(f.destination), []);
    }
    if (event.phase === 'publication' && ['archive_durable', 'lfs_durable'].includes(event.event.phase)) await absent(f.paths.approval);
  } });
  assert.deepEqual(result.candidate, { input: f.paths.input, approval: f.paths.approval });
  assert.equal(result.lfs_archive, f.paths.lfs); assert.deepEqual(await readFile(result.candidate.input), f.source);
  assert.deepEqual(await readFile(result.lfs_archive), LFS); assert.deepEqual(await readFile(result.candidate.approval), f.signed.envelope);
  assert.equal(result.native_content_verified, true); assert.equal(result.lfs_payloads_verified, true);
  assert.equal(result.lfs_companion_signed, false); assert.equal(result.complete_capsule_verified, false);
  assert.equal(result.lfs_companion.bytes, String(LFS.length)); assert.equal(result.lfs_companion.exact_snapshot, true);
  assert.equal(result.streaming.total_payload_bytes_read, String(f.needed));
  assert.equal(result.streaming.network_payload_bytes_read, String(f.source.length + LFS.length));
  assert.equal(result.streaming.publication_payload_bytes_read, String(3 * f.source.length + 2 * LFS.length));
  assert.equal(result.streaming.native_preflight_metered, false); assert.equal(result.streaming.request_attempts, 2);
  assert.equal((await f.calls()).length, 1); redacted(result); await f.noQuarantine(); await f.noSockets();
});

test('paired retry reuses all published inodes and still revalidates both inputs', async t => {
  const f = await fixture(t), first = await f.run();
  const before = await Promise.all(Object.values(f.paths).map(path => lstat(path)));
  const next = await f.run({ checkpoint: first.checkpoint });
  const after = await Promise.all(Object.values(f.paths).map(path => lstat(path)));
  assert.deepEqual(after.map(stat => stat.ino), before.map(stat => stat.ino));
  assert.deepEqual(next.publication.disposition, { archive: 'reused', approval: 'reused', lfs: 'reused' });
  assert.equal(next.streaming.total_payload_bytes_read, String(3 * f.source.length + 2 * LFS.length));
  assert.equal((await f.calls()).length, 2); await f.noQuarantine();
});

test('one-byte-short payload or one-request budgets refuse before quarantine or HTTPS', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ maximumTotalBytes: f.needed - 1 }), code('backup_download_read_budget'));
  await assert.rejects(f.run({ maximumRequests: 1 }), code('backup_download_request_budget'));
  assert.deepEqual(f.requests, []); assert.deepEqual(await f.calls(), []); await f.noQuarantine();
  assert.equal((await f.run({ maximumTotalBytes: f.needed, maximumRequests: 2 })).state, 'complete');
});

for (const pin of ['digest', 'bytes']) test(`wrong independent companion ${pin} cannot use source-only publication`, async t => {
  const f = await fixture(t);
  await assert.rejects(f.run(pin === 'digest' ? { expectedLfsSha256: '0'.repeat(64) } : { expectedLfsBytes: String(LFS.length - 1) }), error => {
    assert.equal(error.code, 'backup_download_no_source'); assert.equal(error.active_component, 'lfs');
    assert.equal(error.lfs_source_attempts.length, 1); redacted(error); return true;
  });
  assert.deepEqual(await f.calls(), []); assert.deepEqual(await readdir(f.destination), []); await f.noQuarantine(); await f.noSockets();
});

test('companion pin size has an independent ceiling checked before acquisition', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ maximumBytes: LFS.length - 1 }), code('backup_download_lfs_archive_limit'));
  assert.deepEqual(f.requests, []); await f.noQuarantine();
});

for (const component of ['source', 'lfs']) test(`${component} corrupt mirror spends the shared pair ledger before its permitted twin`, async t => {
  const f = await fixture(t), bad = (component === 'source' ? f.url : f.lfsUrl).replace('?', '-bad?');
  f.setHandler((req, res) => {
    const body = req.url.startsWith('/lfs') ? LFS : f.source;
    res.end(req.url.includes('-bad?') ? Buffer.alloc(body.length, 0x42) : body);
  });
  const amount = component === 'source' ? f.source.length : LFS.length;
  const extra = { [component === 'source' ? 'sources' : 'lfsSources']: [bad, component === 'source' ? f.url : f.lfsUrl] };
  const result = await f.run({ ...extra, maximumTotalBytes: f.needed + amount, maximumRequests: 3 });
  assert.equal(result.streaming.total_payload_bytes_read, String(f.needed + amount));
  assert.equal(result.streaming.request_attempts, 3);
  assert.deepEqual((component === 'source' ? result.source_attempts : result.lfs_source_attempts).map(row => row.outcome), ['unavailable', 'authenticated']);
  await f.noQuarantine(); await f.noSockets();
});

test('failed source mirror cannot spend the request reserved for its companion', async t => {
  const f = await fixture(t); f.setHandler((_, res) => { res.writeHead(404); res.end(); });
  await assert.rejects(f.run({ sources: [f.url, f.url.replace('/backup', '/second')], maximumRequests: 2 }), code('backup_download_request_budget'));
  assert.equal(f.requests.length, 1); assert.deepEqual(await f.calls(), []); await f.noQuarantine();
});

test('missing companion never publishes the already downloaded source approval', async t => {
  const f = await fixture(t);
  f.setHandler((req, res) => { if (req.url.startsWith('/lfs')) { res.writeHead(404); res.end(); } else res.end(f.source); });
  await assert.rejects(f.run(), code('backup_download_no_source'));
  assert.equal(f.requests.length, 2); assert.deepEqual(await readdir(f.destination), []); assert.deepEqual(await f.calls(), []); await f.noQuarantine();
});

test('LFS redirects are fatal and do not disclose capability URLs or try another mirror', async t => {
  const f = await fixture(t);
  f.setHandler((req, res) => { if (req.url.startsWith('/lfs')) { res.writeHead(307, { location: f.lfsUrl }); res.end(); } else res.end(f.source); });
  await assert.rejects(f.run({ lfsSources: [f.lfsUrl, f.lfsUrl.replace('/lfs', '/other')] }), error => {
    assert.equal(error.code, 'backup_download_redirect_refused'); redacted(error); return true;
  });
  assert.equal(f.requests.length, 2); assert.deepEqual(await readdir(f.destination), []); await f.noQuarantine(); await f.noSockets();
});

test('truncated chunked companion cannot reach native verification', async t => {
  const f = await fixture(t);
  f.setHandler((req, res) => { if (req.url.startsWith('/lfs')) { res.write(LFS.subarray(0, 71)); res.end(); } else res.end(f.source); });
  await assert.rejects(f.run(), code('backup_download_no_source'));
  assert.deepEqual(await f.calls(), []); assert.deepEqual(await readdir(f.destination), []); await f.noQuarantine(); await f.noSockets();
});

test('transport-correct but wrong source/LFS pair is rejected by the native preflight', async t => {
  const f = await fixture(t), wrong = Buffer.alloc(LFS.length, 0x62);
  f.setHandler((req, res) => res.end(req.url.startsWith('/lfs') ? wrong : f.source));
  await assert.rejects(f.run({ expectedLfsSha256: digest(wrong) }), error => {
    assert.equal(error.code, 'backup_native_refused'); assert.equal(error.native_exit_code, 82); return true;
  });
  assert.equal((await f.calls()).length, 1); assert.deepEqual(await readdir(f.destination), []); await f.noQuarantine();
});

test('invalid native exact-snapshot receipt never publishes either body', async t => {
  const f = await fixture(t); await f.mode({ badReceipt: true });
  await assert.rejects(f.run(), code('backup_native_lfs_receipt_mismatch'));
  assert.deepEqual(await readdir(f.destination), []); await f.noQuarantine();
});

test('invalid source signature refuses before both acquisition lanes', async t => {
  const f = await fixture(t), envelope = JSON.parse(await readFile(f.approval));
  const signature = Buffer.from(envelope.signatures[0].sig, 'base64'); signature[0] ^= 1;
  envelope.signatures[0].sig = signature.toString('base64'); await writeFile(f.approval, JSON.stringify(envelope));
  await assert.rejects(f.run(), code('backup_invalid_signature'));
  assert.deepEqual(f.requests, []); assert.deepEqual(await f.calls(), []); await f.noQuarantine();
});

test('LFS cancellation drains sockets and removes only owned pair quarantine', async t => {
  const f = await fixture(t), stop = new AbortController(), untouched = join(f.destination, 'operator-owned');
  await writeFile(untouched, 'keep');
  await assert.rejects(f.run({ signal: stop.signal, onProgress(event) {
    if (event.phase === 'download' && event.component === 'lfs') stop.abort();
  } }), code('backup_cancelled'));
  assert.deepEqual(await readdir(f.destination), ['operator-owned']); await f.noQuarantine(); await f.noSockets();
});

test('one deadline includes a silent companion after the source completes', async t => {
  const f = await fixture(t);
  f.setHandler((req, res) => { if (!req.url.startsWith('/lfs')) res.end(f.source); });
  await assert.rejects(f.run({ timeoutMs: 200 }), code('backup_deadline'));
  assert.deepEqual(await readdir(f.destination), []); await f.noQuarantine(); await f.noSockets();
});

test('observer failures cannot masquerade as recoverable LFS transport errors', async t => {
  const f = await fixture(t), problem = Object.assign(new Error('stop'), { code: 'ECONNRESET' });
  await assert.rejects(f.run({ lfsSources: [f.lfsUrl, f.lfsUrl.replace('/lfs', '/other')], onProgress(event) {
    if (event.phase === 'download' && event.component === 'lfs') throw problem;
  } }), error => error === problem);
  assert.equal(f.requests.length, 2); await f.noQuarantine(); await f.noSockets();
});

test('concurrent pair downloads converge on identical immutable outputs', async t => {
  const f = await fixture(t), [one, two] = await Promise.all([f.run(), f.run()]);
  assert.deepEqual(one.candidate, two.candidate); assert.equal(one.lfs_archive, two.lfs_archive);
  assert.equal((await readdir(f.destination)).length, 3); assert.deepEqual(await readFile(one.lfs_archive), LFS);
  for (const path of Object.values(f.paths)) assert.equal((await lstat(path)).nlink, 1);
  await f.noQuarantine(); await f.noSockets();
});

test('a conflicting published companion is preserved and no new approval is created', async t => {
  const f = await fixture(t), conflict = Buffer.alloc(LFS.length, 0x62); await writeFile(f.paths.lfs, conflict, { mode: 0o600 });
  await assert.rejects(f.run(), code('backup_replica_digest_mismatch'));
  assert.deepEqual(await readFile(f.paths.lfs), conflict); await absent(f.paths.approval); await f.noQuarantine();
});

test('source-only download retains its old result and never invokes native verification', async t => {
  const f = await fixture(t);
  const { lfsSources, expectedLfsSha256, expectedLfsBytes, fg, trustedLocal, verificationInstance, ...sourceOnly } = f.options;
  const result = await downloadRepositoryBackup(sourceOnly);
  assert.equal(result.native_content_verified, false); assert.equal(result.streaming.total_payload_bytes_read, String(4 * f.source.length));
  for (const field of ['lfs_archive', 'lfs_companion', 'lfs_source_attempts', 'lfs_payloads_verified']) assert.equal(Object.hasOwn(result, field), false);
  assert.equal(Object.hasOwn(result.streaming, 'native_preflight_metered'), false); assert.deepEqual(await f.calls(), []);
});

test('pair intent is copied before awaits and malformed or incomplete pins refuse early', async t => {
  const f = await fixture(t);
  for (const extra of [{ lfsSources: undefined }, { expectedLfsSha256: undefined }, { expectedLfsBytes: undefined },
    { fg: undefined }, { verificationInstance: undefined }, { trustedLocal: undefined }, { expectedLfsBytes: 1 },
    { expectedLfsBytes: '01' }, { expectedLfsBytes: '0' }, { expectedLfsSha256: 'A'.repeat(64) },
    { lfsSources: new Array(1) }, { maximumRequests: 33 }]) assert.throws(() => repositoryBackupDownloadOptions({ ...f.options, ...extra }));
  const urls = [f.lfsUrl], options = { ...f.options, lfsSources: urls }, running = downloadRepositoryBackup(options);
  urls[0] = 'https://changed.example/'; options.expectedLfsSha256 = '0'.repeat(64); options.expectedLfsBytes = '1';
  assert.equal((await running).lfs_companion.sha256, digest(LFS));
});

test('witness remains held through native preflight and both body publications', async t => {
  const f = await fixture(t), witness = join(f.root, 'witness'), phases = new Set();
  await initializeRepositoryBackupWitness(witness, f.trustKey, f.options.policy);
  const result = await downloadRepositoryBackupWithWitness({ ...f.options, witness, async onProgress(event) {
    if (event.phase === 'publication' && !phases.has(event.event.phase)) {
      phases.add(event.event.phase);
      await assert.rejects(withRepositoryBackupWitness(witness, f.trustKey, f.options.policy, {}, handle => handle.snapshot()), { code: 'backup_witness_locked' });
    }
  } });
  assert.equal(result.highest_retained_generation_enforced, true); assert.ok(phases.has('native_verified')); assert.ok(phases.has('lfs_durable'));
  await absent(join(witness, '.witness-lock')); await f.noQuarantine();
});

test('LFS capability-file aliases cannot enter witness storage', async t => {
  const f = await fixture(t), witness = join(f.root, 'witness'), alias = join(f.root, 'alias');
  await initializeRepositoryBackupWitness(witness, f.trustKey, f.options.policy); await symlink(witness, alias);
  await assert.rejects(downloadRepositoryBackupWithWitness({ ...f.options, witness, lfsSourceFile: join(alias, 'urls.json') }), { code: 'backup_witness_separate_path_required' });
  assert.deepEqual(f.requests, []); await absent(join(witness, '.witness-lock'));
});

test('failed native child containment retains both acquired inputs and their private quarantine', { skip: process.platform === 'win32' }, async t => {
  const f = await fixture(t); await f.mode({ descendant: true }); let failure;
  try {
    await assert.rejects(f.run(), error => { failure = error; assert.equal(error.code, 'native_import_containment_failed'); return true; });
    assert.equal(failure.download_quarantine_retained, true); assert.equal(failure.retained_downloads.length, 2);
    assert.equal((await lstat(failure.retained_download)).mode & 0o777, 0o700);
    assert.deepEqual(await readFile(failure.retained_downloads[0]), f.source); assert.deepEqual(await readFile(failure.retained_downloads[1]), LFS);
    assert.ok((await lstat(failure.approval_scratch)).isDirectory()); assert.deepEqual(await readdir(f.destination), []);
  } finally {
    // This PID was explicitly created by our test peer, not discovered from an
    // operator directory. Contain it before the test removes retained inputs.
    const pid = Number(await readFile(f.descendantPid, 'utf8')); try { process.kill(pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
});

function argsFor(f, sourceFile, lfsSourceFile) {
  const args = ['--sources', sourceFile, '--lfs-sources', lfsSourceFile, '--expected-lfs-sha256', digest(LFS),
    '--expected-lfs-bytes', String(LFS.length), '--fg', f.fg, '--trusted-local', '--verification-instance', '992',
    '--approval', f.approval, '--trust-key', f.trustKey, '--ca-file', f.caFile, '--replica-directory', f.destination,
    '--max-total-read-bytes', String(f.needed), '--max-requests', '2'];
  for (const [name, value] of Object.entries(f.options.policy)) args.push('--' + name.replaceAll('_', '-'), value);
  return args;
}
test('actual CLI reads two private URL files and emits the complete retained pair', async t => {
  const f = await fixture(t), sources = join(f.root, 'sources.json'), lfsSources = join(f.root, 'lfs-sources.json');
  await writeFile(sources, JSON.stringify([f.url]), { mode: 0o600 }); await writeFile(lfsSources, JSON.stringify([f.lfsUrl]), { mode: 0o600 });
  const args = argsFor(f, sources, lfsSources), parsed = downloadArguments(args);
  assert.equal(parsed.expectedLfsBytes, String(LFS.length)); assert.equal(parsed.maximumRequests, 2);
  const missing = [...args], at = missing.indexOf('--expected-lfs-bytes'); missing.splice(at, 2);
  assert.throws(() => downloadArguments(missing), code('backup_lfs_pair_required'));
  const result = await runNativeProcess(process.execPath, [CLI, ...args, '--progress-json'], { timeoutMs: 10000 });
  assert.equal(result.code, 0, result.stderr.toString());
  const report = JSON.parse(result.stdout); assert.equal(report.lfs_payloads_verified, true); assert.equal(report.native_content_verified, true);
  assert.deepEqual(await readFile(report.lfs_archive), LFS); redacted(report); assert.ok(!result.stderr.toString().includes('capability-do-not-log'));
  await f.noQuarantine();
});
