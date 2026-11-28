// Real files, Ed25519, subprocess ownership and publication. The child below
// is explicitly a protocol fixture over opaque bytes, NOT a native fg/FGLF
// decoder, authority backend, graph verification or restore acceptance test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, readdir, lstat, rm, unlink, link, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { replicateRepositoryBackup, repositoryBackupReplicationOptions } from '../lib/repository-backup-replication.mjs';
import { replicationArguments, runReplicationCommand } from '../replicate_repository_backup_native.mjs';

const ID = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: 'sha256' };
const POLICY = { ...ID, minimum_head_generation: '1' };
const LFS = Buffer.alloc(65553, 0x61), sha = bytes => createHash('sha256').update(bytes).digest('hex');
const absent = path => assert.rejects(lstat(path), { code: 'ENOENT' });
const approvalModule = new URL('../lib/repository-backup-approval.mjs', import.meta.url).href;
const nativeApprovalModule = new URL('../lib/repository-backup-native-approval.mjs', import.meta.url).href;

async function fixture(t, format = 'sha256') {
  const root = await mkdtemp(join(tmpdir(), 'fg-paired-replica-'));
  const retainedScratch = new Set();
  t.after(async () => { for (const path of retainedScratch) await rm(path, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true }); });
  const destination = join(root, 'replicas'); await mkdir(destination, { mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const trustKey = join(root, 'trust.pem');
  await writeFile(trustKey, publicKey.export({ format: 'pem', type: 'spki' }), { mode: 0o600 });
  const lfsArchive = join(root, 'source.fglf'), fg = join(root, 'fake-native.mjs'), config = join(root, 'peer.json'), log = join(root, 'calls');
  await writeFile(lfsArchive, LFS, { mode: 0o600 });
  await writeFile(config, '{}', { mode: 0o600 });
  const identity = { ...ID, object_format: format }, policy = { ...identity, minimum_head_generation: '1' };
  async function signed(name, generation = '7', lfsSha = sha(LFS)) {
    const input = join(root, name + '.fgbackup'), approval = join(root, name + '.approval');
    const bytes = Buffer.from(JSON.stringify({ ...identity, head_generation: generation,
      TEST_ONLY_EXPECTED_COMPANION: lfsSha }));
    await writeFile(input, bytes, { mode: 0o600 });
    const signed = await signRepositoryBackupFile(input, Buffer.from(privateKey.export({ format: 'pem', type: 'pkcs8' })),
      { ...identity, head_generation: generation, issued_at: '2026-01-01T00:00:00Z', expires_at: null });
    await writeFile(approval, signed.envelope, { mode: 0o600 });
    return { input, approval };
  }
  const row = await signed('source'), envelope = await readFile(row.approval), bytes = await readFile(row.input);
  // This peer authenticates real DSSE bytes and enforces the child command
  // grammar/pair pins, but models native archive semantics using opaque JSON.
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
if (hash(lfs) !== flags['--expected-lfs-sha256'] || hash(lfs) !== source.TEST_ONLY_EXPECTED_COMPANION) process.exit(82);
if (config.retain) { await mkdir(args[3]); await writeFile(join(args[3], 'UNKNOWN_NATIVE_WORK'), 'retained'); process.exit(83); }
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
  const options = { candidates: [row], trustKey, policy, destination, maximumBytes: LFS.length,
    lfsArchive, expectedLfsSha256: sha(LFS), fg, trustedLocal: true, verificationInstance: '992', timeoutMs: 10000 };
  const paths = { input: join(destination, `archive-sha256-${sha(bytes)}.fgbackup`),
    approval: join(destination, `checkpoint-sha256-${sha(envelope)}.approval.json`),
    lfs: join(destination, `lfs-sha256-${sha(LFS)}.fglf`) };
  async function calls() { try { return (await readFile(log, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; } }
  const run = async extra => { try { return await replicateRepositoryBackup({ ...options, ...extra }); }
    catch (error) { if (error.verification_scratch) retainedScratch.add(error.verification_scratch); throw error; } };
  return { root, destination, row, signed, paths, options, bytes, envelope, run, calls,
    mode: value => writeFile(config, JSON.stringify(value)) };
}

for (const format of ['sha1', 'sha256']) test(`paired publication verifies exact source and LFS before approval (${format})`, async t => {
  const f = await fixture(t, format), phases = [];
  const result = await f.run({ async onProgress(event) {
    phases.push(event.phase);
    if (['archive_durable', 'lfs_durable'].includes(event.phase)) await absent(f.paths.approval);
  } });
  assert.deepEqual(result.candidate, { input: f.paths.input, approval: f.paths.approval });
  assert.equal(result.lfs_archive, f.paths.lfs); assert.deepEqual(await readFile(result.lfs_archive), LFS);
  assert.deepEqual(await readFile(result.candidate.input), f.bytes);
  assert.deepEqual(await readFile(result.candidate.approval), f.envelope);
  assert.equal(result.native_content_verified, true); assert.equal(result.lfs_companion_signed, false);
  assert.equal(result.lfs_before_approval, true); assert.equal(result.lfs_durable_before_acknowledgement, true);
  assert.equal(result.lfs_companion.bytes, String(LFS.length)); assert.equal(result.lfs_companion.exact_snapshot, true);
  assert.equal(result.streaming.total_payload_bytes_read, String(f.bytes.length * 3 + LFS.length * 2));
  assert.equal(result.streaming.native_preflight_metered, false);
  assert(phases.indexOf('native_verified') < phases.indexOf('copy_archive'));
  assert(phases.indexOf('archive_durable') < phases.indexOf('lfs_durable'));
  assert.equal((await f.calls()).length, 1);
  for (const path of Object.values(f.paths)) { const stat = await lstat(path); assert.equal(stat.mode & 0o777, 0o600); assert.equal(stat.nlink, 1); }
  // A second directory can be recovered solely from the retained pair and the
  // independent trust key after every original archive/control is gone.
  await unlink(f.row.input); await unlink(f.row.approval); await unlink(f.options.lfsArchive);
  const other = join(f.root, 'other'); await mkdir(other, { mode: 0o700 });
  const copied = await f.run({ candidates: [result.candidate], lfsArchive: result.lfs_archive, destination: other });
  assert.deepEqual(await readFile(copied.lfs_archive), LFS);
});

test('exact paired retry verifies and synchronizes all files without inode replacement', async t => {
  const f = await fixture(t), first = await f.run();
  const before = await Promise.all(Object.values(f.paths).map(path => lstat(path, { bigint: true })));
  const second = await f.run();
  assert.deepEqual(second.candidate, first.candidate); assert.equal(second.lfs_archive, first.lfs_archive);
  assert.deepEqual(second.disposition, { archive: 'reused', approval: 'reused', lfs: 'reused' });
  assert.equal(first.lfs_before_approval, true); assert.equal(second.lfs_before_approval, false);
  assert.equal(second.lfs_durable_before_acknowledgement, true);
  assert.equal(second.streaming.total_payload_bytes_read, String(f.bytes.length * 2 + LFS.length));
  const after = await Promise.all(Object.values(f.paths).map(path => lstat(path, { bigint: true })));
  assert.deepEqual(after.map(stat => stat.ino), before.map(stat => stat.ino));
  assert.equal((await f.calls()).length, 2);
});

test('adding a companion to an existing source-only approval makes no historical ordering claim', async t => {
  const f = await fixture(t);
  const { lfsArchive, expectedLfsSha256, fg, trustedLocal, verificationInstance, ...sourceOnly } = f.options;
  const original = await replicateRepositoryBackup(sourceOnly);
  assert.equal(Object.hasOwn(original, 'lfs_before_approval'), false);
  assert.equal(Object.hasOwn(original, 'lfs_durable_before_acknowledgement'), false);
  await absent(f.paths.lfs);
  const approval = await lstat(f.paths.approval, { bigint: true });
  const paired = await f.run();
  assert.deepEqual(paired.disposition, { archive: 'reused', approval: 'reused', lfs: 'created' });
  assert.equal(paired.lfs_before_approval, false);
  assert.equal(paired.lfs_durable_before_acknowledgement, true);
  assert.equal((await lstat(f.paths.approval, { bigint: true })).ino, approval.ino);
  assert.deepEqual(await readFile(f.paths.lfs), LFS);
  assert.deepEqual(await readFile(f.paths.approval), f.envelope);
});

test('copy/readback budget covers both bodies and refuses one byte short before native work', async t => {
  const f = await fixture(t), needed = f.bytes.length * 3 + LFS.length * 2;
  await assert.rejects(f.run({ maximumTotalBytes: needed - 1 }), { code: 'backup_replication_read_budget' });
  assert.deepEqual(await readdir(f.destination), []); assert.deepEqual(await f.calls(), []);
  const result = await f.run({ maximumTotalBytes: needed });
  assert.equal(result.streaming.total_payload_bytes_read, String(needed));
});

test('companion has its own size ceiling before any native work or body staging', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ maximumBytes: LFS.length - 1 }), { code: 'backup_lfs_archive_size_or_type' });
  assert.deepEqual(await f.calls(), []); assert.deepEqual(await readdir(f.destination), []);
});

for (const kind of ['missing', 'digest', 'wrong-pair', 'bad-receipt']) test(`paired ${kind} refusal cannot fall back to an older source`, async t => {
  const f = await fixture(t), high = await f.signed('highest', '8', kind === 'wrong-pair' ? 'b'.repeat(64) : sha(LFS));
  if (kind === 'missing') await unlink(f.options.lfsArchive);
  if (kind === 'digest') await writeFile(f.options.lfsArchive, Buffer.alloc(LFS.length, 0x62));
  if (kind === 'bad-receipt') await f.mode({ badReceipt: true });
  await assert.rejects(f.run({ candidates: [f.row, high] }));
  assert.deepEqual(await readdir(f.destination), []);
  const calls = await f.calls(); assert(calls.length <= 1);
  if (calls.length) assert.equal(calls[0][2], high.input);
});

test('source or companion substitutions after native preflight refuse before publication', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ async onProgress(event) {
    if (event.phase === 'native_verified') await writeFile(f.options.lfsArchive, Buffer.alloc(LFS.length, 0x62));
  } }), { code: 'backup_replica_file_changed' });
  assert.deepEqual(await readdir(f.destination), []);
});

test('cancellation after durable source leaves it reusable and approval absent', async t => {
  const f = await fixture(t), stop = new AbortController();
  await assert.rejects(f.run({ signal: stop.signal, onProgress(event) {
    if (event.phase === 'archive_durable') stop.abort();
  } }), error => { assert.equal(error.code, 'backup_cancelled'); assert.equal(error.publication_state, 'archive_durable'); return true; });
  await absent(f.paths.approval); await absent(f.paths.lfs);
  const before = await lstat(f.paths.input, { bigint: true }), result = await f.run();
  assert.equal(result.disposition.archive, 'reused'); assert.equal((await lstat(f.paths.input, { bigint: true })).ino, before.ino);
});

test('cancellation after durable companion preserves both bodies for the exact retry', async t => {
  const f = await fixture(t), stop = new AbortController();
  await assert.rejects(f.run({ signal: stop.signal, onProgress(event) {
    if (event.phase === 'lfs_durable') stop.abort();
  } }), error => { assert.equal(error.code, 'backup_cancelled'); assert.equal(error.lfs_publication_state, 'lfs_durable'); return true; });
  await absent(f.paths.approval);
  const result = await f.run(); assert.equal(result.disposition.archive, 'reused'); assert.equal(result.disposition.lfs, 'reused');
});

test('wrong existing companion is never overwritten and cannot publish an approval', async t => {
  const f = await fixture(t); await writeFile(f.paths.lfs, Buffer.alloc(LFS.length, 0x62), { mode: 0o600 });
  await assert.rejects(f.run(), { code: 'backup_replica_digest_mismatch' });
  assert.deepEqual(await readFile(f.paths.lfs), Buffer.alloc(LFS.length, 0x62)); await absent(f.paths.approval);
});

test('post-readback companion mutation refuses before approval', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ async onProgress(event) {
    if (event.phase === 'lfs_durable') await writeFile(f.paths.lfs, Buffer.alloc(LFS.length, 0x62));
  } }), { code: 'backup_replica_file_changed' });
  await absent(f.paths.approval);
});

test('hard-link, source and parent-directory aliases refuse without publication', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ lfsArchive: f.row.input, expectedLfsSha256: sha(f.bytes) }), { code: 'backup_lfs_separate_path_required' });
  await link(f.options.lfsArchive, f.paths.lfs);
  await assert.rejects(f.run(), { code: 'backup_lfs_separate_path_required' });
  await unlink(f.paths.lfs);
  const alias = join(f.root, 'alias'); await symlink(f.destination, alias);
  const nested = join(f.destination, 'nested.fglf'); await writeFile(nested, LFS);
  await assert.rejects(f.run({ lfsArchive: join(alias, 'nested.fglf') }), { code: 'backup_lfs_separate_path_required' });
  await absent(f.paths.approval); assert.deepEqual(await f.calls(), []);
});

test('unknown native verification scratch is retained and never auto-cleaned by publisher', async t => {
  const f = await fixture(t); await f.mode({ retain: true });
  let failure;
  await assert.rejects(f.run(), error => { failure = error; return error.code === 'backup_native_refused'; });
  assert(failure.verification_scratch);
  assert.equal(await readFile(join(failure.verification_scratch, 'native', 'UNKNOWN_NATIVE_WORK'), 'utf8'), 'retained');
  assert.deepEqual(await readdir(f.destination), []);
});

test('paired CLI grammar and output retain companion recovery pins', async t => {
  const f = await fixture(t), o = f.options;
  const args = ['--candidate', f.row.input, f.row.approval, '--trust-key', o.trustKey,
    '--replica-directory', o.destination, ...Object.entries(o.policy).flatMap(([key, value]) => ['--' + key.replaceAll('_', '-'), value]),
    '--lfs-archive', o.lfsArchive, '--expected-lfs-sha256', o.expectedLfsSha256,
    '--fg', o.fg, '--trusted-local', '--verification-instance', o.verificationInstance];
  assert.equal(replicationArguments(args).expectedLfsSha256, sha(LFS));
  assert.throws(() => replicationArguments([...args, '--lfs-archive', o.lfsArchive]), { code: 'backup_duplicate_option' });
  const output = { text: '', write(text, done) { this.text += text; done(); } };
  await runReplicationCommand(args, output);
  const result = JSON.parse(output.text); assert.equal(result.lfs_archive, f.paths.lfs);
  assert.equal(result.lfs_companion.sha256, sha(LFS));
});

test('partial pairs and native-only options cannot downgrade to source-only replication', async t => {
  const f = await fixture(t), { lfsArchive, expectedLfsSha256, fg, trustedLocal, verificationInstance, ...base } = f.options;
  assert.throws(() => repositoryBackupReplicationOptions({ ...base, lfsArchive }), { code: 'backup_lfs_pair_required' });
  assert.throws(() => repositoryBackupReplicationOptions({ ...base, expectedLfsSha256 }), { code: 'backup_lfs_pair_required' });
  assert.throws(() => repositoryBackupReplicationOptions({ ...base, fg }), { code: 'backup_replication_inapplicable_native_option' });
  assert.throws(() => repositoryBackupReplicationOptions({ ...base, lfsArchive, expectedLfsSha256, fg, verificationInstance }),
    { code: 'backup_explicit_local_operation_required' });
});
