// Real files, Ed25519 authentication and child processes exercise the operator
// contract. The child is a protocol fixture, NOT native FGLF/Git recovery proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile, readFile, lstat, mkdir, rm, link, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { nativeBackupApprovalBinding } from '../lib/repository-backup-native-approval.mjs';
import { repositoryBackupOptions, runApprovedRepositoryBackup } from '../lib/repository-backup-native.mjs';
import { nativeBackupArguments } from '../restore_repository_backup_native.mjs';
import { runNativeProcess } from '../lib/native-process-owner.mjs';

const SOURCE = Buffer.alloc(65537, 42), LFS = Buffer.alloc(131073, 108);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const identity = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16) };
const cli = fileURLToPath(new URL('../restore_repository_backup_native.mjs', import.meta.url));
const absent = path => assert.rejects(lstat(path), { code: 'ENOENT' });
const failure = expected => error => { assert.equal(error.code, expected); return true; };

async function fixture(t, format = 'sha256') {
  const root = await mkdtemp(join(tmpdir(), 'fg-signed-lfs-test-')), retained = new Set();
  t.after(async () => {
    for (const path of retained) await rm(path, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  });
  const paths = { fg: join(root, 'native-schema-peer'), input: join(root, 'source.fgbackup'),
    lfsArchive: join(root, 'source.fglfs'), approval: join(root, 'approval.json'), trustKey: join(root, 'public.pem'),
    destination: join(root, 'restored'), approvalRecord: join(root, 'restore-approval.json') };
  const config = join(root, 'peer-config.json'), log = join(root, 'peer-calls.jsonl'), privatePath = join(root, 'private.pem');
  const keys = generateKeyPairSync('ed25519');
  const privatePem = Buffer.from(keys.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  const publicPem = Buffer.from(keys.publicKey.export({ format: 'pem', type: 'spki' }));
  await writeFile(paths.input, SOURCE); await writeFile(paths.lfsArchive, LFS);
  await writeFile(paths.trustKey, publicPem); await writeFile(privatePath, privatePem, { mode: 0o600 });
  const signed = await signRepositoryBackupFile(paths.input, privatePem,
    { ...identity, object_format: format, head_generation: '9007199254740993' });
  privatePem.fill(0); await writeFile(paths.approval, signed.envelope);
  const configure = mode => writeFile(config, JSON.stringify(mode)); await configure({});
  await writeFile(paths.fg, `#!${process.execPath}
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { verifyRepositoryBackupApproval } from ${JSON.stringify(new URL('../lib/repository-backup-approval.mjs', import.meta.url).href)};
import { nativeBackupApprovalBinding } from ${JSON.stringify(new URL('../lib/repository-backup-native-approval.mjs', import.meta.url).href)};
const mode = JSON.parse(fs.readFileSync(${JSON.stringify(config)}, 'utf8'));
const args = process.argv.slice(2), operation = args[1], flags = {};
assert.equal(args[0], 'backup'); assert.ok(['verify', 'restore'].includes(operation));
assert.equal(fs.readFileSync(0).length, 0); assert.ok(!args.includes(${JSON.stringify(privatePath)}));
for (let i = 4; i < args.length; i++) {
  const flag = args[i]; assert.ok(!Object.hasOwn(flags, flag));
  flags[flag] = ['--trusted-local', '--resume'].includes(flag) ? true : args[++i];
}
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ operation, args }) + '\\n');
const policy = Object.fromEntries(['tenant_id','repository_id','incarnation_id','object_format','minimum_head_generation']
  .map(k => [k, flags['--' + k.replaceAll('_', '-')]]));
const envelope = fs.readFileSync(flags['--approval']), key = fs.readFileSync(flags['--trust-key']);
const authentication = (await verifyRepositoryBackupApproval(envelope, key, policy)).authentication;
const statement = authentication.statement, bytes = fs.readFileSync(args[2]);
const hash = value => createHash('sha256').update(value).digest('hex');
if (hash(bytes) !== flags['--expected-sha256'] || hash(bytes) !== statement.artifact.sha256) process.exit(91);
let companion;
if (flags['--lfs-archive'] || mode.unsolicited) {
  const body = fs.readFileSync(flags['--lfs-archive'] ?? ${JSON.stringify(paths.lfsArchive)});
  if (!mode.unsolicited && hash(body) !== flags['--expected-lfs-sha256']) process.exit(92);
  companion = { sha256: hash(body), bytes: body.length, objects: 2, payload_bytes: body.length - 100, exact_snapshot: true };
}
if (mode.refuse === operation) process.exit(93);
let already = false;
if (operation === 'restore') {
  const marker = JSON.stringify({ approval: hash(envelope), lfs: companion?.sha256 ?? null });
  try { fs.mkdirSync(args[3], { mode: 0o700 }); fs.writeFileSync(args[3] + '/TEST_ONLY_NOT_A_NATIVE_REPOSITORY', marker); }
  catch (error) {
    if (error.code !== 'EEXIST' || !flags['--resume'] || fs.readFileSync(args[3] + '/TEST_ONLY_NOT_A_NATIVE_REPOSITORY', 'utf8') !== marker) process.exit(94);
    already = true;
  }
  if (mode.loseRestoreResponse && !already) process.exit(95);
}
const pins = nativeBackupApprovalBinding(envelope, key, policy);
const receipt = { type: 'repository_source_backup_' + operation, schema_version: 1, sha256: hash(bytes),
  ...Object.fromEntries(['tenant_id','repository_id','incarnation_id','object_format'].map(k => [k, statement[k]])),
  head_generation: BigInt(statement.head_generation), objects: 2, references: 1, payload_bytes: bytes.length - 9,
  complete: true, scope: 'authority_and_selected_git_objects', object_graph_verified: true,
  original_payload_commitments_verified: true, node_closed: true, signature_verified: true, routing_published: false,
  archive_bytes: bytes.length, transport_version: 1, retained_outcome_checkpoint_verified: false,
  retained_outcome_checkpoint_root: null, retained_outcome_objects: 0, retained_outcome_payload_bytes: 0,
  ...(operation === 'verify' ? { local_edges: 1, external_gitlinks: 0, verification_instance: BigInt(flags['--verification-instance']),
    authority_import_verified: true, git_payloads_written: false, destination_authority_published: false, scratch_removed: true,
    destination_readback_verified: false, newest_checkpoint_verified: false, external_artifacts_verified: false }
    : { destination_instance: BigInt(flags['--destination-instance']), source_tokens_preserved: false, reopened_and_verified: true,
      external_artifacts_restored: false, streaming: true, resume_requested: Boolean(flags['--resume']), already_published: already }),
  approval: { type: 'repository_backup_approval_authentication', signature_verified: true, ...pins,
    minimum_head_generation: policy.minimum_head_generation, statement, newest_checkpoint_verified: false, complete_capsule_verified: false } };
if (companion && !mode.missingCompanion) {
  receipt.lfs_companion = { ...companion, ...mode.companion, ...(operation === 'restore' ? mode.restoreCompanion : {}) };
  receipt[operation === 'verify' ? 'lfs_payloads_verified' : 'lfs_payloads_restored'] = mode.lfsComplete !== false;
}
const text = JSON.stringify(receipt, (_, value) => typeof value === 'bigint' ? '~u64:' + value : value)
  .replace(/"~u64:([0-9]+)"/g, '$1');
process.stdout.write(text + '\\n');
`, { mode: 0o700 });
  const options = { ...paths, operation: 'restore', expectedLfsSha256: digest(LFS),
    policy: { ...identity, object_format: format, minimum_head_generation: '1' }, verificationInstance: '11', destinationInstance: '12',
    trustedLocal: true, maximumBytes: 262144, timeoutMs: 10000 };
  const run = async (extra = {}) => {
    try { return await runApprovedRepositoryBackup({ ...options, ...extra }); }
    catch (error) {
      for (const path of [error.verification_scratch, error.approval_scratch]) if (path) retained.add(path);
      throw error;
    }
  };
  const calls = async () => {
    try { return (await readFile(log, 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  };
  return { root, paths, options, run, calls, configure, signed, publicPem, privatePath, retained,
    verify: () => ({ operation: 'verify', destination: undefined, destinationInstance: undefined, approvalRecord: undefined }),
    sourceOnly: () => ({ lfsArchive: undefined, expectedLfsSha256: undefined }) };
}

for (const format of ['sha1', 'sha256']) test(`${format}: signed restore verifies and restores the same pinned LFS companion`, async t => {
  const f = await fixture(t, format), result = await f.run(), calls = await f.calls();
  assert.equal(result.state, 'complete'); assert.equal(result.authentication.signature_verified, true);
  assert.deepEqual(result.authentication.statement, f.signed.statement);
  assert.equal(result.native.lfs_payloads_restored, true); assert.equal(result.native.external_artifacts_restored, false);
  assert.equal(result.native.head_generation, '9007199254740993');
  assert.deepEqual(result.native.lfs_companion, { sha256: digest(LFS), bytes: String(LFS.length), objects: '2',
    payload_bytes: String(LFS.length - 100), exact_snapshot: true });
  assert.ok(Object.isFrozen(result.native.lfs_companion));
  assert.deepEqual(calls.map(v => v.operation), ['verify', 'restore']);
  for (const { args } of calls) {
    assert.equal(args[args.indexOf('--lfs-archive') + 1], f.paths.lfsArchive);
    assert.equal(args[args.indexOf('--expected-lfs-sha256') + 1], digest(LFS));
    assert.ok(!args.includes(f.privatePath)); assert.ok(!args.includes(f.paths.approval));
  }
  const record = JSON.parse(await readFile(f.paths.approvalRecord, 'utf8'));
  assert.equal(record.type, 'repository_backup_restore_approval_v3');
  assert.deepEqual(record.lfs_companion, { sha256: digest(LFS), bytes: String(LFS.length) });
  assert.equal(record.approval_binding_sha256, nativeBackupApprovalBinding(f.signed.envelope, f.publicPem, f.options.policy).binding_sha256);
  assert.deepEqual(await readFile(f.paths.input), SOURCE); assert.deepEqual(await readFile(f.paths.lfsArchive), LFS);
});

test('paired verify reports exact LFS completion without submitting a restore or record', async t => {
  const f = await fixture(t), result = await f.run(f.verify());
  assert.equal(result.native.lfs_payloads_verified, true); assert.equal(result.native.external_artifacts_verified, false);
  assert.equal(result.destination_changed, false);
  assert.deepEqual((await f.calls()).map(v => v.operation), ['verify']);
  await absent(f.paths.destination); await absent(f.paths.approvalRecord);
});

test('source-only v2 record bytes remain unchanged and resume never adds a companion', async t => {
  const f = await fixture(t), result = await f.run(f.sourceOnly());
  const pins = nativeBackupApprovalBinding(f.signed.envelope, f.publicPem, f.options.policy);
  const expected = Buffer.from(JSON.stringify({ type: 'repository_backup_restore_approval_v2', destination: f.paths.destination,
    native_signed_mode: true, approval_binding_sha256: pins.binding_sha256, destination_instance: '12',
    trusted_key_id: result.authentication.trusted_key_id, policy: f.options.policy, statement: f.signed.statement }) + '\n');
  assert.deepEqual(await readFile(f.paths.approvalRecord), expected); assert.equal(result.native.lfs_companion, undefined);
  await assert.rejects(f.run({ resume: true }), failure('backup_restore_approval_record_mismatch'));
  assert.equal((await f.calls()).length, 2);
  assert.equal((await f.run({ ...f.sourceOnly(), resume: true })).native.already_published, true);
});

test('source-only callers reject unsolicited companion claims', async t => {
  const f = await fixture(t); await f.configure({ unsolicited: true });
  await assert.rejects(f.run(f.sourceOnly()), failure('backup_native_receipt_mismatch'));
  assert.deepEqual((await f.calls()).map(v => v.operation), ['verify']);
  await absent(f.paths.destination); await absent(f.paths.approvalRecord);
});

test('paired options require explicit canonical digest and own the strings before awaiting', async t => {
  const f = await fixture(t);
  for (const extra of [{ expectedLfsSha256: undefined }, { lfsArchive: undefined },
    { expectedLfsSha256: 'A'.repeat(64) }, { expectedLfsSha256: '1'.repeat(63) }, { expectedLfsSha256: 12 }]) {
    assert.throws(() => repositoryBackupOptions({ ...f.options, ...extra }));
  }
  const raw = { ...f.options, ...f.verify() }, running = runApprovedRepositoryBackup(raw);
  raw.lfsArchive = join(f.root, 'absent'); raw.expectedLfsSha256 = '0'.repeat(64);
  const result = await running; assert.equal(result.native.lfs_companion.sha256, digest(LFS));
});

test('wrong companion pin refuses before child invocation or output reservation', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ expectedLfsSha256: '0'.repeat(64) }), failure('backup_lfs_digest_mismatch'));
  assert.deepEqual(await f.calls(), []); await absent(f.paths.destination); await absent(f.paths.approvalRecord);
});

test('missing, symlinked and over-budget companion inputs refuse without native work', async t => {
  const f = await fixture(t), alias = join(f.root, 'lfs-link'); await symlink(f.paths.lfsArchive, alias);
  await assert.rejects(f.run({ lfsArchive: join(f.root, 'absent') }), { code: 'ENOENT' });
  await assert.rejects(f.run({ lfsArchive: alias }), { code: 'ELOOP' });
  await assert.rejects(f.run({ maximumBytes: LFS.length - 1 }), failure('backup_file_size_or_type'));
  assert.deepEqual(await f.calls(), []); await absent(f.paths.destination); await absent(f.paths.approvalRecord);
});

test('source approval authentication precedes any companion acquisition', async t => {
  const f = await fixture(t), other = generateKeyPairSync('ed25519');
  await writeFile(f.paths.trustKey, other.publicKey.export({ format: 'pem', type: 'spki' }));
  await assert.rejects(f.run({ lfsArchive: join(f.root, 'absent') }), failure('backup_untrusted_signer'));
  assert.deepEqual(await f.calls(), []); await absent(f.paths.destination);
});

for (const [name, mode, code] of [
  ['missing companion', { missingCompanion: true }, 'backup_native_receipt_mismatch'],
  ['incomplete payloads', { lfsComplete: false }, 'backup_native_receipt_mismatch'],
  ['changed digest', { companion: { sha256: '0'.repeat(64) } }, 'backup_native_lfs_receipt_mismatch'],
  ['changed bytes', { companion: { bytes: LFS.length - 1 } }, 'backup_native_lfs_receipt_mismatch'],
  ['unverified snapshot', { companion: { exact_snapshot: false } }, 'backup_native_lfs_receipt_mismatch'],
  ['unknown metadata', { companion: { unrecognized: true } }, 'backup_native_lfs_receipt_mismatch'],
  ['string counter', { companion: { objects: '2' } }, 'backup_native_lfs_receipt_mismatch'],
]) test(`native ${name} refuses before recording or restoring`, async t => {
  const f = await fixture(t); await f.configure(mode);
  await assert.rejects(f.run(), failure(code));
  assert.deepEqual((await f.calls()).map(v => v.operation), ['verify']);
  await absent(f.paths.destination); await absent(f.paths.approvalRecord);
});

for (const field of ['objects', 'payload_bytes']) test(`restore ${field} must match the verified companion counts`, async t => {
  const f = await fixture(t);
  await f.configure({ restoreCompanion: { [field]: field === 'objects' ? 3 : LFS.length - 99 } });
  await assert.rejects(f.run(), error => {
    assert.equal(error.code, 'backup_restore_preflight_mismatch'); assert.equal(error.state, 'restore_attempted_unknown'); return true;
  });
  assert.deepEqual((await f.calls()).map(v => v.operation), ['verify', 'restore']);
  assert.ok((await lstat(f.paths.destination)).isDirectory());
  assert.equal(JSON.parse(await readFile(f.paths.approvalRecord)).type, 'repository_backup_restore_approval_v3');
});

for (const phase of ['preflight_verified', 'restore_starting']) test(`companion mutation at ${phase} refuses before native restore`, async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ async onProgress(event) {
    if (event.phase === phase) await writeFile(f.paths.lfsArchive, Buffer.alloc(LFS.length, 109));
  } }), failure('backup_lfs_changed_after_verification'));
  assert.deepEqual((await f.calls()).map(v => v.operation), ['verify']); await absent(f.paths.destination);
  if (phase === 'preflight_verified') await absent(f.paths.approvalRecord);
  else assert.equal(JSON.parse(await readFile(f.paths.approvalRecord)).lfs_companion.sha256, digest(LFS));
});

test('changed companion after acquisition is pinned again by the native verifier', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ async onProgress(event) {
    if (event.phase === 'authenticated') await writeFile(f.paths.lfsArchive, Buffer.alloc(LFS.length, 109));
  } }), error => { assert.equal(error.code, 'backup_native_refused'); assert.equal(error.native_exit_code, 92); return true; });
  assert.deepEqual((await f.calls()).map(v => v.operation), ['verify']);
  await absent(f.paths.destination); await absent(f.paths.approvalRecord);
});

test('lost restore response preserves v3 intent and resume cannot drop or change LFS', async t => {
  const f = await fixture(t); await f.configure({ loseRestoreResponse: true });
  await assert.rejects(f.run(), error => {
    assert.equal(error.code, 'backup_native_refused'); assert.equal(error.state, 'restore_attempted_unknown'); return true;
  });
  const originalRecord = await readFile(f.paths.approvalRecord), alternate = join(f.root, 'other.fglfs');
  const changed = Buffer.alloc(LFS.length, 109); await writeFile(alternate, changed);
  await assert.rejects(f.run({ ...f.sourceOnly(), resume: true }), failure('backup_restore_approval_record_mismatch'));
  await assert.rejects(f.run({ resume: true, lfsArchive: alternate, expectedLfsSha256: digest(changed) }), failure('backup_restore_approval_record_mismatch'));
  assert.equal((await f.calls()).length, 2); assert.deepEqual(await readFile(f.paths.approvalRecord), originalRecord);
  await writeFile(alternate, LFS); await f.configure({});
  const resumed = await f.run({ resume: true, lfsArchive: alternate });
  assert.equal(resumed.native.already_published, true); assert.equal(resumed.native.lfs_payloads_restored, true);
  assert.deepEqual(await readFile(f.paths.approvalRecord), originalRecord);
});

test('companion cannot alias source bytes or a record through a hard link or parent symlink', async t => {
  const f = await fixture(t), hard = join(f.root, 'same-source'), alias = join(f.root, 'parent-alias');
  await link(f.paths.input, hard); await symlink(f.root, alias);
  await assert.rejects(f.run({ lfsArchive: hard, expectedLfsSha256: digest(SOURCE) }), failure('backup_lfs_separate_path_required'));
  await assert.rejects(f.run({ lfsArchive: join(alias, 'source.fglfs'), approvalRecord: f.paths.lfsArchive }), failure('backup_lfs_separate_path_required'));
  assert.deepEqual(await readFile(f.paths.input), SOURCE); assert.deepEqual(await readFile(f.paths.lfsArchive), LFS);
  assert.deepEqual(await f.calls(), []); await absent(f.paths.destination);
});

test('companion inside an existing resume destination refuses before child work', async t => {
  const f = await fixture(t), alias = join(f.root, 'dest-alias');
  await mkdir(f.paths.destination, { mode: 0o700 }); await symlink(f.paths.destination, alias);
  const inside = join(f.paths.destination, 'archive.fglfs'); await writeFile(inside, LFS);
  await assert.rejects(f.run({ resume: true, lfsArchive: join(alias, 'archive.fglfs') }), failure('backup_lfs_separate_path_required'));
  assert.deepEqual(await f.calls(), []); assert.deepEqual(await readFile(inside), LFS);
});

test('cancellation after paired preflight cannot publish a restore approval or start restore', async t => {
  const f = await fixture(t), controller = new AbortController();
  await assert.rejects(f.run({ signal: controller.signal, onProgress(event) {
    if (event.phase === 'preflight_verified') controller.abort();
  } }), failure('backup_cancelled'));
  assert.deepEqual((await f.calls()).map(v => v.operation), ['verify']);
  await absent(f.paths.destination); await absent(f.paths.approvalRecord);
});

function cliArgs(f, operation = 'restore') {
  const args = [operation, f.paths.input, '--fg', f.paths.fg, '--approval', f.paths.approval, '--trust-key', f.paths.trustKey,
    '--trusted-local', '--verification-instance', '11', '--lfs-archive', f.paths.lfsArchive, '--expected-lfs-sha256', digest(LFS)];
  for (const [name, value] of Object.entries(f.options.policy)) args.push('--' + name.replaceAll('_', '-'), value);
  if (operation === 'restore') args.push('--destination', f.paths.destination, '--destination-instance', '12', '--approval-record', f.paths.approvalRecord);
  return args;
}
test('restore CLI carries both companion flags and enforces pair and duplicate grammar', async t => {
  const f = await fixture(t), args = cliArgs(f), parsed = nativeBackupArguments(args);
  assert.equal(parsed.lfsArchive, f.paths.lfsArchive); assert.equal(parsed.expectedLfsSha256, digest(LFS));
  const missing = [...args], index = missing.indexOf('--expected-lfs-sha256'); missing.splice(index, 2);
  assert.throws(() => nativeBackupArguments(missing), failure('backup_lfs_pair_required'));
  assert.throws(() => nativeBackupArguments([...args, '--lfs-archive', f.paths.lfsArchive]), failure('backup_unknown_or_duplicate_option'));
  const result = await runNativeProcess(process.execPath, [cli, ...args], { timeoutMs: 10000 });
  assert.equal(result.code, 0, result.stderr.toString());
  const report = JSON.parse(result.stdout); assert.equal(report.state, 'complete'); assert.equal(report.native.lfs_payloads_restored, true);
});

test('verify CLI exposes companion refusal without creating a destination', async t => {
  const f = await fixture(t), args = cliArgs(f, 'verify');
  args[args.indexOf('--expected-lfs-sha256') + 1] = '0'.repeat(64);
  const result = await runNativeProcess(process.execPath, [cli, ...args], { timeoutMs: 10000 });
  assert.equal(result.code, 1); assert.equal(result.stdout.length, 0);
  const error = JSON.parse(result.stderr); assert.equal(error.code, 'backup_lfs_digest_mismatch');
  assert.equal(error.state, 'not_started'); assert.equal(error.absence_proves_non_publication, false);
  assert.deepEqual(await f.calls(), []); await absent(f.paths.destination); await absent(f.paths.approvalRecord);
});
