// Real crypto, child processes and files exercise the operator protocol. The
// explicit child peer is not execution evidence for the Rust archive engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, lstat, rm, link, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { exportApprovedRepositoryBackup } from '../lib/repository-backup-export.mjs';
import { approveVerifiedRepositoryBackup } from '../lib/repository-backup-verified-sign.mjs';
import { authenticateRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { backupLfsCheckpoint, validateBackupLfsReceipt } from '../lib/repository-backup-lfs.mjs';
import { approvalArguments, runApprovalCommand } from '../attest_repository_backup.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const declarations = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16),
  object_format: 'sha1', head_generation: '7' };
const sourceBytes = Buffer.alloc(70001, 42), lfsBytes = Buffer.alloc(70003, 43);
const sha = hash(lfsBytes);
const errorCode = expected => error => { assert.equal(error.code, expected); return true; };
async function absent(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
async function fixture(action, mode = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-lfs-export-')), retained = new Set();
  const paths = { source: join(dir, 'source'), archive: join(dir, 'source.backup'), output: join(dir, 'approval'),
    lfsRoot: join(dir, 'custody'), lfsOutput: join(dir, 'source.lfs'), privateKey: join(dir, 'private.pem'), fg: join(dir, 'fg-peer') };
  await mkdir(paths.source, { mode: 0o700 }); await mkdir(paths.lfsRoot, { mode: 0o700 });
  const keys = generateKeyPairSync('ed25519'), publicPem = keys.publicKey.export({ format: 'pem', type: 'spki' });
  await writeFile(paths.privateKey, keys.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  await writeFile(paths.fg, `#!${process.execPath}
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const args = process.argv.slice(2), op = args[1], mode = ${JSON.stringify(mode)};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const paths = ${JSON.stringify(paths)};
assert.equal(args[0], 'backup'); assert.equal(fs.readFileSync(0).length, 0);
assert.ok(!args.includes(paths.privateKey)); assert.ok(!args.includes(paths.output));
assert.equal(args.length, 17);
fs.appendFileSync(${JSON.stringify(join(dir, 'calls'))}, JSON.stringify(args) + '\\n');
const value = name => args[args.indexOf(name) + 1];
const identity = { ...${JSON.stringify(declarations)}, object_format: mode.format ?? 'sha1', head_generation: 7 };
const counts = { objects: 2, references: 1, payload_bytes: 9, local_edges: 1, external_gitlinks: 0 };
const checkpoint = { transport_version: 1, retained_outcome_checkpoint_verified: false,
  retained_outcome_checkpoint_root: null, retained_outcome_objects: 0, retained_outcome_payload_bytes: 0 };
const companion = { sha256: '${sha}', bytes: 70003, objects: 2, payload_bytes: 60000, exact_snapshot: true };
let v;
if (op === 'export') {
  assert.equal(value('--lfs-root'), paths.lfsRoot); assert.equal(value('--lfs-output'), paths.lfsOutput);
  fs.writeFileSync(paths.lfsOutput, Buffer.alloc(70003, 43), { flag: 'wx', mode: 0o600 });
  if (!mode.onlyCompanion) fs.writeFileSync(paths.archive, Buffer.alloc(70001, 42), { flag: 'wx', mode: 0o600 });
  v = { type: 'repository_source_backup_export', schema_version: 1, sha256: '${hash(sourceBytes)}', bytes: 70001,
    ...identity, ...counts, ...checkpoint, complete: true, scope: 'authority_and_selected_git_objects',
    object_graph_verified: true, original_payload_commitments_verified: true, source_head_revalidated: true, node_closed: true,
    signature_verified: false, external_artifacts_included: false, physical_orphans_included: false,
    lfs_companion: { ...companion, ...mode.companion }, lfs_payloads_included: true, ...mode.export };
  if (mode.changedAfterExport) fs.writeFileSync(paths.lfsOutput, Buffer.alloc(70003, 44));
} else {
  assert.equal(op, 'verify'); assert.equal(value('--lfs-archive'), paths.lfsOutput);
  const data = fs.readFileSync(args[2]), lfs = fs.readFileSync(value('--lfs-archive'));
  assert.equal(value('--expected-sha256'), hash(data)); assert.equal(value('--expected-lfs-sha256'), hash(lfs));
  v = { type: 'repository_source_backup_verify', schema_version: 1, sha256: hash(data), ...identity, ...counts, ...checkpoint,
    complete: true, scope: 'authority_and_selected_git_objects', object_graph_verified: true,
    original_payload_commitments_verified: true, node_closed: true, signature_verified: false, routing_published: false,
    archive_bytes: data.length, verification_instance: Number(value('--verification-instance')),
    authority_import_verified: true, git_payloads_written: false, destination_authority_published: false,
    scratch_removed: true, destination_readback_verified: false, newest_checkpoint_verified: false, external_artifacts_verified: false,
    lfs_companion: { ...companion, ...mode.verifyCompanion }, lfs_payloads_verified: true, ...mode.verify };
  if (mode.changedAfterVerify) fs.writeFileSync(paths.lfsOutput, Buffer.alloc(70003, 45));
}
if (mode.omitCompanion === op) { delete v.lfs_companion; delete v[op === 'export' ? 'lfs_payloads_included' : 'lfs_payloads_verified']; }
if (mode.stall === op) setInterval(() => {}, 1000);
else { if (mode.exit === op) process.exitCode = 9; process.stdout.write(JSON.stringify(v) + '\\n'); }
`, { mode: 0o700 });
  const options = { ...paths, declarations, verificationInstance: '19', trustedLocal: true, maximumBytes: 100000, timeoutMs: 5000 };
  const capture = async task => { try { return await task(); } catch (error) { if (error.verification_scratch) retained.add(error.verification_scratch); throw error; } };
  const run = extra => capture(() => exportApprovedRepositoryBackup({ ...options, ...extra }));
  const verify = extra => capture(() => approveVerifiedRepositoryBackup({ fg: paths.fg, input: paths.archive, output: paths.output,
    privateKey: paths.privateKey, declarations, verificationInstance: '19', trustedLocal: true, maximumBytes: 100000,
    timeoutMs: 5000, lfsArchive: paths.lfsOutput, expectedLfsSha256: sha, ...extra }));
  const calls = async () => { try { return (await readFile(join(dir, 'calls'), 'utf8')).trim().split('\n').map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; } };
  const seed = async () => { await writeFile(paths.archive, sourceBytes, { mode: 0o600 }); await writeFile(paths.lfsOutput, lfsBytes, { mode: 0o600 }); };
  try { await action({ dir, paths, options, publicPem: Buffer.from(publicPem), run, verify, calls, seed, retained }); }
  finally { for (const path of retained) await rm(path, { recursive: true, force: true }); await rm(dir, { recursive: true, force: true }); }
}
function cliArgs(paths, op = 'export-sign') {
  return [op, ...(op === 'export-sign' ? [paths.source, paths.archive, paths.output] : [paths.archive, paths.output]),
    '--fg', paths.fg, '--private-key', paths.privateKey, '--verification-instance', '19', '--trusted-local',
    '--tenant-id', declarations.tenant_id, '--repository-id', declarations.repository_id, '--incarnation-id', declarations.incarnation_id,
    '--object-format', declarations.object_format, '--head-generation', declarations.head_generation];
}
for (const format of ['sha1', 'sha256']) test(`paired export verifies both archives before signing source (${format})`, async () => fixture(async ({ run, paths, publicPem, calls }) => {
  const result = await run({ declarations: { ...declarations, object_format: format } });
  assert.equal(result.state, 'complete'); assert.equal(result.lfs_archive, paths.lfsOutput);
  assert.deepEqual(result.lfs_companion, { sha256: sha, bytes: '70003', objects: '2', payload_bytes: '60000', exact_snapshot: true });
  assert.equal(result.lfs_payloads_included, true); assert.equal(result.lfs_companion_signed, false);
  assert.equal(result.approval_result.lfs_exact_snapshot_verified, true);
  assert.equal(result.approval_result.native.lfs_payloads_verified, true);
  const { head_generation, ...identity } = { ...declarations, object_format: format };
  const verified = await authenticateRepositoryBackupFile(paths.archive, await readFile(paths.output), publicPem,
    { ...identity, minimum_head_generation: head_generation });
  assert.equal(verified.authentication.signature_verified, true);
  assert.equal(verified.authentication.statement.artifact.sha256, hash(sourceBytes));
  assert.equal(Object.hasOwn(verified.authentication.statement, 'lfs_companion'), false, 'DSSE v1 stays unchanged');
  assert.deepEqual((await calls()).map(a => a[1]), ['export', 'verify']);
  assert.deepEqual(await readFile(paths.lfsOutput), lfsBytes);
}, { format }));

for (const [label, mode, expected] of [
  ['omitted companion', { omitCompanion: 'export' }, 'backup_native_export_receipt_mismatch'],
  ['false inclusion', { export: { lfs_payloads_included: false } }, 'backup_native_export_receipt_mismatch'],
  ['unverified snapshot', { companion: { exact_snapshot: false } }, 'backup_native_lfs_receipt_mismatch'],
  ['unknown companion field', { companion: { extra: true } }, 'backup_native_lfs_receipt_mismatch'],
  ['oversized companion', { companion: { bytes: 100001 } }, 'backup_native_lfs_receipt_mismatch'],
  ['payload exceeds archive', { companion: { payload_bytes: 70004 } }, 'backup_native_lfs_receipt_mismatch'],
  ['invalid digest', { companion: { sha256: 'a'.repeat(63) } }, 'backup_native_lfs_receipt_mismatch'],
  ['string native count', { companion: { objects: '2' } }, 'backup_native_lfs_receipt_mismatch'],
  ['unsafe native count', { companion: { objects: 9007199254740992 } }, 'backup_native_lfs_receipt_mismatch'],
  ['changed exported bytes', { changedAfterExport: true }, 'backup_lfs_artifact_mismatch'],
]) test(`${label} refuses before verifier/key and retains exported bytes`, async () => fixture(async ({ run, paths, calls }) => {
  await rm(paths.privateKey); await assert.rejects(run(), errorCode(expected));
  assert.deepEqual((await calls()).map(a => a[1]), ['export']); await absent(paths.output);
  assert.equal((await lstat(paths.lfsOutput)).size, 70003);
}, mode));
for (const [label, mode, expected] of [
  ['missing verification companion', { omitCompanion: 'verify' }, 'backup_native_receipt_mismatch'],
  ['false verification flag', { verify: { lfs_payloads_verified: false } }, 'backup_native_receipt_mismatch'],
  ['different inventory count', { verifyCompanion: { objects: 1 } }, 'backup_native_lfs_receipt_mismatch'],
  ['different payload count', { verifyCompanion: { payload_bytes: 50000 } }, 'backup_native_lfs_receipt_mismatch'],
  ['changed bytes after verification', { changedAfterVerify: true }, 'backup_lfs_artifact_mismatch'],
]) test(`${label} refuses before private-key read`, async () => fixture(async ({ run, paths, calls }) => {
  await rm(paths.privateKey); await assert.rejects(run(), errorCode(expected));
  assert.deepEqual((await calls()).map(a => a[1]), ['export', 'verify']); await absent(paths.output);
}, mode));

test('retained source and companion can be explicitly verified and approved later', async () => fixture(async ({ seed, verify, paths }) => {
  await seed(); const result = await verify(); assert.equal(result.lfs_companion.sha256, sha);
  assert.equal(result.lfs_companion_signed, false); assert.equal(result.native_content_verified, true);
  assert.ok((await lstat(paths.output)).isFile());
}));
test('wrong companion pin refuses without native child or key access', async () => fixture(async ({ seed, verify, paths, calls }) => {
  await seed(); await rm(paths.privateKey);
  await assert.rejects(verify({ expectedLfsSha256: 'ff'.repeat(32) }), errorCode('backup_lfs_artifact_mismatch'));
  assert.deepEqual(await calls(), []); await absent(paths.output);
}));
test('source and companion cannot be the same physical file', async () => fixture(async ({ seed, verify, paths, calls }) => {
  await seed(); await rm(paths.lfsOutput); await link(paths.archive, paths.lfsOutput);
  await assert.rejects(verify({ expectedLfsSha256: hash(sourceBytes) }), errorCode('backup_lfs_archive_must_be_separate'));
  assert.deepEqual(await calls(), []); await absent(paths.output);
}));
test('a signing-key alias refuses before companion hashing or a native child', async () => fixture(async ({ seed, verify, paths, calls, dir }) => {
  await seed();
  const expected = hash(await readFile(paths.privateKey));
  const aliases = [paths.privateKey, join(dir, 'key-link'), join(dir, 'key-parent', 'private.pem')];
  await link(paths.privateKey, aliases[1]); await symlink(dir, join(dir, 'key-parent'));
  for (const path of aliases) {
    await assert.rejects(verify({ lfsArchive: path, expectedLfsSha256: expected }), errorCode('backup_lfs_archive_must_be_separate'));
  }
  // A symlinked key is not an admissible signer, and cannot disguise the same
  // secret file as an independently selected companion before verification.
  const keyAlias = join(dir, 'key-symlink'); await symlink(paths.privateKey, keyAlias);
  await assert.rejects(verify({ privateKey: keyAlias, lfsArchive: aliases[1], expectedLfsSha256: expected }),
    errorCode('backup_lfs_archive_must_be_separate'));
  assert.deepEqual(await calls(), []); await absent(paths.output);
}));
test('private output collisions and aliases refuse before starting export', async () => fixture(async ({ run, paths, calls, dir }) => {
  await writeFile(paths.lfsOutput, 'existing'); await assert.rejects(run(), errorCode('backup_existing_path'));
  assert.equal(await readFile(paths.lfsOutput, 'utf8'), 'existing'); await rm(paths.lfsOutput);
  await assert.rejects(run({ lfsOutput: paths.archive }), errorCode('backup_outputs_must_be_separate'));
  await assert.rejects(run({ lfsOutput: join(paths.source, 'out') }), errorCode('backup_outputs_must_be_separate'));
  await assert.rejects(run({ archive: join(paths.lfsRoot, 'out') }), errorCode('backup_outputs_must_be_separate'));
  const alias = join(dir, 'alias'); await symlink(dir, alias);
  await assert.rejects(run({ lfsOutput: join(alias, 'source.backup') }), errorCode('backup_outputs_must_be_separate'));
  assert.deepEqual(await calls(), []); await absent(paths.output);
}));
test('incomplete option pairs fail before any I/O and source-only never accepts LFS flags', async () => fixture(async ({ run, verify, paths, calls }) => {
  await assert.rejects(run({ lfsOutput: undefined }), errorCode('backup_lfs_pair_required'));
  await assert.rejects(run({ lfsRoot: undefined }), errorCode('backup_lfs_pair_required'));
  await assert.rejects(verify({ expectedLfsSha256: undefined }), errorCode('backup_lfs_pair_required'));
  await assert.rejects(verify({ lfsArchive: undefined }), errorCode('backup_lfs_pair_required'));
  await assert.rejects(verify({ expectedLfsSha256: 'bad' }), errorCode('backup_invalid_lfs_sha256'));
  assert.throws(() => approvalArguments([...cliArgs(paths), '--lfs-root', paths.lfsRoot]), errorCode('backup_lfs_pair_required'));
  assert.throws(() => approvalArguments([...cliArgs(paths, 'verify-sign'), '--lfs-archive', paths.lfsOutput]), errorCode('backup_lfs_pair_required'));
  assert.throws(() => approvalArguments([...cliArgs(paths), '--lfs-archive', paths.lfsOutput]), errorCode('backup_unknown_or_duplicate_option'));
  assert.deepEqual(await calls(), []);
}));
test('CLI carries both export and verify companion arguments', async () => fixture(async ({ paths }) => {
  const args = [...cliArgs(paths), '--lfs-root', paths.lfsRoot, '--lfs-output', paths.lfsOutput];
  const parsed = approvalArguments(args); assert.equal(parsed.lfsRoot, paths.lfsRoot); assert.equal(parsed.lfsOutput, paths.lfsOutput);
  const result = JSON.parse(await runApprovalCommand(args)); assert.equal(result.lfs_companion.sha256, sha);
  await rm(paths.output);
  const verified = JSON.parse(await runApprovalCommand([...cliArgs(paths, 'verify-sign'), '--lfs-archive', paths.lfsOutput, '--expected-lfs-sha256', sha]));
  assert.equal(verified.lfs_exact_snapshot_verified, true);
}));
test('export failure retains a lone companion and reports both unknown publication paths', async () => fixture(async ({ run, paths, calls }) => {
  await assert.rejects(run(), error => {
    assert.equal(error.code, 'backup_native_export_refused'); assert.equal(error.archive_state, 'export_attempted_unknown');
    assert.equal(error.lfs_archive_state, 'export_attempted_unknown'); assert.equal(error.lfs_archive_path, paths.lfsOutput); return true;
  });
  assert.equal((await lstat(paths.lfsOutput)).size, 70003); await absent(paths.archive); await absent(paths.output);
  assert.deepEqual((await calls()).map(a => a[1]), ['export']);
}, { onlyCompanion: true, exit: 'export' }));
for (const op of ['export', 'verify']) test(`cancellation during ${op} drains child, retains archives, never signs`, async () => fixture(async ({ run, calls, paths }) => {
  const controller = new AbortController(); const result = run({ signal: controller.signal });
  const caught = result.catch(error => error);
  for (let i = 0; i < 200; i++) { if ((await calls()).some(a => a[1] === op)) break; await delay(10); }
  assert.ok((await calls()).some(a => a[1] === op)); controller.abort();
  const error = await caught; assert.equal(error.code, 'native_import_cancelled');
  await absent(paths.output); assert.equal((await lstat(paths.lfsOutput)).size, 70003);
  assert.equal((await calls()).filter(a => a[1] === op).length, 1);
}, { stall: op }));
test('companion receipt checkpoints preserve lossless counters and reject unknown semantics', () => {
  const native = { sha256: sha, bytes: 1024n ** 4n, objects: 100000n, payload_bytes: 1024n ** 4n - 1n, exact_snapshot: true };
  const value = validateBackupLfsReceipt(native, 1024 ** 4);
  assert.equal(value.bytes, '1099511627776'); assert.ok(Object.isFrozen(value)); assert.deepEqual(backupLfsCheckpoint(value), value);
  assert.throws(() => backupLfsCheckpoint({ ...value, bytes: '01' }), errorCode('backup_invalid_lfs_checkpoint'));
  assert.throws(() => backupLfsCheckpoint({ ...value, extra: true }), errorCode('backup_invalid_lfs_checkpoint'));
  assert.throws(() => validateBackupLfsReceipt({ ...native, objects: 0n }, 1024 ** 4), errorCode('backup_native_lfs_receipt_mismatch'));
});
