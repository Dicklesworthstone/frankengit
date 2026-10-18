// Exercises the production operator flow, real Ed25519 and native child argv.
// The child is an explicit protocol fixture, not the Rust archive implementation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, lstat, rm, chmod, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { exportApprovedRepositoryBackup } from '../lib/repository-backup-export.mjs';
import { approveVerifiedRepositoryBackup } from '../lib/repository-backup-verified-sign.mjs';
import { authenticateRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { backupExportCheckpoint } from '../lib/repository-backup-export-receipt.mjs';
import { runNativeProcess } from '../lib/native-process-owner.mjs';
import { approvalArguments } from '../attest_repository_backup.mjs';

const declarations = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16),
  object_format: 'sha1', head_generation: '7' };
const cli = fileURLToPath(new URL('../attest_repository_backup.mjs', import.meta.url));
const code = expected => error => { assert.equal(error.code, expected); return true; };
async function absent(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
async function fixture(action, mode = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-export-sign-test-')), cleanup = new Set();
  const paths = { source: join(dir, 'source'), archive: join(dir, 'backup'), output: join(dir, 'approval'),
    privateKey: join(dir, 'key.pem'), fg: join(dir, 'fg-fixture') };
  await mkdir(paths.source, { mode: 0o700 }); await writeFile(join(paths.source, 'sentinel'), 'source must not change');
  const key = generateKeyPairSync('ed25519'), publicPem = Buffer.from(key.publicKey.export({ type: 'spki', format: 'pem' }));
  await writeFile(paths.privateKey, key.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  await writeFile(paths.fg, `#!${process.execPath}
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const mode = ${JSON.stringify(mode)}, args = process.argv.slice(2), op = args[1];
assert.equal(args.length, 13); assert.equal(args[0], 'backup');
assert.equal(fs.readFileSync(0).length, 0);
fs.appendFileSync(${JSON.stringify(join(dir, 'calls'))}, JSON.stringify(args) + '\\n');
if (mode.stall === op) { setInterval(() => {}, 1000); }
else {
  let bytes, v;
  const counts = { objects: 2, references: 1, payload_bytes: 9, local_edges: 1, external_gitlinks: 0 };
  const identity = { ...${JSON.stringify(declarations)}, head_generation: 7 };
  if (op === 'export') {
    assert.deepEqual([args[2], args[4], args[5], args[6], args[7], args[9], args[11]],
      [${JSON.stringify(paths.source)}, identity.tenant_id, identity.repository_id, '--trusted-local', '--object-format', '--max-archive-bytes', '--timeout-secs']);
    assert.ok(Number(args[10]) >= 1 && Number(args[12]) >= 1);
    bytes = Buffer.alloc(131073, 42); fs.writeFileSync(args[3], bytes, { flag: 'wx', mode: 0o600 });
    v = { type: 'repository_source_backup_export', schema_version: 1, sha256: createHash('sha256').update(bytes).digest('hex'),
      bytes: bytes.length, ...identity, object_format: args[8], ...counts, complete: true, scope: 'authority_and_selected_git_objects',
      object_graph_verified: true, original_payload_commitments_verified: true, source_head_revalidated: true, node_closed: true,
      signature_verified: false, external_artifacts_included: false, physical_orphans_included: false, ...mode.export };
    if (mode.changedArchive) fs.writeFileSync(args[3], Buffer.alloc(bytes.length, 43));
    if (mode.missingArchive) fs.unlinkSync(args[3]);
  } else {
    assert.equal(op, 'verify');
    assert.deepEqual([args[4], args[5], args[7], args[9], args[11]],
      ['--trusted-local', '--expected-sha256', '--verification-instance', '--max-archive-bytes', '--timeout-secs']);
    bytes = fs.readFileSync(args[2]); const sha256 = createHash('sha256').update(bytes).digest('hex');
    assert.equal(sha256, args[6]);
    v = { type: 'repository_source_backup_verify', schema_version: 1, sha256, ...identity,
      object_format: mode.format ?? 'sha1', ...counts, complete: true, scope: 'authority_and_selected_git_objects',
      object_graph_verified: true, original_payload_commitments_verified: true, node_closed: true,
      signature_verified: false, routing_published: false, archive_bytes: bytes.length, verification_instance: Number(args[8]),
      authority_import_verified: true, git_payloads_written: false, destination_authority_published: false, scratch_removed: true,
      destination_readback_verified: false, newest_checkpoint_verified: false, external_artifacts_verified: false, ...mode.verify };
    if (mode.outputRace) fs.writeFileSync(${JSON.stringify(paths.output)}, 'concurrent approval', { flag: 'wx' });
  }
  let text = JSON.stringify(v);
  if (mode.generation) text = text.replace('"head_generation":7', '"head_generation":' + mode.generation);
  if (mode.duplicate && op === 'export') text = text.replace('"complete":true', '"complete":false,"complete":true');
  if (mode.exit === op) process.exitCode = 7;
  process.stdout.write(text + '\\n');
}
`, { mode: 0o700 });
  const options = { ...paths, declarations: { ...declarations }, trustedLocal: true, verificationInstance: '17', maximumBytes: 1024 ** 2, timeoutMs: 5000 };
  const run = async (extra = {}) => {
    try { return await exportApprovedRepositoryBackup({ ...options, ...extra }); }
    catch (error) { if (error.verification_scratch) cleanup.add(error.verification_scratch); throw error; }
  };
  const calls = async () => { try { return (await readFile(join(dir, 'calls'), 'utf8')).trim().split('\n').map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; } };
  try { await action({ dir, paths, options, publicPem, run, calls, cleanup }); }
  finally { for (const path of cleanup) await rm(path, { recursive: true, force: true }); await rm(dir, { recursive: true, force: true }); }
}
function argsFor(paths) {
  return ['export-sign', paths.source, paths.archive, paths.output, '--private-key', paths.privateKey, '--fg', paths.fg,
    '--trusted-local', '--verification-instance', '17', '--tenant-id', declarations.tenant_id,
    '--repository-id', declarations.repository_id, '--incarnation-id', declarations.incarnation_id,
    '--object-format', 'sha1', '--head-generation', '7'];
}
async function waitFor(calls, op) {
  for (let i = 0; i < 200; i++) { if ((await calls()).some(args => args[1] === op)) return; await delay(10); }
  assert.fail(`fixture did not start ${op}`);
}

test('one export-sign command creates an exact verified and cryptographically usable backup', async () => fixture(async ({ run, paths, calls, publicPem }) => {
  const result = await run();
  assert.equal(result.type, 'approved_repository_backup_export'); assert.equal(result.state, 'complete');
  assert.equal(result.archive, paths.archive); assert.equal(result.approval, paths.output);
  assert.equal(result.complete_capsule_exported, false); assert.equal(result.external_artifacts_included, false);
  assert.equal(result.native.sha256, result.approval_result.statement.artifact.sha256);
  assert.equal(String(result.native.bytes), result.approval_result.statement.artifact.bytes);
  assert.equal(result.approval_result.native_content_verified, true);
  const { head_generation, ...identity } = declarations;
  const verified = await authenticateRepositoryBackupFile(paths.archive, await readFile(paths.output), publicPem,
    { ...identity, minimum_head_generation: head_generation });
  assert.equal(verified.authentication.signature_verified, true);
  const invoked = await calls(); assert.deepEqual(invoked.map(args => args[1]), ['export', 'verify']);
  assert.ok(invoked.every(args => !args.includes(paths.privateKey) && !args.includes(paths.output)));
  assert.equal(await readFile(join(paths.source, 'sentinel'), 'utf8'), 'source must not change');
}));
test('sha256 and u64 generation values survive export, verification and signing', async () => fixture(async ({ run }) => {
  const result = await run({ declarations: { ...declarations, object_format: 'sha256', head_generation: '18446744073709551615' } });
  assert.equal(result.native.head_generation, '18446744073709551615');
  assert.equal(result.approval_result.statement.head_generation, '18446744073709551615');
  assert.equal(result.approval_result.statement.object_format, 'sha256');
}, { format: 'sha256', generation: '18446744073709551615' }));
for (const [name, value] of Object.entries({ type: { type: 'repository_source_backup_restore' }, tenant: { tenant_id: '44'.repeat(16) },
  incarnation: { incarnation_id: '44'.repeat(16) }, generation: { head_generation: 8 }, format: { object_format: 'sha256' },
  complete: { complete: false }, graph: { object_graph_verified: false }, commitments: { original_payload_commitments_verified: false },
  head: { source_head_revalidated: false }, close: { node_closed: false }, scope: { scope: 'full_service' },
  signature: { signature_verified: true }, external: { external_artifacts_included: true }, orphans: { physical_orphans_included: true },
  count: { objects: 100001 }, negative: { references: -1 }, bytes: { bytes: 0 }, payload: { payload_bytes: 131074 },
  unknown: { unexpected: true }, hash: { sha256: 'not-a-digest' } })) {
  test(`bad export ${name} refuses before verification or private key access`, async () => fixture(async ({ run, calls, paths }) => {
    await rm(paths.privateKey);
    await assert.rejects(run(), error => { assert.equal(error.code, 'backup_native_export_receipt_mismatch'); assert.equal(error.archive_state, 'export_attempted_unknown'); return true; });
    assert.deepEqual((await calls()).map(args => args[1]), ['export']); await absent(paths.output);
    assert.equal((await readFile(paths.archive)).length, 131073, 'never delete an exported archive on refusal');
  }, { export: value }));
}
test('duplicate export receipt fields never become verified state', async () => fixture(async ({ run, paths }) => {
  await assert.rejects(run(), code('noncanonical_native_import_json')); await absent(paths.output);
}, { duplicate: true }));
test('an export failure can leave an archive but never an approval or automatic retry', async () => fixture(async ({ run, calls, paths }) => {
  await assert.rejects(run(), error => { assert.equal(error.code, 'backup_native_export_refused'); assert.equal(error.native_exit_code, 7); return true; });
  assert.deepEqual((await calls()).map(args => args[1]), ['export']); await absent(paths.output);
  assert.equal((await readFile(paths.archive)).length, 131073);
}, { exit: 'export' }));
test('archive substitution after export is caught before native verification', async () => fixture(async ({ run, calls, paths }) => {
  await assert.rejects(run(), error => { assert.equal(error.code, 'backup_export_artifact_mismatch'); assert.equal(error.archive_state, 'export_reported_complete'); return true; });
  assert.deepEqual((await calls()).map(args => args[1]), ['export']); await absent(paths.output);
}, { changedArchive: true }));
test('a successful export receipt cannot stand in for a missing archive', async () => fixture(async ({ run, paths }) => {
  await assert.rejects(run(), { code: 'ENOENT' }); await absent(paths.output);
}, { missingArchive: true }));
for (const key of ['objects', 'references', 'payload_bytes', 'local_edges', 'external_gitlinks']) {
  test(`export and independent verifier must agree on ${key} before key access`, async () => fixture(async ({ run, paths }) => {
    await rm(paths.privateKey);
    await assert.rejects(run(), code('backup_export_verification_mismatch')); await absent(paths.output);
  }, { verify: { [key]: 10 } }));
}
test('verification failure retains the archive and does not publish an approval', async () => fixture(async ({ run, paths, calls }) => {
  await assert.rejects(run(), code('backup_native_refused')); await absent(paths.output);
  assert.deepEqual((await calls()).map(args => args[1]), ['export', 'verify']);
  assert.equal((await readFile(paths.archive)).length, 131073);
}, { exit: 'verify' }));
test('either preexisting output blocks native export without overwriting', async () => fixture(async ({ run, paths, calls }) => {
  for (const path of [paths.archive, paths.output]) {
    await writeFile(path, 'existing'); await assert.rejects(run(), code('backup_existing_path'));
    assert.equal(await readFile(path, 'utf8'), 'existing'); await rm(path);
  }
  assert.deepEqual(await calls(), []);
}));
test('source, archive and approval must be distinct and outputs stay outside source', async () => fixture(async ({ run, paths, calls }) => {
  for (const extra of [{ output: paths.archive }, { archive: join(paths.source, 'backup') }, { output: join(paths.source, 'approval') }]) {
    await assert.rejects(run(extra), code('backup_outputs_must_be_separate'));
  }
  assert.deepEqual(await calls(), []);
}));
test('output parent aliases cannot hide a backup inside source', async () => fixture(async ({ run, paths, dir, calls }) => {
  const alias = join(dir, 'source-alias'); await symlink(paths.source, alias);
  await assert.rejects(run({ archive: join(alias, 'backup') }), code('backup_outputs_must_be_separate'));
  assert.deepEqual(await calls(), []);
}));
test('source symlinks and nonprivate output parents refuse before export', async () => fixture(async ({ run, paths, dir, calls }) => {
  const alias = join(dir, 'source-alias'); await symlink(paths.source, alias);
  await assert.rejects(run({ source: alias }), code('backup_source_directory_required'));
  await chmod(dir, 0o755); await assert.rejects(run(), code('backup_private_parent_required')); assert.deepEqual(await calls(), []);
}));
test('concurrent approval publication is retained without undoing exported bytes', async () => fixture(async ({ run, paths }) => {
  await assert.rejects(run(), error => { assert.equal(error.code, 'EEXIST'); assert.equal(error.archive_state, 'export_reported_complete'); assert.equal(error.publication_state, 'not_created'); return true; });
  assert.equal(await readFile(paths.output, 'utf8'), 'concurrent approval');
  assert.equal((await readFile(paths.archive)).length, 131073);
}, { outputRace: true }));
for (const op of ['export', 'verify']) {
  test(`cancellation during ${op} drains the child without retry or approval`, async () => fixture(async ({ run, paths, calls }) => {
    const controller = new AbortController();
    const pending = assert.rejects(run({ signal: controller.signal }), code('native_import_cancelled'));
    await waitFor(calls, op); controller.abort(); await pending;
    await absent(paths.output);
    assert.deepEqual((await calls()).map(args => args[1]), op === 'export' ? ['export'] : ['export', 'verify']);
    if (op === 'verify') assert.equal((await readFile(paths.archive)).length, 131073);
  }, { stall: op }));
}
test('pre-cancel and invalid local options have no export side effects', async () => fixture(async ({ run, paths, calls }) => {
  await assert.rejects(run({ signal: AbortSignal.abort() }), code('backup_cancelled'));
  await assert.rejects(run({ trustedLocal: false }), code('backup_explicit_local_operation_required'));
  await assert.rejects(run({ fg: 'fg' }), code('backup_absolute_fg_required'));
  await assert.rejects(run({ maximumBytes: 0 }), code('backup_invalid_options'));
  assert.deepEqual(await calls(), []); await absent(paths.archive); await absent(paths.output);
}));
test('one deadline spans export and independent verification', async () => fixture(async ({ run, paths }) => {
  await assert.rejects(run({ timeoutMs: 300 }), error => { assert.ok(['native_import_deadline', 'backup_deadline'].includes(error.code)); return true; });
  await absent(paths.output);
}, { stall: 'verify' }));
test('invalid equality pins refuse before any file access', async () => {
  const pin = { sha256: '00'.repeat(32), bytes: '10', objects: '0', references: '0', payload_bytes: '0', local_edges: '0', external_gitlinks: '0' };
  for (const value of [{ ...pin, bytes: '00' }, { ...pin, payload_bytes: '11' }, { ...pin, objects: 0 }, { ...pin, extra: true }]) {
    assert.throws(() => backupExportCheckpoint(value), code('backup_invalid_export_checkpoint'));
    await assert.rejects(approveVerifiedRepositoryBackup({ trustedLocal: true, checkpoint: value }), code('backup_invalid_export_checkpoint'));
  }
  const copied = backupExportCheckpoint(pin); pin.bytes = '20'; assert.equal(copied.bytes, '10'); assert.ok(Object.isFrozen(copied));
});
test('actual export-sign CLI returns a usable pair and preserves strict argument parsing', async () => fixture(async ({ paths }) => {
  const args = argsFor(paths); assert.equal(approvalArguments(args).op, 'export-sign');
  assert.throws(() => approvalArguments(args.filter(a => a !== '--trusted-local')), code('backup_missing_option'));
  assert.throws(() => approvalArguments(args.filter(a => a !== paths.archive)), code('backup_three_paths_required'));
  assert.throws(() => approvalArguments([...args, '--trusted-local']), code('backup_unknown_or_duplicate_option'));
  const result = await runNativeProcess(process.execPath, [cli, ...args], { timeoutMs: 5000 });
  assert.equal(result.code, 0, result.stderr.toString()); const report = JSON.parse(result.stdout);
  assert.equal(report.state, 'complete'); assert.equal(report.approval_result.native_content_verified, true);
  assert.equal(report.native.sha256, createHash('sha256').update(await readFile(paths.archive)).digest('hex'));
}));
test('actual CLI reports archive ambiguity separately from approval publication', async () => fixture(async ({ paths }) => {
  const result = await runNativeProcess(process.execPath, [cli, ...argsFor(paths)], { timeoutMs: 5000 });
  assert.equal(result.code, 1); assert.equal(result.stdout.length, 0); const report = JSON.parse(result.stderr);
  assert.equal(report.archive_state, 'export_attempted_unknown'); assert.equal(report.archive_path, paths.archive);
  assert.equal(report.approval_path, paths.output); assert.equal(report.publication_state, 'not_created');
  assert.equal(report.operation_completed, false); await absent(paths.output);
  assert.equal((await readFile(paths.archive)).length, 131073);
}, { exit: 'export' }));
