// Real operator I/O, Ed25519 signatures and subprocesses; the native executable
// is an explicit protocol fixture, NOT evidence that the Rust archive engine ran.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtemp, writeFile, readFile, lstat, rm, chmod, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { approveVerifiedRepositoryBackup } from '../lib/repository-backup-verified-sign.mjs';
import { authenticateRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';
import { runNativeProcess } from '../lib/native-process-owner.mjs';
import { approvalArguments, runApprovalCommand } from '../attest_repository_backup.mjs';

const identity = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), incarnation_id: '33'.repeat(16), object_format: 'sha1' };
const declarations = { ...identity, head_generation: '7' };
const policy = { ...identity, minimum_head_generation: '7' };
const cli = fileURLToPath(new URL('../attest_repository_backup.mjs', import.meta.url));
const code = expected => error => { assert.equal(error.code, expected); return true; };
async function missing(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
async function fixture(action, mode = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-verified-sign-test-'));
  const paths = { fg: join(dir, 'fg-fixture'), input: join(dir, 'archive'), output: join(dir, 'approval'), privateKey: join(dir, 'key.pem') };
  const keys = generateKeyPairSync('ed25519');
  const privatePem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = Buffer.from(keys.publicKey.export({ type: 'spki', format: 'pem' }));
  const archive = Buffer.alloc(131073, 42);
  await writeFile(paths.input, archive, { mode: 0o600 });
  await writeFile(paths.privateKey, privatePem, { mode: 0o600 });
  // The fixture independently checks the adapter's actual argv and archive hash.
  // It intentionally has no Git/archive decoder and makes no native-engine claim.
  await writeFile(paths.fg, `#!${process.execPath}
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
const mode = ${JSON.stringify(mode)}, args = process.argv.slice(2);
assert.equal(args.length, 13);
assert.deepEqual([args[0], args[1], args[4], args[5], args[7], args[9], args[11]],
  ['backup', 'verify', '--trusted-local', '--expected-sha256', '--verification-instance', '--max-archive-bytes', '--timeout-secs']);
assert.ok(Number(args[10]) >= 1 && Number(args[12]) >= 1);
assert.equal(fs.readFileSync(0).length, 0);
const bytes = fs.readFileSync(args[2]), digest = createHash('sha256').update(bytes).digest('hex');
assert.equal(args[6], digest);
fs.appendFileSync(${JSON.stringify(join(dir, 'calls'))}, JSON.stringify(args) + '\\n');
if (mode.stall) { setInterval(() => {}, 1000); }
else {
  const v = { type: 'repository_source_backup_verify', schema_version: 1, sha256: digest,
    ...${JSON.stringify(identity)}, head_generation: 7, objects: 2, references: 1, payload_bytes: 9,
    complete: true, scope: 'authority_and_selected_git_objects', object_graph_verified: true,
    original_payload_commitments_verified: true, node_closed: true, signature_verified: false,
    routing_published: false, archive_bytes: bytes.length, local_edges: 1, external_gitlinks: 0,
    verification_instance: Number(args[8]), authority_import_verified: true, git_payloads_written: false,
    destination_authority_published: false, scratch_removed: true, destination_readback_verified: false,
    newest_checkpoint_verified: false, external_artifacts_verified: false, ...mode.receipt };
  if (mode.leftover) { fs.mkdirSync(args[3]); fs.writeFileSync(path.join(args[3], 'evidence'), 'retain me'); }
  if (mode.change) fs.writeFileSync(args[2], Buffer.alloc(bytes.length + (mode.grow ? 1 : 0), 43));
  if (mode.createOutput) fs.writeFileSync(${JSON.stringify(paths.output)}, 'other publisher', { flag: 'wx' });
  let text = JSON.stringify(v);
  if (mode.generation) text = text.replace('"head_generation":7', '"head_generation":' + mode.generation);
  if (mode.duplicate) text = text.replace('"complete":true', '"complete":false,"complete":true');
  if (mode.invalidJson) text = 'not-json';
  if (mode.trailing) text += '\\n{}';
  if (mode.exit) { process.stderr.write('native refusal'); process.exitCode = mode.exit; }
  process.stdout.write(text + '\\n');
}
`, { mode: 0o700 });
  const options = { ...paths, declarations: { ...declarations }, verificationInstance: '17', trustedLocal: true,
    maximumBytes: 1024 ** 2, timeoutMs: 5000 };
  const cleanup = new Set();
  const run = async (override = {}) => {
    try { return await approveVerifiedRepositoryBackup({ ...options, ...override }); }
    catch (error) { if (error.verification_scratch) cleanup.add(error.verification_scratch); throw error; }
  };
  const calls = async () => { try { return (await readFile(join(dir, 'calls'), 'utf8')).trim().split('\n').map(JSON.parse); }
    catch (error) { if (error.code === 'ENOENT') return []; throw error; } };
  try { await action({ dir, paths, archive, options, privatePem, publicPem, run, calls, cleanup }); }
  finally { for (const path of cleanup) await rm(path, { recursive: true, force: true }); await rm(dir, { recursive: true, force: true }); }
}
function argsFor(paths, op = 'verify-sign') {
  return [op, paths.input, paths.output, '--private-key', paths.privateKey,
    '--tenant-id', identity.tenant_id, '--repository-id', identity.repository_id, '--incarnation-id', identity.incarnation_id,
    '--object-format', 'sha1', '--head-generation', '7',
    ...(op === 'verify-sign' ? ['--fg', paths.fg, '--verification-instance', '17', '--trusted-local'] : [])];
}
async function waitStarted(calls) {
  for (let i = 0; i < 200; i++) { if ((await calls()).length) return; await delay(10); }
  assert.fail('native fixture did not start');
}

test('verified-sign publishes a real interoperable DSSE approval after exact native verification', async () => {
  await fixture(async ({ paths, archive, privatePem, publicPem, run, calls }) => {
    const result = await run();
    assert.equal(result.state, 'complete');
    assert.equal(result.native_content_verified, true);
    assert.equal(result.signed_identity_matched_native, true);
    assert.equal(result.complete_capsule_verified, false);
    assert.equal(result.newest_checkpoint_verified, false);
    assert.equal(result.statement.artifact.sha256, createHash('sha256').update(archive).digest('hex'));
    assert.equal(result.streaming.initial.read_calls, 3);
    assert.equal(result.streaming.signing.read_calls, 3);
    assert.equal(result.streaming.signing.maximum_read_bytes, 65536);
    const approval = await readFile(paths.output);
    const verified = await authenticateRepositoryBackupFile(paths.input, approval, publicPem, policy);
    assert.equal(verified.authentication.signature_verified, true);
    assert.equal(verified.authentication.native_content_verified, false, 'a signature alone must not imply native verification');
    assert.deepEqual(verified.authentication.statement, result.statement);
    assert.equal(createHash('sha256').update(approval).digest('hex'), result.sha256);
    const invoked = await calls(); assert.equal(invoked.length, 1);
    assert.ok(!invoked[0].includes(paths.privateKey) && !invoked[0].includes(paths.output));
    await missing(dirname(invoked[0][3]));
    assert.equal(await readFile(paths.privateKey, 'utf8'), privatePem);
    assert.deepEqual(await readFile(paths.input), archive);
    assert.equal((await lstat(paths.output)).mode & 0o777, 0o600);
  });
});

test('sha256 and generations above JavaScript safe integers remain exact', async () => {
  await fixture(async ({ run, paths, publicPem }) => {
    const result = await run({ declarations: { ...declarations, object_format: 'sha256', head_generation: '18446744073709551615' } });
    assert.equal(result.native.head_generation, '18446744073709551615');
    const verified = await authenticateRepositoryBackupFile(paths.input, await readFile(paths.output), publicPem,
      { ...policy, object_format: 'sha256', minimum_head_generation: '18446744073709551615' });
    assert.equal(verified.authentication.statement.head_generation, '18446744073709551615');
  }, { receipt: { object_format: 'sha256' }, generation: '18446744073709551615' });
});

for (const [name, receipt] of Object.entries({ tenant: { tenant_id: '00'.repeat(16) }, repository: { repository_id: '00'.repeat(16) },
  incarnation: { incarnation_id: '00'.repeat(16) }, format: { object_format: 'sha256' }, generation: { head_generation: 8 },
  digest: { sha256: '00'.repeat(32) }, size: { archive_bytes: 1 }, incomplete: { complete: false },
  graph: { object_graph_verified: false }, commitments: { original_payload_commitments_verified: false },
  authority: { authority_import_verified: false }, cleanup: { scratch_removed: false }, closure: { node_closed: false },
  routing: { routing_published: true }, destination: { destination_authority_published: true },
  unexpected: { extra: true }, oversized: { objects: 100001 }, scope: { scope: 'complete_capsule' } })) {
  test(`mismatched native ${name} refuses without publishing or reading a missing key`, async () => {
    await fixture(async ({ run, paths }) => {
      await rm(paths.privateKey);
      await assert.rejects(run(), code('backup_native_receipt_mismatch'));
      await missing(paths.output);
    }, { receipt });
  });
}

test('wrong verification instance refuses', async () => fixture(async ({ run, paths }) => {
  await assert.rejects(run(), code('backup_native_instance_mismatch')); await missing(paths.output);
}, { receipt: { verification_instance: 18 } }));
for (const [mode, expected] of [['duplicate', 'noncanonical_native_import_json'], ['invalidJson', 'invalid_native_import_json'],
  ['trailing', 'invalid_native_import_json']]) {
  test(`${mode} native receipt refuses`, async () => fixture(async ({ run, paths }) => {
    await assert.rejects(run(), code(expected)); await missing(paths.output);
  }, { [mode]: true }));
}
test('nonzero native exit is never treated as verified', async () => fixture(async ({ run, paths }) => {
  await assert.rejects(run(), error => { assert.equal(error.code, 'backup_native_refused'); assert.equal(error.native_exit_code, 7); return true; });
  await missing(paths.output);
}, { exit: 7 }));
for (const grow of [false, true]) {
  test(`archive ${grow ? 'size' : 'same-size content'} changes during verification refuse publication`, async () => fixture(async ({ run, paths }) => {
    await assert.rejects(run(), code('backup_artifact_changed_after_verification')); await missing(paths.output);
  }, { change: true, grow }));
}
test('a lying scratch removal receipt retains unknown native evidence', async () => fixture(async ({ run, paths }) => {
  await assert.rejects(run(), asyncError => {
    assert.equal(asyncError.code, 'backup_existing_path');
    assert.ok(asyncError.verification_scratch); return true;
  });
  await missing(paths.output);
}, { leftover: true }));
test('existing output is rejected before a native process starts', async () => fixture(async ({ run, paths, calls }) => {
  await writeFile(paths.output, 'existing');
  await assert.rejects(run(), code('backup_existing_path'));
  assert.equal(await readFile(paths.output, 'utf8'), 'existing'); assert.deepEqual(await calls(), []);
}));
test('concurrent output creation is never overwritten', async () => fixture(async ({ run, paths }) => {
  await assert.rejects(run(), error => { assert.equal(error.code, 'EEXIST'); assert.equal(error.publication_state, 'not_created'); return true; });
  assert.equal(await readFile(paths.output, 'utf8'), 'other publisher');
}, { createOutput: true }));
test('oversized archive refuses before native spawn', async () => fixture(async ({ run, paths, calls }) => {
  await assert.rejects(run({ maximumBytes: 10 }), code('backup_file_size_or_type'));
  await missing(paths.output); assert.deepEqual(await calls(), []);
}));
test('untrusted invocation and malformed options refuse before native spawn', async () => fixture(async ({ run, paths, calls }) => {
  for (const override of [{ trustedLocal: false }, { unexpected: true }]) await assert.rejects(run(override), code('backup_explicit_local_operation_required'));
  await assert.rejects(run({ fg: 'fg' }), code('backup_absolute_fg_required'));
  await assert.rejects(run({ verificationInstance: '0' }), code('backup_invalid_decimal'));
  await assert.rejects(run({ timeoutMs: 0 }), code('backup_invalid_options'));
  await missing(paths.output); assert.deepEqual(await calls(), []);
}));
test('declarations are snapshotted before the first await', async () => fixture(async ({ run }) => {
  const data = { ...declarations }; const result = run({ declarations: data });
  data.repository_id = '00'.repeat(16); data.head_generation = '8';
  assert.equal((await result).statement.repository_id, declarations.repository_id);
}));
test('expired or future approval declarations refuse before native spawn', async () => fixture(async ({ run, calls }) => {
  await assert.rejects(run({ declarations: { ...declarations, issued_at: '2020-01-01T00:00:00Z', expires_at: '2020-01-02T00:00:00Z' } }), code('backup_approval_expired'));
  await assert.rejects(run({ declarations: { ...declarations, issued_at: '9999-01-01T00:00:00Z' } }), code('backup_approval_in_future'));
  assert.deepEqual(await calls(), []);
}));
test('private keys must be private, single-link, nonsymlink regular files', async () => fixture(async ({ run, paths, dir }) => {
  await chmod(paths.privateKey, 0o644);
  await assert.rejects(run(), code('backup_private_owner_required'));
  await chmod(paths.privateKey, 0o600);
  const alias = join(dir, 'key-link'); await link(paths.privateKey, alias);
  await assert.rejects(run(), code('backup_private_key_links'));
  await rm(alias); await symlink(paths.privateKey, alias);
  await assert.rejects(run({ privateKey: alias }), { code: 'ELOOP' });
  await missing(paths.output);
}));
test('a nonprivate approval parent refuses before native spawn', async () => fixture(async ({ run, dir, calls }) => {
  await chmod(dir, 0o755);
  await assert.rejects(run(), code('backup_private_parent_required')); assert.deepEqual(await calls(), []);
}));
test('pre-cancellation performs no native operation', async () => fixture(async ({ run, calls }) => {
  await assert.rejects(run({ signal: AbortSignal.abort() }), code('backup_cancelled')); assert.deepEqual(await calls(), []);
}));
test('in-flight cancellation drains the child and publishes no approval', async () => fixture(async ({ run, calls, paths }) => {
  const controller = new AbortController();
  const pending = assert.rejects(run({ signal: controller.signal }), code('native_import_cancelled'));
  await waitStarted(calls); controller.abort(); await pending; await missing(paths.output);
}, { stall: true }));
test('a native execution deadline refuses instead of hanging or signing', async () => fixture(async ({ run, paths }) => {
  await assert.rejects(run({ timeoutMs: 300 }), error => { assert.ok(['native_import_deadline', 'backup_deadline'].includes(error.code)); return true; });
  await missing(paths.output);
}, { stall: true }));
test('verify-sign CLI parser keeps trust explicit and rejects duplicate/inapplicable flags', async () => fixture(async ({ paths }) => {
  const args = argsFor(paths); const parsed = approvalArguments(args);
  assert.equal(parsed.op, 'verify-sign'); assert.equal(parsed.trustedLocal, true); assert.equal(parsed.fg, paths.fg);
  assert.throws(() => approvalArguments(args.filter(a => a !== '--trusted-local')), code('backup_missing_option'));
  for (const flag of ['--fg', '--verification-instance', '--trusted-local']) {
    assert.throws(() => approvalArguments([...args, flag, '17']), code('backup_unknown_or_duplicate_option'));
  }
  assert.throws(() => approvalArguments([...argsFor(paths, 'sign'), '--trusted-local']), code('backup_unknown_or_duplicate_option'));
  const literal = approvalArguments([...args.slice(0, 1), ...args.slice(3), '--', '-archive', '-approval']);
  assert.deepEqual(literal.paths, ['-archive', '-approval']);
}));
test('the actual CLI writes a usable approval and a truthful operation report', async () => fixture(async ({ paths, publicPem }) => {
  const result = await runNativeProcess(process.execPath, [cli, ...argsFor(paths)], { timeoutMs: 5000 });
  assert.equal(result.code, 0, result.stderr.toString());
  const report = JSON.parse(result.stdout);
  assert.equal(report.native_content_verified, true); assert.equal(report.state, 'complete');
  const verified = await authenticateRepositoryBackupFile(paths.input, await readFile(paths.output), publicPem, policy);
  assert.equal(verified.authentication.signature_verified, true);
}));
test('the actual CLI reports retained verification scratch on refusal', async () => fixture(async ({ paths, cleanup }) => {
  const result = await runNativeProcess(process.execPath, [cli, ...argsFor(paths)], { timeoutMs: 5000 });
  assert.equal(result.code, 1); assert.equal(result.stdout.length, 0);
  const report = JSON.parse(result.stderr); if (report.verification_scratch) cleanup.add(report.verification_scratch);
  assert.equal(report.code, 'backup_native_refused'); assert.equal(report.publication_state, 'not_created');
  assert.equal(report.operation_completed, false); assert.ok(report.verification_scratch); await missing(paths.output);
}, { exit: 7 }));
test('existing offline sign and check remain usable without a native executable', async () => fixture(async ({ paths, publicPem, calls, dir }) => {
  const result = JSON.parse(await runApprovalCommand(argsFor(paths, 'sign')));
  assert.equal(result.native_content_verified, false); assert.deepEqual(await calls(), []);
  const trust = join(dir, 'public.pem'); await writeFile(trust, publicPem);
  const checked = JSON.parse(await runApprovalCommand(['check', paths.input, paths.output, '--trust-key', trust,
    '--tenant-id', identity.tenant_id, '--repository-id', identity.repository_id, '--incarnation-id', identity.incarnation_id,
    '--object-format', 'sha1', '--minimum-head-generation', '7']));
  assert.equal(checked.signature_verified, true); assert.equal(checked.native_content_verified, false);
}));
