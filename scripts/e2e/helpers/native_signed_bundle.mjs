// Live operator/fg integration over generated Git packs, not a Git differential
// oracle, signature-key-management proof, memory benchmark or forge restore.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';
import { runNativeProcess } from '../../lib/native-process-owner.mjs';
import { signSourceBackupFile } from '../../lib/source-attestation.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const cli = join(root, 'scripts/verify_git_bundle.mjs');
const input = process.argv.slice(2);
assert.equal(input.length, 6, 'expected --fg PATH --fg-source-cut COMMIT --work DIRECTORY');
assert.deepEqual([input[0], input[2], input[4]], ['--fg', '--fg-source-cut', '--work']);
const fg = await realpath(input[1]), work = await realpath(input[5]);
assert.match(input[3], /^[0-9a-f]{40}$/);
assert.equal(process.versions.node, (await readFile(join(root, 'tests/node-version'), 'utf8')).trim());
assert.deepEqual(await readdir(work), [], 'campaign requires a new empty work directory');
const hash = data => createHash('sha256').update(data).digest('hex');
const fgDigest = hash(await readFile(fg));
const MIB = 1024 * 1024, ref = 'refs/heads/main', repository = 'signed-bundle-e2e/repository';
const summary = { node: process.versions.node, fg, fg_sha256: fgDigest,
  fg_source_cut: input[3], source_cut_is_caller_supplied: true, expected_checks: 18,
  checks: {}, commands: [], client_files: {}, non_claim: 'Generated native packs; no upstream Git, new Rust build, whole operator lane, forge authority or performance claim.' };
for (const name of ['scripts/verify_git_bundle.mjs', 'scripts/lib/native-bundle-verifier.mjs',
  'scripts/lib/source-attestation.mjs', 'scripts/lib/source-attestation-options.mjs']) {
  summary.client_files[name] = hash(await readFile(join(root, name)));
}
const stop = new AbortController();
const interrupt = () => stop.abort();
process.once('SIGINT', interrupt); process.once('SIGTERM', interrupt);
// Only this standalone campaign changes its environment. All child executables
// are absolute paths; no foreign Git/helper can be found through PATH.
process.env.PATH = '';
process.env.TMPDIR = join(work, 'temporary');
await mkdir(process.env.TMPDIR, { mode: 0o700 });

function fixture(format) {
  const object = (kind, body) => ({ kind, body,
    id: createHash(format).update(`${kind} ${body.length}\0`).update(body).digest() });
  const blob = object('blob', Buffer.alloc(17 * MIB, 0x61));
  const tree = object('tree', Buffer.concat([Buffer.from('100644 large.txt\0'), blob.id]));
  const commit = object('commit', Buffer.from(`tree ${tree.id.toString('hex')}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nlarge signed bundle\n`));
  const header = Buffer.alloc(12); header.write('PACK'); header.writeUInt32BE(2, 4); header.writeUInt32BE(3, 8);
  const parts = [header];
  for (const value of [blob, tree, commit]) {
    let size = value.body.length;
    const bytes = [(({ commit: 1, tree: 2, blob: 3 }[value.kind]) << 4) | (size & 15)]; size >>>= 4;
    if (size) bytes[0] |= 128;
    while (size) { const byte = size & 127; size >>>= 7; bytes.push(byte | (size ? 128 : 0)); }
    // Stored DEFLATE keeps the valid input above the old 16 MiB ceiling.
    parts.push(Buffer.from(bytes), deflateSync(value.body, { level: 0 }));
  }
  const pack = Buffer.concat(parts), tip = commit.id.toString('hex');
  const prefix = format === 'sha1' ? '# v2 git bundle\n' : '# v3 git bundle\n@object-format=sha256\n';
  return { tip, bytes: Buffer.concat([Buffer.from(`${prefix}${tip} ${ref}\n\n`), pack,
    createHash(format).update(pack).digest()]) };
}

async function invoke(label, executable, args) {
  const result = await runNativeProcess(executable, args, { timeoutMs: 45000, signal: stop.signal,
    stdoutLimit: 2 * MIB, stderrLimit: 65536 });
  await writeFile(join(work, `${label}.stdout`), result.stdout, { flag: 'wx', mode: 0o600 });
  await writeFile(join(work, `${label}.stderr`), result.stderr, { flag: 'wx', mode: 0o600 });
  summary.commands.push({ label, executable, args, exit: result.code, signal: result.signal,
    stdout_sha256: hash(result.stdout), stderr_sha256: hash(result.stderr), owned_group_quiescent: true });
  assert.equal(result.signal, null, result.stderr.toString());
  return result;
}
async function check(key, action) {
  try { await action(); summary.checks[key] = 'pass'; }
  catch (error) { summary.checks[key] = 'fail'; throw error; }
}
function refused(result, expected, nativeReason) {
  assert.equal(result.code, 1, result.stderr.toString());
  assert.equal(result.stdout.length, 0);
  const error = JSON.parse(result.stderr);
  assert.equal(error.verified, false); assert.equal(error.error, expected);
  if (nativeReason !== undefined) {
    assert.equal(error.details.exit_code, 2); assert.equal(error.details.signal, null);
    const diagnostic = JSON.parse(error.details.diagnostic);
    assert.equal(diagnostic.type, 'bundle_error'); assert.equal(diagnostic.schema_version, 1);
    assert.match(diagnostic.error, nativeReason);
  }
}
function nativeFacts(report, format, bytes, tip) {
  assert.equal(report.object_format, format); assert.equal(report.object_count, 3);
  assert.equal(report.bundle_bytes, bytes.length); assert.equal(report.artifact_sha256, hash(bytes));
  assert.equal(report.storage_profile, 'file-backed-native-full-bundle-v1');
  assert.equal(report.scratch_removed, true);
  for (const name of ['objects_verified', 'object_graph_verified', 'pack_checksum_verified']) assert.equal(report[name], true);
  for (const name of ['signatures_verified', 'origin_authenticated', 'forge_state_verified', 'repository_changed']) assert.equal(report[name], false);
  assert.deepEqual(report.references, [{ ref_hex: Buffer.from(ref).toString('hex'), object_id: tip }]);
}

try {
  for (const format of ['sha1', 'sha256']) {
    const directory = join(work, format); await mkdir(directory, { mode: 0o700 });
    const { bytes, tip } = fixture(format), artifact = join(directory, 'valid.bundle');
    assert.ok(bytes.length > 16 * MIB && bytes.length < 18 * MIB);
    await writeFile(artifact, bytes, { flag: 'wx', mode: 0o600 });
    const keys = generateKeyPairSync('ed25519', { privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' } });
    const trust = join(directory, 'trusted.pem'); await writeFile(trust, keys.publicKey, { flag: 'wx', mode: 0o600 });
    const sign = async (path, name, expired = false) => {
      const now = Date.now() - (expired ? 120000 : 0);
      const approval = await signSourceBackupFile(path, Buffer.from(keys.privateKey), {
        repository, sequence: '18446744073709551615',
        ...(expired ? { expires_at: new Date(now + 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') } : {}),
      }, { maximumBytes: 18 * MIB, now, signal: stop.signal });
      const envelope = join(directory, name); await writeFile(envelope, approval.envelope, { flag: 'wx', mode: 0o600 });
      return ['--attestation', envelope, '--trust-key', trust, '--repository', repository,
        '--minimum-sequence', '18446744073709551615'];
    };
    const approval = await sign(artifact, 'valid.dsse.json');
    const options = ['--native-fg', fg, '--native-file-backed', '--native-timeout-secs', '30',
      '--expect-format', format, '--expect-ref', `${ref}=${format}:${tip}`, '--exact-refs'];
    const command = (label, path, auth, extra = [], chosen = options) =>
      invoke(`${format}-${label}`, process.execPath, [cli, path, ...auth, ...chosen, ...extra]);
    let signedReport;
    await check(`${format}.default`, async () => {
      refused(await command('default', artifact, approval), 'invalid_attestation_artifact');
    });
    await check(`${format}.file_backed`, async () => {
      const result = await command('file-backed', artifact, approval, ['--native-max-input-mib', '18', '--native-max-expanded-mib', '18']);
      assert.equal(result.code, 0, result.stderr.toString()); signedReport = JSON.parse(result.stdout);
      nativeFacts(signedReport, format, bytes, tip);
      assert.equal(signedReport.source_attestation.signature_verified, true);
      assert.equal(signedReport.source_attestation.statement.artifact.sha256, hash(bytes));
      assert.equal(signedReport.source_attestation.statement.artifact.bytes, bytes.length);
    });
    await check(`${format}.rust_read`, async () => {
      const scratch = join(directory, 'native-scratch'); await mkdir(scratch, { mode: 0o700 });
      const result = await invoke(`${format}-rust-read`, fg, ['bundle', 'verify', '--file-backed', '--scratch-dir', scratch,
        '--max-input-mib', '18', '--max-expanded-mib', '18', '--timeout-secs', '30', '--expect-sha256', hash(bytes),
        '--expect-format', format, '--expect-ref-hex', `${Buffer.from(ref).toString('hex')}=${tip}`, '--exact-refs', artifact]);
      assert.equal(result.code, 0, result.stderr.toString()); const report = JSON.parse(result.stdout);
      nativeFacts(report, format, bytes, tip);
      for (const key of ['artifact_sha256', 'pack_checksum', 'pack_sha256', 'payload_bytes', 'local_edges']) assert.equal(report[key], signedReport[key]);
      assert.deepEqual(await readdir(scratch), []);
    });
    await check(`${format}.wrong_signer`, async () => {
      const other = generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'pem' } });
      const key = join(directory, 'wrong.pem'); await writeFile(key, other.publicKey, { flag: 'wx', mode: 0o600 });
      const wrong = [...approval]; wrong[wrong.indexOf('--trust-key') + 1] = key;
      refused(await command('wrong-signer', artifact, wrong, ['--native-max-input-mib', '18']), 'attestation_key_hint_mismatch');
    });
    await check(`${format}.wrong_ref`, async () => {
      const wrong = [...options], at = wrong.indexOf('--expect-ref') + 1;
      wrong[at] = `${ref}=${format}:${tip[0] === '0' ? '1' : '0'}${tip.slice(1)}`;
      refused(await command('wrong-ref', artifact, approval, ['--native-max-input-mib', '18'], wrong),
        'native_verification_refused', /^expected_reference_mismatch:/);
    });
    await check(`${format}.expanded`, async () => {
      refused(await command('expanded', artifact, approval, ['--native-max-input-mib', '18', '--native-max-expanded-mib', '1']),
        'native_verification_refused', /^bundle_pack: ObjectSizeLimit \{ actual: 17825792, limit: 1048576 \}$/);
    });
    const badBytes = Buffer.from(bytes); badBytes[badBytes.length - 1] ^= 1;
    const invalid = join(directory, 'invalid.bundle'); await writeFile(invalid, badBytes, { flag: 'wx', mode: 0o600 });
    await check(`${format}.signed_invalid`, async () => {
      const signedInvalid = await sign(invalid, 'invalid.dsse.json');
      refused(await command('signed-invalid', invalid, signedInvalid, ['--native-max-input-mib', '18']),
        'native_verification_refused', /^bundle_pack: TrailerChecksumMismatch$/);
    });
    await check(`${format}.tampered`, async () => {
      refused(await command('tampered', invalid, approval, ['--native-max-input-mib', '18']), 'native_expected_sha256_mismatch');
    });
    await check(`${format}.expired`, async () => {
      const expired = await sign(artifact, 'expired.dsse.json', true);
      refused(await command('expired', artifact, expired, ['--native-max-input-mib', '18']), 'attestation_expired');
    });
    assert.equal(hash(await readFile(artifact)), hash(bytes), 'positive artifact must remain unchanged');
    assert.deepEqual(await readdir(process.env.TMPDIR), [], 'native adapter must finalize its snapshots and scratch');
  }
  assert.equal(Object.keys(summary.checks).length, summary.expected_checks);
  assert.equal(summary.commands.length, 18);
  assert.equal(hash(await readFile(fg)), fgDigest, 'the selected native executable changed');
} catch (error) {
  summary.error = error.stack ?? String(error); console.error(summary.error); process.exitCode = 1;
} finally {
  process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt);
  await writeFile(join(work, 'summary.json'), JSON.stringify(summary, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
