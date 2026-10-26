// Real Ed25519/DSSE and CLI/filesystem/process integration. The fake fg below
// tests the adapter contract, not Rust Git semantics or native build readiness.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as signEd25519 } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmod, copyFile, lstat, mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { attestationPAE, signSourceBackup, signSourceBackupFile } from '../../scripts/lib/source-attestation.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const opaque = Buffer.from('signed operator bytes; this is NOT a Git fixture\n');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const name = Buffer.from('refs/heads/main').toString('hex');
const repo = 'Dicklesworthstone/frankengit';
const instant = value => new Date(value).toISOString().replace(/\.\d{3}Z$/, 'Z');
const keypair = () => generateKeyPairSync('ed25519', {
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' },
});
async function fixture(t) {
  const path = await mkdtemp(join(tmpdir(), 'fg-signed-native-test-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  // Copy the exact entry point and production helpers. The legacy backend is
  // an import sentinel, so a native run must not load or retry that decoder.
  for (const file of ['scripts/verify_git_bundle.mjs', 'scripts/lib/native-bundle-verifier.mjs',
    'scripts/lib/source-attestation.mjs', 'scripts/lib/source-attestation-options.mjs']) {
    const output = join(path, file); await mkdir(dirname(output), { recursive: true }); await copyFile(join(root, file), output);
  }
  const legacy = join(path, 'crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs');
  await mkdir(dirname(legacy), { recursive: true });
  await writeFile(legacy, `import { writeFileSync } from 'node:fs';
writeFileSync(${JSON.stringify(join(path, 'legacy-loaded'))}, 'loaded');
throw new Error('legacy_decoder_was_loaded');\n`);
  return { path, cli: join(path, 'scripts/verify_git_bundle.mjs'), legacy };
}
async function fakeFg(f, { mode = 'ok', original = null, expires = null, controls = [] } = {}) {
  const fg = join(f.path, `fg-${mode}`), log = join(f.path, `fg-${mode}.json`);
  await writeFile(fg, `#!${process.execPath}\n` + `
const fs = require('node:fs'), crypto = require('node:crypto');
const args = process.argv.slice(2), get = key => args[args.indexOf(key) + 1];
const path = args.at(-1), file = fs.openSync(path, 'r'), size = fs.fstatSync(file).size;
const digest = crypto.createHash('sha256'), chunk = Buffer.alloc(65536);
for (let position = 0; position < size;) {
  const read = fs.readSync(file, chunk, 0, Math.min(chunk.length, size - position), position);
  if (!read) throw new Error('fake_verifier_short_read'); digest.update(chunk.subarray(0, read)); position += read;
}
fs.closeSync(file); const hash = digest.digest('hex');
fs.writeFileSync(${JSON.stringify(log)}, JSON.stringify({ path, args, hash, pid: process.pid }));
const format = args.includes('--expect-format') ? get('--expect-format') : 'sha1';
const pins = args.flatMap((arg, at) => arg === '--expect-ref-hex' ? [args[at + 1]] : []).map(pin => {
  const at = pin.lastIndexOf('='); return { ref_hex: pin.slice(0, at), object_id: pin.slice(at + 1) };
});
const refs = pins.length ? pins : [{ ref_hex: '${name}', object_id: '1'.repeat(format === 'sha1' ? 40 : 64) }];
const report = { type:'git_bundle_verification',schema_version:1,profile:'native-full-bundle-graph-v1',
  object_format:format,bundle_bytes:size,artifact_sha256:hash,pack_bytes:0,
  pack_checksum:'1'.repeat(format === 'sha1' ? 40 : 64),object_count:3,reference_count:refs.length,
  payload_bytes:0,local_edges:2,external_gitlinks:0,delta_objects:0,resolution_passes:1,
  advertised_head:null,references:refs,pack_checksum_verified:true,objects_verified:true,
  object_graph_verified:true,graph_scope:'all-included-objects-and-advertised-direct-refs',
  gitlink_targets_verified:false,signatures_verified:false,origin_authenticated:false,
  current_branch_verified:false,strict_fsck_equivalent:false,repository_opened:false,
  repository_changed:false,forge_state_verified:false,caller_expectations_matched:true,
  expectations:{artifact_sha256:get('--expect-sha256'),object_format:args.includes('--expect-format')?format:null,
    ref_set:pins.length?(args.includes('--exact-refs')?'exact':'contains'):null,references:pins} };
if (args.includes('--file-backed')) Object.assign(report, {
  storage_profile:'file-backed-native-full-bundle-v1',scratch_bytes:0,scratch_removed:true,
  pack_sha256:crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex') });
const mode = ${JSON.stringify(mode)};
if (mode === 'remove-controls' || mode === 'expire-controls') for (const control of ${JSON.stringify(controls)}) fs.unlinkSync(control);
if (mode === 'refuse') { console.error('native refused authenticated but invalid content'); process.exit(2); }
if (mode === 'remove-source') fs.unlinkSync(${JSON.stringify(original)});
if (mode === 'hang') { process.on('SIGTERM', () => {}); setInterval(() => {}, 1000); }
else if (mode === 'expire' || mode === 'expire-controls') setTimeout(() => process.stdout.write(JSON.stringify(report) + '\\n'), Math.max(1, ${JSON.stringify(expires)} - Date.now() + 100));
else process.stdout.write(JSON.stringify(report) + '\\n');
`);
  await chmod(fg, 0o700); return { fg, log };
}
async function signed(f, metadata = {}, keys = keypair()) {
  const input = join(f.path, 'backup.bundle'), envelope = join(f.path, 'backup.dsse.json'), key = join(f.path, 'trusted.pem');
  const approval = await signSourceBackup(opaque, Buffer.from(keys.privateKey), {
    repository: repo, sequence: '18446744073709551615', ...metadata,
  });
  await writeFile(input, opaque); await writeFile(envelope, approval.envelope); await writeFile(key, keys.publicKey);
  return { input, envelope, key, approval, args: ['--attestation', envelope, '--trust-key', key,
    '--repository', repo, '--minimum-sequence', '18446744073709551615'] };
}
// Re-sign a deliberate metadata contradiction with a real independent key.
// This tests the adapter's separate signed-size obligation, not native Git data.
async function replaceSignedArtifact(approval, keys, changes) {
  const envelope = JSON.parse(approval.approval.envelope);
  const statement = JSON.parse(Buffer.from(envelope.payload, 'base64'));
  Object.assign(statement.artifact, changes);
  const payload = Buffer.from(JSON.stringify(statement));
  envelope.payload = payload.toString('base64');
  envelope.signatures[0].sig = signEd25519(null, attestationPAE(payload), keys.privateKey).toString('base64');
  await writeFile(approval.envelope, JSON.stringify(envelope));
}
function run(f, args) {
  const child = spawn(process.execPath, [f.cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, killSignal: 'SIGKILL' });
  let stdout = '', stderr = '';
  child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { child, done };
}
async function absent(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
async function started(log) {
  for (let at = 0; at < 500; at++) {
    try { return JSON.parse(await readFile(log)); } catch { await new Promise(resolve => setTimeout(resolve, 10)); }
  }
  throw new Error('native child did not start');
}
function refused(result, code) {
  assert.equal(result.code, 1, result.stderr); assert.equal(result.stdout, '');
  const error = JSON.parse(result.stderr); assert.equal(error.verified, false);
  if (code !== undefined) assert.equal(error.error, code);
}

test('explicit native mode does not even load the legacy JavaScript decoder', async t => {
  const f = await fixture(t), mock = await fakeFg(f), input = join(f.path, 'unsigned.bundle');
  await writeFile(input, opaque);
  const result = await run(f, [input, '--native-fg', mock.fg]).done;
  assert.equal(result.code, 0, result.stderr); assert.equal(JSON.parse(result.stdout).verifier_backend, 'native-fg');
  await absent(join(f.path, 'legacy-loaded'));
  const help = await run(f, ['--help']).done; assert.equal(help.code, 0); assert.match(help.stdout, /--native-fg/);
  await absent(join(f.path, 'legacy-loaded'));
});

test('real detached approvals compose with both native hash domains and exact pins', async t => {
  const f = await fixture(t), mock = await fakeFg(f), approval = await signed(f);
  for (const format of ['sha1', 'sha256']) {
    const oid = '2'.repeat(format === 'sha1' ? 40 : 64);
    const result = await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg,
      '--expect-format', format, '--expect-ref', `refs/heads/main=${format}:${oid}`, '--exact-refs', '--expect-sha256', sha(opaque)]).done;
    assert.equal(result.code, 0, result.stderr); const report = JSON.parse(result.stdout);
    assert.equal(report.object_format, format); assert.equal(report.object_graph_verified, true);
    assert.equal(report.source_attestation.signature_verified, true);
    assert.equal(report.source_attestation.minimum_sequence, '18446744073709551615');
    assert.equal(report.source_attestation.statement.artifact.sha256, report.artifact_sha256);
    assert.equal(report.input_snapshot_sha256, sha(opaque)); assert.equal(report.origin_authenticated, false);
    assert.equal(report.signatures_verified, false); assert.equal(report.forge_state_verified, false);
    assert.equal(report.source_attestation.object_closure_verified, false);
    assert.equal(report.expectations.ref_set, 'exact');
    const log = JSON.parse(await readFile(mock.log)); assert.notEqual(log.path, approval.input);
    assert.ok(!log.args.includes(approval.envelope) && !log.args.includes(approval.key));
    await absent(dirname(log.path));
  }
  assert.deepEqual(await readFile(approval.input), opaque); await absent(join(f.path, 'legacy-loaded'));
});

test('signer, repository, sequence and byte tampering refuse before launching fg', async t => {
  for (const mode of ['signer', 'signature', 'repository', 'floor', 'below-floor', 'bytes', 'size', 'expired']) {
    await t.test(mode, async () => {
      const f = await fixture(t), mock = await fakeFg(f), approval = await signed(f);
      if (mode === 'signer') await writeFile(approval.key, keypair().publicKey);
      if (mode === 'signature') {
        const envelope = JSON.parse(approval.approval.envelope); envelope.signatures[0].sig = Buffer.alloc(64).toString('base64');
        await writeFile(approval.envelope, JSON.stringify(envelope));
      }
      if (mode === 'repository') approval.args[approval.args.indexOf('--repository') + 1] = 'another/repository';
      if (mode === 'floor') approval.args[approval.args.indexOf('--minimum-sequence') + 1] = '18446744073709551616';
      if (mode === 'below-floor') {
        const keys = keypair();
        const old = await signSourceBackup(opaque, Buffer.from(keys.privateKey), { repository: repo, sequence: '1' });
        await writeFile(approval.envelope, old.envelope); await writeFile(approval.key, keys.publicKey);
      }
      if (mode === 'bytes') await writeFile(approval.input, Buffer.alloc(opaque.length));
      if (mode === 'size') await writeFile(approval.input, 'truncated');
      if (mode === 'expired') {
        // Sign under a fixed past clock; the actual CLI always uses current time.
        const keys = keypair(), now = Date.now() - 100000;
        const old = await signSourceBackup(opaque, Buffer.from(keys.privateKey), {
          repository: repo, sequence: '18446744073709551615', expires_at: instant(now + 10000),
        }, { now });
        await writeFile(approval.envelope, old.envelope); await writeFile(approval.key, keys.publicKey);
      }
      refused(await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg]).done);
      await absent(mock.log); await absent(join(f.path, 'legacy-loaded'));
    });
  }
});

test('authentication precedes input-file access and invalid native options precede authentication', async t => {
  const f = await fixture(t), mock = await fakeFg(f), approval = await signed(f);
  await writeFile(approval.key, keypair().publicKey);
  refused(await run(f, [join(f.path, 'missing.bundle'), ...approval.args, '--native-fg', mock.fg]).done, 'attestation_key_hint_mismatch');
  await rm(approval.key);
  refused(await run(f, [approval.input, ...approval.args, '--native-fg', 'fg']).done, 'native_absolute_fg_path_required');
  await absent(mock.log); await absent(join(f.path, 'legacy-loaded'));
});

test('signed input is not reopened after snapshot verification even if its original path disappears', async t => {
  for (const profile of [[], ['--native-file-backed']]) {
    const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f, { mode: 'remove-source', original: approval.input });
    const result = await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg, ...profile]).done;
    assert.equal(result.code, 0, result.stderr); const report = JSON.parse(result.stdout);
    assert.equal(report.artifact_sha256, sha(opaque)); assert.equal(report.source_attestation.signature_verified, true);
    await absent(approval.input); const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.path));
  }
});

test('an authenticated artifact does not bypass native refusal or independent identity pins', async t => {
  const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f, { mode: 'refuse' });
  refused(await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg]).done, 'native_verification_refused');
  await absent(join(f.path, 'legacy-loaded'));
  const permitted = await fakeFg(f);
  refused(await run(f, [approval.input, ...approval.args, '--native-fg', permitted.fg, '--expect-sha256', '0'.repeat(64)]).done, 'native_expected_sha256_mismatch');
  await absent(permitted.log);
});

test('approval expiry during verification uses the captured original controls after native cleanup', async t => {
  for (const profile of [[], ['--native-file-backed']]) {
    const f = await fixture(t), expires = Math.ceil((Date.now() + 2000) / 1000) * 1000;
    const approval = await signed(f, { expires_at: instant(expires) });
    const mock = await fakeFg(f, { mode: 'expire-controls', expires, controls: [approval.envelope, approval.key] });
    refused(await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg, ...profile]).done, 'attestation_expired');
    const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.path));
    await absent(approval.envelope); await absent(approval.key); await absent(join(f.path, 'legacy-loaded'));
  }
});

test('native deadline and SIGTERM both reap the signed verification child', async t => {
  for (const [deadline, fileBacked] of [[true, false], [false, false], [true, true], [false, true]]) {
    const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f, { mode: 'hang' });
    const extra = [...(deadline ? ['--native-timeout-secs', '1'] : []), ...(fileBacked ? ['--native-file-backed'] : [])];
    const running = run(f, [approval.input, ...approval.args, '--native-fg', mock.fg, ...extra]);
    const log = await started(mock.log);
    if (!deadline) running.child.kill('SIGTERM');
    refused(await running.done, deadline ? 'native_verification_deadline' : 'native_verification_cancelled');
    assert.throws(() => process.kill(log.pid, 0), { code: 'ESRCH' }); await absent(dirname(log.path));
    await absent(join(f.path, 'legacy-loaded'));
  }
});

test('partial/duplicate authentication groups and native options never downgrade', async t => {
  const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f);
  for (const args of [
    [approval.input, '--native-fg', mock.fg, '--attestation', approval.envelope],
    [approval.input, '--native-fg', mock.fg, ...approval.args, '--trust-key', approval.key],
    [approval.input, '--native-fg', mock.fg, '--native-fg', mock.fg],
    [approval.input, '--native-fg', mock.fg, '--native-timeout-secs', '0'],
    [approval.input, '--native-fg', mock.fg, '--native-timeout-secs', '3601'],
    [approval.input, '--native-timeout-secs', '1'],
    [approval.input, '--native-fg', mock.fg, '--expect-ref', 'refs/heads/main=' + '1'.repeat(40)],
  ]) refused(await run(f, args).done);
  await absent(mock.log); await absent(join(f.path, 'legacy-loaded'));
});

test('default selection still uses the original legacy backend and owned authenticated bytes', async t => {
  const f = await fixture(t), approval = await signed(f);
  // This sentinel tests dispatch compatibility, not the legacy Git decoder.
  await writeFile(f.legacy, `export const BUNDLE_VERIFY_LIMITS = { maxInputBytes:16777216, maxRefs:1024 };
export function normalizeBundleExpectation(value) { if(value.sha256 !== '${sha(opaque)}') throw new Error('legacy_pin_mismatch'); }
export async function verifyGitBundle(bytes) { return { backend:'legacy', bytes:bytes.length }; }
export async function verifyGitBundleAgainst(bytes, expected) { normalizeBundleExpectation(expected); return { backend:'legacy-pinned', bytes:bytes.length }; }\n`);
  const plain = await run(f, [approval.input]).done;
  assert.deepEqual(JSON.parse(plain.stdout), { backend: 'legacy', bytes: opaque.length });
  const result = await run(f, [approval.input, ...approval.args, '--expect-sha256', sha(opaque)]).done;
  assert.equal(result.code, 0, result.stderr); const report = JSON.parse(result.stdout);
  assert.equal(report.backend, 'legacy-pinned'); assert.equal(report.bytes, opaque.length);
  assert.equal(report.source_attestation.signature_verified, true);
});


test('legacy reference ceilings are checked before opening missing inputs', async t => {
  const f = await fixture(t);
  await writeFile(f.legacy, `export const BUNDLE_VERIFY_LIMITS = { maxInputBytes:16777216, maxRefs:1 };
export function normalizeBundleExpectation() {}
`);
  refused(await run(f, [join(f.path, 'missing.bundle'), '--expect-format', 'sha1',
    '--expect-ref', 'refs/heads/a=' + '1'.repeat(40), '--expect-ref', 'refs/heads/b=' + '2'.repeat(40)]).done, 'expectation_reference_limit');
});

test('literal input paths and native-only flags retain their exact parsing roles', async t => {
  const f = await fixture(t), mock = await fakeFg(f), input = join(f.path, '--native-fg');
  await writeFile(input, opaque);
  const result = await run(f, ['--native-fg', mock.fg, '--', input]).done;
  assert.equal(result.code, 0, result.stderr); assert.equal(JSON.parse(result.stdout).artifact_sha256, sha(opaque));
  refused(await run(f, ['--native-fg', mock.fg, '--', input, '--expect-format', 'sha1']).done, 'one_bundle_path_required');
});


test('file-backed signed and unsigned commands preserve both hash domains and explicit resource budgets', async t => {
  const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f);
  for (const authenticated of [false, true]) {
    for (const format of ['sha1', 'sha256']) {
      const oid = '2'.repeat(format === 'sha1' ? 40 : 64);
      const result = await run(f, [approval.input, ...(authenticated ? approval.args : []),
        '--native-fg', mock.fg, '--native-file-backed', '--native-max-input-mib', '16384',
        '--native-max-expanded-mib', '16384', '--native-max-blob-mib', '512', '--expect-format', format,
        '--expect-ref', `refs/heads/main=${format}:${oid}`, '--exact-refs']).done;
      assert.equal(result.code, 0, result.stderr); const report = JSON.parse(result.stdout);
      assert.equal(report.storage_profile, 'file-backed-native-full-bundle-v1');
      assert.equal(report.scratch_removed, true); assert.equal(report.object_format, format);
      assert.equal(report.expectations.artifact_sha256, sha(opaque));
      assert.equal(report.expectations.ref_set, 'exact'); assert.equal(report.signatures_verified, false);
      assert.equal(report.origin_authenticated, false); assert.equal(report.forge_state_verified, false);
      if (authenticated) {
        assert.equal(report.source_attestation.signature_verified, true);
        assert.equal(report.source_attestation.statement.artifact.bytes, report.bundle_bytes);
      } else assert.equal(report.source_attestation, undefined);
      const log = JSON.parse(await readFile(mock.log)), get = flag => log.args[log.args.indexOf(flag) + 1];
      assert.ok(log.args.includes('--file-backed')); assert.notEqual(log.path, approval.input);
      assert.equal(log.args[log.args.indexOf('--max-blob-mib') + 1], '512');
      assert.equal(get('--max-input-mib'), '16384'); assert.equal(get('--max-expanded-mib'), '16384');
      assert.equal(get('--expect-sha256'), sha(opaque));
      assert.ok(!log.args.includes(approval.envelope) && !log.args.includes(approval.key));
      await absent(get('--scratch-dir')); await absent(dirname(log.path));
    }
  }
  await absent(join(f.path, 'legacy-loaded')); assert.deepEqual(await readFile(approval.input), opaque);
});

test('native profile changes are explicit and defaults remain bounded', async t => {
  const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f);
  for (const [extra, fileBacked, input, expanded] of [
    [[], false, '16', '128'], [['--native-file-backed'], true, '16', '128'],
    [['--native-max-input-mib', '128', '--native-max-expanded-mib', '1'], false, '128', '1'],
  ]) {
    const result = await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg, ...extra]).done;
    assert.equal(result.code, 0, result.stderr);
    const log = JSON.parse(await readFile(mock.log)), get = flag => log.args[log.args.indexOf(flag) + 1];
    assert.equal(log.args.includes('--file-backed'), fileBacked);
    assert.equal(get('--max-input-mib'), input); assert.equal(get('--max-expanded-mib'), expanded);
    await absent(dirname(log.path));
  }
});

test('file-backed approval and independent-pin refusals happen before missing artifact access', async t => {
  for (const failure of ['signature', 'independent-pin', 'signed-budget']) {
    const f = await fixture(t), keys = keypair(), approval = await signed(f, {}, keys), mock = await fakeFg(f);
    let extra = [], code;
    if (failure === 'signature') {
      await writeFile(approval.key, keypair().publicKey); code = 'attestation_key_hint_mismatch';
    } else if (failure === 'independent-pin') {
      extra = ['--expect-sha256', '0'.repeat(64)]; code = 'native_expected_sha256_mismatch';
    } else {
      await replaceSignedArtifact(approval, keys, { bytes: 1024 * 1024 + 1 });
      extra = ['--native-max-input-mib', '1']; code = 'invalid_attestation_artifact';
    }
    refused(await run(f, [join(f.path, 'missing.bundle'), ...approval.args,
      '--native-fg', mock.fg, '--native-file-backed', ...extra]).done, code);
    await absent(mock.log); await absent(join(f.path, 'legacy-loaded'));
  }
});

test('a signed claim cannot select its own input allowance', async t => {
  const f = await fixture(t), keys = keypair(), approval = await signed(f, {}, keys), mock = await fakeFg(f);
  await replaceSignedArtifact(approval, keys, { bytes: 16 * 1024 * 1024 + 1 });
  const args = [join(f.path, 'missing.bundle'), ...approval.args, '--native-fg', mock.fg, '--native-file-backed'];
  refused(await run(f, args).done, 'invalid_attestation_artifact');
  // A larger externally selected allowance authenticates that same statement.
  // The deliberately absent artifact then fails at file access, before fg.
  refused(await run(f, [...args, '--native-max-input-mib', '17']).done, 'ENOENT');
  await absent(mock.log); await absent(join(f.path, 'legacy-loaded'));
});

test('signed length is checked independently of a matching artifact digest and native report', async t => {
  for (const profile of [[], ['--native-file-backed']]) {
    const f = await fixture(t), keys = keypair(), approval = await signed(f, {}, keys), mock = await fakeFg(f);
    await replaceSignedArtifact(approval, keys, { bytes: opaque.length + 1 });
    refused(await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg, ...profile]).done, 'attestation_artifact_mismatch');
    const log = JSON.parse(await readFile(mock.log)); assert.equal(log.hash, sha(opaque));
    await absent(dirname(log.path)); await absent(join(f.path, 'legacy-loaded'));
  }
});

test('approval revalidation does not reopen removed control paths or discard a valid captured approval', async t => {
  const f = await fixture(t), approval = await signed(f);
  const mock = await fakeFg(f, { mode: 'remove-controls', controls: [approval.envelope, approval.key] });
  const result = await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg, '--native-file-backed']).done;
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).source_attestation.signature_verified, true);
  await absent(approval.envelope); await absent(approval.key);
  const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.path));
});

test('file-backed artifact tampering still refuses before launching fg', async t => {
  const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f);
  await writeFile(approval.input, Buffer.alloc(opaque.length));
  refused(await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg, '--native-file-backed']).done, 'native_expected_sha256_mismatch');
  await absent(mock.log); await absent(join(f.path, 'legacy-loaded'));
});

test('native storage options reject invalid, implicit and legacy combinations before authentication', async t => {
  const f = await fixture(t), mock = await fakeFg(f), missing = join(f.path, 'missing.bundle');
  for (const [flags, code] of [
    [['--native-file-backed'], 'native_fg_required_for_file_limits'],
    [['--native-max-input-mib', '1'], 'native_fg_required_for_file_limits'],
    [['--native-max-expanded-mib', '1'], 'native_fg_required_for_file_limits'],
    [['--native-max-blob-mib', '64'], 'native_fg_required_for_file_limits'],
    [['--native-fg', mock.fg, '--native-max-blob-mib', '32'], 'native_blob_limit_requires_file_profile'],
    [['--native-fg', mock.fg, '--native-file-backed', '--native-max-blob-mib', '0'], 'native_blob_limit'],
    [['--native-fg', mock.fg, '--native-file-backed', '--native-max-blob-mib', '16385'], 'native_blob_limit'],
    [['--native-fg', mock.fg, '--native-file-backed', '--native-max-blob-mib', '64', '--native-max-blob-mib', '128'], 'duplicate_option'],
    [['--native-fg', mock.fg, '--native-file-backed', '--native-file-backed'], 'duplicate_option'],
    [['--native-fg', mock.fg, '--native-max-input-mib', '129'], 'native_input_limit'],
    [['--native-fg', mock.fg, '--native-max-expanded-mib', '129'], 'native_expanded_limit'],
    [['--native-fg', mock.fg, '--native-file-backed', '--native-max-input-mib', '16385'], 'native_input_limit'],
    [['--native-fg', mock.fg, '--native-file-backed', '--native-max-expanded-mib', '16385'], 'native_expanded_limit'],
    [['--native-fg', mock.fg, '--native-max-input-mib', '1.5'], 'native_input_limit'],
    [['--native-fg', mock.fg, '--native-file-backed', '--native-max-expanded-mib', '0'], 'native_expanded_limit'],
    [['--native-fg', mock.fg, '--native-file-backed', '--native-max-input-mib', '1', '--native-max-input-mib', '2'], 'duplicate_option'],
  ]) refused(await run(f, [missing, ...flags, '--attestation', join(f.path, 'missing.dsse'),
    '--trust-key', join(f.path, 'missing.key'), '--repository', repo, '--minimum-sequence', '1']).done, code);
  await absent(mock.log); await absent(join(f.path, 'legacy-loaded'));
});


test('a real signed17MiB file crosses the old ceiling only with an explicit input allowance', async t => {
  // This is real streaming-signature/file/process orchestration over opaque
  // sparse bytes. The fake fg is intentionally not proof of Rust Git semantics.
  const f = await fixture(t), keys = keypair(), mock = await fakeFg(f);
  const input = join(f.path, 'large.bundle'), envelope = join(f.path, 'large.dsse.json'), key = join(f.path, 'large.pem');
  const bytes = 17 * 1024 * 1024, file = await open(input, 'wx', 0o600);
  try { await file.truncate(bytes); } finally { await file.close(); }
  const approval = await signSourceBackupFile(input, Buffer.from(keys.privateKey), {
    repository: repo, sequence: '18446744073709551615',
  }, { maximumBytes: bytes });
  assert.equal(approval.statement.artifact.bytes, bytes);
  assert.ok(approval.streaming.maximum_read_bytes <= 65536);
  await writeFile(envelope, approval.envelope); await writeFile(key, keys.publicKey);
  const args = [input, '--attestation', envelope, '--trust-key', key, '--repository', repo,
    '--minimum-sequence', '18446744073709551615', '--native-fg', mock.fg, '--native-file-backed'];
  refused(await run(f, args).done, 'invalid_attestation_artifact'); await absent(mock.log);
  const result = await run(f, [...args, '--native-max-input-mib', '17']).done;
  assert.equal(result.code, 0, result.stderr); const report = JSON.parse(result.stdout);
  assert.equal(report.bundle_bytes, bytes); assert.equal(report.artifact_sha256, approval.statement.artifact.sha256);
  assert.equal(report.source_attestation.signature_verified, true);
  assert.equal(report.source_attestation.statement.artifact.bytes, bytes);
  assert.equal(report.storage_profile, 'file-backed-native-full-bundle-v1');
  const log = JSON.parse(await readFile(mock.log)); assert.equal(log.hash, approval.statement.artifact.sha256);
  assert.notEqual(log.path, input); await absent(dirname(log.path)); await absent(join(f.path, 'legacy-loaded'));
  assert.equal((await lstat(input)).size, bytes);
});
