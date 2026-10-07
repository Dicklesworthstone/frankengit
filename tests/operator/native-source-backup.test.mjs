// Real Ed25519/DSSE and CLI/filesystem/process integration. The fake fg below
// tests the adapter contract, not Rust Git semantics or native build readiness.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { spawn } from 'node:child_process';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signSourceBackup } from '../../scripts/lib/source-attestation.mjs';

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
async function fakeFg(f, { mode = 'ok', original = null, expires = null } = {}) {
  const fg = join(f.path, `fg-${mode}`), log = join(f.path, `fg-${mode}.json`);
  await writeFile(fg, `#!${process.execPath}\n` + `
const fs = require('node:fs'), crypto = require('node:crypto');
const args = process.argv.slice(2), get = key => args[args.indexOf(key) + 1];
const path = args.at(-1), bytes = fs.readFileSync(path), hash = crypto.createHash('sha256').update(bytes).digest('hex');
fs.writeFileSync(${JSON.stringify(log)}, JSON.stringify({ path, args, hash, pid: process.pid }));
const format = args.includes('--expect-format') ? get('--expect-format') : 'sha1';
const pins = args.flatMap((arg, at) => arg === '--expect-ref-hex' ? [args[at + 1]] : []).map(pin => {
  const at = pin.lastIndexOf('='); return { ref_hex: pin.slice(0, at), object_id: pin.slice(at + 1) };
});
const refs = pins.length ? pins : [{ ref_hex: '${name}', object_id: '1'.repeat(format === 'sha1' ? 40 : 64) }];
const report = { type:'git_bundle_verification',schema_version:1,profile:'native-full-bundle-graph-v1',
  object_format:format,bundle_bytes:bytes.length,artifact_sha256:hash,pack_bytes:0,
  pack_checksum:'1'.repeat(format === 'sha1' ? 40 : 64),object_count:3,reference_count:refs.length,
  payload_bytes:0,local_edges:2,external_gitlinks:0,delta_objects:0,resolution_passes:1,
  advertised_head:null,references:refs,pack_checksum_verified:true,objects_verified:true,
  object_graph_verified:true,graph_scope:'all-included-objects-and-advertised-direct-refs',
  gitlink_targets_verified:false,signatures_verified:false,origin_authenticated:false,
  current_branch_verified:false,strict_fsck_equivalent:false,repository_opened:false,
  repository_changed:false,forge_state_verified:false,caller_expectations_matched:true,
  expectations:{artifact_sha256:get('--expect-sha256'),object_format:args.includes('--expect-format')?format:null,
    ref_set:pins.length?(args.includes('--exact-refs')?'exact':'contains'):null,references:pins} };
const mode = ${JSON.stringify(mode)};
if (mode === 'refuse') { console.error('native refused authenticated but invalid content'); process.exit(2); }
if (mode === 'remove-source') fs.unlinkSync(${JSON.stringify(original)});
if (mode === 'hang') { process.on('SIGTERM', () => {}); setInterval(() => {}, 1000); }
else if (mode === 'expire') setTimeout(() => process.stdout.write(JSON.stringify(report) + '\\n'), Math.max(1, ${JSON.stringify(expires)} - Date.now() + 100));
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

test('signed input is not reopened after authentication even if its original path disappears', async t => {
  const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f, { mode: 'remove-source', original: approval.input });
  const result = await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg]).done;
  assert.equal(result.code, 0, result.stderr); const report = JSON.parse(result.stdout);
  assert.equal(report.artifact_sha256, sha(opaque)); assert.equal(report.source_attestation.signature_verified, true);
  await absent(approval.input); const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.path));
});

test('an authenticated artifact does not bypass native refusal or independent identity pins', async t => {
  const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f, { mode: 'refuse' });
  refused(await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg]).done, 'native_verification_refused');
  await absent(join(f.path, 'legacy-loaded'));
  const permitted = await fakeFg(f);
  refused(await run(f, [approval.input, ...approval.args, '--native-fg', permitted.fg, '--expect-sha256', '0'.repeat(64)]).done, 'native_expected_sha256_mismatch');
  await absent(permitted.log);
});

test('approval expiry during native verification refuses an otherwise successful report', async t => {
  const f = await fixture(t), expires = Math.ceil((Date.now() + 2000) / 1000) * 1000;
  const approval = await signed(f, { expires_at: instant(expires) }), mock = await fakeFg(f, { mode: 'expire', expires });
  refused(await run(f, [approval.input, ...approval.args, '--native-fg', mock.fg]).done, 'attestation_expired');
  const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.path));
  await absent(join(f.path, 'legacy-loaded'));
});

test('native deadline and SIGTERM both reap the signed verification child', async t => {
  for (const deadline of [true, false]) {
    const f = await fixture(t), approval = await signed(f), mock = await fakeFg(f, { mode: 'hang' });
    const extra = deadline ? ['--native-timeout-secs', '1'] : [];
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
