// Executed adapter/process tests use a deliberately fake fg. Only the explicitly
// enabled final native test is evidence about the Rust verifier itself.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, lstat, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeNativeBundleExpectation, verifyNativeGitBundle, verifyNativeGitBundleFile } from '../../scripts/lib/native-bundle-verifier.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const cli = join(root, 'scripts/verify_git_bundle_native.mjs');
const opaque = Buffer.from('opaque adapter fixture, NOT a Git bundle');
const sha = value => createHash('sha256').update(value).digest('hex');
const ref = Buffer.from('refs/heads/main').toString('hex');
async function sandbox(t) {
  const path = await mkdtemp(join(tmpdir(), 'fg-native-bridge-test-'));
  t.after(() => rm(path, { recursive: true, force: true })); return path;
}
async function fakeFg(directory, mode = 'ok') {
  const path = join(directory, `fg-${mode}`), log = join(directory, `${mode}.json`);
  await writeFile(path, `#!${process.execPath}\n` + `
const fs = require('node:fs'), crypto = require('node:crypto');
const args = process.argv.slice(2), get = key => args[args.indexOf(key) + 1];
const input = args[args.length - 1], bytes = fs.readFileSync(input);
const format = args.includes('--expect-format') ? get('--expect-format') : 'sha1';
const id = '1'.repeat(format === 'sha1' ? 40 : 64);
const pins = args.flatMap((arg, at) => arg === '--expect-ref-hex' ? [args[at + 1]] : []).map(value => {
  const at = value.lastIndexOf('='); return { ref_hex: value.slice(0, at), object_id: value.slice(at + 1) };
});
pins.sort((a,b) => a.ref_hex < b.ref_hex ? -1 : a.ref_hex > b.ref_hex ? 1 : 0);
const refs = pins.length ? pins : [{ ref_hex: '${ref}', object_id: id }];
const hash = crypto.createHash('sha256').update(bytes).digest('hex');
fs.writeFileSync(${JSON.stringify(log)}, JSON.stringify({ args, input, pid: process.pid, hash,
  fileMode: fs.statSync(input).mode & 511, directoryMode: fs.statSync(require('node:path').dirname(input)).mode & 511 }));
const report = { type:'git_bundle_verification',schema_version:1,profile:'native-full-bundle-graph-v1',
  object_format:format,bundle_bytes:bytes.length,artifact_sha256:hash,pack_bytes:0,pack_checksum:id,
  object_count:3,reference_count:refs.length,payload_bytes:0,local_edges:2,external_gitlinks:0,
  delta_objects:0,resolution_passes:1,advertised_head:null,references:refs,
  pack_checksum_verified:true,objects_verified:true,object_graph_verified:true,
  graph_scope:'all-included-objects-and-advertised-direct-refs',gitlink_targets_verified:false,
  signatures_verified:false,origin_authenticated:false,current_branch_verified:false,
  strict_fsck_equivalent:false,repository_opened:false,repository_changed:false,forge_state_verified:false,
  caller_expectations_matched:true,expectations:{artifact_sha256:get('--expect-sha256'),
    object_format:args.includes('--expect-format')?format:null,
    ref_set:pins.length?(args.includes('--exact-refs')?'exact':'contains'):null,references:pins} };
const mode = ${JSON.stringify(mode)};
if (mode === 'refuse') { console.error('typed native refusal'); process.exit(2); }
if (mode === 'signal') process.kill(process.pid, 'SIGTERM');
else if (mode === 'hang') { process.on('SIGTERM', () => {}); setInterval(() => {}, 1000); }
else if (mode === 'large') process.stdout.write('x'.repeat(8192));
else if (mode === 'stderr') process.stderr.write('x'.repeat(70000));
else if (mode === 'utf8') process.stdout.write(Buffer.from([255]));
else if (mode === 'duplicate') process.stdout.write(JSON.stringify(report).replace('{', '{"schema_version":0,'));
else if (mode === 'documents') process.stdout.write(JSON.stringify(report) + '\\n{}');
else {
  if (mode === 'hash') report.artifact_sha256 = '0'.repeat(64);
  if (mode === 'size') report.bundle_bytes++;
  if (mode === 'claim') report.origin_authenticated = true;
  if (mode === 'incomplete') report.object_graph_verified = false;
  if (mode === 'profile') report.profile = 'another-engine';
  if (mode === 'extra') report.unchecked_authorization = true;
  if (mode === 'echo') report.expectations.artifact_sha256 = '0'.repeat(64);
  if (mode === 'format') report.expectations.object_format = null;
  if (mode === 'refs') report.references = [];
  if (mode === 'count') report.object_count = 100001;
  if (mode === 'substitute') { fs.unlinkSync(input); fs.writeFileSync(input + '.foreign', 'foreign'); fs.renameSync(input + '.foreign', input); }
  process.stdout.write(JSON.stringify(report) + '\\n');
}
`);
  await chmod(path, 0o700); return { fg: path, log };
}
async function absent(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
async function waitFor(path) {
  for (let n = 0; n < 300; n++) {
    try { return JSON.parse(await readFile(path, 'utf8')); } catch { await new Promise(resolve => setTimeout(resolve, 10)); }
  }
  throw new Error('test child did not start');
}
async function runCli(args, options = {}) {
  return await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'], ...options });
    let stdout = '', stderr = '';
    child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

test('owned snapshot is private, hash-bound and removed only after the child exits', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory);
  const result = await verifyNativeGitBundle(opaque, { fg: mock.fg });
  const log = JSON.parse(await readFile(mock.log));
  assert.equal(log.hash, sha(opaque)); assert.equal(log.fileMode, 0o600); assert.equal(log.directoryMode, 0o700);
  assert.deepEqual(log.args.slice(0, 2), ['bundle', 'verify']); assert.equal(log.args.at(-2), '--');
  assert.equal(log.args[log.args.indexOf('--expect-sha256') + 1], sha(opaque));
  assert.equal(result.verifier_backend, 'native-fg'); assert.equal(result.caller_identity_pins_supplied, false);
  assert.equal(result.origin_authenticated, false); assert.equal(result.repository_changed, false);
  await absent(dirname(log.input));
});

test('copies mutable bytes and every pin before asynchronous staging', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory);
  const bytes = Buffer.from(opaque), expected = { object_format: 'sha256', refs: [{ ref_hex: ref, object_id: 'sha256:' + '2'.repeat(64) }], exact_refs: true };
  const pending = verifyNativeGitBundle(bytes, { fg: mock.fg, expected });
  bytes.fill(0); expected.refs[0].object_id = '3'.repeat(64); expected.object_format = 'sha1';
  const result = await pending;
  assert.equal(result.artifact_sha256, sha(opaque)); assert.equal(result.object_format, 'sha256');
  assert.deepEqual(result.references, [{ ref_hex: ref, object_id: '2'.repeat(64) }]);
  assert.equal(result.expectations.ref_set, 'exact'); assert.equal(result.caller_identity_pins_supplied, true);
});

test('native reference constraints retain both domains and lossless byte names', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory);
  for (const format of ['sha1', 'sha256']) {
    const name = Buffer.concat([Buffer.from('refs/heads/'), Buffer.from([255])]).toString('hex');
    const id = 'a'.repeat(format === 'sha1' ? 40 : 64);
    const result = await verifyNativeGitBundle(opaque, { fg: mock.fg, expected: { object_format: format, refs: [{ ref_hex: name, object_id: id }] } });
    assert.deepEqual(result.references, [{ ref_hex: name, object_id: id }]); assert.equal(result.expectations.ref_set, 'contains');
  }
});

test('independent SHA-256 mismatch refuses before process creation', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory);
  await assert.rejects(verifyNativeGitBundle(opaque, { fg: mock.fg, expected: { sha256: '0'.repeat(64) } }), { code: 'native_expected_sha256_mismatch' });
  await absent(mock.log);
  const result = await verifyNativeGitBundle(opaque, { fg: mock.fg, expected: { sha256: sha(opaque) } });
  assert.equal(result.caller_identity_pins_supplied, true);
});

test('invalid constraints and resource ceilings fail closed', async () => {
  for (const expected of [
    { sha256: 'A'.repeat(64) }, { object_format: 'SHA1' }, { exact_refs: 'true' }, { exact_refs: true },
    { refs: [{ ref_hex: ref, object_id: '1'.repeat(40) }] },
    { object_format: 'sha1', refs: [{ ref_hex: ref, object_id: 'sha256:' + '1'.repeat(64) }] },
    { object_format: 'sha1', refs: [{ ref_hex: ref, object_id: '1'.repeat(40) }, { ref_hex: ref, object_id: '1'.repeat(40) }] },
    { object_format: 'sha1', refs: [{ ref_hex: 'abf', object_id: '1'.repeat(40) }] }, { invented: true },
  ]) assert.throws(() => normalizeNativeBundleExpectation(expected));
  for (const options of [{ fg: 'fg' }, { fg: '/fg', maxInputMiB: 129 }, { fg: '/fg', timeoutMs: 0 },
    { fg: '/fg', maxObjects: 0 }, { fg: '/fg', maxRefs: 4097 }, { fg: '/fg', maxReportBytes: 9 * 1024 * 1024 },
    { fg: '/fg', maxInputMib: 1 }]) await assert.rejects(verifyNativeGitBundle(opaque, options));
  await assert.rejects(verifyNativeGitBundle(new Uint8Array(new SharedArrayBuffer(4)), { fg: '/fg' }), { code: 'native_shared_input_refused' });
});

test('actual file input is copied once; literal names are not process arguments', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, '--hostile $(touch nope).bundle');
  await writeFile(path, opaque);
  const result = await verifyNativeGitBundleFile(path, { fg: mock.fg });
  assert.equal(result.artifact_sha256, sha(opaque));
  const log = JSON.parse(await readFile(mock.log)); assert.ok(!log.args.includes(path));
  assert.deepEqual(await readFile(path), opaque); await absent(join(directory, 'nope'));
});

test('rejects symlink, directory, empty and oversized inputs before spawning', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'bundle');
  await writeFile(path, opaque); await symlink(path, join(directory, 'link')); await writeFile(join(directory, 'empty'), '');
  await writeFile(join(directory, 'large'), Buffer.alloc(1024 * 1024 + 1));
  for (const input of [directory, join(directory, 'link'), join(directory, 'empty'), join(directory, 'large')]) {
    await assert.rejects(verifyNativeGitBundleFile(input, { fg: mock.fg, maxInputMiB: 1 }));
  }
  await absent(mock.log);
});

test('a missing fg is a refusal, never a JavaScript verifier fallback', async t => {
  const directory = await sandbox(t);
  await assert.rejects(verifyNativeGitBundle(opaque, { fg: join(directory, 'missing-fg') }), { code: 'native_verifier_start_failed' });
});

test('pre-cancellation creates no process; runtime cancellation reaps an uncooperative child', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory, 'hang');
  const early = new AbortController(); early.abort();
  await assert.rejects(verifyNativeGitBundle(opaque, { fg: mock.fg, signal: early.signal }), { code: 'native_verification_cancelled' });
  await absent(mock.log);
  const controller = new AbortController();
  const pending = verifyNativeGitBundle(opaque, { fg: mock.fg, signal: controller.signal });
  const rejected = assert.rejects(pending, { code: 'native_verification_cancelled' });
  const log = await waitFor(mock.log); controller.abort(); await rejected;
  assert.throws(() => process.kill(log.pid, 0), { code: 'ESRCH' }); await absent(dirname(log.input));
});

test('one deadline terminates and reaps the child rather than only racing a Promise', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory, 'hang');
  await assert.rejects(verifyNativeGitBundle(opaque, { fg: mock.fg, timeoutMs: 600 }), { code: 'native_verification_deadline' });
  const log = JSON.parse(await readFile(mock.log)); assert.throws(() => process.kill(log.pid, 0), { code: 'ESRCH' });
  await absent(dirname(log.input));
});

test('rejects unsuccessful, malformed, over-budget and contradictory native reports', async t => {
  const directory = await sandbox(t);
  for (const mode of ['refuse', 'signal', 'large', 'stderr', 'utf8', 'duplicate', 'documents',
    'hash', 'size', 'claim', 'incomplete', 'profile', 'extra', 'echo', 'format', 'refs', 'count']) {
    await t.test(mode, async () => {
      const mock = await fakeFg(directory, mode);
      await assert.rejects(verifyNativeGitBundle(opaque, { fg: mock.fg, maxReportBytes: mode === 'large' ? 2048 : 2 * 1024 * 1024,
        expected: { object_format: 'sha1', refs: [{ ref_hex: ref, object_id: '1'.repeat(40) }], exact_refs: true } }));
      const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.input));
    });
  }
});

test('cleanup retains an observed replacement instead of deleting foreign bytes', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory, 'substitute');
  await assert.rejects(verifyNativeGitBundle(opaque, { fg: mock.fg }), { code: 'native_snapshot_cleanup_refused' });
  const log = JSON.parse(await readFile(mock.log));
  t.after(() => rm(dirname(log.input), { recursive: true, force: true }));
  assert.equal(await readFile(log.input, 'utf8'), 'foreign');
});

test('native byte ceiling accepts an input larger than the legacy 16 MiB profile', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory);
  const bytes = Buffer.alloc(16 * 1024 * 1024 + 17, 42);
  const result = await verifyNativeGitBundle(bytes, { fg: mock.fg, maxInputMiB: 17 });
  assert.equal(result.bundle_bytes, bytes.length); assert.equal(result.artifact_sha256, sha(bytes));
  await assert.rejects(verifyNativeGitBundle(bytes, { fg: mock.fg, maxInputMiB: 16 }), { code: 'native_input_size_or_type' });
});

test('CLI invokes the native adapter and preserves native pins and receipt non-claims', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'data.bundle');
  await writeFile(path, opaque);
  const result = await runCli([path, '--fg', mock.fg, '--expect-sha256', sha(opaque), '--expect-format', 'sha256',
    '--expect-ref', 'refs/heads/main=' + '2'.repeat(64), '--exact-refs']);
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(result.stdout); assert.equal(report.object_format, 'sha256');
  assert.equal(report.expectations.ref_set, 'exact'); assert.equal(report.origin_authenticated, false);
  assert.equal(report.input_snapshot_sha256, sha(opaque));
});

test('CLI refuses malformed and duplicate options without creating a process', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory);
  for (const extra of [['--fg', mock.fg], ['--max-input-mib', '0'], ['--max-refs', '01'], ['--unknown'],
    ['--expect-ref', 'refs/heads/main=' + '1'.repeat(40)], ['--expect-format', 'sha256', '--expect-ref', 'refs/heads/main=' + '1'.repeat(40)]]) {
    const result = await runCli(['missing.bundle', '--fg', mock.fg, ...extra]); assert.notEqual(result.code, 0); assert.equal(result.stdout, '');
  }
  await absent(mock.log);
  const help = await runCli(['--help']); assert.equal(help.code, 0); assert.match(help.stdout, /native Rust/);
});

function gitFixture(format) {
  const object = (kind, body) => ({ kind, body, id: createHash(format).update(`${kind} ${body.length}\0`).update(body).digest() });
  const blob = object('blob', Buffer.from('native bridge fixture\n'));
  const tree = object('tree', Buffer.concat([Buffer.from('100644 a.txt\0'), blob.id]));
  const commit = object('commit', Buffer.from(`tree ${tree.id.toString('hex')}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nfixture\n`));
  const header = Buffer.alloc(12); header.write('PACK'); header.writeUInt32BE(2, 4); header.writeUInt32BE(3, 8);
  const parts = [header];
  for (const item of [blob, tree, commit]) {
    let size = item.body.length; const encoded = []; let byte = ({ commit: 1, tree: 2, blob: 3 }[item.kind] << 4) | (size & 15); size >>>= 4;
    if (size) byte |= 128; encoded.push(byte);
    while (size) { byte = size & 127; size >>>= 7; encoded.push(byte | (size ? 128 : 0)); }
    parts.push(Buffer.from(encoded), deflateSync(item.body));
  }
  const pack = Buffer.concat(parts), tip = commit.id.toString('hex');
  const prelude = format === 'sha1' ? '# v2 git bundle\n' : '# v3 git bundle\n@object-format=sha256\n';
  return { bytes: Buffer.concat([Buffer.from(`${prelude}${tip} refs/heads/main\n${tip} HEAD\n\n`), pack, createHash(format).update(pack).digest()]), tip };
}

test('test-only SHA-1/SHA-256 fixtures pass the exact Git 2.47.3 local oracle', async t => {
  const probe = spawnSync('git', ['--version'], { encoding: 'utf8' });
  if (probe.status !== 0 || probe.stdout.trim() !== 'git version 2.47.3') { t.skip('pinned local Git 2.47.3 oracle unavailable'); return; }
  const directory = await sandbox(t);
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_ALLOW_PROTOCOL: 'file' };
  for (const format of ['sha1', 'sha256']) {
    const fixture = gitFixture(format), path = join(directory, `${format}.bundle`), repo = join(directory, format);
    await writeFile(path, fixture.bytes);
    for (const args of [['init', '--bare', `--object-format=${format}`, repo], ['-C', repo, 'bundle', 'verify', path],
      ['-C', repo, 'fetch', path, 'refs/heads/main:refs/heads/main'], ['-C', repo, 'fsck', '--strict']]) {
      const result = spawnSync('git', args, { env, encoding: 'utf8' }); assert.equal(result.status, 0, result.stderr);
    }
  }
});

test('actual fg verifies both native domains and refuses corrupt input', { skip: !process.env.FG_NATIVE_BIN }, async t => {
  const directory = await sandbox(t);
  for (const format of ['sha1', 'sha256']) {
    const fixture = gitFixture(format), path = join(directory, `${format}.bundle`); await writeFile(path, fixture.bytes);
    const result = await verifyNativeGitBundleFile(path, { fg: process.env.FG_NATIVE_BIN,
      expected: { object_format: format, refs: [{ ref_hex: ref, object_id: fixture.tip }], exact_refs: true } });
    assert.equal(result.object_graph_verified, true); assert.equal(result.object_count, 3);
    fixture.bytes[fixture.bytes.length - 1] ^= 1;
    await assert.rejects(verifyNativeGitBundle(fixture.bytes, { fg: process.env.FG_NATIVE_BIN }));
  }
});
