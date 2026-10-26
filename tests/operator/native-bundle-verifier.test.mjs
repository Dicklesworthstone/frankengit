// Executed adapter/process tests use a deliberately fake fg. Only the explicitly
// enabled final native test is evidence about the Rust verifier itself.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { spawn, spawnSync } from 'node:child_process';
import fsPromises, { appendFile, chmod, lstat, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeNativeBundleExpectation, normalizeNativeBundleOptions, verifyNativeGitBundle, verifyNativeGitBundleFile, withVerifiedNativeGitBundleFile } from '../../scripts/lib/native-bundle-verifier.mjs';

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
const scratch = args.includes('--scratch-dir') ? get('--scratch-dir') : null;
if (args.includes('--file-backed') || mode === 'memory-file-claim') {
  Object.assign(report, { storage_profile: 'file-backed-native-full-bundle-v1', scratch_bytes: 0,
    scratch_removed: true, pack_sha256: crypto.createHash('sha256').update('').digest('hex') });
}
if (mode === 'file-residue' || mode === 'hang-residue') {
  fs.writeFileSync(require('node:path').join(scratch, '.fg-bundle-fake.scratch'), 'retained native scratch');
}
if (mode === 'refuse') { console.error('typed native refusal'); process.exit(2); }
if (mode === 'signal') process.kill(process.pid, 'SIGTERM');
else if (mode === 'hang' || mode === 'hang-residue') { process.on('SIGTERM', () => {}); setInterval(() => {}, 1000); }
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
  if (mode === 'ref-count') report.reference_count++;
  if (mode === 'zero-ref-count') report.reference_count = 0;
  if (mode === 'file-missing') delete report.pack_sha256;
  if (mode === 'file-profile') report.storage_profile = 'unknown-file-profile';
  if (mode === 'file-negative') report.scratch_bytes = -1;
  if (mode === 'file-over-budget') report.scratch_bytes = 2 * Number(get('--max-expanded-mib')) * 1024 * 1024 + 1;
  if (mode === 'file-unsafe-count') report.scratch_bytes = Number.MAX_SAFE_INTEGER + 1;
  if (mode === 'file-unremoved') report.scratch_removed = false;
  if (mode === 'file-digest') report.pack_sha256 = 'A'.repeat(64);
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
    'hash', 'size', 'claim', 'incomplete', 'profile', 'extra', 'echo', 'format', 'refs', 'count', 'ref-count', 'zero-ref-count']) {
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

test('file-backed limits are explicit and never enlarge byte-array verification', async () => {
  const normal = normalizeNativeBundleOptions({ fg: '/fg' });
  assert.equal(normal.fileBacked, false); assert.equal(normal.maxInputMiB, 128);
  const defaults = normalizeNativeBundleOptions({ fg: '/fg', fileBacked: true });
  assert.equal(defaults.maxInputMiB, 128); assert.equal(defaults.maxExpandedMiB, 128);
  for (const size of [129, 16384]) {
    const wide = normalizeNativeBundleOptions({ fg: '/fg', fileBacked: true, maxInputMiB: size, maxExpandedMiB: size });
    assert.equal(wide.maxInputMiB, size); assert.equal(wide.maxExpandedMiB, size);
    assert.equal(wide.maxObjects, normal.maxObjects); assert.equal(wide.maxRefs, normal.maxRefs);
    await assert.rejects(verifyNativeGitBundle(opaque, wide), { code: 'native_file_backed_requires_file' });
  }
  for (const patch of [{ fileBacked: 'true' }, { fileBacked: null }, { maxInputMiB: 129 },
    { maxExpandedMiB: 129 }, { fileBacked: true, maxInputMiB: 16385 },
    { fileBacked: true, maxExpandedMiB: 16385 }, { fileBacked: true, maxObjects: 100001 },
    { fileBacked: true, maxRefs: 4097 }, { fileBacked: true, scratchDirectory: '/caller-owned' }]) {
    assert.throws(() => normalizeNativeBundleOptions({ fg: '/fg', ...patch }));
  }
});

async function withSourceHandle(path, decorate, operation) {
  const original = fsPromises.open;
  fsPromises.open = async (...args) => {
    const handle = await original(...args);
    if (args[0] === path) decorate(handle);
    return handle;
  };
  syncBuiltinESMExports();
  try { return await operation(); }
  finally { fsPromises.open = original; syncBuiltinESMExports(); }
}

test('file-backed snapshot hashes and copies bounded chunks with exact native pins', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
  const bytes = Buffer.alloc(256 * 1024 + 17, 42), digest = sha(bytes);
  await writeFile(path, bytes);
  for (const format of ['sha1', 'sha256']) {
    const reads = [], allocations = [], allocate = Buffer.alloc;
    t.mock.method(Buffer, 'alloc', (size, ...args) => {
      allocations.push(size); assert.ok(size <= 65536, 'no complete input allocation in the file profile');
      return allocate(size, ...args);
    });
    let result;
    try {
      result = await withSourceHandle(path, handle => {
        const read = handle.read.bind(handle);
        handle.read = async (...args) => { reads.push(args[2]); return await read(...args); };
      }, () => verifyNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true,
        maxInputMiB: 16384, maxExpandedMiB: 16384,
        expected: { sha256: digest, object_format: format, exact_refs: true,
          refs: [{ ref_hex: ref, object_id: '2'.repeat(format === 'sha1' ? 40 : 64) }] } }));
    } finally { t.mock.restoreAll(); }
    assert.ok(reads.length > 4); assert.equal(Math.max(...reads), 65536);
    assert.equal(Math.max(...allocations), 65536);
    assert.equal(result.artifact_sha256, digest); assert.equal(result.bundle_bytes, bytes.length);
    assert.equal(result.storage_profile, 'file-backed-native-full-bundle-v1');
    assert.equal(result.scratch_removed, true); assert.equal(result.caller_identity_pins_supplied, true);
    const log = JSON.parse(await readFile(mock.log));
    assert.ok(log.args.includes('--file-backed')); assert.ok(!log.args.includes(path));
    assert.equal(log.args[log.args.indexOf('--scratch-dir') + 1], dirname(log.input));
    assert.equal(log.args[log.args.indexOf('--max-input-mib') + 1], '16384');
    assert.equal(log.args[log.args.indexOf('--max-expanded-mib') + 1], '16384');
    assert.equal(log.hash, digest); assert.equal(log.fileMode, 0o600); assert.equal(log.directoryMode, 0o700);
    await absent(dirname(log.input));
  }
  assert.deepEqual(await readFile(path), bytes);
});

for (const mode of ['truncate', 'grow', 'replace', 'cancel']) {
  test('file-backed snapshot refuses source ' + mode + ' during the owned copy', async t => {
    const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
    const bytes = Buffer.alloc(128 * 1024 + 17, 42), controller = new AbortController();
    await writeFile(path, bytes);
    let changed = false;
    await withSourceHandle(path, handle => {
      const read = handle.read.bind(handle);
      handle.read = async (...args) => {
        const result = await read(...args);
        if (!changed && args[3] === 0) {
          changed = true;
          if (mode === 'truncate') await writeFile(path, 'short');
          if (mode === 'grow') await appendFile(path, 'extra');
          if (mode === 'replace') { await rename(path, path + '.old'); await writeFile(path, bytes); }
          if (mode === 'cancel') controller.abort();
        }
        return result;
      };
    }, () => assert.rejects(verifyNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true, signal: controller.signal }),
      { code: { truncate: 'native_input_truncated', grow: 'native_input_grew',
        replace: 'native_input_changed', cancel: 'native_verification_cancelled' }[mode] }));
    assert.equal(changed, true); await absent(mock.log);
  });
}

test('file-backed cancellation during final source close cannot return success', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
  const controller = new AbortController(); await writeFile(path, opaque);
  await withSourceHandle(path, handle => {
    const close = handle.close.bind(handle);
    handle.close = async () => { await close(); controller.abort(); };
  }, () => assert.rejects(verifyNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true, signal: controller.signal }),
    { code: 'native_verification_cancelled' }));
  const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.input));
});

test('file-backed digest mismatch refuses before starting native verification', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
  await writeFile(path, opaque);
  await assert.rejects(verifyNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true,
    expected: { sha256: '0'.repeat(64) } }), { code: 'native_expected_sha256_mismatch' });
  await absent(mock.log);
});

test('file-backed reports require complete truthful storage fields within the selected budget', async t => {
  const directory = await sandbox(t), path = join(directory, 'input.bundle'); await writeFile(path, opaque);
  for (const mode of ['file-missing', 'file-profile', 'file-negative', 'file-over-budget',
    'file-unsafe-count', 'file-unremoved', 'file-digest']) {
    const mock = await fakeFg(directory, mode);
    await assert.rejects(verifyNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true }),
      { code: 'native_invalid_file_report' });
    const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.input));
  }
  const mock = await fakeFg(directory, 'memory-file-claim');
  await assert.rejects(verifyNativeGitBundleFile(path, { fg: mock.fg }), { code: 'native_invalid_report' });
});

for (const mode of ['file-residue', 'hang-residue']) {
  test('file-backed ' + mode + ' retains native scratch and reports its location after child close', async t => {
    const directory = await sandbox(t), mock = await fakeFg(directory, mode), path = join(directory, 'input.bundle');
    const controller = new AbortController(); await writeFile(path, opaque);
    const operation = verifyNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true, signal: controller.signal });
    let failure;
    const rejected = assert.rejects(operation, error => { failure = error; return error.code === 'native_snapshot_cleanup_refused'; });
    const log = await waitFor(mock.log);
    t.after(() => rm(dirname(log.input), { recursive: true, force: true }));
    if (mode === 'hang-residue') {
      await waitForScratch(join(dirname(log.input), '.fg-bundle-fake.scratch'));
      controller.abort();
    }
    await rejected;
    assert.throws(() => process.kill(log.pid, 0), { code: 'ESRCH' });
    assert.equal(failure.details.directory, dirname(log.input));
    if (mode === 'hang-residue') assert.equal(failure.details.verification_error, 'native_verification_cancelled');
    await absent(log.input);
    assert.equal(await readFile(join(dirname(log.input), '.fg-bundle-fake.scratch'), 'utf8'), 'retained native scratch');
  });
}
async function waitForScratch(path) {
  for (let at = 0; at < 300; at++) {
    try { await lstat(path); return; } catch { await new Promise(resolve => setTimeout(resolve, 10)); }
  }
  throw new Error('test native scratch was not created');
}

test('file-backed CLI uses explicit limits and canonicalizes its owned temporary root', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
  await writeFile(path, opaque);
  const actual = join(directory, 'scratch'), alias = join(directory, 'alias');
  await mkdir(actual, { mode: 0o700 }); await symlink(actual, alias);
  const result = await runCli([path, '--fg', mock.fg, '--file-backed', '--max-input-mib', '16384',
    '--max-expanded-mib', '16384'], { env: { ...process.env, TMPDIR: alias } });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).storage_profile, 'file-backed-native-full-bundle-v1');
  const log = JSON.parse(await readFile(mock.log));
  assert.ok(log.input.startsWith(actual + '/')); assert.ok(!log.input.startsWith(alias + '/'));
  await absent(dirname(log.input));
  const invalid = await runCli([path, '--fg', mock.fg, '--file-backed', '--file-backed']);
  assert.notEqual(invalid.code, 0); assert.equal(JSON.parse(invalid.stderr).error, 'duplicate_option');
});


test('declared artifact length refuses before source open, byte copy or native spawn', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
  await writeFile(path, opaque);
  for (const fileBacked of [false, true]) {
    let opened = false;
    await withSourceHandle(path, () => { opened = true; },
      () => assert.rejects(verifyNativeGitBundleFile(path, { fg: mock.fg, fileBacked,
        expectedBytes: opaque.length + 1 }), { code: 'native_expected_size_mismatch' }));
    assert.equal(opened, false);
  }
  await assert.rejects(verifyNativeGitBundle(opaque, { fg: mock.fg, expectedBytes: opaque.length + 1 }),
    { code: 'native_expected_size_mismatch' });
  for (const expectedBytes of [0, -1, 1.5, '1', Number.MAX_SAFE_INTEGER, 129 * 1024 * 1024]) {
    assert.throws(() => normalizeNativeBundleOptions({ fg: mock.fg, expectedBytes }),
      { code: 'native_invalid_expected_bytes' });
  }
  await absent(mock.log);
});

test('verified file lease exposes bounded private reads and revokes them after consumption', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
  const bytes = Buffer.alloc(128 * 1024 + 17, 42); await writeFile(path, bytes);
  let reader, snapshotPath;
  const token = { consumed: true };
  const result = await withVerifiedNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true,
    expectedBytes: bytes.length }, async snapshot => {
    assert.deepEqual(Object.keys(snapshot).sort(), ['read', 'report', 'size']);
    assert.equal(Object.isFrozen(snapshot), true); assert.equal(Object.isFrozen(snapshot.report.references), true);
    assert.equal(Object.isFrozen(snapshot.report.expectations.references), true);
    assert.equal(snapshot.size, bytes.length);
    reader = snapshot.read;
    const log = JSON.parse(await readFile(mock.log)); snapshotPath = log.input;
    assert.notEqual(snapshotPath, path); assert.throws(() => process.kill(log.pid, 0), { code: 'ESRCH' });
    // The original is no longer an input to the consumer.
    await writeFile(path, 'changed original');
    let read = 0;
    while (read < bytes.length) {
      const part = await snapshot.read(read, Math.min(65536, bytes.length - read));
      assert.deepEqual(part, bytes.subarray(read, read + part.length)); read += part.length;
    }
    assert.equal((await snapshot.read(bytes.length, 0)).length, 0);
    for (const [offset, length] of [[-1, 1], [0, -1], [0, 65537], [bytes.length, 1],
      [0.5, 1], [0, 1.5], [Number.MAX_SAFE_INTEGER, 1]]) {
      await assert.rejects(snapshot.read(offset, length), { code: 'native_snapshot_read_range' });
    }
    return token;
  });
  assert.equal(result, token); await absent(dirname(snapshotPath));
  await assert.rejects(reader(0, 1), { code: 'native_snapshot_closed' });
});

test('native scratch residue prevents consumer entry despite a success report', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory, 'file-residue'), path = join(directory, 'input.bundle');
  await writeFile(path, opaque); let entered = false;
  await assert.rejects(withVerifiedNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true },
    async () => { entered = true; }), error => error.code === 'native_snapshot_cleanup_refused'
      && error.cause?.code === 'native_snapshot_not_quiescent');
  assert.equal(entered, false);
  const log = JSON.parse(await readFile(mock.log));
  t.after(() => rm(dirname(log.input), { recursive: true, force: true }));
  await absent(log.input);
  assert.equal(await readFile(join(dirname(log.input), '.fg-bundle-fake.scratch'), 'utf8'), 'retained native scratch');
});

test('consumer owns cancellation after verified handoff and can finish its result', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
  const controller = new AbortController(); await writeFile(path, opaque);
  const result = await withVerifiedNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true,
    signal: controller.signal }, async snapshot => {
    controller.abort();
    assert.deepEqual(await snapshot.read(0, opaque.length), opaque);
    return { state: 'complete' }; // Consumer lifecycle simulation, not a native publication.
  });
  assert.deepEqual(result, { state: 'complete' });
  const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.input));
});

test('consumer failure is unchanged after successful cleanup', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
  await writeFile(path, opaque);
  const original = Object.assign(new Error('publication observer failed'), { code: 'observer_failed', state: 'published' });
  await assert.rejects(withVerifiedNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true },
    async () => { throw original; }), error => error === original);
  const log = JSON.parse(await readFile(mock.log)); await absent(dirname(log.input));
});

test('cleanup failure retains the consumer cause and its publication state', async t => {
  const directory = await sandbox(t), mock = await fakeFg(directory), path = join(directory, 'input.bundle');
  await writeFile(path, opaque);
  const original = Object.assign(new Error('publication observer failed'), { code: 'observer_failed', state: 'published' });
  let snapshotPath;
  await assert.rejects(withVerifiedNativeGitBundleFile(path, { fg: mock.fg, fileBacked: true }, async () => {
    const log = JSON.parse(await readFile(mock.log)); snapshotPath = log.input;
    await writeFile(join(dirname(log.input), 'keep'), 'unrecognized retained entry');
    throw original;
  }), error => error.code === 'native_snapshot_cleanup_refused' && error.cause === original
    && error.cause.state === 'published' && error.details.consumer_error === 'observer_failed'
    && error.details.directory === dirname(snapshotPath));
  t.after(() => rm(dirname(snapshotPath), { recursive: true, force: true }));
  await absent(snapshotPath);
  assert.equal(await readFile(join(dirname(snapshotPath), 'keep'), 'utf8'), 'unrecognized retained entry');
});

test('verified file consumer selection refuses before source access', async () => {
  await assert.rejects(withVerifiedNativeGitBundleFile('/absent', { fg: '/fg' }, () => {}),
    { code: 'native_file_backed_required' });
  await assert.rejects(withVerifiedNativeGitBundleFile('/absent', { fg: '/fg', fileBacked: true }, null),
    { code: 'native_invalid_consumer' });
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
