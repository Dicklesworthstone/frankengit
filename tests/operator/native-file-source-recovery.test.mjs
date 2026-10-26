// Executes the real filesystem owner against independently recorded Git bodies.
// Most cases select a deliberately fake fg and exercise snapshot/publication
// behavior. Only the explicit FG_NATIVE_BIN gates execute the Rust verifier.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fsPromises, { access, lstat, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { basename, dirname, join } from 'node:path';
import { recoverGitBundle, recoverGitBundleFile } from '../../scripts/lib/source-recovery.mjs';
import { harness, readFixture } from './fixtures/native-recovery-harness.mjs';
import { makeLargeRecoveryHarness } from './fixtures/native-recovery-large.mjs';

const MARKER = '.frankengit-source-recovery.json';
const LOCK = '.frankengit-source-recovery.lock';
const HEAD_STAGE = '.frankengit-source-recovery-head';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const absent = async path => assert.rejects(access(path), { code: 'ENOENT' });
async function fixture(t, format = 'sha1') {
  const h = await harness(t, format);
  h.input = join(h.root, 'source.bundle'); await writeFile(h.input, h.bytes); return h;
}
const recoverFile = (h, options = {}, request = h.request) => recoverGitBundleFile(h.input,
  h.destination, request, { ...h.options, ...options });
async function packPath(h) {
  const root = join(h.destination, 'objects/pack');
  const names = await readdir(root), name = names.find(name => name.endsWith('.pack'));
  assert.ok(name); return join(root, name);
}
async function snapshot(h) {
  const calls = await h.calls(); assert.ok(calls.length); return calls.at(-1).at(-1);
}
async function snapshotRemoved(h) { await absent(dirname(await snapshot(h))); }
async function withSnapshotHandles(h, decorate, operation) {
  const original = fsPromises.open;
  fsPromises.open = async (...args) => {
    const handle = await original(...args);
    if (typeof args[0] === 'string' && basename(args[0]) === 'input.bundle' && args[0] !== h.input) decorate(handle);
    return handle;
  };
  syncBuiltinESMExports();
  try { return await operation(); }
  finally { fsPromises.open = original; syncBuiltinESMExports(); }
}
function readArguments(args) {
  return args[0] instanceof Uint8Array
    ? { buffer: args[0], offset: args[1] ?? 0, length: args[2], position: args[3] }
    : { buffer: args[0].buffer, offset: args[0].offset ?? 0, length: args[0].length, position: args[0].position };
}
async function interruptPack(h) {
  const controller = new AbortController(); let interrupted = false;
  await assert.rejects(recoverFile(h, { signal: controller.signal, onProgress(event) {
    if (event.phase.startsWith('writing:objects/pack/') && event.phase.endsWith('.pack') && !interrupted) {
      assert.ok(event.written > 0 && event.written < event.total);
      interrupted = true; controller.abort();
    }
  } }), error => error.state === 'staging' && error.code === 'recovery_cancelled');
  assert.equal(interrupted, true); await absent(join(h.destination, 'HEAD'));
  const path = await packPath(h), prefix = await readFile(path);
  assert.deepEqual(prefix, h.expected_pack.subarray(0, prefix.length));
  await snapshotRemoved(h);
  return { path, prefix, identity: await lstat(path), marker: await readFile(join(h.destination, MARKER)) };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: actual native fg file-backed recovery integration`, {
    skip: !process.env.FG_NATIVE_BIN && 'no built native fg supplied',
  }, async t => {
    const h = await fixture(t, format);
    const request = { ...h.request, expectations: { sha256: hash(h.bytes), object_format: format } };
    const result = await recoverFile(h, { nativeFg: process.env.FG_NATIVE_BIN }, request);
    assert.equal(result.state, 'complete');
    assert.equal(result.verification.object_graph_verified, true);
    assert.equal(result.verification.storage_profile, 'file-backed-native-full-bundle-v1');
    assert.equal(result.files_synced, true); assert.equal(result.directories_synced, true);
    assert.deepEqual(await h.calls(), [], 'the fake native fixture must not execute');
    const path = await packPath(h), packOffset = h.bytes.indexOf(Buffer.from('\n\n')) + 2;
    assert.deepEqual(await readFile(path), h.bytes.subarray(packOffset));
    assert.deepEqual(await readFile(path.replace(/\.pack$/, '.idx')), await readFixture(format, 'idx'));
    assert.equal(await readFile(join(h.destination, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
    const marker = JSON.parse(await readFile(join(h.destination, MARKER)));
    assert.equal(marker.plan_sha256, result.plan_sha256);
    await absent(join(h.destination, LOCK)); await absent(join(h.destination, HEAD_STAGE));
  });

  test(`${format}: file recovery materializes exact golden pack/index with the existing marker`, async t => {
    const h = await fixture(t, format), phases = [];
    const result = await recoverFile(h, { onProgress: async event => {
      phases.push(event.phase);
      if (event.phase === 'before_publication') await absent(join(h.destination, 'HEAD'));
    } });
    assert.equal(result.state, 'complete'); assert.equal(result.type, 'frankengit-source-recovery-v1');
    assert.equal(result.verification.storage_profile, 'file-backed-native-full-bundle-v1');
    assert.equal(result.files_synced, true); assert.equal(result.directories_synced, true);
    assert.equal(result.native_authority_restored, false); assert.equal(result.forge_state_restored, false);
    assert.ok(phases.indexOf('staged:HEAD') < phases.indexOf('published'));
    const path = await packPath(h), packOffset = h.bytes.indexOf(Buffer.from('\n\n')) + 2;
    assert.deepEqual(await readFile(path), h.bytes.subarray(packOffset));
    assert.deepEqual(await readFile(path.replace(/\.pack$/, '.idx')), await readFixture(format, 'idx'));
    assert.equal(await readFile(join(h.destination, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
    const marker = JSON.parse(await readFile(join(h.destination, MARKER)));
    assert.equal(marker.schema, 'frankengit-native-source-recovery-plan-v1');
    assert.equal(marker.plan_sha256, result.plan_sha256);
    assert.equal(marker.files.find(file => file.path.endsWith('.pack')).sha256, hash(h.bytes.subarray(packOffset)));
    await absent(join(h.destination, LOCK)); await absent(join(h.destination, HEAD_STAGE));
    await snapshotRemoved(h);
  });

  for (const firstFile of [false, true]) test(`${format}: ${firstFile ? 'file-to-memory' : 'memory-to-file'} resume keeps exact approval/pins and v1 identity`, async t => {
    const h = await fixture(t, format), nativeApprovalBinding = 'a'.repeat(64);
    const request = { ...h.request, expectations: { sha256: hash(h.bytes), object_format: format } };
    const first = firstFile
      ? await recoverFile(h, { nativeApprovalBinding, nativeArtifact: { sha256: hash(h.bytes), bytes: h.bytes.length } }, request)
      : await recoverGitBundle(h.bytes, h.destination, request, { ...h.options, nativeApprovalBinding });
    const marker = await readFile(join(h.destination, MARKER)), path = await packPath(h), identity = await lstat(path);
    const second = firstFile
      ? await recoverGitBundle(h.bytes, h.destination, request, { ...h.options, nativeApprovalBinding, resume: true })
      : await recoverFile(h, { nativeApprovalBinding, nativeArtifact: { sha256: hash(h.bytes), bytes: h.bytes.length },
        nativeLimits: { maxInputMiB: 1, maxExpandedMiB: 1 }, resume: true }, request);
    assert.equal(second.state, 'complete'); assert.equal(second.already_published, true);
    assert.equal(second.plan_sha256, first.plan_sha256); assert.equal(second.appended_bytes, 0);
    assert.deepEqual(await readFile(join(h.destination, MARKER)), marker);
    assert.equal((await lstat(path)).ino, identity.ino); await snapshotRemoved(h);
  });
}

test('a large pack is replayed through bounded reads and materialized byte-for-byte', async t => {
  const h = await makeLargeRecoveryHarness(t), reads = [];
  const result = await withSnapshotHandles(h, handle => {
    const read = handle.read.bind(handle);
    handle.read = async (...args) => {
      const request = readArguments(args);
      assert.ok(Number.isSafeInteger(request.length) && request.length > 0 && request.length <= 65536);
      const result = await read(...args); reads.push(result.bytesRead); return result;
    };
  }, () => recoverFile(h));
  assert.equal(result.state, 'complete'); assert.ok(reads.length > 8);
  assert.ok(Math.max(...reads) <= 65536);
  assert.ok(reads.reduce((total, count) => total + count, 0) >= h.expected_pack.length * 2);
  const path = await packPath(h);
  assert.deepEqual(await readFile(path), h.expected_pack);
  assert.deepEqual(await readFile(path.replace(/\.pack$/, '.idx')), h.expected_index);
  await snapshotRemoved(h);
});

test('an interrupted streamed pack resumes its exact prefix without replacing the inode', async t => {
  const h = await makeLargeRecoveryHarness(t), retained = await interruptPack(h);
  const result = await recoverFile(h, { resume: true });
  assert.equal(result.state, 'complete'); assert.equal(result.already_published, false);
  assert.ok(result.reused_bytes >= retained.prefix.length);
  assert.ok(result.appended_bytes >= h.expected_pack.length - retained.prefix.length);
  assert.equal((await lstat(retained.path)).ino, retained.identity.ino);
  assert.deepEqual(await readFile(retained.path), h.expected_pack);
  assert.deepEqual(await readFile(join(h.destination, MARKER)), retained.marker);
  await snapshotRemoved(h);
});

test('prefix validation drains the unretained pack tail and refuses corruption before appending', async t => {
  const h = await makeLargeRecoveryHarness(t), retained = await interruptPack(h);
  let poison = false, changed = 0;
  await withSnapshotHandles(h, handle => {
    const read = handle.read.bind(handle);
    handle.read = async (...args) => {
      const result = await read(...args), request = readArguments(args);
      // Fault only the returned bytes, leaving descriptor metadata unchanged.
      // A prefix-only comparison would miss this corrupt unretained trailer.
      if (poison && result.bytesRead && request.position + result.bytesRead === h.bytes.length) {
        request.buffer[request.offset + result.bytesRead - 1] ^= 1; changed++;
      }
      return result;
    };
  }, () => assert.rejects(recoverFile(h, { resume: true, onProgress(event) {
    if (event.phase === 'verified') poison = true;
  } }), error => ['existing_unknown', 'staging'].includes(error.state)));
  assert.ok(changed > 0, 'the complete source tail was consumed');
  assert.deepEqual(await readFile(retained.path), retained.prefix);
  assert.deepEqual(await readFile(join(h.destination, MARKER)), retained.marker);
  await absent(join(h.destination, 'HEAD')); await snapshotRemoved(h);
  assert.equal((await recoverFile(h, { resume: true })).state, 'complete');
});

test('changed retained pack bytes refuse without truncation or publication', async t => {
  const h = await makeLargeRecoveryHarness(t), retained = await interruptPack(h);
  const corrupt = Buffer.from(retained.prefix); corrupt[0] ^= 1; await writeFile(retained.path, corrupt);
  await assert.rejects(recoverFile(h, { resume: true }), error => error.code === 'recovery_file_mismatch');
  assert.deepEqual(await readFile(retained.path), corrupt);
  assert.deepEqual(await readFile(join(h.destination, MARKER)), retained.marker);
  await absent(join(h.destination, 'HEAD')); await snapshotRemoved(h);
});

test('the original pathname is not reopened once a verified private snapshot owns the source', async t => {
  const h = await fixture(t), replacement = Buffer.from('unrelated original-path replacement');
  const result = await recoverFile(h, { async onProgress(event) {
    if (event.phase === 'verified') await writeFile(h.input, replacement);
  } });
  assert.equal(result.state, 'complete'); assert.deepEqual(await readFile(h.input), replacement);
  assert.deepEqual(await readFile(await packPath(h)), h.bytes.subarray(128)); await snapshotRemoved(h);
});

test('file recovery keeps the existing live-owner refusal while a publisher is paused', { timeout: 15000 }, async t => {
  const h = await makeLargeRecoveryHarness(t);
  let entered, release, paused = false;
  const ready = new Promise(resolve => { entered = resolve; }), gate = new Promise(resolve => { release = resolve; });
  const running = recoverFile(h, { async onProgress(event) {
    if (!paused && event.phase.startsWith('writing:objects/pack/') && event.phase.endsWith('.pack')) {
      paused = true; entered(); await gate;
    }
  } });
  try {
    await Promise.race([ready, running.then(() => { throw Error('publisher did not pause'); })]);
    await assert.rejects(recoverFile(h, { resume: true }), error => error.code === 'recovery_owner_active');
    await absent(join(h.destination, 'HEAD'));
  } finally { release(); }
  assert.equal((await running).state, 'complete');
  for (const args of await h.calls()) await absent(dirname(args.at(-1)));
});

for (const phase of ['verified', 'staged:config', 'publication_ready']) {
  test(`cancellation at ${phase} never publishes HEAD and releases the private snapshot`, async t => {
    const h = await fixture(t), controller = new AbortController();
    await assert.rejects(recoverFile(h, { signal: controller.signal, onProgress(event) {
      if (event.phase === phase) controller.abort();
    } }), error => error.code === 'recovery_cancelled' && error.state === (phase === 'verified' ? 'not_created' : 'staging'));
    await absent(join(h.destination, 'HEAD')); await snapshotRemoved(h);
    if (phase === 'verified') await absent(h.destination);
    else assert.equal((await recoverFile(h, { resume: true })).state, 'complete');
  });
}

test('post-HEAD cancellation finishes filesystem and snapshot responsibility', async t => {
  const h = await fixture(t), controller = new AbortController();
  const result = await recoverFile(h, { signal: controller.signal, onProgress(event) {
    if (event.phase === 'published') controller.abort();
  } });
  assert.equal(result.state, 'complete'); assert.equal(result.cancellation_requested, true);
  assert.equal(result.files_synced, true); assert.equal(result.directories_synced, true);
  await absent(join(h.destination, LOCK)); await absent(join(h.destination, HEAD_STAGE)); await snapshotRemoved(h);
  assert.equal((await recoverFile(h, { resume: true })).already_published, true);
});

test('a post-HEAD observer error retains published state after all finalization', async t => {
  const h = await fixture(t);
  await assert.rejects(recoverFile(h, { onProgress(event) {
    if (event.phase === 'published') throw Object.assign(Error('injected observer'), { code: 'injected_after_head' });
  } }), error => error.code === 'injected_after_head' && error.state === 'published');
  assert.equal(await readFile(join(h.destination, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
  await absent(join(h.destination, LOCK)); await absent(join(h.destination, HEAD_STAGE)); await snapshotRemoved(h);
  assert.equal((await recoverFile(h, { resume: true })).already_published, true);
});

test('snapshot cleanup failure after HEAD reports complete state and preserves foreign residue', async t => {
  const h = await fixture(t); let retainedDirectory, retainedSnapshot;
  await assert.rejects(recoverFile(h, { async onProgress(event) {
    if (event.phase === 'published') {
      retainedSnapshot = await snapshot(h); retainedDirectory = dirname(retainedSnapshot);
      t.after(() => rm(retainedDirectory, { recursive: true, force: true }));
      await writeFile(join(retainedDirectory, 'foreign-residue'), 'preserve');
    }
  } }), error => error.code === 'native_snapshot_cleanup_refused' && error.state === 'complete'
    && error.snapshot_directory === retainedDirectory);
  assert.equal(await readFile(join(retainedDirectory, 'foreign-residue'), 'utf8'), 'preserve');
  await absent(retainedSnapshot); await absent(join(h.destination, LOCK)); await absent(join(h.destination, HEAD_STAGE));
  assert.equal(await readFile(join(h.destination, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
  assert.equal((await recoverFile(h, { resume: true })).already_published, true);
});

for (const kind of ['size', 'digest']) test(`approved artifact ${kind} mismatch refuses before child or destination writes`, async t => {
  const h = await fixture(t), nativeArtifact = { sha256: hash(h.bytes), bytes: h.bytes.length };
  if (kind === 'size') nativeArtifact.bytes++; else nativeArtifact.sha256 = '0'.repeat(64);
  await assert.rejects(recoverFile(h, { nativeArtifact, nativeApprovalBinding: 'b'.repeat(64) }), error => error.state === 'not_created');
  assert.equal((await h.calls()).length, 0); await absent(h.destination);
});
