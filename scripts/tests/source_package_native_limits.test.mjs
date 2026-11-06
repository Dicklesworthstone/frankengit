// Real private files exercise executable preflight only, not native proof or
// authority admission. Fault hooks mutate the actual files and count actual
// bytes/buffers delivered by both bulk and descriptor-based readers.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { prepareNativePackageRead } from '../operator/source_package_native.mjs';

const LIMIT = 256 * 1024 * 1024, QUANTUM = 65536;
const plan = { selected: { expected_head: `alg:1:${'a'.repeat(64)}`, endpoint: 'http://127.0.0.1:1/repo' },
  cost: { blobRequests: 0 }, files: [] };
const payload = Buffer.alloc(2 * QUANTUM + 17);
for (let i = 0; i < payload.length; i++) payload[i] = i % 251;

async function executable(t, value = payload) {
  const root = await fs.mkdtemp(join(tmpdir(), 'fg-executable-budget-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const path = join(root, 'fg');
  if (typeof value === 'number') {
    const file = await fs.open(path, 'wx', 0o700);
    try { await file.truncate(value); } finally { await file.close(); }
  } else await fs.writeFile(path, value, { mode: 0o700 });
  return path;
}

function observe(t, path, { afterStat, afterData } = {}) {
  const original = { lstat: fs.lstat, readFile: fs.readFile, open: fs.open };
  const handles = [], state = { bytes: 0, maximumBuffer: 0 };
  let dataObserved = false;
  async function data(bytes, capacity) {
    state.bytes += bytes; state.maximumBuffer = Math.max(state.maximumBuffer, capacity);
    if (bytes && !dataObserved) { dataObserved = true; await afterData?.(); }
  }
  t.mock.method(fs, 'lstat', async (selected, ...args) => {
    const stat = await original.lstat(selected, ...args);
    if (selected === path) await afterStat?.(stat);
    return stat;
  });
  t.mock.method(fs, 'readFile', async (selected, ...args) => {
    const bytes = await original.readFile(selected, ...args);
    if (selected === path) await data(bytes.length, bytes.length);
    return bytes;
  });
  t.mock.method(fs, 'open', async (selected, ...args) => {
    const file = await original.open(selected, ...args);
    if (selected === path) {
      handles.push(file); const read = file.read.bind(file);
      t.mock.method(file, 'read', async (buffer, ...options) => {
        const result = await read(buffer, ...options);
        await data(result.bytesRead, buffer.byteLength);
        return result;
      });
    }
    return file;
  });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  state.closed = async () => {
    for (const file of handles) await assert.rejects(file.stat(), { code: 'EBADF' });
  };
  return state;
}

test('executable digest and identity are preserved across bounded reads', async t => {
  const path = await executable(t), state = observe(t, path), before = await fs.lstat(path);
  const result = await prepareNativePackageRead(path, plan, 1, () => {});
  assert.equal(result.fg, path);
  assert.equal(result.digest, createHash('sha256').update(payload).digest('hex'));
  for (const key of ['dev', 'ino', 'size', 'mode', 'uid', 'mtimeMs', 'ctimeMs']) assert.equal(result.identity[key], before[key]);
  assert.equal(state.bytes, payload.length);
  assert.ok(state.maximumBuffer <= QUANTUM, `whole executable buffer: ${state.maximumBuffer}`);
  await state.closed();
});

test('an exactly maximum-sized sparse executable is permitted without a whole-file buffer', async t => {
  const path = await executable(t, LIMIT), state = observe(t, path);
  const result = await prepareNativePackageRead(path, plan, 1, () => {});
  const oracle = createHash('sha256'), zeros = Buffer.alloc(1024 * 1024);
  for (let i = 0; i < 256; i++) oracle.update(zeros);
  assert.equal(result.digest, oracle.digest('hex')); assert.equal(state.bytes, LIMIT);
  assert.ok(state.maximumBuffer <= QUANTUM, `whole executable buffer: ${state.maximumBuffer}`);
  await state.closed();
});

test('one byte over the executable limit refuses before data I/O', async t => {
  const path = await executable(t, LIMIT + 1), state = observe(t, path);
  await assert.rejects(prepareNativePackageRead(path, plan, 1, () => {}), { code: 'native_source_proof_executable_limit' });
  assert.equal(state.bytes, 0); await state.closed();
});

test('growth after the selected metadata snapshot cannot bypass the limit', async t => {
  const path = await executable(t); let checks = 0, armed = false, changed = false;
  const state = observe(t, path, { afterStat: async () => {
    if (armed && !changed) { changed = true; await fs.truncate(path, LIMIT + 1); }
  } });
  try {
    await assert.rejects(prepareNativePackageRead(path, plan, 1, () => {
      // The second checkpoint follows executable validation, immediately before
      // the selected identity snapshot. Return its real old metadata, then grow.
      if (++checks === 2) armed = true;
    }), { code: 'native_source_proof_executable_limit' });
    assert.equal(changed, true); assert.equal(state.bytes, 0);
  } finally { t.diagnostic(`growth-race bytes delivered: ${state.bytes}`); await state.closed(); }
});

test('cancellation after the first data read stops within one bounded quantum', async t => {
  const path = await executable(t), stop = new AbortController();
  const state = observe(t, path, { afterData: () => stop.abort(new Error('selected preflight cancelled')) });
  await assert.rejects(prepareNativePackageRead(path, plan, 1, () => stop.signal.throwIfAborted()), error => error === stop.signal.reason);
  assert.ok(state.bytes > 0 && state.bytes <= QUANTUM, `bytes before cancellation: ${state.bytes}`);
  await state.closed();
});

for (const change of ['grow', 'replace']) test(`${change} during hashing cannot publish a digest`, async t => {
  const path = await executable(t), state = observe(t, path, { afterData: async () => {
    if (change === 'grow') await fs.appendFile(path, Buffer.from([42]));
    else { await fs.rename(path, `${path}.old`); await fs.writeFile(path, payload, { mode: 0o700 }); }
  } });
  await assert.rejects(prepareNativePackageRead(path, plan, 1, () => {}), { code: 'native_source_proof_executable_changed' });
  await state.closed();
});

test('an empty preflight executable keeps the existing digest semantics', async t => {
  const path = await executable(t, Buffer.alloc(0)), state = observe(t, path);
  const result = await prepareNativePackageRead(path, plan, 1, () => {});
  assert.equal(result.digest, createHash('sha256').digest('hex')); assert.equal(state.bytes, 0);
  await state.closed();
});
