import test from 'node:test';
import assert from 'node:assert/strict';
import { open, mkdtemp, realpath, readFile, writeFile, readdir, stat, unlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeNew } from '../../scripts/operator/workflow_watch_io.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'fg-custody-write-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const probe = join(root, 'probe'), handle = await open(probe, 'wx', 0o600);
  const prototype = Object.getPrototypeOf(handle);
  await handle.close(); await unlink(probe);
  return { root, output: join(root, 'result'), prototype };
}

// Exercise the actual writer, regular files, links and directory syncs. Only
// method results are faulted, after the corresponding real handle operation.
// These are cleanup/error-propagation tests, not power-loss/durability proof.
function faults(t, prototype, injected = {}) {
  const original = { writeFile: prototype.writeFile, sync: prototype.sync };
  const events = []; let writer;
  t.mock.method(prototype, 'writeFile', async function (...args) {
    writer = this; events.push('write');
    // Node's close method belongs to each handle, unlike writeFile and sync.
    const close = this.close;
    t.mock.method(this, 'close', async function () {
      events.push('close'); await close.call(this);
      await injected.after_close?.();
      if (Object.hasOwn(injected, 'close')) throw injected.close;
    });
    await original.writeFile.apply(this, args);
    if (Object.hasOwn(injected, 'write')) throw injected.write;
  });
  t.mock.method(prototype, 'sync', async function () {
    const stage = this === writer;
    if (!stage) {
      assert.equal((await this.stat()).isDirectory(), true);
      const close = this.close;
      t.mock.method(this, 'close', async function () {
        events.push('directory_close'); await close.call(this);
      });
    }
    const event = stage ? 'file_sync' : 'directory_sync'; events.push(event);
    await original.sync.call(this);
    if (Object.hasOwn(injected, event)) throw injected[event];
  });
  return events;
}

const settle = task => task.then(() => ({ fulfilled: true }), reason => ({ fulfilled: false, reason }));
const complete = ['write', 'file_sync', 'close', 'directory_sync', 'directory_close'];

test('successful custody write keeps exact private bytes and removes only its staging name', async t => {
  const f = await fixture(t), bytes = Buffer.from([0, 255, 10, 13]);
  const events = faults(t, f.prototype);
  await writeNew(f.output, bytes);
  assert.deepEqual(events, complete);
  assert.deepEqual(await readdir(f.root), ['result']);
  assert.deepEqual(await readFile(f.output), bytes);
  const selected = await stat(f.output);
  assert.equal(selected.mode & 0o777, 0o600); assert.equal(selected.nlink, 1);
});

test('write failure stays primary when close also fails; unlink and directory sync still run', async t => {
  const f = await fixture(t), first = new Error('injected write error');
  const events = faults(t, f.prototype, { write: first, close: new Error('injected close error') });
  const result = await settle(writeNew(f.output, Buffer.from('private bytes')));
  assert.equal(result.fulfilled, false); assert.equal(result.reason, first);
  assert.deepEqual(events, ['write', 'close', 'directory_sync', 'directory_close']);
  assert.deepEqual(await readdir(f.root), []);
});

test('failed file sync stays primary through close failure without publishing a destination', async t => {
  const f = await fixture(t), first = new Error('injected file sync error');
  const events = faults(t, f.prototype, { file_sync: first, close: new Error('injected close error') });
  const result = await settle(writeNew(f.output, Buffer.from('private bytes')));
  assert.equal(result.fulfilled, false); assert.equal(result.reason, first);
  assert.deepEqual(events, complete); assert.deepEqual(await readdir(f.root), []);
});

test('a real EEXIST remains primary through close failure and preserves the existing result', async t => {
  const f = await fixture(t); await writeFile(f.output, 'original', { mode: 0o600 });
  const events = faults(t, f.prototype, { close: new Error('injected close error') });
  const result = await settle(writeNew(f.output, Buffer.from('replacement')));
  assert.equal(result.fulfilled, false); assert.equal(result.reason.code, 'EEXIST');
  assert.deepEqual(events, complete); assert.deepEqual(await readdir(f.root), ['result']);
  assert.equal(await readFile(f.output, 'utf8'), 'original');
});

test('post-link close failure still removes staging and syncs without erasing the visible result', async t => {
  const f = await fixture(t), first = new Error('injected close error'), bytes = Buffer.from('visible');
  const events = faults(t, f.prototype, { close: first });
  const result = await settle(writeNew(f.output, bytes));
  assert.equal(result.fulfilled, false); assert.equal(result.reason, first);
  assert.deepEqual(events, complete); assert.deepEqual(await readdir(f.root), ['result']);
  assert.deepEqual(await readFile(f.output), bytes);
  t.mock.restoreAll();
  await assert.rejects(writeNew(f.output, Buffer.from('replacement')), { code: 'EEXIST' });
  assert.deepEqual(await readFile(f.output), bytes);
});

test('directory sync failure after link is reported while the visible bytes remain create-only', async t => {
  const f = await fixture(t), first = new Error('injected directory sync error'), bytes = Buffer.from('visible');
  const events = faults(t, f.prototype, { directory_sync: first });
  const result = await settle(writeNew(f.output, bytes));
  assert.equal(result.fulfilled, false); assert.equal(result.reason, first);
  assert.deepEqual(events, complete); assert.deepEqual(await readdir(f.root), ['result']);
  assert.deepEqual(await readFile(f.output), bytes);
});

test('close remains primary when the later directory sync also fails', async t => {
  const f = await fixture(t), first = new Error('injected close error');
  const events = faults(t, f.prototype, { close: first, directory_sync: new Error('injected directory sync error') });
  const result = await settle(writeNew(f.output, Buffer.from('visible')));
  assert.equal(result.fulfilled, false); assert.equal(result.reason, first);
  assert.deepEqual(events, complete); assert.deepEqual(await readdir(f.root), ['result']);
});

test('a real unlink ENOENT still syncs the directory and preserves the visible result', async t => {
  const f = await fixture(t), bytes = Buffer.from('visible');
  const events = faults(t, f.prototype, { after_close: async () => {
    const staging = (await readdir(f.root)).filter(name => name.startsWith('result.writing-'));
    assert.equal(staging.length, 1); await unlink(join(f.root, staging[0]));
  } });
  const result = await settle(writeNew(f.output, bytes));
  assert.equal(result.fulfilled, false); assert.equal(result.reason.code, 'ENOENT');
  assert.deepEqual(events, complete); assert.deepEqual(await readdir(f.root), ['result']);
  assert.deepEqual(await readFile(f.output), bytes);
});

test('write stays primary when directory sync later fails', async t => {
  const f = await fixture(t), first = new Error('injected write error');
  const events = faults(t, f.prototype, { write: first, directory_sync: new Error('injected directory sync error') });
  const result = await settle(writeNew(f.output, Buffer.from('private bytes')));
  assert.equal(result.fulfilled, false); assert.equal(result.reason, first);
  assert.deepEqual(events, ['write', 'close', 'directory_sync', 'directory_close']);
  assert.deepEqual(await readdir(f.root), []);
});

test('falsy thrown write values are preserved through a later cleanup error', async t => {
  const f = await fixture(t);
  for (const first of [undefined, null, false, 0, '']) {
    const events = faults(t, f.prototype, { write: first, close: new Error('injected close error') });
    const result = await settle(writeNew(f.output, Buffer.from('private bytes')));
    assert.equal(result.fulfilled, false); assert.equal(result.reason, first);
    assert.deepEqual(events, ['write', 'close', 'directory_sync', 'directory_close']);
    assert.deepEqual(await readdir(f.root), []); t.mock.restoreAll();
  }
});

test('falsy close failures still reject after publication and complete the remaining cleanup', async t => {
  const f = await fixture(t), bytes = Buffer.from('visible');
  for (const [index, reason] of [undefined, null, false, 0, ''].entries()) {
    const output = join(f.root, `result-${index}`), events = faults(t, f.prototype, { close: reason });
    const result = await settle(writeNew(output, bytes));
    assert.equal(result.fulfilled, false); assert.equal(result.reason, reason);
    assert.deepEqual(events, complete); assert.deepEqual(await readFile(output), bytes);
    assert.equal((await readdir(f.root)).some(name => name.includes('.writing-')), false);
    t.mock.restoreAll();
  }
});
