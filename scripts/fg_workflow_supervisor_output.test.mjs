import test from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { writeRecord } from './fg_workflow_supervisor.mjs';
const tick = () => new Promise(resolve => setImmediate(resolve));

test('JSON reporting awaits the write callback instead of accumulating output', async () => {
  let release, settled = false; const chunks = [];
  const output = new Writable({ highWaterMark: 1, write(bytes, _encoding, done) { chunks.push(bytes); release = done; } });
  const pending = writeRecord(output, { cycle: 1 }).then(() => { settled = true; });
  await tick(); assert.equal(settled, false); assert.equal(Buffer.concat(chunks).toString(), '{"cycle":1}\n');
  release(); await pending; await tick();
  assert.equal(output.listenerCount('error'), 0); assert.equal(output.listenerCount('close'), 0); output.destroy();
});

test('a broken report stream is a controlled failure, including a late error event', async () => {
  const output = new Writable({ write(_bytes, _encoding, done) { done(new Error('broken pipe')); } });
  await assert.rejects(writeRecord(output, { cycle: 1 }), /broken pipe/); await tick();
  assert.equal(output.listenerCount('error'), 0);
});

test('closed output and a stalled reader cannot keep a service running indefinitely', async () => {
  const closed = new Writable({ write() { this.destroy(); } });
  await assert.rejects(writeRecord(closed, {}), /stream closed/);
  const stalled = new Writable({ write() {} });
  await assert.rejects(writeRecord(stalled, {}, 5), /deadline/); await tick(); stalled.destroy();
});

test('report size and deadline controls are bounded before writing', () => {
  const output = new Writable({ write() { assert.fail('No output should be admitted.'); } });
  assert.throws(() => writeRecord(output, { payload: 'x'.repeat(1024 * 1024) }), /byte budget/);
  assert.throws(() => writeRecord(output, {}, 0), /timeout/);
  assert.throws(() => writeRecord(output, {}, 30001), /timeout/); output.destroy();
});
