import test from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

for (const [label, draining, drainErrors] of [
  ['stdout drains and exits successfully', true, true],
  ['stdout deadline permits process exit', false, true],
  ['blocked stderr uses the bounded failure exit', false, false],
]) test(`real ${label}`, { timeout: 5000 }, async t => {
  const probe = fileURLToPath(new URL('../tests/operator/fixtures/supervisor-output-probe.mjs', import.meta.url));
  const root = await mkdtemp(join(tmpdir(), 'fg-supervisor-output-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const cleanup = join(root, 'cleanup');
  const child = spawn(process.execPath, [probe, cleanup, ...(!drainErrors ? ['--block-stderr'] : [])], { stdio: ['ignore', 'pipe', 'pipe'] });
  const closed = new Promise(resolve => child.once('close', resolve));
  const diagnostics = [], chunks = [];
  if (drainErrors) child.stderr.on('data', bytes => diagnostics.push(bytes));
  if (draining) child.stdout.on('data', bytes => chunks.push(bytes));
  let timer;
  try {
    const result = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code, signal) => resolve({ code, signal }));
      timer = setTimeout(() => child.kill('SIGKILL'), 2000);
    });
    clearTimeout(timer);
    if (!draining) child.stdout.destroy();
    if (!drainErrors) child.stderr.destroy();
    await closed;
    t.diagnostic(JSON.stringify({ draining, drainErrors, ...result, stderr: Buffer.concat(diagnostics).toString() }));
    assert.equal(result.signal, null, 'the child must exit without the parent watchdog killing it');
    assert.equal(result.code, draining ? 0 : 1);
    assert.equal(await readFile(cleanup, 'utf8'), 'cleanup completed\n');
    if (draining) {
      assert.equal(JSON.parse(Buffer.concat(chunks)).payload, 'x'.repeat(512 * 1024));
      assert.equal(Buffer.concat(diagnostics).length, 0);
    } else if (drainErrors) {
      assert.equal(Buffer.concat(diagnostics).toString(), 'workflow-supervisor: Supervisor report deadline exceeded.\n');
    }
  } finally {
    clearTimeout(timer);
    child.stdout.destroy(); child.stderr.destroy();
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await closed;
  }
});
