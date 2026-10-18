// Real child processes test native operator lifetime, never forge authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runNative } from '../../scripts/operator/workflow_watch_io.mjs';

async function executable(t, source) {
  const root = await mkdtemp(join(tmpdir(), 'fg-native-owner-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = join(root, 'peer');
  await writeFile(file, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
  return file;
}
for (const stream of ['stdout', 'stderr']) {
  test(`exited leader with inherited ${stream} cannot trigger signalling of its released group ID`, { timeout: 8000 }, async t => {
    const file = await executable(t, `import { spawn } from 'node:child_process';
      const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 2200)'], { stdio: ['ignore', ${stream === 'stdout' ? "'inherit', 'ignore'" : "'ignore', 'inherit'"}] });
      child.unref(); process.stdout.write('terminal leader'); process.exit(0);`);
    const signals = [];
    // No signal is necessary for the finite orphan. Record attempted signalling
    // without killing it: the previous implementation targets a RELEASED ID.
    t.mock.method(process, 'kill', (pid, signal) => { signals.push({ pid, signal }); return true; });
    const result = await runNative(file, [], { timeoutMs: 6000 });
    assert.equal(result.forced, true);
    assert.equal(result.reason, 'native_pipes_not_closed');
    assert.deepEqual(signals, [], 'a released PID/group must never be signalled');
    assert.equal(result.stdout.toString(), 'terminal leader');
  });
}

test('active native deadline signals the owned group but never escalates after its leader exits', { timeout: 5000 }, async t => {
  const file = await executable(t, `process.on('SIGTERM', () => { process.stdout.write('drained'); process.exit(0); });
    process.stdout.write('ready:'); setTimeout(() => process.exit(1), 3000);`);
  const actual = process.kill.bind(process), signals = [];
  t.mock.method(process, 'kill', (pid, signal) => { signals.push({ pid, signal }); return actual(pid, signal); });
  const result = await runNative(file, [], { timeoutMs: 400 });
  assert.equal(result.forced, true);
  assert.equal(result.reason, 'native_deadline_exceeded');
  assert.equal(result.stdout.toString(), 'ready:drained');
  assert.deepEqual(signals.map(value => value.signal), ['SIGTERM']);
  await new Promise(resolve => setTimeout(resolve, 300));
  assert.equal(signals.length, 1);
});

test('normal completion and pre-spawn cancellation preserve exact output and ownership', { timeout: 5000 }, async t => {
  const file = await executable(t, `process.stdout.write('exact'); process.stderr.write('diagnostic'); process.exit(7);`);
  const result = await runNative(file, [], { timeoutMs: 3000 });
  assert.equal(result.code, 7); assert.equal(result.signal, null); assert.equal(result.forced, false);
  assert.equal(result.stdout.toString(), 'exact'); assert.equal(result.stderr.toString(), 'diagnostic');
  const stopped = new AbortController(); stopped.abort(new Error('pre-stopped'));
  assert.throws(() => runNative(file, [], { signal: stopped.signal }), /pre-stopped/);
});
