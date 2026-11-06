// Real child processes test native operator lifetime, never forge authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
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

for (const stream of ['stdout', 'stderr']) for (const drain of [false, true]) {
  test(`${stream} reader failure finalizes its real child in ${drain ? 'dispatch drain' : 'read'} mode`,
    { skip: process.platform !== 'linux', timeout: 8000 }, async t => {
      const directory = await mkdtemp(join(tmpdir(), 'fg-workflow-pipe-'));
      t.after(() => rm(directory, { recursive: true, force: true }));
      const marker = join(directory, 'child.pid');
      const module = new URL('../../scripts/operator/workflow_watch_io.mjs', import.meta.url).href;
      // Isolate the operator too: the broken implementation throws an unhandled
      // stream error. Inject EIO on an actual child pipe, not a fabricated result.
      const source = `import { ChildProcess } from 'node:child_process';
        import { runNative } from ${JSON.stringify(module)};
        const original = ChildProcess.prototype.spawn;
        ChildProcess.prototype.spawn = function(options) {
          const result = Reflect.apply(original, this, [options]);
          this[${JSON.stringify(stream)}].once('data', () =>
            this[${JSON.stringify(stream)}].destroy(Object.assign(new Error('injected pipe EIO'), { code: 'EIO' })));
          return result;
        };
        const child = ${JSON.stringify(`require('node:fs').writeFileSync(${JSON.stringify(marker)}, String(process.pid));
          process.stdout.write('stdout-ready'); process.stderr.write('stderr-ready');
          setTimeout(() => process.exit(0), 10000);`)};
        const result = await runNative(process.execPath, ['-e', child], { timeoutMs: 3000, drain: ${drain} });
        process.stdout.write(JSON.stringify({ ...result, stdout: result.stdout.toString(), stderr: result.stderr.toString() }));`;
      let pid;
      try {
        const parent = spawnSync(process.execPath, ['--input-type=module', '-e', source],
          { timeout: 6000, maxBuffer: 65536, encoding: 'utf8' });
        pid = Number(await readFile(marker, 'utf8'));
        assert.ok(Number.isSafeInteger(pid) && pid > 1);
        assert.equal(parent.error, undefined);
        assert.equal(parent.signal, null);
        assert.equal(parent.status, 0, parent.stderr);
        const result = JSON.parse(parent.stdout);
        assert.equal(result.forced, true, 'unreadable output cannot establish a successful receipt');
        assert.equal(result.reason, stream === 'stdout' ? 'native_output_failed' : 'native_diagnostic_failed');
        assert.equal(result.spawn_error, null);
        assert.equal(result[stream], `${stream}-ready`);
        assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' }, 'native leader must be reaped before return');
      } finally {
        // A failing preimage may strand its child. Kill only this fixture's
        // still-live process, whose argv retains the exact private marker path.
        if (pid) {
          let command;
          try { command = await readFile(`/proc/${pid}/cmdline`); }
          catch (error) { if (error.code !== 'ENOENT' && error.code !== 'ESRCH') throw error; }
          if (command?.includes(Buffer.from(marker))) {
            try { process.kill(pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
          }
        }
      }
    });
}
