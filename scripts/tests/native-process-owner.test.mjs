// Actual Node child processes exercise operator ownership, not the Rust engine.
// No fixture result is evidence of native Git/authority interoperability.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getEventListeners } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { runNativeProcess } from '../lib/native-process-owner.mjs';
import { importLifetime, importJson, runImportProcess } from '../lib/native-import-process.mjs';

const posix = process.platform !== 'win32';
const execute = (source, options = {}) => runNativeProcess(process.execPath, ['-e', source], { timeoutMs: 5000, ...options });
const code = expected => error => { assert.equal(error.code, expected); return true; };
async function waitFile(path) {
  for (let i = 0; i < 200; i++) {
    try { return await readFile(path, 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await delay(10);
  }
  assert.fail('Owned process did not become ready');
}
function killOwned(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) return;
  try { process.kill(pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}
async function liveProcess(pid) {
  try {
    process.kill(pid, 0);
    // A reparented zombie cannot run. PID 1 may reap it after the test returns.
    if (process.platform === 'linux') {
      const stat = await readFile(`/proc/${pid}/stat`, 'utf8');
      if (stat.slice(stat.lastIndexOf(')') + 2).startsWith('Z ')) return false;
    }
    return true;
  } catch (error) { if (['ESRCH', 'ENOENT'].includes(error.code)) return false; throw error; }
}
async function withDirectory(action) {
  const dir = await mkdtemp(join(tmpdir(), 'fgit-native-owner-'));
  try { await action(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

test('success preserves exact output, diagnostic and exit status', async () => {
  const result = await execute('process.stdout.write(Buffer.from([0,255,10])); process.stderr.write("diagnostic");');
  assert.deepEqual(result, { code: 0, signal: null, stdout: Buffer.from([0,255,10]), stderr: Buffer.from('diagnostic') });
});
test('nonzero exit remains a native result, never an automatic retry', async () => {
  const result = await execute('process.stdout.write("refused"); process.exitCode = 7;');
  assert.equal(result.code, 7); assert.equal(result.stdout.toString(), 'refused');
});
test('stdin accepts the existing string recovery key protocol', async () => {
  const result = await execute('process.stdin.pipe(process.stdout)', { stdin: 'fg-source-import-exact-key' });
  assert.equal(result.stdout.toString(), 'fg-source-import-exact-key');
});
test('stdin snapshots mutable bytes before asynchronous consumption', async () => {
  const input = Uint8Array.of(0, 128, 255, 10);
  const result = execute('process.stdin.pipe(process.stdout)', { stdin: input });
  input.fill(7);
  assert.deepEqual((await result).stdout, Buffer.from([0, 128, 255, 10]));
});
for (const stream of ['stdout', 'stderr']) {
  test(`${stream} accepts exactly its byte budget`, async () => {
    const result = await execute(`process.${stream}.write(Buffer.alloc(4096, 97))`, { [`${stream}Limit`]: 4096 });
    assert.equal(result[stream].length, 4096);
  });
  test(`${stream} refuses one byte beyond its byte budget`, async () => {
    await assert.rejects(execute(`process.${stream}.write(Buffer.alloc(4097, 97))`, { [`${stream}Limit`]: 4096 }), code(`native_process_${stream}_limit`));
  });
}
test('zero output budget still permits an empty stream', async () => {
  assert.equal((await execute('', { stdoutLimit: 0, stderrLimit: 0 })).code, 0);
  await assert.rejects(execute('console.log("x")', { stdoutLimit: 0 }), code('native_process_stdout_limit'));
});
test('a missing executable produces a bounded spawn refusal', async () => {
  await assert.rejects(runNativeProcess(join(tmpdir(), 'fgit-definitely-absent-executable'), [], { timeoutMs: 1000 }), code('native_process_spawn_failed'));
});
test('pre-cancelled work never spawns or writes a marker', async () => withDirectory(async dir => {
  const marker = join(dir, 'not-started'), controller = new AbortController(); controller.abort();
  await assert.rejects(execute(`require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'bad')`, { signal: controller.signal }), code('native_process_cancelled'));
  await assert.rejects(readFile(marker), error => error.code === 'ENOENT');
}));
test('invalid ownership options refuse before a child starts', async () => {
  for (const options of [{timeoutMs: 0}, {timeoutMs: Infinity}, {stdoutLimit: -1}, {stderrLimit: 0.5}, {signal: {}}, {stdin: {}}]) {
    await assert.rejects(execute('', options), code('native_process_invalid_options'));
  }
  await assert.rejects(runNativeProcess('node', [], {timeoutMs: 1000}), code('native_process_invalid_options'));
});
test('cancellation drains the actual running process and removes its listener', async () => withDirectory(async dir => {
  const marker = join(dir, 'pid'), controller = new AbortController();
  const promise = execute(`require('node:fs').writeFileSync(${JSON.stringify(marker)}, String(process.pid)); setInterval(() => {}, 1000);`, { signal: controller.signal });
  const observed = assert.rejects(promise, code('native_process_cancelled'));
  const pid = Number(await waitFile(marker)); controller.abort(); await observed;
  assert.equal(await liveProcess(pid), false);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
}));
test('deadline escalates when the running child ignores SIGTERM', {skip: !posix}, async () => withDirectory(async dir => {
  const marker = join(dir, 'pid');
  const promise = execute(`process.on('SIGTERM', () => {}); require('node:fs').writeFileSync(${JSON.stringify(marker)}, String(process.pid)); setInterval(() => {}, 1000);`, {timeoutMs: 500});
  const observed = assert.rejects(promise, code('native_process_deadline'));
  const pid = Number(await waitFile(marker)); await observed;
  assert.equal(await liveProcess(pid), false);
}));
test('a late close cannot bypass a starved deadline callback', async () => {
  const result = execute('', {timeoutMs: 50});
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 120);
  await assert.rejects(result, code('native_process_deadline'));
});
test('signal exit is not fabricated as ordinary success', {skip: !posix}, async () => {
  const result = await execute('process.kill(process.pid, "SIGKILL")');
  assert.equal(result.code, null); assert.equal(result.signal, 'SIGKILL');
});
for (const inherited of [true, false]) {
  test(`leader exit cannot strand descendants with ${inherited ? 'inherited' : 'closed'} output`, {skip: !posix}, async () => withDirectory(async dir => {
    const marker = join(dir, 'pid'); let pid;
    const source = `const {spawn} = require('node:child_process');
      const child = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000)'],
        {stdio: ${inherited ? "['ignore','inherit','inherit']" : "'ignore'"}});
      require('node:fs').writeFileSync(${JSON.stringify(marker)}, String(child.pid)); process.exit(0);`;
    const promise = execute(source);
    const observed = assert.rejects(promise, error => {
      assert.ok(['native_process_descendants_remaining', 'native_process_containment_failed'].includes(error.code)); return true;
    });
    try { pid = Number(await waitFile(marker)); await observed; assert.equal(await liveProcess(pid), false); }
    finally { killOwned(pid); }
  }));
}
test('escaped inherited output reports failed containment instead of hanging', {skip: !posix, timeout: 8000}, async () => withDirectory(async dir => {
  const marker = join(dir, 'pid'), controller = new AbortController(); let pid;
  const source = `const {spawn} = require('node:child_process');
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {detached: true, stdio: ['ignore','inherit','inherit']});
    require('node:fs').writeFileSync(${JSON.stringify(marker)}, String(child.pid)); process.exit(0);`;
  const promise = execute(source, {signal: controller.signal});
  const observed = assert.rejects(promise, error => {
    assert.equal(error.code, 'native_process_containment_failed');
    assert.equal(error.details.reason, 'native_process_cancelled');
    assert.equal(error.details.leader_exited, true); assert.equal(error.details.output_closed, false);
    assert.equal(error.details.process_group, 'absent'); return true;
  });
  try {
    pid = Number(await waitFile(marker)); await delay(50); controller.abort(); await observed;
    // The fixture deliberately escaped the trusted-process-group profile. A
    // failure is reported, not a claim of reaping; this test owns its cleanup.
    assert.equal(await liveProcess(pid), true);
  } finally { killOwned(pid); }
}));
test('import adapter retains string keys and its established result shape', async () => {
  const result = await runImportProcess(process.execPath, ['-e', 'process.stdin.pipe(process.stdout)'], importLifetime(5000), 'original-key');
  assert.deepEqual(Object.keys(result), ['code', 'stdout', 'stderr']); assert.equal(result.stdout.toString(), 'original-key');
});
for (const [source, expected] of [
  ['process.stdout.write(Buffer.alloc(65537))', 'native_import_report_limit'],
  ['process.stderr.write(Buffer.alloc(65537))', 'native_import_diagnostic_limit'],
  ['setInterval(() => {}, 1000)', 'native_import_deadline'],
]) {
  test(`import adapter preserves ${expected}`, async () => {
    await assert.rejects(runImportProcess(process.execPath, ['-e', source], importLifetime(300)), code(expected));
  });
}
test('import adapter preserves explicit cancellation and abnormal exit refusals', async () => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(runImportProcess(process.execPath, ['-e', ''], {check() {}, remaining: () => 5000, signal: controller.signal}), code('native_import_cancelled'));
  if (posix) await assert.rejects(runImportProcess(process.execPath, ['-e', 'process.kill(process.pid, "SIGKILL")'], importLifetime(5000)), code('native_import_process_interrupted'));
});
test('native receipt parsing still preserves u64 and rejects duplicate keys', () => {
  assert.equal(importJson(Buffer.from('{"generation":18446744073709551615}')).generation, 18446744073709551615n);
  assert.throws(() => importJson(Buffer.from('{"value":1,"value":2}')), code('noncanonical_native_import_json'));
  assert.throws(() => importJson(Buffer.from('{"value":18446744073709551616}')), code('invalid_native_import_json'));
});
