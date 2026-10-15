// Real Chromium execution of the production encoder and its unchanged helper.
// Import URLs alone are rewritten to data URLs, so this lane needs no network,
// HTTP navigation, fake DOM or running Rust node. It is not a publication test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { fullFilePatch, FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';

const exec = promisify(execFile);
const source = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const chromium = process.env.FG_TEST_CHROMIUM || 'chromium';
const dataModule = text => `data:text/javascript;base64,${Buffer.from(text).toString('base64')}`;

async function debugConnection(child) {
  const url = await new Promise((resolve, reject) => {
    let diagnostic = '';
    const timer = setTimeout(() => done(new Error(`Chromium did not open its debug endpoint: ${diagnostic}`)), 10_000);
    function done(error, value) {
      clearTimeout(timer); child.stderr.off('data', data); child.off('error', failed); child.off('exit', exited);
      if (error) reject(error); else resolve(value);
    }
    function failed(error) { done(error); }
    function exited(code) { done(new Error(`Chromium exited before debugging (${code}): ${diagnostic}`)); }
    function data(chunk) {
      diagnostic = (diagnostic + chunk).slice(-16 * 1024);
      const match = /DevTools listening on (ws:\/\/127\.0\.0\.1:[0-9]+\/[^\s]+)/.exec(diagnostic);
      if (match) done(null, match[1]);
    }
    child.stderr.on('data', data); child.once('error', failed); child.once('exit', exited);
  });
  const socket = new WebSocket(url), pending = new Map(); let id = 0;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.close(); reject(new Error('Chromium debug handshake timed out')); }, 5000);
    socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
    socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('Chromium debug handshake failed')); }, { once: true });
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data), request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id); clearTimeout(request.timer);
    if (message.error) request.reject(new Error(JSON.stringify(message.error))); else request.resolve(message.result);
  });
  socket.addEventListener('close', () => {
    for (const request of pending.values()) { clearTimeout(request.timer); request.reject(new Error('Chromium debug socket closed')); }
    pending.clear();
  });
  return {
    close: () => socket.close(),
    call(method, params = {}, sessionId) {
      return new Promise((resolve, reject) => {
        const key = ++id, timer = setTimeout(() => { pending.delete(key); reject(new Error(`Chromium ${method} timed out`)); }, 10_000);
        pending.set(key, { resolve, reject, timer }); socket.send(JSON.stringify({ id: key, method, params, ...(sessionId ? { sessionId } : {}) }));
      });
    },
  };
}

test('real Chromium executes the shipped compact encoder as offline ES modules', { timeout: 45_000 }, async t => {
  try { const { stdout } = await exec(chromium, ['--version'], { timeout: 5000 }); t.diagnostic(stdout.trim()); }
  catch (error) { if (error.code === 'ENOENT') { t.skip('install Chromium or set FG_TEST_CHROMIUM to run the real-browser lane'); return; } throw error; }
  const core = dataModule(await readFile(new URL('pulls-core.mjs', source)));
  const raw = await readFile(new URL('source-edit-patch.mjs', source), 'utf8');
  assert.equal(raw.split("'./pulls-core.mjs'").length, 2, 'rewrite only the known module specifier');
  const encoded = dataModule(raw.replace("'./pulls-core.mjs'", JSON.stringify(core)));
  const profile = await mkdtemp(join(tmpdir(), 'fgit-patch-chromium-'));
  let child, debug;
  try {
    child = spawn(chromium, ['--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
      '--disable-background-networking', '--disable-extensions', '--no-first-run', '--no-default-browser-check',
      `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
    debug = await debugConnection(child);
    const { targetId } = await debug.call('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await debug.call('Target.attachToTarget', { targetId, flatten: true });
    const response = await debug.call('Runtime.evaluate', { awaitPromise: true, returnByValue: true, expression: `(async () => {
      const {fullFilePatch, FILE_LIMIT} = await import(${JSON.stringify(encoded)});
      const before = new TextEncoder().encode((('a'.repeat(63)) + '\\n').repeat(FILE_LIMIT / 64));
      const after = before.slice(); after[4 * 64] = 98; after[FILE_LIMIT - 5 * 64] = 99;
      const edits = Array.from({length: 8}, (_, i) => ({
        path_hex: Array.from(new TextEncoder().encode('file-' + i), b => b.toString(16).padStart(2, '0')).join(''),
        before: {bytes: before, mode: 0o100644}, after: {bytes: after, mode: 0o100644}
      }));
      const patch = fullFilePatch(edits);
      return {count: patch.edits.length, bytes: Array.from(patch.bytes)};
    })()` }, sessionId);
    assert.equal(response.exceptionDetails, undefined, JSON.stringify(response.exceptionDetails));
    const before = new TextEncoder().encode(`${'a'.repeat(63)}\n`.repeat(FILE_LIMIT / 64)), after = before.slice();
    after[4 * 64] = 98; after[FILE_LIMIT - 5 * 64] = 99;
    const edits = Array.from({ length: 8 }, (_, i) => ({ path_hex: Buffer.from(`file-${i}`).toString('hex'),
      before: { bytes: before, mode: 0o100644 }, after: { bytes: after, mode: 0o100644 } }));
    const expected = fullFilePatch(edits);
    assert.equal(response.result.value.count, 8);
    assert.deepEqual(new Uint8Array(response.result.value.bytes), expected.bytes);
    assert(expected.bytes.length < 12 * 1024);
  } finally {
    if (debug) { try { await debug.call('Browser.close'); } catch { /* Closing can race the final protocol reply. */ } debug.close(); }
    if (child && child.exitCode === null && child.signalCode === null) {
      await new Promise(resolve => {
        const timer = setTimeout(() => child.kill('SIGKILL'), 2000);
        child.once('exit', () => { clearTimeout(timer); resolve(); });
      });
    }
    await rm(profile, { recursive: true, force: true });
  }
});
