// Real Chromium, checked-in HTML/modules, and real HTTP. The API is a controlled
// fixture: this checks browser wiring/CSP/transport, NOT native merge admission.
// Run: CHROME=/path/to/chromium node tests/browser/pulls-fast-forward-chromium.mjs
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { observation, terminal, missingOutcome, token, sourceRoot } from './helpers/pulls-workflow-fixture.mjs';

const chromePath = process.env.CHROME;
if (!chromePath) throw new Error('CHROME is required; missing browser is not a passing test.');
const profile = await mkdtemp(join(tmpdir(), 'fg-pr-browser-'));
let observed = observation(), mode = 'committed', writes = [], errors = [], socket, chrome;
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'";
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/repository/api/v1/')) {
      assert.equal(req.headers.authorization, `Bearer ${token}`);
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; assert.ok(size <= 8192); chunks.push(chunk); }
      const body = Buffer.concat(chunks).toString('utf8');
      const send = (value, status = 200) => { const bytes = Buffer.from(JSON.stringify(value));
        res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': bytes.length }); res.end(bytes); };
      const path = url.pathname.slice('/repository/api/v1/'.length);
      if (req.method === 'GET' && path === 'pulls') return send({ ...observed.reply, type: 'pull_request_page', after: 0, limit: 20,
        pull_requests: [observed.reply.pull_request], next_after: null });
      if (req.method === 'GET' && path === 'pulls/7') return send(observed.reply);
      if (req.method === 'POST' && path === 'pulls/7/fast-forward') {
        writes.push({ body, key: req.headers['idempotency-key'] });
        assert.equal(req.headers['content-type'], 'application/x-www-form-urlencoded');
        if (mode === 'lost') { req.socket.destroy(); return; }
        return send(terminal(observed, Object.fromEntries(new URLSearchParams(body)), mode), mode === 'refused' ? 409 : 200);
      }
      if (req.method === 'POST' && path === 'outcomes') { assert.equal(body, ''); return send(missingOutcome(observed)); }
      throw new Error(`Unexpected API request: ${req.method} ${path}`);
    }
    const name = url.pathname === '/repository/ui/pulls/' ? 'pulls.html' : url.pathname.replace('/repository/ui/', '');
    if (!/^(?:pulls(?:-[a-z]+)?|markdown)\.(?:mjs|html|css)$/.test(name)) { res.writeHead(404); res.end(); return; }
    const bytes = await readFile(new URL(name, sourceRoot));
    res.writeHead(200, { 'Content-Type': name.endsWith('.mjs') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html',
      'Content-Length': bytes.length, 'Content-Security-Policy': csp }); res.end(bytes);
  } catch (error) { errors.push(error.message); res.writeHead(500); res.end('fixture failure'); }
});
try {
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  chrome = spawn(chromePath, ['--headless', '--no-sandbox', '--no-proxy-server', '--disable-gpu', '--no-first-run', '--disable-background-networking',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const endpoint = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Chrome startup timed out')), 10000); let output = '';
    chrome.once('error', error => { clearTimeout(timer); reject(error); });
    chrome.stderr.on('data', bytes => { output = (output + bytes).slice(-16384); const match = /DevTools listening on (ws:\/\/[^\s]+)/.exec(output);
      if (match) { clearTimeout(timer); resolve(match[1]); } });
    chrome.once('exit', code => { clearTimeout(timer); reject(new Error(`Chrome exited at startup: ${code}`)); });
  });
  socket = new WebSocket(endpoint); await once(socket, 'open');
  let serial = 0; const waiting = new Map();
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.method === 'Runtime.exceptionThrown') errors.push(JSON.stringify(message.params.exceptionDetails));
    if (message.id && waiting.has(message.id)) { const callback = waiting.get(message.id); waiting.delete(message.id); callback(message); }
  });
  const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++serial, timer = setTimeout(() => { waiting.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    waiting.set(id, message => { clearTimeout(timer); message.error ? reject(new Error(JSON.stringify(message.error))) : resolve(message.result); });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  const version = await call('Browser.getVersion');
  const { targetId } = await call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
  await call('Runtime.enable', {}, sessionId); await call('Page.enable', {}, sessionId);
  const evaluate = async expression => {
    const result = await call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails)); return result.result.value;
  };
  const wait = async expression => { for (let i = 0; i < 200; i++) { if (await evaluate(expression)) return; await delay(25); }
    throw new Error(`Browser condition timed out: ${expression}; status=${await evaluate('document.querySelector("#status")?.textContent ?? document.body?.innerText')}; fixtureErrors=${JSON.stringify(errors)}`); };
  const click = id => evaluate(`document.getElementById(${JSON.stringify(id)}).click()`);
  const connect = async format => {
    observed = observation(format); writes = [];
    await call('Page.navigate', { url: `http://127.0.0.1:${server.address().port}/repository/ui/pulls/` }, sessionId);
    await wait('document.querySelector("#status")?.textContent.includes("Connect with")');
    await evaluate(`document.getElementById('token').value=${JSON.stringify(token)};document.getElementById('connection').requestSubmit()`);
    await wait('document.querySelector("#pr-list button")');
    await evaluate('document.querySelector("#pr-list button").click()');
    await wait('document.querySelector("#fast-forward-stage")?.disabled === false');
  };
  const stage = async () => { await click('fast-forward-stage'); await wait('document.querySelector("#pending").textContent.includes("Prepared fast-forward")'); };
  const send = async () => { await click('confirm'); await wait('document.querySelector("#send").disabled === false'); await click('send'); };
  for (const format of ['sha1', 'sha256']) {
    mode = 'committed'; await connect(format);
    // Change real editable controls; they must not supply a merge's coordinates.
    await evaluate("document.getElementById('source-ref').value='refs/heads/unreviewed';document.getElementById('pr-number').value='999'");
    await stage(); assert.equal(writes.length, 0);
    assert.equal(await evaluate('document.querySelector("#send").disabled'), true);
    assert.equal(await evaluate('document.querySelector("#confirm").checked'), false);
    await send(); await wait('document.querySelector("#status").textContent.includes("Canonical committed")');
    assert.equal(writes.length, 1); const fields = Object.fromEntries(new URLSearchParams(writes[0].body));
    assert.equal(fields.source_ref, 'refs/heads/topic+one'); assert.equal(fields.pull_request_version, '3');
    assert.equal(fields.source_tip.length, format === 'sha1' ? 40 : 64); assert.equal(Object.keys(fields).length, 6);
    assert.equal(await evaluate('document.querySelector("#fast-forward-stage").disabled'), true);
    assert.equal(await evaluate('document.querySelector("#pending").textContent'), 'No prepared mutation.');
    console.log(JSON.stringify({ profile: 'real-browser-controlled-api', case: `${format}-confirmed-publication`, passed: true }));
    mode = 'refused'; await connect(format); await stage(); await send();
    await wait('document.querySelector("#status").textContent.includes("Canonical refused")'); assert.equal(writes.length, 1);
    console.log(JSON.stringify({ profile: 'real-browser-controlled-api', case: `${format}-policy-refusal`, passed: true }));
    mode = 'lost'; await connect(format); await stage(); await send();
    await wait('document.querySelector("#status").textContent.includes("Outcome remains unknown")');
    const first = { ...writes[0] }; await click('recover');
    await wait('document.querySelector("#status").textContent.includes("key_not_observed")'); assert.equal(writes.length, 1);
    mode = 'committed'; await send(); await wait('document.querySelector("#status").textContent.includes("Canonical committed")');
    assert.equal(writes.length, 2); assert.deepEqual(writes[1], first);
    console.log(JSON.stringify({ profile: 'real-browser-controlled-api', case: `${format}-lost-reply-explicit-retry`, passed: true }));
  }
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ browser: version.product, cases: 6, errors, native_server: false }));
} finally {
  socket?.close();
  if (chrome && chrome.exitCode === null) { const stopped = once(chrome, 'exit'); chrome.kill('SIGTERM');
    const kill = setTimeout(() => chrome.kill('SIGKILL'), 3000); await stopped; clearTimeout(kill); }
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  await rm(profile, { recursive: true, force: true, maxRetries: 3 });
}
