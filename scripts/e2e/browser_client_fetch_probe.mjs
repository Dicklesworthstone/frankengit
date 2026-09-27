// Real-engine probe: each browser API client, on its own served page, makes
// one API request through the platform fetch.
//
// Drives an installed Chrome over the DevTools protocol (Node's WebSocket
// client; --experimental-websocket on Node 22.2). For every page it loads the
// served document, imports that page's own client module in the page context
// (same origin, under the page's CSP), constructs the client with its
// production defaults, connects with the given token and performs one read.
// It prints one JSON object of observations and asserts nothing itself;
// browser_client_fetch_smoke.py and suites/browser/client_fetch.sh do.
//
// usage: node --experimental-websocket browser_client_fetch_probe.mjs \
//          <chrome> <base-url> <token> <profile-dir>
import { spawn } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [chrome, base, token, profileDir] = process.argv.slice(2);
if (!chrome || !/^http:\/\/127\.0\.0\.1:\d+\//.test(base ?? '') || !/^[0-9a-f]{64}$/.test(token ?? '') || !profileDir) {
  console.error('usage: browser_client_fetch_probe.mjs <chrome> <base-url> <token> <profile-dir>');
  process.exit(2);
}

// One read per client class. `call` runs in the page with `client` bound.
const PAGES = [
  { page: 'ui/issues/', module: '../issues.mjs', cls: 'IssueClient', call: 'client.read()' },
  { page: 'ui/pulls/', module: '../pulls-core.mjs', cls: 'Transport', call: "client.request('pulls')" },
  { page: 'ui/history/', module: './history.mjs', cls: 'HistoryClient', call: "client.open('refs/heads/main', 'sha1')" },
];

const browser = spawn(chrome, [
  '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--disable-extensions', '--remote-debugging-port=0', `--user-data-dir=${profileDir}`, 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
let browserLog = '';
browser.stderr.on('data', chunk => { browserLog = (browserLog + chunk).slice(-8192); });

async function until(predicate, what, timeoutMs = 30_000) {
  const started = Date.now();
  for (;;) {
    const value = await predicate();
    if (value) return value;
    if (Date.now() - started > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await sleep(100);
  }
}

let socket;
try {
  const portFile = join(profileDir, 'DevToolsActivePort');
  const port = await until(() => existsSync(portFile) && readFileSync(portFile, 'utf8').split('\n')[0], 'DevToolsActivePort');
  const targets = await until(async () => {
    const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    return list.find(target => target.type === 'page') && list;
  }, 'a page target');
  socket = new WebSocket(targets.find(target => target.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });

  let nextId = 0;
  const pending = new Map();
  const exceptions = [];
  // Every API response the browser received, as the network layer saw it.
  let responses = [];
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.method === 'Network.responseReceived' && message.params.response.url.includes('/api/v1/')) {
      responses.push({ url: new URL(message.params.response.url).pathname, status: message.params.response.status });
    }
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(JSON.stringify(message.error))); else resolve(message.result);
    } else if (message.method === 'Runtime.exceptionThrown') {
      exceptions.push(message.params.exceptionDetails?.exception?.description ?? message.params.exceptionDetails?.text);
    }
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async expression => {
    const reply = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (reply.exceptionDetails) throw new Error(`evaluation failed: ${reply.exceptionDetails.text}`);
    return reply.result.value;
  };
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Network.enable');

  const pages = [];
  for (const { page, module, cls, call } of PAGES) {
    responses = [];
    await send('Page.navigate', { url: new URL(page, base).href });
    await until(() => evaluate(`document.readyState === 'complete' && location.pathname.endsWith(${JSON.stringify(`/${page}`)})`), `the ${page} document`);
    const observed = await evaluate(`(async () => {
      const outcome = { page: ${JSON.stringify(page)}, client: ${JSON.stringify(cls)}, resolved: false, error: null };
      try {
        const m = await import(new URL(${JSON.stringify(module)}, location.href).href);
        const client = new m[${JSON.stringify(cls)}]({ href: location.href });
        await client.connect(${JSON.stringify(token)});
        const reply = await ${call};
        outcome.resolved = true;
        outcome.reply = reply === undefined ? null : JSON.stringify(reply).slice(0, 300);
      } catch (error) {
        outcome.error = String(error?.message ?? error);
      }
      return outcome;
    })()`);
    await sleep(200);
    observed.api = responses;
    pages.push(observed);
  }
  const version = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).Browser;
  console.log(JSON.stringify({ type: 'browser_client_fetch_probe', browser: version, pages, exceptions }));
} catch (error) {
  console.log(JSON.stringify({ type: 'browser_client_fetch_probe_failed', error: String(error?.message ?? error), browser_log: browserLog }));
  process.exitCode = 1;
} finally {
  try { socket?.close(); } catch {}
  browser.kill('SIGTERM');
}
