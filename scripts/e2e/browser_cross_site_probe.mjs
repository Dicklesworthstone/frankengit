// Real-engine probe: a page on another origin makes Chrome send state-changing
// requests to the served API, and the served pages' own clients make the
// permitted same-origin twins. frankengit-root-doctrine-x2mv.4.31.
//
// Drives an installed Chrome over the DevTools protocol (Node's WebSocket
// client; --experimental-websocket on Node 22.2). For each attacker origin it
// loads that origin's page, then (1) posts the page's form fields with a
// no-cors fetch and (2) submits the form as a top-level navigation. It then
// loads the served issue and history pages and, in each, performs one
// state-changing or POST request with the page's own client. The network
// layer records every API request's status and the Origin and Sec-Fetch-Site
// Chrome actually sent. It prints one JSON object of observations and asserts
// nothing itself; browser_cross_site_smoke.py and suites/browser/cross_site.sh do.
//
// usage: node --experimental-websocket browser_cross_site_probe.mjs \
//          <chrome> <base-url> <token> <profile-dir> <attacker-port>
import { spawn } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [chrome, base, token, profileDir, attackerPort] = process.argv.slice(2);
if (!chrome || !/^http:\/\/127\.0\.0\.1:\d+\/.*\/$/.test(base ?? '') || !/^[0-9a-f]{64}$/.test(token ?? '') || !profileDir
    || !/^\d+$/.test(attackerPort ?? '')) {
  console.error('usage: browser_cross_site_probe.mjs <chrome> <base-url> <token> <profile-dir> <attacker-port>');
  process.exit(2);
}

// `localhost` is another site than `127.0.0.1`; the other port on the same
// address is the same site but another origin. Both must be refused.
const ATTACKERS = [
  { relation: 'cross-site', origin: `http://localhost:${attackerPort}` },
  { relation: 'same-site', origin: `http://127.0.0.1:${attackerPort}` },
];

// Allow both ports explicitly: an OS-assigned port can be one Chrome refuses
// as unsafe, which would fail navigation without the server seeing a request.
const serverPort = new URL(base).port;
const browser = spawn(chrome, [
  `--explicitly-allowed-ports=${serverPort},${attackerPort}`,
  '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--disable-extensions', '--remote-debugging-port=0', `--user-data-dir=${profileDir}`, 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
let browserLog = '';
browser.stderr.on('data', chunk => { browserLog = (browserLog + chunk).slice(-8192); });

async function until(predicate, what, timeoutMs = 30_000) {
  const started = Date.now();
  let lastError;
  for (;;) {
    let value;
    try { value = await predicate(); } catch (error) { lastError = error; }
    if (value) return value;
    if (Date.now() - started > timeoutMs) {
      throw new Error(`timed out waiting for ${what}${lastError ? ` (last error: ${lastError.message ?? lastError})` : ''}`);
    }
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
  // Every request the network layer saw, by request id. Extra-info events
  // carry the headers Chrome put on the wire (Origin, Sec-Fetch-Site) and can
  // arrive before or after the request event.
  let requests = new Map();
  const record = id => { if (!requests.has(id)) requests.set(id, {}); return requests.get(id); };
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    const params = message.params ?? {};
    if (message.method === 'Network.requestWillBeSent') {
      Object.assign(record(params.requestId), { url: params.request.url, method: params.request.method });
    } else if (message.method === 'Network.requestWillBeSentExtraInfo') {
      const headers = Object.fromEntries(Object.entries(params.headers).map(([name, value]) => [name.toLowerCase(), value]));
      Object.assign(record(params.requestId), { origin: headers.origin ?? null, site: headers['sec-fetch-site'] ?? null });
    } else if (message.method === 'Network.responseReceived') {
      record(params.requestId).status = params.response.status;
    } else if (message.method === 'Network.loadingFailed') {
      record(params.requestId).failed = params.errorText;
    } else if (message.method === 'Runtime.exceptionThrown') {
      exceptions.push(params.exceptionDetails?.exception?.description ?? params.exceptionDetails?.text);
    }
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(JSON.stringify(message.error))); else resolve(message.result);
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
  const open = async (url, what) => {
    await send('Page.navigate', { url });
    await until(() => evaluate(`document.readyState === 'complete' && location.href === ${JSON.stringify(url)}`), what);
  };
  // The API requests made while `action` runs, as the network layer saw them.
  const observe = async action => {
    requests = new Map();
    const value = await action();
    await sleep(500);
    const api = [...requests.values()].filter(r => r.url?.includes('/api/v1/'))
      .map(({ url, method, status = null, origin = null, site = null, failed = null }) =>
        ({ path: new URL(url).pathname, method, status, origin, site, failed }));
    return { value, api };
  };
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Network.enable');

  const attacks = [];
  for (const { relation, origin } of ATTACKERS) {
    const page = `${origin}/attack.html`;
    await open(page, `the ${relation} attacker page`);
    const fetched = await observe(() => evaluate(`(async () => {
      const form = document.forms[0];
      try {
        const reply = await fetch(form.action, { method: 'POST', mode: 'no-cors', credentials: 'include',
          body: new URLSearchParams(new FormData(form)) });
        return reply.type;
      } catch (error) { return 'error: ' + String(error?.message ?? error); }
    })()`));
    const submitted = await observe(async () => {
      const action = await evaluate('document.forms[0].action');
      await evaluate('setTimeout(() => document.forms[0].submit(), 0), true');
      await until(() => evaluate(`document.readyState === 'complete' && location.href === ${JSON.stringify(action)}`),
        `the ${relation} form navigation`);
      return evaluate('document.body ? document.body.innerText.slice(0, 300) : ""');
    });
    attacks.push({ relation, origin, fetch: fetched, form: submitted });
  }

  const twins = [];
  await open(new URL('ui/issues/', base).href, 'the served issue page');
  twins.push({ client: 'IssueClient', action: 'open issue 1', ...await observe(() => evaluate(`(async () => {
    try {
      const m = await import(new URL('../issues.mjs', location.href).href);
      const client = new m.IssueClient({ href: location.href });
      await client.connect(${JSON.stringify(token)});
      await client.stage(1, 0, 'open', { title: 'same-origin twin', body: 'permitted' });
      const terminal = await client.send();
      return { resolved: true, reply: JSON.stringify(terminal).slice(0, 300), error: null };
    } catch (error) { return { resolved: false, error: String(error?.message ?? error) }; }
  })()`)) });
  await open(new URL('ui/history/', base).href, 'the served history page');
  twins.push({ client: 'HistoryClient', action: 'open refs/heads/main', ...await observe(() => evaluate(`(async () => {
    try {
      const m = await import(new URL('./history.mjs', location.href).href);
      const client = new m.HistoryClient({ href: location.href });
      await client.connect(${JSON.stringify(token)});
      const reply = await client.open('refs/heads/main', 'sha1');
      return { resolved: true, reply: JSON.stringify(reply).slice(0, 300), error: null };
    } catch (error) { return { resolved: false, error: String(error?.message ?? error) }; }
  })()`)) });

  const version = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).Browser;
  console.log(JSON.stringify({ type: 'browser_cross_site_probe', browser: version, attacks, twins, exceptions }));
} catch (error) {
  console.log(JSON.stringify({ type: 'browser_cross_site_probe_failed', error: String(error?.message ?? error), browser_log: browserLog }));
  process.exitCode = 1;
} finally {
  try { socket?.close(); } catch {}
  browser.kill('SIGTERM');
}
