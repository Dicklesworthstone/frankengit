// Real-engine probe: every served page boots, connects, reads and (where it
// writes) commits one change in a real Chrome, and a token without the scope
// is refused. frankengit-root-doctrine-x2mv.4.46.
//
// Drives an installed Chrome over the DevTools protocol (Node's WebSocket
// client; --experimental-websocket on Node 22.2). For each scenario in
// browser_pages_scenarios.mjs it loads the served page, installs small UI
// helpers in the page (set a control, submit a form, click, wait for text),
// and runs the scenario's steps as a user would: through the page's own
// controls, never by importing its client module. It records, per page,
// every uncaught exception, console error and CSP violation, and each
// scenario's observations. It prints one JSON object and asserts nothing
// itself; browser_pages_smoke.py and suites/browser/pages.sh do.
//
// usage: node --experimental-websocket browser_pages_probe.mjs <config.json>
//   config: { chrome, profileDir, base, tokens: {full, read, other}, seed: {...},
//             files: {bundle} }
import { spawn } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { SCENARIOS } from './browser_pages_scenarios.mjs';

const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const { chrome, profileDir, base } = config;
if (!chrome || !/^http:\/\/127\.0\.0\.1:\d+\/.*\/$/.test(base ?? '') || !profileDir) {
  console.error('usage: browser_pages_probe.mjs <config.json> with chrome, profileDir and base');
  process.exit(2);
}

const serverPort = new URL(base).port;
const browser = spawn(chrome, [
  `--explicitly-allowed-ports=${serverPort}`,
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

// In-page helpers, installed after each navigation. Every step goes through
// the page's own controls and dispatches the events a user's input would.
const HELPERS = `(() => {
  const byId = id => { const el = document.getElementById(id); if (!el) throw new Error('no element #' + id); return el; };
  window.__fg = {
    set(id, value) {
      const el = byId(id);
      el.value = value;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    },
    check(id, on = true) {
      const el = byId(id);
      if (el.checked !== on) el.click();
    },
    submit(id) { byId(id).requestSubmit(); },
    click(id) { byId(id).click(); },
    text(id) { return document.getElementById(id)?.textContent ?? ''; },
    visible(id) { const el = document.getElementById(id); return Boolean(el && !el.hidden && el.offsetParent !== null); },
    enabled(id) { const el = document.getElementById(id); return Boolean(el && !el.disabled); },
    async until(predicate, what, timeoutMs = 30000) {
      const started = Date.now();
      for (;;) {
        let value;
        try { value = predicate(); } catch { value = false; }
        if (value) return value;
        if (Date.now() - started > timeoutMs) {
          const statuses = [...document.querySelectorAll('[role=status], [aria-live]')].map(el => '#' + el.id + ': ' + el.textContent.slice(0, 600));
          throw new Error('timed out waiting for ' + what + '; status: ' + statuses.join(' | '));
        }
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    },
  };
  return true;
})()`;

// Recorded before any page script runs, so a violation during boot counts.
const VIOLATIONS = `window.__fgViolations = [];
document.addEventListener('securitypolicyviolation', event => {
  window.__fgViolations.push(event.violatedDirective + ' ' + (event.blockedURI || ''));
});`;

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
  // Every error is tagged with the step that was running, so an expected 403
  // in a forbidden twin never hides an error during boot, read or write.
  let page = { errors: [], api: [] };
  let current = 'boot';
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    const params = message.params ?? {};
    if (message.method === 'Runtime.exceptionThrown') {
      page.errors.push({ step: current, kind: 'exception', text: params.exceptionDetails?.exception?.description ?? params.exceptionDetails?.text });
    } else if (message.method === 'Runtime.consoleAPICalled' && params.type === 'error') {
      page.errors.push({ step: current, kind: 'console', text: params.args?.map(arg => arg.value ?? arg.description).join(' ') });
    } else if (message.method === 'Log.entryAdded' && params.entry?.level === 'error') {
      page.errors.push({ step: current, kind: `log-${params.entry.source}`, text: params.entry.text });
    } else if (message.method === 'Network.responseReceived' && params.response.url.includes('/api/v1/')) {
      page.api.push({ step: current, path: new URL(params.response.url).pathname, status: params.response.status });
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
    if (reply.exceptionDetails) {
      throw new Error(`evaluation failed: ${reply.exceptionDetails.exception?.description ?? reply.exceptionDetails.text}`);
    }
    return reply.result.value;
  };
  await send('Page.enable');
  await send('Runtime.enable');
  await send('Network.enable');
  await send('Log.enable');
  await send('Page.addScriptToEvaluateOnNewDocument', { source: VIOLATIONS });

  // Opens a served page and installs the helpers; a scenario may reload.
  const open = async relative => {
    const url = new URL(relative, base).href;
    await send('Page.navigate', { url });
    await until(() => evaluate(`document.readyState === 'complete' && location.href === ${JSON.stringify(url)}`), relative);
    await sleep(300);
    await evaluate(HELPERS);
  };
  // Runs one step in the page: `body` is an async function body with `fg`,
  // `seed` and `token` in scope.
  const step = (body, token = '') => evaluate(`(async () => {
    const fg = window.__fg, seed = ${JSON.stringify(config.seed ?? {})}, token = ${JSON.stringify(token)};
    ${body}
  })()`);
  // Chooses a local file for a file input, as a user's file picker would; the
  // browser dispatches the input's own change event.
  const upload = async (id, file) => {
    const { root } = await send('DOM.getDocument', { depth: 0 });
    const { nodeId } = await send('DOM.querySelector', { nodeId: root.nodeId, selector: `#${id}` });
    if (!nodeId) throw new Error(`no file input #${id}`);
    await send('DOM.setFileInputFiles', { nodeId, files: [file] });
  };

  const pages = [];
  const chosen = config.only?.length ? SCENARIOS.filter(scenario => config.only.includes(scenario.name)) : SCENARIOS;
  for (const scenario of chosen) {
    page = { errors: [], api: [] };
    current = 'boot';
    const record = { name: scenario.name, path: scenario.path, booted: false, steps: {}, error: null };
    try {
      await open(scenario.path);
      record.booted = true;
      for (const [label, run] of Object.entries(scenario.steps)) {
        current = label;
        record.steps[label] = await run({ open, step, upload, tokens: config.tokens, seed: config.seed, files: config.files ?? {} });
      }
    } catch (error) {
      record.error = `${current}: ${String(error?.message ?? error)}`;
    }
    await sleep(300);
    record.violations = await evaluate('window.__fgViolations ?? []').catch(() => ['unavailable']);
    Object.assign(record, page);
    pages.push(record);
  }
  const version = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).Browser;
  console.log(JSON.stringify({ type: 'browser_pages_probe', browser: version, pages }));
} catch (error) {
  console.log(JSON.stringify({ type: 'browser_pages_probe_failed', error: String(error?.message ?? error), browser_log: browserLog }));
  process.exitCode = 1;
} finally {
  try { socket?.close(); } catch {}
  browser.kill('SIGTERM');
}
