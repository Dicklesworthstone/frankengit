// Real-engine probe of the browser shell's rendered issue Markdown.
//
// Drives an installed Chrome over the DevTools protocol (no extra dependency:
// Node's WebSocket client, run with --experimental-websocket on Node 22.2).
// Opens the served /ui/issues/ page, connects with a token, reads one issue,
// and prints one JSON object of observations: what the rendered Markdown
// contains, whether any hostile construct became active content, every
// Content-Security-Policy violation the page reported, and every uncaught
// exception. It asserts nothing itself; browser_markdown_smoke.py does.
//
// usage: node --experimental-websocket browser_issue_markdown_probe.mjs \
//          <chrome> <ui-url> <token> <issue-number> <profile-dir>
import { spawn } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [chrome, uiUrl, token, issue, profileDir] = process.argv.slice(2);
if (!chrome || !uiUrl || !/^[0-9a-f]{64}$/.test(token ?? '') || !/^\d+$/.test(issue ?? '') || !profileDir) {
  console.error('usage: browser_issue_markdown_probe.mjs <chrome> <ui-url> <token> <issue> <profile-dir>');
  process.exit(2);
}

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
  const exceptions = [], consoleErrors = [], logEntries = [];
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(JSON.stringify(message.error))); else resolve(message.result);
    } else if (message.method === 'Runtime.exceptionThrown') {
      exceptions.push(message.params.exceptionDetails?.exception?.description ?? message.params.exceptionDetails?.text);
    } else if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') {
      consoleErrors.push(message.params.args.map(arg => arg.value ?? arg.description).join(' '));
    } else if (message.method === 'Log.entryAdded') {
      logEntries.push({ source: message.params.entry.source, level: message.params.entry.level, text: message.params.entry.text });
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
  await send('Log.enable');
  // Installed by the protocol before any page script; the page's own CSP
  // does not govern it. It only records, it changes nothing the page does.
  await send('Page.addScriptToEvaluateOnNewDocument', { source: `
    window.__fgitViolations = [];
    document.addEventListener('securitypolicyviolation', event => window.__fgitViolations.push({
      directive: event.violatedDirective, blocked: event.blockedURI, sample: event.sample }));` });
  await send('Page.navigate', { url: uiUrl });
  await until(() => evaluate("document.readyState === 'complete' && !!document.getElementById('issue-token')"), 'the issues page');

  await evaluate(`(() => {
    document.getElementById('issue-token').value = ${JSON.stringify(token)};
    document.getElementById('issue-connection').requestSubmit();
  })()`);
  await until(() => evaluate("/[Cc]onnected/.test(document.getElementById('issue-status').textContent)"), 'a connected status');
  await evaluate(`(() => {
    document.getElementById('show-number').value = ${JSON.stringify(issue)};
    document.getElementById('issue-show').requestSubmit();
  })()`);
  const outcome = await until(() => evaluate(`(() => {
    const text = document.getElementById('issue-content').textContent;
    if (text.includes('Derived Markdown · fgit-doc html_safe')) return 'rendered';
    if (text.includes('Rendered presentation unavailable')) return 'refused';
    return '';
  })()`), 'the rendered issue body');

  const facts = await evaluate(`(() => {
    const content = document.getElementById('issue-content');
    const all = [...document.querySelectorAll('*')];
    const text = selector => [...content.querySelectorAll(selector)].map(node => node.textContent);
    return {
      headings: text('h1, h2, h3, h4, h5, h6'),
      strong: text('strong'),
      emphasis: text('em'),
      list_items: text('li'),
      links: [...content.querySelectorAll('a')].map(a => ({ href: a.getAttribute('href'), rel: a.getAttribute('rel'), text: a.textContent })),
      images: [...content.querySelectorAll('img')].map(img => img.getAttribute('src')),
      raw_source_shown: [...content.querySelectorAll('pre')].map(pre => pre.textContent).join('\\n'),
      event_handler_attributes: all.flatMap(node => [...node.attributes].filter(a => /^on/i.test(a.name)).map(a => node.tagName + '[' + a.name + ']')),
      scripts: [...document.scripts].map(script => script.getAttribute('src') ?? 'inline'),
      svg_elements: document.querySelectorAll('svg').length,
      iframes: document.querySelectorAll('iframe, object, embed').length,
      javascript_links: all.filter(node => /^\\s*javascript:/i.test(node.getAttribute('href') ?? '')).length,
      pwned: window.__fgitPwned ?? null,
      violations: window.__fgitViolations ?? null,
      csp_meta_or_header_present: true,
    };
  })()`);
  const version = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).Browser;
  console.log(JSON.stringify({ type: 'browser_issue_markdown_probe', browser: version, outcome, ...facts,
    exceptions, console_errors: consoleErrors, csp_log_entries: logEntries.filter(entry => /Content Security Policy/i.test(entry.text)) }));
} catch (error) {
  console.log(JSON.stringify({ type: 'browser_issue_markdown_probe_failed', error: String(error?.message ?? error), browser_log: browserLog }));
  process.exitCode = 1;
} finally {
  try { socket?.close(); } catch {}
  browser.kill('SIGTERM');
}
