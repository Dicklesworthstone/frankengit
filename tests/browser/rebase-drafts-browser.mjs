// Real Chromium, real DOM/File/Fetch/WebCrypto, exact served UI modules.
// The loopback API is the explicitly synthetic native-wire fixture, NOT fg.
// Run: node tests/browser/rebase-drafts-browser.mjs /absolute/path/to/chromium
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { fixture, token } from './rebase-session-fixtures.mjs';

const root = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const chromium = process.argv[2];
if (!chromium?.startsWith('/')) throw Error('Supply an absolute Chromium executable path.');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(action, label, ms = 10000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { const value = await action(); if (value) return value; await delay(25); }
  throw Error(`Timed out: ${label}`);
}
class CDP {
  next = 1; pending = new Map(); events = []; socket;
  async open(url) {
    this.socket = new WebSocket(url);
    await new Promise((resolve, reject) => { this.socket.addEventListener('open', resolve, { once: true }); this.socket.addEventListener('error', reject, { once: true }); });
    this.socket.addEventListener('message', ({ data }) => {
      const m = JSON.parse(data);
      if (!m.id) { this.events.push(m); return; }
      const p = this.pending.get(m.id); if (!p) return; this.pending.delete(m.id); clearTimeout(p.timer);
      if (m.error) p.reject(Error(JSON.stringify(m.error))); else p.resolve(m.result);
    });
    return this;
  }
  call(method, params = {}) {
    const id = this.next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(Error(`CDP timeout: ${method}`)); }, 10000);
      this.pending.set(id, { resolve, reject, timer }); this.socket.send(JSON.stringify({ id, method, params }));
    });
  }
  async eval(expression) {
    const r = await this.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw Error(JSON.stringify(r.exceptionDetails)); return r.result.value;
  }
  close() { for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(Error('CDP closed')); } this.pending.clear(); this.socket?.close(); }
}
const assets = new Set(['rebase.mjs', 'rebase-data.mjs', 'rebase-inspection.mjs', 'rebase-view.mjs',
  'pulls-core.mjs', 'pulls-candidate.mjs', 'pulls-actions.mjs', 'source-edit-protocol.mjs', 'source-edit-patch.mjs']);
const security = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
};
let f, chrome, browser, page, chromeExited;
const scratch = await mkdtemp(join(tmpdir(), 'fg-rebase-draft-browser-'));
const results = [], hashes = {};
const check = (name, value) => { assert(value, name); results.push(name); };
const server = createServer(async (req, res) => {
  try {
    let name;
    if (req.method === 'GET' && req.url === '/repo.git/ui/rebase/') name = 'rebase.html';
    else if (req.method === 'GET' && req.url === '/repo.git/ui/browser.css') name = 'browser.css';
    else if (req.method === 'GET' && req.url.startsWith('/repo.git/ui/rebase/')) {
      const candidate = req.url.slice('/repo.git/ui/rebase/'.length); if (assets.has(candidate)) name = candidate;
    }
    if (name) {
      const bytes = await readFile(new URL(name, root)); hashes[name] = createHash('sha256').update(bytes).digest('hex');
      res.writeHead(200, { ...security, 'Content-Type': name.endsWith('.html') ? 'text/html; charset=utf-8' : name.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8' }); res.end(bytes); return;
    }
    if (!f || req.method !== 'POST' || !req.url.startsWith('/repo.git/api/v1/')) { res.writeHead(404); res.end(); return; }
    if (req.headers.authorization !== `Bearer ${token}`) { res.writeHead(401); res.end(); return; }
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > 2 * 1024 * 1024) throw Error('Test request exceeds limit'); chunks.push(chunk); }
    const bytes = Buffer.concat(chunks), type = req.headers['content-type'] ?? '';
    const body = !size ? undefined : type.startsWith('application/x-www-form-urlencoded') ? bytes.toString('utf8') : new Uint8Array(bytes);
    try {
      const reply = await f.fetchImpl(new URL(req.url, 'http://127.0.0.1'), { method: 'POST', body, headers: req.headers });
      res.writeHead(reply.status, { ...security, ...Object.fromEntries(reply.headers) }); res.end(new Uint8Array(await reply.arrayBuffer()));
    } catch (error) {
      if (f.config.lose && req.url.endsWith('/apply')) req.socket.destroy();
      else { res.writeHead(500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ fixture_error: error.message })); }
    }
  } catch (error) { if (!res.headersSent) res.writeHead(500); res.end(error.message); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
try {
  let chromeError = '';
  chrome = spawn(chromium, ['--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run',
    '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', `--user-data-dir=${join(scratch, 'profile')}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  chrome.stderr.on('data', chunk => { chromeError = (chromeError + chunk.toString()).slice(-16000); });
  chromeExited = new Promise(resolve => chrome.once('exit', resolve));
  const active = await until(async () => { try { return (await readFile(join(scratch, 'profile', 'DevToolsActivePort'), 'utf8')).trim().split('\n'); } catch { if (chrome.exitCode !== null) throw Error(chromeError); return false; } }, 'Chromium startup');
  browser = await new CDP().open(`ws://127.0.0.1:${active[0]}${active[1]}`);
  const version = await browser.call('Browser.getVersion');
  await browser.call('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: scratch });
  const { targetId } = await browser.call('Target.createTarget', { url: 'about:blank' });
  page = await new CDP().open(`ws://127.0.0.1:${active[0]}/devtools/page/${targetId}`);
  await page.call('Page.enable'); await page.call('Runtime.enable'); await page.call('Log.enable');
  page.socket.addEventListener('message', ({ data }) => { const m = JSON.parse(data); if (m.method === 'Page.javascriptDialogOpening') void page.call('Page.handleJavaScriptDialog', { accept: true }); });
  const e = id => `document.getElementById(${JSON.stringify(id)})`;
  const click = async id => { await page.eval(`${e(id)}.click()`); await until(() => page.eval(`!${e('connect')}.disabled`), `${id} settled`); };
  const set = (id, value) => page.eval(`${e(id)}.value=${JSON.stringify(value)};${e(id)}.dispatchEvent(new Event('input',{bubbles:true}))`);
  async function upload(selector, path) {
    const { root } = await page.call('DOM.getDocument'); const { nodeId } = await page.call('DOM.querySelector', { nodeId: root.nodeId, selector });
    assert(nodeId, selector); await page.call('DOM.setFileInputFiles', { nodeId, files: [path] });
  }
  async function boot() {
    const navigation = await page.call('Page.navigate', { url: `${origin}/repo.git/ui/rebase/` });
    if (navigation.errorText) throw Error(`Browser navigation refused: ${navigation.errorText}`);
    await until(() => page.eval(`document.readyState==='complete' && !!${e('load-draft')} && ${e('load-draft')}.disabled`), 'page boot');
    await set('token', token); await click('connect');
  }
  async function download(id, name) {
    const path = join(scratch, name); await rm(path, { force: true }); await click(id);
    await until(async () => (await readdir(scratch)).includes(name), name); return path;
  }
  for (const algorithm of ['sha1', 'sha256']) {
    f = await fixture(algorithm); f.config.sequence = [f.stopped(0), f.stopped(1)]; await boot();
    await set('format', algorithm); await click('select');
    for (const key of ['upstream', 'committer', 'timestamp']) await set(key, String(f.input[key]));
    await click('prepare'); check(`${algorithm}: real browser reaches conflicted preparation`, await page.eval(`${e('report')}.textContent.includes('Stopped: conflicted')`));
    const binary = Uint8Array.from({ length: 256 }, (_, i) => i), binaryPath = join(scratch, 'resolution.bin'); await writeFile(binaryPath, binary);
    await page.eval(`document.querySelector('#conflicts select').value='file';document.querySelector('#conflicts select').dispatchEvent(new Event('change'))`);
    await upload('#conflicts input[type=file]', binaryPath);
    await page.eval(`document.querySelectorAll('#conflicts select')[1].value='100755';document.querySelectorAll('#conflicts select')[1].dispatchEvent(new Event('change'))`);
    await click('resolve'); check(`${algorithm}: accepted binary resolution reaches second original commit`, await page.eval(`${e('report')}.textContent.includes(${JSON.stringify(f.original[1])})`));
    await page.eval(`document.querySelector('#conflicts select').value='hex';document.querySelector('#conflicts select').dispatchEvent(new Event('change'));${e('include-choices')}.checked=true;${e('include-choices')}.dispatchEvent(new Event('change'))`);
    const count = f.calls.length, draftPath = await download('save-draft', 'frankengit-rebase-draft.json');
    check(`${algorithm}: saving actual download sends no request`, f.calls.length === count);
    const draft = JSON.parse(await readFile(draftPath, 'utf8')), payload = JSON.parse(draft.payload);
    check(`${algorithm}: binary draft retains every byte and executable mode`, payload.recipes[0].paths[0].bytes_hex === Buffer.from(binary).toString('hex') && payload.recipes[0].paths[0].mode === 0o100755);
    check(`${algorithm}: second empty file is not deletion`, payload.recipes[1].paths[0].bytes_hex === '' && payload.recipes[1].paths[0].choice === 'file');
    check(`${algorithm}: draft omits token and publication identity`, !(await readFile(draftPath, 'utf8')).includes(token) && !('key' in draft) && !('candidate' in payload));
    await boot(); await upload('#draft-file', draftPath); const beforeLoad = f.calls.length; await click('load-draft');
    check(`${algorithm}: reload restores through real File input without HTTP`, f.calls.length === beforeLoad);
    check(`${algorithm}: restored form is pinned and cannot publish`, await page.eval(`${e('format')}.value===${JSON.stringify(algorithm)} && ${e('upstream')}.value===${JSON.stringify(f.input.upstream)} && ${e('stage')}.disabled && ${e('prepare')}.disabled && !${e('resume-draft')}.disabled`));
    f.config.root = r => { if (r.ref === f.command.onto_ref) r.source_commit = f.id(99); }; await click('resume-draft');
    check(`${algorithm}: stale resume uploads no saved resolutions`, f.calls.slice(beforeLoad).every(c => c.endpoint === 'source/tree'));
    check(`${algorithm}: stale draft remains resumable, not publishable`, await page.eval(`${e('stage')}.disabled && !${e('resume-draft')}.disabled && ${e('status')}.textContent.includes('changed')`));
    f.config.root = null; const beforeResume = f.calls.length; await click('resume-draft');
    check(`${algorithm}: explicit resume rechecks both roots and inspects complete candidate`, JSON.stringify(f.calls.slice(beforeResume).map(c => c.endpoint)) === JSON.stringify(['source/tree', 'source/tree', 'source/rebase/resolve', 'source/rebase/inspect']));
    const resolved = f.calls.findLast(c => c.endpoint === 'source/rebase/resolve');
    check(`${algorithm}: resumed HTTP upload preserves binary and empty files`, Buffer.from(resolved.files.get('file_0')).equals(Buffer.from(binary)) && resolved.files.get('file_1').length === 0);
    check(`${algorithm}: complete inspection renders before publication`, await page.eval(`!${e('stage')}.disabled && ${e('inspection')}.textContent.includes('Net change') && ${e('inspection')}.textContent.includes('Rewritten commit 2')`));
    const beforeStage = f.calls.length; await click('stage'); await click('send');
    check(`${algorithm}: prepare and unconfirmed send do not publish`, f.calls.length === beforeStage);
    check(`${algorithm}: pending write blocks draft replacement`, await page.eval(`${e('save-draft')}.disabled && ${e('load-draft')}.disabled && ${e('resume-draft')}.disabled`));
    const pending = JSON.parse(await page.eval(`${e('pending')}.textContent`)); f.config.lose = true;
    await page.eval(`${e('confirm-send')}.checked=true`); await click('send');
    check(`${algorithm}: lost reply retains original key and uncertainty`, JSON.parse(await page.eval(`${e('pending')}.textContent`)).key === pending.key && await page.eval(`${e('status')}.textContent.includes('Outcome unknown')`));
    const receiptPath = await download('save-receipt', 'frankengit-rebase-retry.json'); const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
    check(`${algorithm}: publication recovery remains a distinct original-key receipt`, receipt.schema === 'frankengit-rebase-retry-v1' && receipt.key === pending.key);
    f.config.lose = false; f.config.outcome = 'committed'; await click('recover');
    check(`${algorithm}: outcome lookup is bodyless and retains original key`, f.calls.at(-1).endpoint === 'outcomes' && f.calls.at(-1).options.body === undefined && new Headers(f.calls.at(-1).options.headers).get('Idempotency-Key') === pending.key);
    check(`${algorithm}: recovery settles without another apply`, f.calls.filter(c => c.endpoint.endsWith('/apply')).length === 1 && await page.eval(`${e('pending')}.textContent==='No outstanding history rewrite.'`));
    await click('disconnect'); check(`${algorithm}: disconnect clears token and draft view`, await page.eval(`${e('token')}.value==='' && ${e('report')}.textContent==='' && ${e('draft-file')}.value===''`));
  }
  check('no uncaught browser exceptions', !page.events.some(e => e.method === 'Runtime.exceptionThrown'));
  check('no CSP violations', !page.events.some(e => e.method === 'Log.entryAdded' && /Content Security Policy|violates.*directive/i.test(e.params.entry.text)));
  console.log(JSON.stringify({ evidence: 'Real Chromium with synthetic native-wire HTTP fixture; NOT native Rust/fg integration', browser: version.product,
    node: process.version, checks: results.length, passed: results, asset_sha256: hashes }, null, 2));
} catch (error) {
  if (page) console.error(JSON.stringify({ diagnostic: await page.eval('({url:location.href,title:document.title,text:document.body?.innerText?.slice(0,1500)})').catch(() => null), events: page.events.filter(e => ['Runtime.exceptionThrown','Log.entryAdded'].includes(e.method)).slice(-10) }));
  throw error;
} finally {
  page?.close(); browser?.close();
  if (chrome && chrome.exitCode === null) { chrome.kill('SIGTERM'); await Promise.race([chromeExited, delay(2000)]); if (chrome.exitCode === null) { chrome.kill('SIGKILL'); await chromeExited; } }
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(scratch, { recursive: true, force: true });
}
