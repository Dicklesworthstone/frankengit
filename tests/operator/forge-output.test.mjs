// Simulated HTTP authority; real shipped CLI, files, sockets and OS backpressure.
// These cases establish process/output behavior, not native repository authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { listenForFetch } from '../fetch-peer.mjs';

const tenant = '11'.repeat(16), repository = '22'.repeat(16), principal = '33'.repeat(16);
const token = 'ab'.repeat(32), head = 'alg:2:' + '12'.repeat(32), count = 1000;

async function fixture(t, cli) {
  const root = await mkdtemp(join(tmpdir(), 'fg-output-'));
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, token, { mode: 0o600 });
  let pages = 0;
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const after = Number(url.searchParams.get('after')), limit = Number(url.searchParams.get('limit'));
    assert.equal(req.method, 'GET'); assert.equal(req.headers.authorization, `Bearer ${token}`);
    assert.equal(req.headers['idempotency-key'], undefined);
    if (after) assert.equal(url.searchParams.get('expected_head'), head);
    const rows = Array.from({ length: Math.min(limit, count - after) }, (_, i) => {
      const base = { number: after + i + 1, title: 'x'.repeat(240), state: 'open' };
      return cli === 'forge_inbox' ? { ...base, issue_version: 4, preference_version: 2,
        mode: 'automatic', read_through: 1, latest_other_version: 3, unread: true, reasons: ['author', 'participant'] }
        : { ...base, version: 1, body: '', labels: [], opened_by: principal, last_actor: principal, comments: 0 };
    });
    const common = { schema_version: 1, tenant_id: tenant, repository_id: repository, snapshot_token: head,
      after, limit, next_after: after + rows.length < count ? rows.at(-1).number : null };
    const reply = cli === 'forge_inbox' ? { ...common, type: 'notification_page', principal_id: principal,
      repository_incarnation: '44'.repeat(16), source_positions: { authority_head_generation: 1,
        forge_position_root: 'forge-' + head, outbox_root: 'outbox-' + head, complete: true },
      unread_only: false, include_muted: false, threads: rows }
      : { ...common, type: 'issue_page', issues: rows };
    pages++;
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(reply));
  });
  await listenForFetch(server);
  t.after(async () => {
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    await rm(root, { recursive: true, force: true });
  });
  const route = cli === 'forge_inbox' ? 'notifications' : 'issues';
  const args = ['list', ...(cli === 'forge_inbox' ? ['--kind', 'issue'] : []), '--url',
    `http://127.0.0.1:${server.address().port}/repo/ui/${route}/`, '--tenant-id', tenant,
    '--repository-id', repository, '--token-file', tokenFile, '--limit', '100', '--max-pages', '10'];
  return { root, args, pages: () => pages };
}

function launch(t, cli, args, drained, { fillError = false, drainError = true } = {}) {
  // Declared host-IO control: fill the actual inherited descriptor until EAGAIN.
  // It creates no response, native outcome or replacement command behavior.
  const loader = `import {writeSync} from 'node:fs'; void process.stderr;
    let blocked=false; const bytes=Buffer.alloc(4096,32);
    const fill=()=>{blocked=false;for(let i=0;i<2048;i++){try{writeSync(2,bytes);}catch(e){
      if(!['EAGAIN','EWOULDBLOCK'].includes(e.code))throw e;blocked=true;break;}}};
    fill(); await new Promise(resolve=>setTimeout(resolve,20)); fill();
    writeSync(3,blocked?'B':'N');`;
  const prefix = fillError ? ['--import', 'data:text/javascript,' + encodeURIComponent(loader)] : [];
  const child = spawn(process.execPath, [...prefix, resolve(`scripts/${cli}.mjs`), ...args],
    { stdio: ['ignore', 'pipe', 'pipe', ...(fillError ? ['pipe'] : [])] });
  const output = [], errors = [], control = [];
  if (drained) child.stdout.on('data', value => output.push(value));
  if (drainError) child.stderr.on('data', value => errors.push(value));
  if (fillError) child.stdio[3].on('data', value => control.push(value));
  const exited = once(child, 'exit').then(([code, signal]) => ({ code, signal }));
  const outputStarted = drained ? Promise.resolve() : once(child.stdout, 'readable');
  const closed = once(child, 'close'), errorsClosed = once(child.stderr, 'close');
  const controlClosed = fillError ? once(child.stdio[3], 'close') : Promise.resolve();
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await exited; }
    child.stdout.destroy(); child.stderr.destroy(); child.stdio[3]?.destroy();
  });
  return { child, exited, outputStarted, closed, errorsClosed, controlClosed, control: () => Buffer.concat(control).toString(),
    output: () => Buffer.concat(output), errors: () => Buffer.concat(errors).toString() };
}

async function bounded(promise, milliseconds, message) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

const boundedExit = (run, milliseconds = 4000) => bounded(run.exited, milliseconds, 'CLI did not reap with blocked stdout');

for (const cli of ['forge_inbox', 'forge_issues']) {
  test(`${cli}: drained large output is the permitted twin`, { timeout: 10000 }, async t => {
    const f = await fixture(t, cli), run = launch(t, cli, [...f.args, '--timeout-ms', '1500'], true);
    assert.deepEqual(await boundedExit(run), { code: 0, signal: null });
    await run.closed;
    assert.equal(run.errors(), ''); assert.ok(run.output().length > 300000);
    const result = JSON.parse(run.output());
    assert.equal(result.complete, true); assert.equal(result.page_count, 10);
    assert.equal(result.pages.flatMap(page => page.threads ?? page.issues).length, count);
    assert.equal(f.pages(), 10); assert.deepEqual(await readdir(f.root), ['token']);
  });

  test(`${cli}: whole-invocation deadline reaps blocked output`, { timeout: 10000 }, async t => {
    const f = await fixture(t, cli), run = launch(t, cli, [...f.args, '--timeout-ms', '1500'], false);
    assert.deepEqual(await boundedExit(run), { code: 2, signal: null });
    await run.errorsClosed;
    const error = JSON.parse(run.errors());
    assert.equal(error.operation_completed, true); assert.equal(error.code, 'operator_output_cancelled_or_deadline');
    assert.equal(f.pages(), 10); assert.deepEqual(await readdir(f.root), ['token']);
  });

  test(`${cli}: SIGTERM drains blocked output without a forced kill`, { timeout: 10000 }, async t => {
    const f = await fixture(t, cli), run = launch(t, cli, [...f.args, '--timeout-ms', '10000'], false);
    await bounded(run.outputStarted, 2500, 'CLI never started result delivery');
    assert.ok(run.child.stdout.readableLength > 0); assert.equal(f.pages(), 10);
    run.child.kill('SIGTERM');
    assert.deepEqual(await boundedExit(run, 1500), { code: 2, signal: null });
    await run.errorsClosed;
    const error = JSON.parse(run.errors());
    assert.equal(error.operation_completed, true); assert.equal(error.code, 'operator_output_cancelled_or_deadline');
    assert.deepEqual(await readdir(f.root), ['token']);
  });

  test(`${cli}: drained diagnostics preserve the original validation error`, { timeout: 10000 }, async t => {
    const f = await fixture(t, cli), run = launch(t, cli, [...f.args, '--unknown-option', 'x'], true, { fillError: true });
    assert.deepEqual(await boundedExit(run), { code: 2, signal: null }); await run.closed;
    const error = JSON.parse(run.errors());
    assert.equal(error.operation_completed, false); assert.match(error.code, /unknown.*option/);
    assert.equal(run.output().length, 0); assert.equal(f.pages(), 0);
    assert.deepEqual(await readdir(f.root), ['token']);
  });

  test(`${cli}: a reader closed during delivery preserves completed-operation failure`, { timeout: 10000 }, async t => {
    const f = await fixture(t, cli), run = launch(t, cli, [...f.args, '--timeout-ms', '1500'], false);
    await bounded(run.outputStarted, 2500, 'CLI never started result delivery');
    assert.ok(run.child.stdout.readableLength > 0); run.child.stdout.destroy();
    assert.deepEqual(await boundedExit(run, 1500), { code: 2, signal: null }); await run.errorsClosed;
    const error = JSON.parse(run.errors());
    assert.equal(error.operation_completed, true); assert.match(error.code, /^(EPIPE|ECONNRESET|ENOTCONN)$/);
    assert.equal(f.pages(), 10); assert.deepEqual(await readdir(f.root), ['token']);
  });

  test(`${cli}: blocked diagnostics have a finite finalization drain`, { timeout: 10000 }, async t => {
    const f = await fixture(t, cli), run = launch(t, cli, [...f.args, '--unknown-option', 'x'], true,
      { fillError: true, drainError: false });
    assert.deepEqual(await boundedExit(run, 1500), { code: 2, signal: null }); await run.controlClosed;
    assert.equal(run.control(), 'B', 'the real stderr descriptor reached backpressure');
    assert.equal(run.output().length, 0); assert.equal(f.pages(), 0);
    assert.deepEqual(await readdir(f.root), ['token']);
  });
}
