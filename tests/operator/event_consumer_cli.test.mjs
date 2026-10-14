import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, readdir, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Writable } from 'node:stream';
import { setTimeout as sleep } from 'node:timers/promises';
import { main } from '../../scripts/fg_events.mjs';
import { eventBytes } from '../../scripts/operator/event_feed.mjs';
import { openEventArchive } from '../../scripts/operator/event_archive.mjs';
import { config, page, row, peer, json, TOKEN } from './event_feed_fixture.mjs';
const CLI = resolve('scripts/fg_events.mjs');
function start(args) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NODE_OPTIONS: '' } });
  let stdout = '', stderr = '';
  child.stdout.on('data', b => { stdout += b; }); child.stderr.on('data', b => { stderr += b; });
  const complete = new Promise((accept, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('event CLI did not drain')); }, 10000);
    child.once('error', e => { clearTimeout(timer); reject(e); });
    child.once('close', (code, signal) => { clearTimeout(timer); accept({ code, signal, stdout, stderr }); });
  });
  return { child, complete, stdout: () => stdout, stderr: () => stderr };
}
async function run(args) { return start(args).complete; }
function records(text) { return text.trim() ? text.trim().split('\n').map(line => JSON.parse(line)) : []; }
async function fixture(configuration) {
  const parent = await mkdtemp(join(tmpdir(), 'fg-events-cli-')), root = join(parent, 'archive'), cfg = join(parent, 'config.json'), token = join(parent, 'token');
  await writeFile(cfg, eventBytes(configuration), { mode: 0o600 }); await writeFile(token, `${TOKEN}\n`, { mode: 0o600 });
  const args = (action, extra = []) => [action, '--archive', root, '--config', cfg, '--trusted-local',
    ...(action !== 'inspect' ? ['--token-file', token] : []), ...extra];
  return { parent, root, cfg, token, args, configuration, close: () => rm(parent, { recursive: true, force: true }) };
}
async function initialized(configuration) {
  const f = await fixture(configuration); const result = await run(f.args('init'));
  assert.equal(result.code, 0, result.stderr); return f;
}
async function waitFor(predicate) {
  const end = performance.now() + 7000;
  while (!predicate()) { if (performance.now() > end) throw new Error('condition not reached'); await sleep(5); }
}

for (const format of ['sha1', 'sha256']) test(`${format}: CLI init, bounded capture, restart and network-free inspect`, async () => {
  let cfg;
  const server = await peer((q, r, n) => {
    assert.equal(new URL(q.url, 'http://fixture.test').searchParams.get('after'), n === 1 ? '0' : '9007199254740993:4294967295');
    json(r, n === 1 ? page(cfg, { rows: [], resume: '9007199254740993:4294967295', more: true }) :
      page(cfg, { rows: [row('18446744073709551615', '4294967295')], head: '02' }));
  });
  cfg = config(server.endpoint, format); const f = await fixture(cfg);
  try {
    const init = await run(f.args('init')); assert.equal(init.code, 0, init.stderr);
    assert.equal(server.requests.length, 0); assert.equal(records(init.stdout)[0].network_attempted, false);
    const first = await run(f.args('capture', ['--max-pages', '1'])); assert.equal(first.code, 1, first.stderr);
    const [saved, summary] = records(first.stdout); assert.equal(saved.events, 0); assert.equal(saved.local_synced, true);
    assert.equal(summary.resume_after, '9007199254740993:4294967295'); assert.equal(summary.caught_up_at_observed_head, false);
    const done = await run(f.args('capture', ['--expected-tail', summary.tail_sha256])); assert.equal(done.code, 0, done.stderr);
    const tail = records(done.stdout).at(-1).tail_sha256; assert.equal(server.requests.length, 2);
    await server.close();
    const before = await readFile(join(f.root, 'page-00000002', 'record.json'));
    const inspection = await run(f.args('inspect', ['--expected-tail', tail, '--page', '2'])); assert.equal(inspection.code, 0, inspection.stderr);
    const report = records(inspection.stdout)[0]; assert.equal(report.pages, 2); assert.equal(report.events, 1);
    assert.equal(report.network_attempted, false); assert.equal(report.archive_modified, false); assert.equal(report.durability_verified, false);
    assert.equal(report.selected_page.page.events[0].event_frame_hex, '00ff80');
    assert.equal(report.resume_after, '18446744073709551615:4294967295');
    assert.deepEqual(await readFile(join(f.root, 'page-00000002', 'record.json')), before);
    assert(!init.stdout.includes(TOKEN)); assert(!first.stdout.includes(TOKEN));
  } finally { await f.close(); if (server.sockets.size) await server.close(); }
});

test('read-only inspect does not create a missing archive and capture does not initialize implicitly', async () => {
  const f = await fixture(config());
  try {
    for (const action of ['inspect', 'capture']) {
      const result = await run(f.args(action)); assert.equal(result.code, 2); assert.equal(result.stdout, '');
      assert.equal(records(result.stderr)[0].saved_pages_may_exist, true);
    }
    assert.deepEqual((await readdir(f.parent)).sort(), ['config.json', 'token']);
  } finally { await f.close(); }
});

test('CLI refuses ambiguous arguments, over-bounds and write options on inspection before creating data', async () => {
  const f = await fixture(config());
  try {
    const invalid = [[], ['send'], f.args('init', ['--config', f.cfg]), f.args('init', ['--max-pages', '1']),
      f.args('inspect', ['--token-file', f.token]), f.args('capture', ['--max-pages', '0']), f.args('capture', ['--max-pages', '65']),
      f.args('capture', ['--max-bytes', '33554433']), f.args('capture', ['--timeout-ms', '01']), f.args('capture', ['--expected-tail', 'bad']),
      f.args('watch', ['--poll-ms', '99']), f.args('watch', ['--max-sweeps', '0']), f.args('capture', ['--auto-retry']),
      f.args('capture').filter(a => a !== '--trusted-local'), f.args('capture', ['--ca-file'])];
    for (const args of invalid) { const result = await run(args); assert.equal(result.code, 2, JSON.stringify(args)); assert.equal(result.stdout, ''); }
    assert.deepEqual((await readdir(f.parent)).sort(), ['config.json', 'token']);
    const help = await run(['--help']); assert.equal(help.code, 0); assert(help.stdout.includes('capture'));
  } finally { await f.close(); }
});

test('config and credential must be independently retained private files; failures do not print secrets', async () => {
  const f = await fixture(config());
  try {
    await chmod(f.cfg, 0o644); assert.equal((await run(f.args('init'))).code, 2); await chmod(f.cfg, 0o600);
    await chmod(f.token, 0o644); assert.equal((await run(f.args('init'))).code, 2); await chmod(f.token, 0o600);
    await writeFile(f.token, 'do-not-print-private-token');
    const bad = await run(f.args('init')); assert.equal(bad.code, 2); assert(!bad.stderr.includes('do-not-print-private-token'));
    await writeFile(f.token, TOKEN); assert.equal((await run(f.args('init'))).code, 0);
    await writeFile(f.cfg, '{"type":1,"type":2}'); assert.equal((await run(f.args('inspect'))).code, 2);
  } finally { await f.close(); }
});

for (const signal of ['SIGTERM', 'SIGKILL']) test(`${signal}: stopped mid-request preserves the previously saved cursor and restart resumes`, async () => {
  let cfg;
  const server = await peer((q, r, n) => {
    const after = new URL(q.url, 'http://fixture.test').searchParams.get('after');
    assert.equal(after, n === 1 ? '0' : '1:0');
    if (n === 1) json(r, page(cfg, { more: true }));
    else if (n === 2) { /* held request is cancelled/killed */ }
    else json(r, page(cfg, { rows: [row('2')] }));
  });
  cfg = config(server.endpoint); const f = await initialized(cfg);
  try {
    const active = start(f.args('capture'));
    await waitFor(() => server.requests.length === 2 && records(active.stdout()).some(r => r.type === 'frankengit_event_page_saved'));
    active.child.kill(signal); const stopped = await active.complete;
    if (signal === 'SIGKILL') assert.equal(stopped.signal, 'SIGKILL');
    else { assert.equal(stopped.code, 130, stopped.stderr); assert.equal(records(stopped.stderr)[0].code, 'event_cancelled'); }
    assert.equal((await openEventArchive(f.root, cfg)).summary().resume_after, '1:0');
    const resumed = await run(f.args('capture')); assert.equal(resumed.code, 0, resumed.stderr);
    assert.equal(records(resumed.stdout).at(-1).events, 2); assert.equal(server.requests.length, 3);
  } finally { await f.close(); await server.close(); }
});

test('independent concurrent CLI processes cannot overwrite each other’s saved page', async () => {
  let cfg; const responses = [];
  const server = await peer((_q, r) => {
    responses.push(r);
    if (responses.length === 2) for (const response of responses) json(response, page(cfg));
  });
  cfg = config(server.endpoint); const f = await initialized(cfg);
  try {
    const a = start(f.args('capture')), b = start(f.args('capture'));
    const results = await Promise.all([a.complete, b.complete]);
    assert.deepEqual(results.map(r => r.code).sort(), [0, 2]);
    const lost = results.find(r => r.code === 2); assert.equal(records(lost.stderr)[0].code, 'event_archive_changed');
    const archive = await openEventArchive(f.root, cfg); assert.equal(archive.summary().pages, 1); assert.equal(archive.summary().events, 1);
    assert.equal(server.requests.length, 2);
  } finally { await f.close(); await server.close(); }
});

test('bounded watch handles append polling and suppresses identical quiet-page growth', async () => {
  let cfg;
  const server = await peer((q, r, n) => {
    const after = new URL(q.url, 'http://fixture.test').searchParams.get('after');
    assert.equal(after, n === 1 ? '0' : '1:0');
    json(r, n === 1 ? page(cfg) : page(cfg, { rows: [], resume: '1:0' }));
  });
  cfg = config(server.endpoint); const f = await initialized(cfg);
  try {
    const result = await run(f.args('watch', ['--poll-ms', '100', '--max-sweeps', '4']));
    assert.equal(result.code, 1, result.stderr); assert.equal(server.requests.length, 4);
    const summaries = records(result.stdout).filter(r => r.type === 'frankengit_event_capture_complete');
    assert.deepEqual(summaries.map(r => r.pages), [1, 2, 2, 2]);
    assert.deepEqual(summaries.map(r => r.sweep), [1, 2, 3, 4]);
    assert.equal((await openEventArchive(f.root, cfg)).summary().events, 1);
  } finally { await f.close(); await server.close(); }
});

test('watch stops on its first HTTP failure instead of retrying in the background', async () => {
  const server = await peer((_q, r) => json(r, { error: 'private-error-body' }, 503));
  const cfg = config(server.endpoint), f = await initialized(cfg);
  try {
    const result = await run(f.args('watch', ['--poll-ms', '100', '--max-sweeps', '10']));
    assert.equal(result.code, 2); assert.equal(server.requests.length, 1); assert(!result.stderr.includes('private-error-body'));
    assert.equal(records(result.stderr)[0].http_status, 503); assert.equal((await openEventArchive(f.root, cfg)).summary().pages, 0);
  } finally { await f.close(); await server.close(); }
});

test('credential rotation between watch sweeps is refused before another request', async () => {
  let cfg;
  const server = await peer((_q, r) => json(r, page(cfg)));
  cfg = config(server.endpoint); const f = await initialized(cfg);
  try {
    const active = start(f.args('watch', ['--poll-ms', '1000', '--max-sweeps', '3']));
    await waitFor(() => active.stdout().includes('frankengit_event_capture_complete'));
    await writeFile(f.token, '43'.repeat(32));
    const result = await active.complete; assert.equal(result.code, 2); assert.equal(server.requests.length, 1);
    assert.equal(records(result.stderr)[0].code, 'event_archive_binding_mismatch');
    assert.equal((await openEventArchive(f.root, cfg)).summary().pages, 1);
  } finally { await f.close(); await server.close(); }
});

test('a broken output stream loses the receipt, not the saved page', async () => {
  let cfg; const server = await peer((_q, r) => json(r, page(cfg))); cfg = config(server.endpoint);
  const f = await initialized(cfg);
  let errors = '';
  const stdout = new Writable({ write(_chunk, _encoding, done) { done(new Error('broken output')); } });
  const stderr = new Writable({ write(chunk, _encoding, done) { errors += chunk; done(); } });
  try {
    const result = await main(f.args('capture'), { stdout, stderr }); assert.equal(result, 2);
    assert.equal(records(errors)[0].code, 'event_archive_output_failed');
    assert.equal(records(errors)[0].retained.local_synced, true);
    assert.equal((await openEventArchive(f.root, cfg)).summary().pages, 1);
  } finally { await f.close(); await server.close(); }
});

test('SIGTERM interrupts a permanently blocked output callback after persistence', async () => {
  let cfg; const server = await peer((_q, r) => json(r, page(cfg))); cfg = config(server.endpoint);
  const f = await initialized(cfg); let writing;
  const started = new Promise(resolve => { writing = resolve; });
  const stdout = new Writable({ write(_chunk, _encoding, _done) { writing(); } });
  let errors = ''; const stderr = new Writable({ write(chunk, _encoding, done) { errors += chunk; done(); } });
  try {
    const result = main(f.args('capture'), { stdout, stderr }); await started;
    assert.equal((await openEventArchive(f.root, cfg)).summary().pages, 1);
    process.emit('SIGTERM');
    assert.equal(await result, 130); assert(stdout.destroyed);
    assert.equal(records(errors)[0].retained.pages, 1);
  } finally { await f.close(); await server.close(); }
});

test('SIGKILL after staging a complete synced page cannot select that abandoned candidate on restart', async () => {
  const { pathToFileURL } = await import('node:url');
  const f = await initialized(config()), marker = join(f.parent, 'stage-ready');
  const script = `
    import { writeFileSync } from 'node:fs';
    import { openEventArchive } from ${JSON.stringify(pathToFileURL(resolve('scripts/operator/event_archive.mjs')).href)};
    const [root, configText, pageText, marker] = process.argv.slice(1);
    const archive = await openEventArchive(root, JSON.parse(configText), { synchronize: true });
    let probes = 0;
    await archive.append(JSON.parse(pageText), () => {
      if (++probes === 2) {
        writeFileSync(marker, 'ready', { mode: 0o600 });
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
      }
    });
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, f.root, JSON.stringify(f.configuration), JSON.stringify(page(f.configuration)), marker], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = ''; child.stderr.on('data', b => { stderr += b; }); const closed = once(child, 'close');
  try {
    const deadline = performance.now() + 5000;
    while (true) {
      try { if ((await readFile(marker, 'utf8')) === 'ready') break; } catch (e) { if (e.code !== 'ENOENT') throw e; }
      if (performance.now() > deadline || child.exitCode !== null) throw new Error(`stage checkpoint absent: ${stderr}`);
      await sleep(5);
    }
    const entries = await readdir(f.root); assert(entries.some(name => name.startsWith('.stage-'))); assert(!entries.includes('page-00000001'));
    child.kill('SIGKILL'); assert.equal((await closed)[1], 'SIGKILL');
    const recovered = await openEventArchive(f.root, f.configuration, { synchronize: true });
    assert.equal(recovered.summary().pages, 0); assert.equal(recovered.summary().resume_after, '0');
    await recovered.append(page(f.configuration)); assert.equal(recovered.summary().pages, 1);
    assert((await readdir(f.root)).some(name => name.startsWith('.stage-')), 'unselected residue is retained, not used or silently erased');
  } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await closed; await f.close(); }
});
