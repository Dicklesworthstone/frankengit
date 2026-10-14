// Real CLI/TLS/filesystem composition. Object service is a contract fixture,
// not a native fg archive or evidence about a cloud provider's durability.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile, writeFile, unlink, chmod, link } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { tlsFixture, DATA, ID } from './backup-download-fixture.mjs';
import { uploadArguments, runUploadCommand } from '../upload_repository_backup.mjs';
import { downloadRepositoryBackup } from '../lib/repository-backup-download.mjs';
import { selectRepositoryBackup } from '../lib/repository-backup-selection.mjs';

const CLI = fileURLToPath(new URL('../upload_repository_backup.mjs', import.meta.url));
async function fixture(t, format = 'sha256') {
  const f = await tlsFixture(t), objects = new Map(), events = []; let hook;
  const now = Date.now(), date = n => new Date(n).toISOString().replace('.000Z', 'Z');
  await f.sign(DATA, { object_format: format, issued_at: date(Math.floor(now / 1000) * 1000 - 60000),
    expires_at: date(Math.floor(now / 1000) * 1000 + 3600000) }, now);
  f.setHandler(async (req, res) => {
    const path = new URL(req.url, f.url).pathname; events.push(req.method + ' ' + path);
    if (hook && await hook(req, res, path)) return;
    if (req.method === 'GET') { const value = objects.get(path); res.writeHead(value ? 200 : 404, { 'content-length': value?.length ?? 0 }); res.end(value); return; }
    assert.equal(req.headers['if-none-match'], '*');
    if (objects.has(path)) { res.writeHead(412, { 'content-length': 0 }); res.end(); return; }
    try { const parts = []; for await (const part of req) parts.push(part); objects.set(path, Buffer.concat(parts)); res.writeHead(201, { 'content-length': 0 }); res.end(); }
    catch { res.destroy(); }
  });
  const origin = new URL(f.url).origin;
  const target = Object.fromEntries(['archive', 'approval'].map(k => [k, { get: `${origin}/${k}?SECRET=read`, put: `${origin}/${k}?SECRET=write` }]));
  const targetFile = f.root + '/targets.json'; await writeFile(targetFile, JSON.stringify(target), { mode: 0o600 });
  const policy = { ...ID, object_format: format, minimum_head_generation: '1' };
  const args = ['--input', f.local, '--approval', f.approval, '--trust-key', f.trustKey, '--target', targetFile,
    '--ca-file', f.caFile, ...Object.entries(policy).flatMap(([k, v]) => ['--' + k.replaceAll('_', '-'), v]),
    '--max-archive-bytes', String(DATA.length), '--max-total-bytes', String(DATA.length * 3), '--timeout-secs', '3'];
  return { ...f, target, targetFile, objects, events, args, policy, hook(fn) { hook = fn; } };
}
function launch(t, args) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', part => { stdout += part; if (stdout.length > 131072) child.kill('SIGKILL'); });
  child.stderr.on('data', part => { stderr += part; if (stderr.length > 131072) child.kill('SIGKILL'); });
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); });
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000); done.finally(() => clearTimeout(timer));
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await done; });
  return { child, done };
}
function errorOf(result) { assert.equal(result.code, 1); return JSON.parse(result.stderr.trim().split('\n').at(-1)); }
for (const format of ['sha1', 'sha256']) test(`CLI upload, delete source, download and select exact recovery bytes (${format})`, async t => {
  const f = await fixture(t, format), result = await launch(t, [...f.args, '--progress-json']).done;
  assert.equal(result.code, 0, result.stderr); assert.ok(!result.stdout.includes('SECRET')); assert.ok(!result.stderr.includes('SECRET'));
  const receipt = JSON.parse(result.stdout); assert.equal(receipt.state, 'complete');
  assert.equal(result.stderr.trim().split('\n').length, 4); assert.ok(!f.args.join(' ').includes('SECRET'));
  assert.deepEqual(f.objects.get('/approval'), await readFile(f.approval));
  await unlink(f.local);
  const recovered = await downloadRepositoryBackup({ sources: [f.target.archive.get], approval: f.approval, trustKey: f.trustKey,
    caFile: f.caFile, destination: f.destination, policy: f.policy, maximumBytes: DATA.length, maximumTotalBytes: DATA.length * 4, timeoutMs: 3000 });
  const selected = await selectRepositoryBackup([recovered.candidate], f.trustKey, f.policy);
  assert.deepEqual(await readFile(selected.report.selected.input), DATA);
  assert.deepEqual(selected.report.checkpoint, receipt.checkpoint);
});
test('CLI exact checkpoint restart does not repeat either remote PUT', async t => {
  const f = await fixture(t); const first = JSON.parse((await launch(t, f.args).done).stdout), before = f.events.length;
  const result = await launch(t, [...f.args, '--checkpoint', first.checkpoint.approval_sha256, first.checkpoint.trusted_key_id]).done;
  assert.equal(result.code, 0, result.stderr); assert.deepEqual(f.events.slice(before), ['GET /approval', 'GET /archive', 'GET /approval']);
});
test('private target file ownership and link rules apply before network', async t => {
  const f = await fixture(t); await chmod(f.targetFile, 0o644);
  assert.equal(errorOf(await launch(t, f.args).done).code, 'backup_private_owner_required');
  await chmod(f.targetFile, 0o600); await link(f.targetFile, f.targetFile + '.alias');
  assert.equal(errorOf(await launch(t, f.args).done).code, 'backup_private_key_links'); assert.equal(f.events.length, 0);
});
test('malformed endpoint JSON is redacted and refuses before network', async t => {
  const f = await fixture(t); await writeFile(f.targetFile, 'SECRET-INVALID-JSON');
  const result = await launch(t, f.args).done; assert.equal(errorOf(result).code, 'backup_upload_target_file');
  assert.ok(!result.stderr.includes('SECRET')); assert.equal(f.events.length, 0);
});
test('CLI argument validation refuses unknown, duplicate and missing values', async t => {
  const f = await fixture(t);
  for (const tail of [['--insecure'], ['--timeout-secs', '4'], ['--checkpoint'], ['--target'], ['--max-total-bytes', '0']]) {
    assert.throws(() => uploadArguments([...f.args, ...tail]));
  }
  assert.equal(f.events.length, 0);
});
test('help neither reads files nor makes requests', async t => {
  const f = await fixture(t), result = await launch(t, ['--help']).done;
  assert.equal(result.code, 0); assert.match(result.stdout, /If-None-Match/); assert.equal(f.events.length, 0);
});
test('SIGTERM drains a held remote request without sending approval', async t => {
  const f = await fixture(t); let running, remoteClosed;
  f.hook((req, res, path) => { if (path === '/archive' && req.method === 'PUT') {
    // A paused HTTP receiver can defer observing FIN indefinitely. Consume its
    // body while withholding the response, and await an explicit close barrier.
    remoteClosed = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('peer did not observe close')), 2000);
      req.socket.once('close', () => { clearTimeout(timer); resolve(); });
    });
    req.resume(); running.child.kill('SIGTERM'); return true;
  } });
  running = launch(t, f.args); const result = await running.done;
  assert.equal(errorOf(result).code, 'backup_cancelled'); assert.equal(f.objects.has('/approval'), false);
  await remoteClosed; assert.equal(f.sockets.size, 0);
});
test('SIGKILL after remote archive acceptance recovers by reads without another archive PUT', async t => {
  const f = await fixture(t); let running;
  f.hook(async (req, res, path) => {
    if (path === '/archive' && req.method === 'PUT') {
      const parts = []; for await (const part of req) parts.push(part); f.objects.set(path, Buffer.concat(parts));
      running.child.kill('SIGKILL'); return true;
    }
  });
  running = launch(t, f.args); assert.equal((await running.done).signal, 'SIGKILL');
  const before = f.events.length; f.hook(null);
  const result = await launch(t, f.args).done; assert.equal(result.code, 0, result.stderr);
  assert.equal(f.events.slice(before).includes('PUT /archive'), false); assert.deepEqual(f.objects.get('/archive'), DATA);
});
test('SIGKILL after remote approval acceptance does not duplicate either PUT on restart', async t => {
  const f = await fixture(t); let running;
  f.hook(async (req, res, path) => {
    if (path === '/approval' && req.method === 'PUT') {
      const parts = []; for await (const part of req) parts.push(part); f.objects.set(path, Buffer.concat(parts));
      running.child.kill('SIGKILL'); return true;
    }
  });
  running = launch(t, f.args); assert.equal((await running.done).signal, 'SIGKILL');
  const before = f.events.length; f.hook(null);
  const result = await launch(t, f.args).done; assert.equal(result.code, 0, result.stderr);
  assert.equal(f.events.slice(before).some(e => e.startsWith('PUT')), false);
});
test('broken final stdout retains complete publication receipt', async t => {
  const f = await fixture(t); let running, approvalsRead = 0;
  f.hook((req, res, path) => { if (req.method === 'GET' && path === '/approval' && ++approvalsRead === 2) running.child.stdout.destroy(); });
  running = launch(t, f.args); const result = await running.done;
  const error = errorOf(result); assert.equal(error.publication_state, 'complete'); assert.equal(error.completed_result.state, 'complete');
  assert.deepEqual(f.objects.get('/archive'), DATA); assert.ok(!result.stderr.includes('SECRET'));
});
test('failed progress delivery before first PUT refuses further work', async t => {
  const f = await fixture(t), broken = { write(text, callback) { callback(Object.assign(new Error('closed'), { code: 'EPIPE' })); } };
  await assert.rejects(runUploadCommand([...f.args, '--progress-json'], broken, broken), { code: 'EPIPE' });
  assert.equal(f.events.length, 0);
});
test('CLI budget refusal has no remote side effects', async t => {
  const f = await fixture(t), args = f.args.slice(); args[args.indexOf('--max-total-bytes') + 1] = String(DATA.length * 3 - 1);
  assert.equal(errorOf(await launch(t, args).done).code, 'backup_upload_budget'); assert.equal(f.events.length, 0);
});
test('a service that withholds 100-continue times out without receiving archive bytes', async t => {
  const f = await fixture(t); let bytes = 0;
  f.server.on('checkContinue', req => { req.on('data', part => { bytes += part.length; }); });
  const args = f.args.slice(); args[args.indexOf('--timeout-secs') + 1] = '1';
  const result = await launch(t, args).done;
  assert.equal(errorOf(result).code, 'backup_deadline'); assert.equal(bytes, 0); assert.equal(f.objects.size, 0);
});
