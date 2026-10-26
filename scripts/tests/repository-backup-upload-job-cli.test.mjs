// Real CLI, TLS, signatures and filesystem custody. The object services and
// opaque archive are fixtures, not native fg or cloud-durability evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile, unlink, mkdir, chmod, link, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tlsFixture, DATA, ID } from './backup-download-fixture.mjs';
import { uploadJobArguments, runUploadJobCommand, uploadJobError } from '../repository_backup_upload_job.mjs';

const CLI = fileURLToPath(new URL('../repository_backup_upload_job.mjs', import.meta.url));
async function fixture(t, format = 'sha256') {
  const stores = [await tlsFixture(t), await tlsFixture(t)], source = stores[0];
  const now = Math.floor(Date.now() / 1000) * 1000, stamp = value => new Date(value).toISOString().replace('.000Z', 'Z');
  await source.sign(DATA, { object_format: format, issued_at: stamp(now - 60000), expires_at: stamp(now + 3600000) }, now);
  let hook;
  for (const [index, store] of stores.entries()) {
    store.objects = new Map(); store.events = [];
    store.setHandler(async (req, res) => {
      const path = new URL(req.url, store.url).pathname; store.events.push(`${req.method} ${path}`);
      if (hook && await hook(index, req, res, path)) return;
      if (req.method === 'GET') {
        const bytes = store.objects.get(path); res.writeHead(bytes ? 200 : 404, { 'content-length': bytes?.length ?? 0 }); res.end(bytes); return;
      }
      assert.equal(req.method, 'PUT'); assert.equal(req.headers['if-none-match'], '*');
      if (store.objects.has(path)) { res.writeHead(412, { 'content-length': 0 }); res.end(); return; }
      try {
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        store.objects.set(path, Buffer.concat(chunks)); res.writeHead(201, { 'content-length': 0 }); res.end();
      } catch { res.destroy(); }
    });
    const origin = new URL(store.url).origin;
    store.target = Object.fromEntries(['archive', 'approval'].map(kind => [kind,
      { get: `${origin}/${kind}?SECRET=read`, put: `${origin}/${kind}?SECRET=write` }]));
    store.targetFile = join(source.root, `capabilities-${index}.json`);
    await writeFile(store.targetFile, JSON.stringify(store.target), { mode: 0o600 });
  }
  const jobDirectory = join(source.root, 'upload-job'); await mkdir(jobDirectory, { mode: 0o700 });
  const policy = { ...ID, object_format: format, minimum_head_generation: '1' };
  const common = ['--trusted-local', '--trust-key', source.trustKey,
    ...Object.entries(policy).flatMap(([key, value]) => ['--' + key.replaceAll('_', '-'), value]),
    ...stores.flatMap(store => ['--target', store.targetFile]), '--ca-file', source.caFile,
    '--max-archive-bytes', String(DATA.length), '--max-total-bytes', String(DATA.length * 6), '--timeout-secs', '20'];
  const sealArgs = ['seal', '--job-directory', jobDirectory, '--input', source.local, '--approval', source.approval, ...common];
  return { ...source, stores, common, sealArgs, jobDirectory, policy,
    runArgs: intent => ['run', '--intent', intent, ...common], hook(value) { hook = value; } };
}
function launch(t, args) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  for (const [stream, save] of [[child.stdout, value => { stdout += value; }], [child.stderr, value => { stderr += value; }]]) {
    stream.on('data', part => { save(part.toString()); if (stdout.length + stderr.length > 1024 * 1024) child.kill('SIGKILL'); });
  }
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); });
  const timer = setTimeout(() => child.kill('SIGKILL'), 30000); done.finally(() => clearTimeout(timer));
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await done; });
  return { child, done };
}
const errorOf = result => { assert.equal(result.code, 1, result.stdout + result.stderr); return JSON.parse(result.stderr.trim().split('\n').at(-1)); };
const success = result => { assert.equal(result.code, 0, result.stderr); return JSON.parse(result.stdout); };
async function seal(t, f) {
  const result = success(await launch(t, f.sealArgs).done);
  assert.equal(result.state, 'complete'); assert.equal(f.stores.reduce((n, store) => n + store.events.length, 0), 0);
  return result.job.intent;
}

for (const format of ['sha1', 'sha256']) test(`${format}: CLI seals exact custody then publishes to two HTTPS stores after original source/control loss`, async t => {
  const f = await fixture(t, format), expectedApproval = await readFile(f.approval), intent = await seal(t, f);
  const independentKey = join(f.root, 'independently-retained-public-key.pem'); await writeFile(independentKey, await readFile(f.trustKey));
  await unlink(f.local); await unlink(f.approval); await unlink(f.trustKey);
  const args = f.runArgs(intent); args[args.indexOf('--trust-key') + 1] = independentKey;
  const result = await launch(t, [...args, '--progress-json']).done, report = success(result);
  assert.equal(report.state, 'complete'); assert.equal(report.completed_targets.length, 2);
  assert.ok(!result.stdout.includes('SECRET')); assert.ok(!result.stderr.includes('SECRET'));
  assert.ok(!result.stdout.includes('https://')); assert.ok(!result.stderr.includes('https://'));
  for (const store of f.stores) {
    assert.deepEqual(store.objects.get('/archive'), DATA); assert.deepEqual(store.objects.get('/approval'), expectedApproval);
    assert.ok(store.events.indexOf('PUT /archive') < store.events.indexOf('PUT /approval'));
  }
  for (const name of await readdir(f.jobDirectory)) {
    if (name.endsWith('.json')) assert.ok(!(await readFile(join(f.jobDirectory, name), 'utf8')).includes('SECRET'));
  }
});

test('lost response on the second store preserves the first completion and exact resume with refreshed capabilities', async t => {
  const f = await fixture(t), intent = await seal(t, f); let first = null;
  f.hook(async (index, req, res, path) => {
    first ??= index;
    if (index !== first && req.method === 'PUT' && path === '/archive') {
      const parts = []; for await (const part of req) parts.push(part);
      f.stores[index].objects.set(path, Buffer.concat(parts)); res.destroy(); return true;
    }
  });
  const error = errorOf(await launch(t, f.runArgs(intent)).done);
  assert.equal(error.upload_job.completed_targets.length, 1); assert.notEqual(error.state, 'complete');
  assert.ok(error.upload_job.active_target); assert.equal(error.job.intent, intent);
  f.hook(null); await unlink(f.local); await unlink(f.approval);
  const prior = f.stores.map(store => store.events.length);
  for (const store of f.stores) {
    const refreshed = Object.fromEntries(Object.entries(store.target).map(([kind, pair]) => [kind,
      Object.fromEntries(Object.entries(pair).map(([method, value]) => [method, value.replace('SECRET=', 'SECRET=refreshed-')]))]));
    await writeFile(store.targetFile, JSON.stringify(refreshed));
  }
  const report = success(await launch(t, f.runArgs(intent)).done); assert.equal(report.completed_targets.length, 2);
  const resumedEvents = f.stores.flatMap((store, index) => store.events.slice(prior[index]));
  assert.equal(resumedEvents.filter(value => value === 'PUT /archive').length, 0);
  assert.equal(resumedEvents.filter(value => value === 'PUT /approval').length, 1);
});

test('a changed logical destination or unmet stronger floor refuses before remote requests', async t => {
  const f = await fixture(t), intent = await seal(t, f), changed = structuredClone(f.stores[0].target);
  for (const method of ['get', 'put']) changed.archive[method] = changed.archive[method].replace('/archive?', '/different-archive?');
  await writeFile(f.stores[0].targetFile, JSON.stringify(changed));
  assert.notEqual(errorOf(await launch(t, f.runArgs(intent)).done).state, 'complete');
  assert.equal(f.stores.reduce((n, store) => n + store.events.length, 0), 0);
  await writeFile(f.stores[0].targetFile, JSON.stringify(f.stores[0].target));
  const stronger = f.runArgs(intent); stronger[stronger.indexOf('--minimum-head-generation') + 1] = '9007199254740994';
  errorOf(await launch(t, stronger).done);
  assert.equal(f.stores.reduce((n, store) => n + store.events.length, 0), 0);
});

test('private capability files and malformed JSON refuse with redacted diagnostics', async t => {
  const f = await fixture(t), target = f.stores[0].targetFile;
  await chmod(target, 0o644); assert.equal(errorOf(await launch(t, f.sealArgs).done).code, 'backup_private_owner_required');
  await chmod(target, 0o600); await link(target, target + '.alias');
  assert.equal(errorOf(await launch(t, f.sealArgs).done).code, 'backup_private_key_links'); await unlink(target + '.alias');
  await writeFile(target, 'SECRET-invalid-JSON'); const result = await launch(t, f.sealArgs).done;
  assert.equal(errorOf(result).code, 'backup_upload_job_target_file'); assert.ok(!result.stderr.includes('SECRET'));
  assert.deepEqual(await readdir(f.jobDirectory), []); assert.equal(f.stores.reduce((n, store) => n + store.events.length, 0), 0);
});

test('grammar, applicable options and limits are validated before any control file access', async () => {
  const base = ['run', '--trusted-local', '--intent', '/missing/job.json', '--trust-key', '/missing/key.pem', '--target', '/missing/capabilities.json',
    ...Object.entries({ ...ID, minimum_head_generation: '1' }).flatMap(([key, value]) => ['--' + key.replaceAll('_', '-'), value])];
  for (const tail of [['--input', '/missing/source'], ['--approval', '/missing/approval'], ['--job-directory', '/missing/directory'],
    ['--max-archive-bytes', '0'], ['--max-total-bytes', '0'], ['--timeout-secs', '3601'], ['--insecure'], ['--trusted-local'], ['--target']]) {
    assert.throws(() => uploadJobArguments([...base, ...tail]));
  }
  assert.throws(() => uploadJobArguments(base.filter(value => value !== '--trusted-local')));
  assert.equal(uploadJobArguments(base).operation, 'run');
});

test('the aggregate payload allowance covers all targets before the first remote request', async t => {
  const f = await fixture(t), intent = await seal(t, f), args = f.runArgs(intent);
  args[args.indexOf('--max-total-bytes') + 1] = String(DATA.length * 6 - 1);
  errorOf(await launch(t, args).done); assert.equal(f.stores.reduce((n, store) => n + store.events.length, 0), 0);
});

test('SIGTERM drains a held PUT and keeps a resumable immutable intent', async t => {
  const f = await fixture(t), intent = await seal(t, f); let running, closed;
  f.hook((index, req, res, path) => {
    if (req.method === 'PUT' && path === '/archive') {
      closed = new Promise(resolve => req.socket.once('close', resolve)); req.resume(); running.child.kill('SIGTERM'); return true;
    }
  });
  running = launch(t, f.runArgs(intent)); const error = errorOf(await running.done);
  assert.equal(error.code, 'backup_cancelled'); assert.equal(error.job.intent, intent); await closed;
  assert.ok(f.stores.every(store => !store.objects.has('/approval')));
  f.hook(null); assert.equal(success(await launch(t, f.runArgs(intent)).done).state, 'complete');
});

test('failed final output preserves the completed job result and does not cause duplicate PUTs', async t => {
  const f = await fixture(t), intent = await seal(t, f);
  const broken = { write(_text, callback) { callback(Object.assign(new Error('closed'), { code: 'EPIPE' })); } };
  await assert.rejects(runUploadJobCommand(f.runArgs(intent), broken), error => {
    const report = uploadJobError(error); assert.equal(report.code, 'EPIPE'); assert.equal(report.state, 'complete');
    assert.equal(report.completed_result.completed_targets.length, 2); assert.equal(report.job.intent, intent); return true;
  });
  const prior = f.stores.map(store => store.events.length);
  assert.equal(success(await launch(t, f.runArgs(intent)).done).state, 'complete');
  assert.ok(f.stores.every((store, index) => store.events.slice(prior[index]).every(value => value.startsWith('GET '))));
});

test('help runs without opening a job, trust file or network connection', async t => {
  const result = await launch(t, ['--help']).done;
  assert.equal(result.code, 0); assert.match(result.stdout, /If-None-Match/); assert.match(result.stdout, /independently trusted key/);
});
