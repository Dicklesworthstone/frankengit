import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, readdir, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { Writable } from 'node:stream';
import { createServer as tlsServer } from 'node:https';
import { main } from '../../scripts/fg_source_archive.mjs';
import { inspectSourceArchive } from '../../scripts/operator/source_archive_tar.mjs';
import { captureSource } from '../../scripts/operator/source_archive.mjs';
import { fixture, token } from './fixtures/source_archive_native.mjs';
const cli = new URL('../../scripts/fg_source_archive.mjs', import.meta.url).pathname;
const save = (path, value) => writeFile(path, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value), { mode: 0o600 });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFor(check) { for (let i = 0; i < 300; i++) { if (await check()) return; await sleep(10); } throw new Error('test wait failed'); }
async function setup(t, options = {}) {
  const f = await fixture(t, options), root = await mkdtemp(join(tmpdir(), 'fg-source-cli-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const selectionFile = join(root, 'selection.json'), tokenFile = join(root, 'token'), output = join(root, 'source.tar');
  await save(selectionFile, f.selection); await save(tokenFile, token + '\n');
  const args = ['capture', '--selection', selectionFile, '--token-file', tokenFile, '--layout', 'portable', '--output', output];
  return { ...f, root, selectionFile, tokenFile, output, args };
}
function child(args) {
  const process = spawn(globalThis.process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = ''; process.stdout.on('data', part => { stdout += part; }); process.stderr.on('data', part => { stderr += part; });
  const done = new Promise((resolve, reject) => { process.once('error', reject); process.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); });
  return { process, done };
}
for (const format of ['sha1', 'sha256']) test(`${format}: actual capture CLI publishes an archive that reopens without network or credentials`, async t => {
  const f = await setup(t, { format }), run = await child(f.args).done;
  assert.equal(run.code, 0, run.stderr); const receipt = JSON.parse(run.stdout);
  assert.equal(receipt.source_commit, f.repo.commit); assert.equal(receipt.native_content_and_paths_verified, true);
  assert.ok(!run.stdout.includes(token)); assert.ok(!run.stdout.includes('hello'));
  const bytes = await readFile(f.output); assert.equal(inspectSourceArchive(bytes, receipt.archive_sha256).files, 3);
  await rm(f.tokenFile); await rm(f.selectionFile);
  const count = f.calls.length, reopened = await child(['inspect', '--archive', f.output, '--sha256', receipt.archive_sha256]).done;
  assert.equal(reopened.code, 0, reopened.stderr); assert.equal(f.calls.length, count);
  assert.equal(JSON.parse(reopened.stdout).archive_sha256, receipt.archive_sha256);
});
test('an existing destination is never replaced and refuses before network use', async t => {
  const f = await setup(t); await save(f.output, 'original');
  const run = await child(f.args).done; assert.equal(run.code, 2); assert.equal(f.calls.length, 0); assert.equal(await readFile(f.output, 'utf8'), 'original');
});
test('a destination created while reading is preserved and output is explicitly unconfirmed', async t => {
  const f = await setup(t); let created = false;
  f.control.mutate = async () => { if (!created) { created = true; await save(f.output, 'other writer'); } };
  const run = await child(f.args).done; assert.equal(run.code, 4, run.stderr);
  assert.equal(await readFile(f.output, 'utf8'), 'other writer');
  const error = JSON.parse(run.stderr); assert.ok(error.publication_unconfirmed.archive_sha256); assert.equal(error.retained_receipt, undefined);
});
test('simultaneous exporters cannot overwrite or corrupt one another', async t => {
  const f = await setup(t); let arrivals = 0, release; const gate = new Promise(resolve => { release = resolve; });
  f.control.mutate = async (_r, c) => { if (c.operation === 'log') { if (++arrivals === 2) release(); await gate; } };
  const results = await Promise.all([child(f.args).done, child(f.args).done]);
  assert.deepEqual(results.map(r => r.code).sort(), [0, 4]);
  const receipt = JSON.parse(results.find(r => r.code === 0).stdout);
  assert.equal(inspectSourceArchive(await readFile(f.output), receipt.archive_sha256).files, 3);
  assert.ok(!(await readdir(f.root)).some(name => name.includes('.writing-')));
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`actual ${signal} during acquisition creates no successful archive prefix`, async t => {
  const f = await setup(t); f.control.mutate = () => sleep(250);
  const run = child(f.args); t.after(() => { if (run.process.exitCode === null && run.process.signalCode === null) run.process.kill('SIGKILL'); });
  await waitFor(() => f.calls.length > 0); run.process.kill(signal); const result = await run.done;
  if (signal === 'SIGTERM') { assert.equal(result.code, 3, result.stderr); assert.equal(JSON.parse(result.stderr).retained_receipt, undefined); }
  else assert.equal(result.signal, 'SIGKILL');
  assert.ok(!(await readdir(f.root)).includes('source.tar'));
});
test('failed source verification and portable-name refusal leave no archive file', async t => {
  const f = await setup(t); f.control.mutate = (r, c) => { if (c.operation === 'blob') r.object_id = 'f'.repeat(40); };
  assert.equal((await child(f.args).done).code, 2); assert.ok(!(await readdir(f.root)).includes('source.tar'));
  const raw = await setup(t, { definitions: [{ path: Buffer.from([255]), data: Buffer.from('value') }] });
  assert.equal((await child(raw.args).done).code, 2);
  const args = [...raw.args]; args[args.indexOf('--layout') + 1] = 'objects';
  assert.equal((await child(args).done).code, 0);
});
test('broken stdout retains a verified artifact and the CLI returns delivery failure', async t => {
  const f = await setup(t); let diagnostics = '';
  const stdout = new Writable({ write(_data, _enc, done) { done(new Error('broken output')); } });
  const stderr = new Writable({ write(data, _enc, done) { diagnostics += data; done(); } });
  assert.equal(await main(f.args, { stdout, stderr }), 4);
  const receipt = JSON.parse(diagnostics).retained_receipt;
  assert.equal(inspectSourceArchive(await readFile(f.output), receipt.archive_sha256).files, 3);
});
test('secrets, configurations and output parents must be private and not symlink aliases', async t => {
  for (const mode of ['token-permissions', 'token-link', 'parent-permissions', 'parent-link', 'high-bit-token']) {
    const f = await setup(t);
    if (mode === 'token-permissions') await chmod(f.tokenFile, 0o644);
    if (mode === 'token-link') { await rm(f.tokenFile); await symlink(f.selectionFile, f.tokenFile); }
    if (mode === 'parent-permissions') await chmod(f.root, 0o755);
    if (mode === 'parent-link') { const alias = f.root + '-alias'; await symlink(f.root, alias); t.after(() => rm(alias)); f.args[f.args.indexOf('--output') + 1] = join(alias, 'source.tar'); }
    if (mode === 'high-bit-token') await save(f.tokenFile, Buffer.alloc(64, 0xe1));
    const run = await child(f.args).done; assert.equal(run.code, 2, mode + run.stderr); assert.equal(f.calls.length, 0);
  }
});
test('caller budgets can tighten but never increase export authority or cost', async t => {
  const f = await setup(t), limits = join(f.root, 'limits.json'); await save(limits, { maxRequests: 1 });
  const run = await child([...f.args, '--limits', limits]).done; assert.equal(run.code, 2); assert.equal(f.calls.length, 1);
  await save(limits, { timeoutMs: 120001 }); const count = f.calls.length;
  assert.equal((await child([...f.args, '--limits', limits]).done).code, 2); assert.equal(f.calls.length, count);
});
test('closed command grammar rejects duplicates, implicit layout and acquisition options on inspect', async t => {
  const f = await setup(t);
  for (const args of [[...f.args, '--output', f.output], [...f.args, '--force', 'yes'], ['capture'],
    ['inspect', '--archive', f.output, '--sha256', 'a'.repeat(64), '--token-file', f.tokenFile]]) assert.equal((await child(args).done).code, 2);
  assert.equal(f.calls.length, 0);
});
test('private-CA TLS validates the certificate and hostname instead of weakening verification', async t => {
  const f = await setup(t), key = join(f.root, 'key.pem'), cert = join(f.root, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=archive.invalid', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  await chmod(cert, 0o600);
  const server = tlsServer({ key: await readFile(key), cert: await readFile(cert) }, f.server.listeners('request')[0]);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  const selection = { ...f.selection, endpoint: `https://127.0.0.1:${server.address().port}/repo.git` };
  await assert.rejects(captureSource(selection, token), /transport/); assert.equal(f.calls.length, 0);
  assert.equal((await captureSource(selection, token, { ca: await readFile(cert) })).capture.files.length, 3);
  await save(f.selectionFile, selection);
  const run = await child([...f.args, '--ca-file', cert]).done; assert.equal(run.code, 0, run.stderr);
});
test('private CA trust never disables hostname verification', async t => {
  const f = await setup(t), key = join(f.root, 'wrong.key'), cert = join(f.root, 'wrong.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=unrelated.invalid', '-addext', 'subjectAltName=DNS:unrelated.invalid'], { stdio: 'ignore' });
  const server = tlsServer({ key: await readFile(key), cert: await readFile(cert) }, f.server.listeners('request')[0]);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  await assert.rejects(captureSource({ ...f.selection, endpoint: `https://127.0.0.1:${server.address().port}/repo.git` }, token, { ca: await readFile(cert) }), /transport/);
  assert.equal(f.calls.length, 0, 'no credentialed HTTP message before hostname validation');
});
test('malformed server JSON never copies its untrusted contents into CLI diagnostics', async t => {
  const f = await setup(t); f.control.respond = (_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.end('TOP_SECRET_UNVERIFIED_SOURCE');
  };
  const run = await child(f.args).done; assert.equal(run.code, 2); assert.ok(!run.stderr.includes('TOP_SECRET_UNVERIFIED_SOURCE'));
  assert.ok(!run.stdout.includes('TOP_SECRET_UNVERIFIED_SOURCE'));
});
