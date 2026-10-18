import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { readFile, writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { main } from '../../scripts/remote_bundle.mjs';
import { inspectRemoteBundle, prepareRemoteBundle, runRemoteBundle } from '../../scripts/operator/remote_bundle.mjs';
import { hash, BUNDLE_REMOTE_LIMITS as L } from '../../scripts/operator/remote_bundle_protocol.mjs';
import { fixture, payload } from './remote-bundle-fixture.mjs';
import { sourceFixture } from './remote-bundle-export-fixture.mjs';

const script = fileURLToPath(new URL('../../scripts/remote_bundle.mjs', import.meta.url));
function start(t, args) {
  const child = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  const exited = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('test child deadline')); }, 15000);
    child.stdout.on('data', b => { stdout += b; if (stdout.length > 2 * L.intent) child.kill('SIGKILL'); });
    child.stderr.on('data', b => { stderr += b; if (stderr.length > 2 * L.intent) child.kill('SIGKILL'); });
    child.on('error', e => { clearTimeout(timer); reject(e); });
    child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
  });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  return { child, exited };
}
const run = (t, args) => start(t, args).exited;
function result(r, code = 0) { assert.equal(r.code, code, r.stderr); assert.equal(r.signal, null); assert.equal(r.stderr, ''); return JSON.parse(r.stdout); }
async function prepareArgs(f) {
  const selectionFile = join(f.root, 'selection.json'); await writeFile(selectionFile, JSON.stringify(f.selection), { mode: 0o600 });
  return ['prepare', '--workdir', f.options.workdir, '--selection', selectionFile, '--token-file', f.token,
    '--bundle-file', f.bundle, '--bundle-confirm', hash(payload)];
}
const jobArgs = (r, op = 'run') => [op, '--workdir', r.workdir, '--confirm', r.intent_sha256];

test('real CLI export, inspect, prepare, upload and credential-free status', async t => {
  const source = await sourceFixture(t, { format: 'sha256' }), dest = await fixture(t, { format: 'sha256', operation: 'fetch' });
  const selectionFile = join(source.root, 'source.json'); await writeFile(selectionFile, JSON.stringify(source.selection), { mode: 0o600 });
  const saved = result(await run(t, ['export', '--workdir', source.options.workdir, '--selection', selectionFile, '--token-file', source.token]));
  await source.close(); await unlink(source.token);
  const checked = result(await run(t, ['inspect-download', '--workdir', saved.workdir, '--confirm', saved.download_sha256]));
  const args = await prepareArgs(dest); args[args.indexOf('--bundle-file') + 1] = checked.bundle_file; args[args.indexOf('--bundle-confirm') + 1] = checked.artifact_sha256;
  const request = result(await run(t, args)); assert.equal(request.state, 'ready'); assert.equal(dest.requests.length, 0);
  const inspected = result(await run(t, jobArgs(request, 'inspect'))); assert.equal(inspected.payload_verified, true);
  const uploaded = result(await run(t, [...jobArgs(request), '--token-file', dest.token])); assert.equal(uploaded.complete, true);
  await unlink(dest.token); await unlink(join(request.workdir, 'repository.bundle')); await dest.close();
  const status = result(await run(t, jobArgs(request, 'status'))); assert.equal(status.complete, true); assert.equal(status.network_accessed, false);
  const cached = result(await run(t, jobArgs(request))); assert.equal(cached.complete, true); assert.equal(cached.mutation_submitted, false);
});
for (const signal of ['SIGTERM', 'SIGINT', 'SIGKILL']) test(`actual ${signal} during committed reply recovers without a duplicate upload`, async t => {
  let child, stopped = false;
  const f = await fixture(t, { intercept: ({ call, res }) => {
    if (call.path.includes('/source/bundle/')) {
      res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); stopped = child.kill(signal); return false;
    }
  } });
  const request = result(await run(t, await prepareArgs(f)));
  const pending = start(t, [...jobArgs(request), '--token-file', f.token]); child = pending.child;
  const ended = await pending.exited; assert.equal(stopped, true);
  if (signal === 'SIGKILL') { assert.equal(ended.code, null); assert.equal(ended.signal, 'SIGKILL'); }
  else { assert.equal(ended.code, 4); assert(JSON.parse(ended.stderr).retained_result); }
  await unlink(join(request.workdir, 'repository.bundle'));
  const before = result(await run(t, jobArgs(request, 'status'))); assert.equal(before.state, 'unresolved'); assert.equal(before.complete, false);
  const recovered = result(await run(t, [...jobArgs(request, 'recover'), '--token-file', f.token]));
  assert.equal(recovered.complete, true); assert.equal(recovered.mutation_submitted, false);
  assert.equal(f.requests.filter(r => r.path.includes('/source/bundle/')).length, 1);
  assert(f.requests.every(r => r.key === request.key));
});
test('CLI unknown outcome fences upload until explicit original-key retry', async t => {
  let drop = true;
  const f = await fixture(t, { noCommit: true, intercept: ({ call, req, states }) => {
    if (call.path.includes('/source/bundle/')) { if (drop) { req.socket.destroy(); return false; } states.set(call.key, 'committed'); }
  } });
  const request = result(await run(t, await prepareArgs(f)));
  result(await run(t, [...jobArgs(request), '--token-file', f.token]), 3);
  result(await run(t, [...jobArgs(request), '--token-file', f.token]), 3);
  assert.equal(f.requests.filter(r => r.payload).length, 1);
  drop = false; const done = result(await run(t, [...jobArgs(request), '--token-file', f.token, '--retry-key', request.key]));
  assert.equal(done.complete, true); const bodies = f.requests.filter(r => r.payload); assert.equal(bodies.length, 2); assert(bodies[0].body.equals(bodies[1].body));
});
test('native refusal exits 1, but offline status still succeeds without suggesting retry', async t => {
  const f = await fixture(t, { refuse: true }), request = result(await run(t, await prepareArgs(f)));
  const refused = result(await run(t, [...jobArgs(request), '--token-file', f.token]), 1); assert.equal(refused.state, 'refused');
  assert.equal(result(await run(t, jobArgs(request, 'status'))).state, 'refused');
});
test('broken output keeps the prepared original key and complete private payload', async t => {
  const f = await fixture(t); let diagnostic = '';
  const stdout = new Writable({ write(_b, _e, cb) { cb(new Error('broken pipe')); } });
  const stderr = new Writable({ write(b, _e, cb) { diagnostic += b; cb(); } });
  assert.equal(await main(await prepareArgs(f), { stdout, stderr }), 4);
  const request = JSON.parse(diagnostic).retained_result; assert(request.intent_sha256); assert.equal(f.requests.length, 0);
  assert.equal((await inspectRemoteBundle({ workdir: request.workdir, confirm: request.intent_sha256, verifyPayload: true })).payload_verified, true);
  assert.equal(result(await run(t, [...jobArgs(request), '--token-file', f.token])).complete, true);
});
test('strict CLI grammar rejects overrides and unsafe numeric spellings before HTTP', async t => {
  const f = await fixture(t), p = result(await run(t, await prepareArgs(f)));
  for (const args of [
    [...jobArgs(p), '--force', 'true'], [...jobArgs(p), '--timeout-ms', '1e2'], [...jobArgs(p), '--timeout-ms', '01'],
    [...jobArgs(p), '--timeout-ms', '300001'], [...jobArgs(p), '--confirm', p.intent_sha256],
    [...jobArgs(p, 'recover'), '--retry-key', p.key], [...jobArgs(p), '--url', f.endpoint],
    ['__proto__'], ['run'], ['status', '--workdir', 'relative', '--confirm', p.intent_sha256],
  ]) { const r = await run(t, args); assert.equal(r.code, 2); assert.equal(r.stdout, ''); }
  assert.equal(f.requests.length, 0); assert.equal(result(await run(t, jobArgs(p, 'status'))).attempts, 0);
});
test('help describes explicit keys, native authority and bounded payloads', async t => {
  const help = result(await run(t, ['--help'])).usage; assert.match(help, /67108864/); assert.match(help, /native server/); assert.match(help, /ORIGINAL_KEY/);
});
test('all 32 attempt slots are cumulative across restarts and bound unresolved recovery', async t => {
  const f = await fixture(t, { noCommit: true, intercept: ({ call, req }) => { if (call.path.includes('/source/bundle/')) { req.socket.destroy(); return false; } } });
  const p = await prepareRemoteBundle(f.options), opts = { workdir: p.workdir, confirm: p.intent_sha256, tokenFile: f.token };
  for (let n = 1; n <= L.attempts; n++) { const r = await runRemoteBundle(opts); assert.equal(r.attempts, n); assert.equal(r.complete, false); }
  const count = f.requests.length; await assert.rejects(runRemoteBundle(opts), /attempt_limit/); assert.equal(f.requests.length, count);
  assert.equal(f.requests.filter(r => r.payload).length, 1); assert.equal((await inspectRemoteBundle({ workdir: p.workdir, confirm: p.intent_sha256 })).attempts, 32);
});
test('actual 64 MiB multipart upload uses retained bytes and native confirmation schema', async t => {
  const f = await fixture(t), bytes = Buffer.alloc(L.bundle, 0x27); await writeFile(f.bundle, bytes);
  const p = await prepareRemoteBundle({ ...f.options, bundleConfirm: hash(bytes) });
  const r = await runRemoteBundle({ workdir: p.workdir, confirm: p.intent_sha256, tokenFile: f.token });
  assert.equal(r.complete, true); assert(f.requests.find(c => c.payload).payload.equals(bytes));
});
