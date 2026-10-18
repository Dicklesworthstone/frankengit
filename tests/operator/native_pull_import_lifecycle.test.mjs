import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { writeFile, readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main } from '../../scripts/migrate_native_pulls.mjs';
import { importFixture, row } from './native-pull-import-fixture.mjs';
const script = fileURLToPath(new URL('../../scripts/migrate_native_pulls.mjs', import.meta.url));
function child(t, args) {
  const proc = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL'); });
  return { proc, done: new Promise((resolve, reject) => {
    let out = '', err = ''; const timer = setTimeout(() => { proc.kill('SIGKILL'); reject(new Error('CLI test deadline')); }, 20000);
    proc.stdout.on('data', b => { out += b; if (out.length > 2 * 1024 * 1024) proc.kill('SIGKILL'); });
    proc.stderr.on('data', b => { err += b; if (err.length > 2 * 1024 * 1024) proc.kill('SIGKILL'); });
    proc.on('error', e => { clearTimeout(timer); reject(e); });
    proc.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, out, err }); });
  }) };
}
function value(result, code = 0) {
  assert.equal(result.code, code, result.err); assert.equal(result.signal, null); assert.equal(result.err, ''); return JSON.parse(result.out);
}
async function prepared(t, settings = {}) {
  const f = await importFixture(t, settings), selection = join(f.root, 'selection.json');
  await writeFile(selection, JSON.stringify(f.selection), { mode: 0o600 });
  const p = value(await child(t, ['prepare', '--archive-dir', f.archiveDir, '--archive-confirm', f.archiveConfirm,
    '--selection', selection, '--token-file', f.tokenFile, '--workdir', f.workdir]).done);
  const args = operation => [operation, '--workdir', f.workdir, '--confirm', p.plan_sha256];
  const network = (operation = 'run') => [...args(operation), '--token-file', f.tokenFile];
  return { ...f, prepared: p, args, network };
}
const sends = f => f.requests.filter(r => r.path.startsWith('/dest/') && !r.path.endsWith('/outcomes'));
test('real process batches, status, recovery and completed offline execution', async t => {
  const f = await prepared(t);
  const paused = value(await child(t, [...f.network(), '--max-operations', '2']).done, 3);
  assert.equal(paused.committed_steps, 2); assert.equal(paused.state, 'ready');
  const count = f.requests.length;
  const status = value(await child(t, f.args('status')).done); assert.equal(status.journal_sha256, paused.journal_sha256);
  const nothing = value(await child(t, f.args('recover')).done, 3); assert.equal(nothing.new_operations, 0); assert.equal(f.requests.length, count);
  assert.equal(value(await child(t, f.network()).done).complete, true); assert.equal(sends(f).length, 11);
  await unlink(f.tokenFile); assert.equal(value(await child(t, f.args('run')).done).complete, true);
});
for (const signal of ['SIGTERM', 'SIGINT', 'SIGKILL']) test(`fresh process recovers after ${signal} during a committed response`, async t => {
  let block = false, proc;
  const f = await prepared(t, { mutate: (request, res) => {
    if (block && request.path.endsWith('/open')) { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{');
      assert(proc.kill(signal)); return false; }
  } });
  const firstIntent = await readFile(join(f.workdir, 'requests', 'step-000001', 'intent.json'));
  block = true; const pending = child(t, f.network()); proc = pending.proc; const stopped = await pending.done;
  if (signal === 'SIGKILL') { assert.equal(stopped.signal, 'SIGKILL'); assert.equal(stopped.out, ''); }
  else { const result = value(stopped, 3); assert.equal(result.state, 'pending'); }
  block = false;
  const status = value(await child(t, f.args('status')).done); assert.equal(status.state, 'pending'); assert.equal(status.current.action, 'open');
  assert.equal(value(await child(t, f.network()).done).complete, true);
  assert.equal(sends(f).length, 11); assert.equal(new Set(sends(f).map(r => r.key)).size, 11);
  assert((await readFile(join(f.workdir, 'requests', 'step-000001', 'intent.json'))).equals(firstIntent));
});
test('CLI exposes explicit retry only for the retained pending key', async t => {
  let drop = true;
  const f = await prepared(t, { beforeDestination: ({ request, req }) => { if (drop && request.path.endsWith('/open')) { req.socket.destroy(); return false; } } });
  const first = value(await child(t, f.network()).done, 3);
  value(await child(t, f.network()).done, 3); assert.equal(sends(f).length, 1);
  drop = false;
  const done = value(await child(t, [...f.network(), '--retry-key', first.current.key]).done); assert.equal(done.complete, true);
  assert.equal(sends(f).length, 12); assert.equal(sends(f)[0].key, sends(f)[1].key);
});
test('native refusal has its own CLI exit code and stops successors', async t => {
  const f = await prepared(t, { refuse: ({ action }) => action === 'open' });
  const result = value(await child(t, f.network()).done, 1); assert.equal(result.state, 'refused'); assert.equal(sends(f).length, 1);
});
test('closed stdout retains native outcomes and repeated execution does not resend', async t => {
  const f = await prepared(t); let errors = '';
  const stdout = new Writable({ write(_c, _e, callback) { callback(new Error('broken pipe')); } });
  const stderr = new Writable({ write(c, _e, callback) { errors += c; callback(); } });
  assert.equal(await main(f.network(), { stdout, stderr }), 4);
  const retained = JSON.parse(errors).retained_result; assert.equal(retained.complete, true);
  const count = f.requests.length; assert.equal(value(await child(t, f.args('run')).done).complete, true); assert.equal(f.requests.length, count);
});
test('command argument refusal cannot authorize retry or override the sealed destination', async t => {
  const f = await prepared(t), count = f.requests.length;
  for (const args of [
    [...f.network(), '--max-operations', '0'], [...f.network(), '--max-operations', '1e2'],
    [...f.network(), '--max-operations', '01'], [...f.network(), '--max-operations', '8193'],
    [...f.network(), '--endpoint', 'http://127.0.0.1/other'],
    [...f.network('recover'), '--retry-key', 'original'], [...f.args('status'), '--token-file', f.tokenFile],
  ]) { const result = await child(t, args).done; assert.equal(result.code, 2); assert.equal(result.out, ''); }
  assert.equal(f.requests.length, count);
});
