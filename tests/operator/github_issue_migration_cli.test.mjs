// Real CLI parsing, streams and signals; native migration execution is injected.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { main } from '../../scripts/migrate_github_issues.mjs';

const argv = ['run', '--workdir', '/private/migration', '--confirm', 'a'.repeat(64),
  '--url', 'https://forge.example/repository/', '--tenant', '1'.repeat(32), '--repository', '2'.repeat(32),
  '--token-file', '/private/token'];
function capture() {
  let text = '';
  const stream = new Writable({ write(chunk, _encoding, done) { text += chunk.toString(); done(); } });
  return { stream, json: () => JSON.parse(text), text: () => text };
}
function result(extra = {}) {
  return { type: 'github_issue_migration_progress', schema_version: 1, committed_observed: 2,
    mutation_calls: 2, mutation_count_complete: true, complete: true, batches: [], ...extra };
}
async function invoke(args = argv, execute = async () => result(), stdout) {
  const out = capture(), err = capture();
  const code = await main(args, { stdout: stdout ?? out.stream, stderr: err.stream, execute });
  return { code, out, err };
}

test('run forwards exact destination, pin and original custody, with explicit global controls', async () => {
  let received;
  const value = await invoke([...argv, '--max-mutations', '10000', '--timeout-ms', '3600000', '--retry-unresolved'], async o => {
    received = o; return result();
  });
  assert.equal(value.code, 0); assert.equal(value.err.text(), '');
  assert.equal(received.operation, 'run'); assert.equal(received.confirm, 'a'.repeat(64));
  assert.equal(received.workdir, '/private/migration'); assert.equal(received.tokenFile, '/private/token');
  assert.equal(received.maxMutations, 10000); assert.equal(received.timeoutMs, 3600000);
  assert.equal(received.retryUnresolved, true); assert.ok(received.signal instanceof AbortSignal);
  assert.equal(value.out.json().complete, true);
});

test('status sends no retry or mutation control and reports incomplete recovery separately', async () => {
  const value = await invoke(['status', ...argv.slice(1)], async o => {
    assert.equal(o.operation, 'status'); assert.equal(o.maxMutations, undefined); assert.equal(o.retryUnresolved, undefined);
    return result({ complete: false, mutation_calls: 0 });
  });
  assert.equal(value.code, 3); assert.equal(value.out.json().complete, false);
});

test('canonical refusal has its own exit without rewriting the returned progress', async () => {
  const r = result({ complete: false, batches: [{ stop_reason: 'terminal_refusal', refusal: { tx: 'original' } }] });
  const value = await invoke(argv, async () => r);
  assert.equal(value.code, 1); assert.deepEqual(value.out.json(), r);
});

for (const [name, args] of [
  ['missing arguments', ['run']], ['unknown operation', ['retry', ...argv.slice(1)]],
  ['duplicate flag', [...argv, '--confirm', 'b'.repeat(64)]], ['unknown flag', [...argv, '--force']],
  ['missing value', [...argv, '--timeout-ms']], ['zero timeout', [...argv, '--timeout-ms', '0']],
  ['large timeout', [...argv, '--timeout-ms', '3600001']], ['fractional budget', [...argv, '--max-mutations', '1.5']],
  ['large budget', [...argv, '--max-mutations', '10001']], ['signed budget', [...argv, '--max-mutations', '+2']],
  ['status retry', ['status', ...argv.slice(1), '--retry-unresolved']],
  ['status mutations', ['status', ...argv.slice(1), '--max-mutations', '1']],
  ['embedded newline', argv.map((v, i) => i === 2 ? '/private\nmigration' : v)],
  ['extra positional value', [...argv, 'false']]
]) test(`closed CLI grammar refuses ${name} before execution`, async () => {
  let calls = 0;
  const value = await invoke(args, async () => { calls++; return result(); });
  assert.equal(calls, 0); assert.equal(value.code, 2); assert.equal(value.err.json().absence_proves_non_commit, false);
});

test('SIGTERM cancels the owned invocation and removes only this command signal listeners', async () => {
  const term = process.listenerCount('SIGTERM'), interrupt = process.listenerCount('SIGINT');
  let calls = 0;
  const value = await invoke(argv, async o => {
    calls++; process.emit('SIGTERM'); assert.equal(o.signal.aborted, true); o.signal.throwIfAborted();
  });
  assert.equal(value.code, 3); assert.equal(calls, 1);
  assert.equal(process.listenerCount('SIGTERM'), term); assert.equal(process.listenerCount('SIGINT'), interrupt);
});

for (const [label, extra, expected] of [
  ['no mutation input failure', { committed_observed: 0, mutation_calls: 0 }, 2],
  ['known pending submission', { committed_observed: 0, mutation_calls: 1 }, 3],
  ['inexact submission count', { committed_observed: 0, mutation_calls: 0, mutation_count_complete: false }, 3],
  ['committed prefix then failure', { committed_observed: 1, mutation_calls: 1 }, 4]
]) test(`error retains ${label}`, async () => {
  const progress = result({ ...extra, complete: false });
  const value = await invoke(argv, async () => { const error = new Error('failed'); error.migration_progress = progress; throw error; });
  assert.equal(value.code, expected); assert.deepEqual(value.err.json().migration_progress, progress);
});

test('known terminal survives local receipt failure with exact batch and step coordinates', async () => {
  const terminal = { batch: 2, index: 7, outcome: 'committed', tx: 'original', rcr: 'decision' };
  const value = await invoke(argv, async () => {
    const error = new Error('receipt fsync failed'); error.migration_observed_terminal = terminal;
    error.migration_cleanup_error = 'owner close failed'; throw error;
  });
  assert.equal(value.code, 4); assert.deepEqual(value.err.json().observed_terminal, terminal);
  assert.equal(value.err.json().cleanup_error, 'owner close failed');
});

test('broken output preserves the complete result and does not execute again', async () => {
  const stream = new Writable({ write(_chunk, _encoding, done) { done(new Error('broken reader')); } });
  let calls = 0;
  const value = await invoke(argv, async () => { calls++; return result(); }, stream);
  assert.equal(value.code, 4); assert.equal(calls, 1); assert.equal(value.err.json().migration_progress.complete, true);
});

test('synchronously throwing output is bounded and preserves completed progress', async () => {
  const stream = new Writable(); stream.write = () => { throw new Error('synchronous output failure'); };
  const value = await invoke(argv, async () => result(), stream);
  assert.equal(value.code, 4); assert.equal(value.err.json().migration_progress.complete, true);
});

test('oversized output stops before emitting an unbounded record', async () => {
  const value = await invoke(argv, async () => result({ padding: 'x'.repeat(1024 * 1024) }));
  assert.equal(value.code, 4); assert.equal(value.out.text(), '');
});

test('the installed CLI help executes without loading native client dependencies', () => {
  const run = spawnSync(process.execPath, ['scripts/migrate_github_issues.mjs', '--help'], { encoding: 'utf8', timeout: 10000 });
  assert.equal(run.status, 0, run.stderr); assert.match(JSON.parse(run.stdout).usage, /run\|status/);
  assert.match(run.stdout, /NOT a cross-batch transaction/);
});
