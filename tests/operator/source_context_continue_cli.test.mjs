// Actual CLI child processes and private bundles; the network peer is explicit.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_source_context.mjs';
import { inspectBundle } from '../../scripts/operator/source_context_export.mjs';
import { fixture, input, TOKEN } from './source_context_continue_fixtures.mjs';
import { hex } from './source_context_fixtures.mjs';
const CLI = new URL('../../scripts/fg_source_context.mjs', import.meta.url).pathname;
const exists = path => lstat(path).then(() => true, e => { if (e.code === 'ENOENT') return false; throw e; });
function child(args) {
  const process = spawn(globalThis.process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  process.stdout.on('data', b => { stdout += b; }); process.stderr.on('data', b => { stderr += b; });
  return { process, done: new Promise((resolve, reject) => {
    process.once('error', reject); process.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  }) };
}
async function setup(t, q = input(), delta = { terms: ['untrusted'] }, settings = {}) {
  const f = await fixture(t, q, settings), tokenFile = join(f.root, 'token'), followupFile = join(f.root, 'followup.json'), output = join(f.root, 'next');
  await writeFile(tokenFile, TOKEN + '\n', { mode: 0o600 });
  await writeFile(followupFile, JSON.stringify(delta), { mode: 0o600 });
  return { ...f, tokenFile, followupFile, output, args: ['continue', '--bundle', f.bundle, '--expected-sha256', f.receipt.manifest_sha256,
    '--followup-file', followupFile, '--token-file', tokenFile, '--output', output] };
}
for (const format of ['sha1', 'sha256']) test(`${format}: continue CLI produces a separately inspectable pinned capture`, async t => {
  const f = await setup(t, input(format)), run = await child(f.args).done;
  assert.equal(run.code, 0, run.stderr);
  const receipt = JSON.parse(run.stdout), data = JSON.parse(await readFile(join(f.output, 'capture.json'), 'utf8'));
  assert.equal(receipt.continued_from.manifest_sha256, f.receipt.manifest_sha256);
  assert.equal(receipt.continued_from.capture_sha256, f.receipt.capture_sha256);
  assert.equal(data.summary.query.expected_head, f.capture.summary.source.snapshot_token);
  assert.equal(data.summary.query.minimum_lexical.number, '7');
  assert.deepEqual(data.summary.query.terms, ['untrusted']);
  const reopened = await child(['inspect', '--bundle', f.output, '--expected-sha256', receipt.manifest_sha256]).done;
  assert.equal(reopened.code, 0, reopened.stderr); assert.equal(f.p.calls.length, 1);
  assert.deepEqual(await f.readParent(), f.originalBytes);
  assert.ok(!run.stdout.includes(TOKEN)); assert.ok(!JSON.stringify(data).includes(TOKEN));
});

test('legacy capture and inspect remain usable with the same CLI', async t => {
  const f = await setup(t), queryFile = join(f.root, 'query.json');
  await writeFile(queryFile, JSON.stringify(input()), { mode: 0o600 });
  const run = await child(['capture', '--endpoint', f.p.endpoint, '--query-file', queryFile,
    '--token-file', f.tokenFile, '--output', f.output]).done;
  assert.equal(run.code, 0, run.stderr); const result = JSON.parse(run.stdout);
  assert.equal(Object.hasOwn(result, 'continued_from'), false);
  assert.equal((await inspectBundle(f.output, result.manifest_sha256)).complete, true);
});

for (const extra of [['--endpoint', 'https://different.invalid/repo'], ['--query-file', '/private/query'],
  ['--expected-sha256', 'f'.repeat(64)], ['--token', TOKEN], ['--force']]) {
  test(`CLI refuses redirected control ${extra[0]} before network work`, async t => {
    const f = await setup(t), run = await child([...f.args, ...extra]).done;
    assert.equal(run.code, 2); assert.equal(f.p.calls.length, 0); assert.equal(await exists(f.output), false);
  });
}
for (const suffix of ['', '/nested']) test(`output cannot modify the prior bundle directory: ${suffix}`, async t => {
  const f = await setup(t), args = f.args.slice(); args[args.indexOf('--output') + 1] = f.bundle + suffix;
  const run = await child(args).done;
  assert.equal(run.code, 2); assert.match(run.stderr, /output_inside_prior_bundle/);
  assert.equal(f.p.calls.length, 0); assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('require-complete refuses the new partial export without damaging the earlier partial evidence', async t => {
  const q = input('sha1', { limits: { context_max_files: 1 } });
  const files = [{ path: Buffer.from('a'), bytes: Buffer.from('recover') }, { path: Buffer.from('b'), bytes: Buffer.from('recover') }];
  const f = await setup(t, q, { terms: ['recover'] }, { files });
  const run = await child([...f.args, '--require-complete']).done;
  assert.equal(run.code, 3, run.stderr); const result = JSON.parse(run.stdout);
  assert.equal(result.exported, false); assert.equal(result.continued_from.manifest_sha256, f.receipt.manifest_sha256);
  assert.equal(await exists(f.output), false); assert.deepEqual(await f.readParent(), f.originalBytes);
  const accepted = await child(f.args).done;
  assert.equal(accepted.code, 3, accepted.stderr); assert.equal(await exists(join(f.output, 'manifest.json')), true);
});

test('widening and stale-source refusals never create a new export', async t => {
  const f = await setup(t, input('sha1', { prefixes_hex: [hex('src')] }), { terms: ['recover'], prefixes_hex: [] });
  let run = await child(f.args).done;
  assert.equal(run.code, 2); assert.match(run.stderr, /scope_widened/); assert.equal(f.p.calls.length, 0);
  await writeFile(f.followupFile, JSON.stringify({ terms: ['recover'] })); f.state.status = 409;
  run = await child(f.args).done;
  assert.equal(run.code, 2); assert.equal(f.p.calls.length, 1); assert.equal(await exists(f.output), false);
  assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('stdout failure preserves both receipts and the successfully written child bundle', async t => {
  const f = await setup(t); let errors = '';
  const stdout = new Writable({ write(_b, _e, done) { done(new Error('stdout failed')); } });
  const stderr = new Writable({ write(b, _e, done) { errors += b; done(); } });
  assert.equal(await main(f.args, { stdout, stderr }), 4);
  const result = JSON.parse(errors).retained_export;
  assert.equal(result.continued_from.manifest_sha256, f.receipt.manifest_sha256);
  assert.equal((await inspectBundle(f.output, result.manifest_sha256)).complete, true);
  assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('SIGTERM drains a follow-up without exporting a prefix or erasing the parent', async t => {
  const f = await setup(t); f.state.hang = true;
  const ready = new Promise(resolve => { f.state.started = resolve; });
  const run = child(f.args);
  t.after(() => { if (run.process.exitCode === null && run.process.signalCode === null) run.process.kill('SIGKILL'); });
  await ready; run.process.kill('SIGTERM'); const result = await run.done;
  assert.equal(result.code, 2, result.stderr); assert.equal(f.p.calls.length, 1);
  assert.equal(await exists(f.output), false); assert.deepEqual(await f.readParent(), f.originalBytes);
});
