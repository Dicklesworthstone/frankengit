// Real child processes and owner-private files. Explicit native-schema socket
// peers supply object bytes; no Rust node or authenticated-head proof is faked.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { mkdtemp, writeFile, readFile, lstat, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from '../../scripts/fg_context_proof.mjs';
import { inspectContextProof } from '../../scripts/operator/source_context_proof.mjs';
import { sha256 } from '../../scripts/operator/source_archive.mjs';
import { setup, bytes, token } from './source_context_proof_fixtures.mjs';
const cli = new URL('../../scripts/fg_context_proof.mjs', import.meta.url).pathname;
function child(args) {
  const process = spawn(globalThis.process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  process.stdout.on('data', b => stdout += b); process.stderr.on('data', b => stderr += b);
  return { process, done: new Promise((resolve, reject) => { process.once('error', reject); process.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); }) };
}
async function fixture(t, format = 'sha1') {
  const f = await setup(t, format), root = await mkdtemp(join(tmpdir(), 'fg-context-proof-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const selection = join(root, 'selection.json'), context = join(root, 'capture.json'), credential = join(root, 'token'), output = join(root, 'proof.json');
  const data = bytes({ schema: 'frankengit-source-context-capture-v1', endpoint: f.selection.endpoint, native_response: f.context });
  await writeFile(selection, bytes(f.selection), { mode: 0o600 }); await writeFile(context, data, { mode: 0o600 });
  await writeFile(credential, token + '\n', { mode: 0o600 });
  const common = ['--selection', selection, '--context', context, '--context-sha256', sha256(data)];
  return { ...f, root, selectionFile: selection, contextFile: context, credential, output, data, common,
    args: ['capture', ...common, '--token-file', credential, '--output', output] };
}
const exists = path => lstat(path).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
for (const format of ['sha1', 'sha256']) test(`${format}: capture publishes proof, inspect needs only independently pinned files`, async t => {
  const f = await fixture(t, format), run = await child(f.args).done;
  assert.equal(run.code, 0, run.stderr); const result = JSON.parse(run.stdout);
  assert.equal(result.verified_file_count, 2); assert.equal(result.selected_path_membership_verified, true);
  assert.equal(result.authority_verified, false); assert.equal(result.search_evidence_verified, false);
  assert.equal((await lstat(f.output)).mode & 0o777, 0o600);
  const proof = await readFile(f.output); assert.ok(!proof.includes(token));
  await rm(f.credential); const calls = f.calls.length;
  const inspect = await child(['inspect', ...f.common, '--proof', f.output, '--proof-sha256', result.proof_sha256]).done;
  assert.equal(inspect.code, 0, inspect.stderr); assert.equal(f.calls.length, calls);
  assert.equal(JSON.parse(inspect.stdout).proof_sha256, result.proof_sha256);
  assert.equal(inspectContextProof(proof, result.proof_sha256, f.data, sha256(f.data), f.selection).verified_files.length, 2);
  assert.deepEqual(await readFile(f.contextFile), f.data);
});
test('existing output, wrong context hash, unsafe credential and symlink refuse without connecting', async t => {
  const f = await fixture(t); await writeFile(f.output, 'preserved', { mode: 0o600 });
  assert.equal((await child(f.args).done).code, 2); assert.equal(await readFile(f.output, 'utf8'), 'preserved'); await rm(f.output);
  const wrong = f.args.map(a => a === sha256(f.data) ? '0'.repeat(64) : a);
  assert.equal((await child(wrong).done).code, 2);
  await chmod(f.credential, 0o644); assert.equal((await child(f.args).done).code, 2); await chmod(f.credential, 0o600);
  const alias = join(f.root, 'alias'); await symlink(f.credential, alias);
  assert.equal((await child(f.args.map(a => a === f.credential ? alias : a)).done).code, 2);
  assert.equal(f.calls.length, 0); assert.equal(await exists(f.output), false);
});
test('corrupted proof or saved context fails offline even when the other input is intact', async t => {
  const f = await fixture(t), run = await child(f.args).done; assert.equal(run.code, 0, run.stderr);
  const r = JSON.parse(run.stdout), proof = await readFile(f.output), args = ['inspect', ...f.common, '--proof', f.output, '--proof-sha256', r.proof_sha256];
  const calls = f.calls.length;
  await writeFile(f.output, '{}'); assert.equal((await child(args).done).code, 2);
  await writeFile(f.output, proof); await writeFile(f.contextFile, '{}'); assert.equal((await child(args).done).code, 2);
  assert.equal(f.calls.length, calls);
});
test('independent native commit cannot be replaced by the context file or command controls', async t => {
  const f = await fixture(t); await writeFile(f.selectionFile, bytes({ ...f.selection, expected_commit: 'e'.repeat(40) }));
  assert.equal((await child(f.args).done).code, 2); assert.equal(f.calls.length, 0);
  for (const extra of [['--force', 'true'], ['--token', token], ['--endpoint', f.selection.endpoint], ['--context-sha256', sha256(f.data)]]) {
    assert.equal((await child([...f.args, ...extra]).done).code, 2);
  }
  const inspect = ['inspect', ...f.common, '--proof', f.output, '--proof-sha256', 'e'.repeat(64), '--token-file', f.credential];
  assert.equal((await child(inspect).done).code, 2); assert.equal(f.calls.length, 0);
});
test('failed source verification and insufficient full-blob budget never publish a successful prefix', async t => {
  const f = await fixture(t); f.control.mutate = (value, call) => { if (call.operation === 'blob') value.content_hex += 'ff'; };
  assert.equal((await child(f.args).done).code, 2); assert.equal(await exists(f.output), false);
  f.control.mutate = undefined; const limits = join(f.root, 'limits.json');
  await writeFile(limits, bytes({ maxTotalBlobBytes: 1 }), { mode: 0o600 });
  assert.equal((await child([...f.args, '--limits', limits]).done).code, 2); assert.equal(await exists(f.output), false);
});
test('concurrent exporters cannot replace or combine each other', async t => {
  const f = await fixture(t), results = await Promise.all([child(f.args).done, child(f.args).done]);
  assert.equal(results.filter(r => r.code === 0).length, 1);
  const receipt = JSON.parse(results.find(r => r.code === 0).stdout), proof = await readFile(f.output);
  assert.equal(inspectContextProof(proof, receipt.proof_sha256, f.data, sha256(f.data), f.selection).verified_files.length, 2);
});
test('broken stdout retains the published proof and a bounded inspection receipt', async t => {
  const f = await fixture(t); let diagnostics = '';
  const stdout = new Writable({ write(_bytes, _encoding, done) { done(new Error('stdout closed')); } });
  const stderr = new Writable({ write(bytes, _encoding, done) { diagnostics += bytes; done(); } });
  assert.equal(await main(f.args, { stdout, stderr }), 4);
  const result = JSON.parse(diagnostics).retained_receipt;
  assert.equal(result.verified_file_count, 2);
  const proof = await readFile(f.output); assert.equal(sha256(proof), result.proof_sha256);
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`${signal} during acquisition leaves original input and no proof output`, async t => {
  const f = await fixture(t); let observe; const observed = new Promise(resolve => observe = resolve);
  f.control.respond = (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); observe(); };
  const running = child(f.args); t.after(() => { if (running.process.exitCode === null && running.process.signalCode === null) running.process.kill('SIGKILL'); });
  await observed; running.process.kill(signal); const result = await running.done;
  if (signal === 'SIGTERM') assert.equal(result.code, 3, result.stderr); else assert.equal(result.signal, signal);
  assert.equal(f.calls.length, 1); assert.equal(await exists(f.output), false); assert.deepEqual(await readFile(f.contextFile), f.data);
});
test('one explicit deadline bounds the multi-request proof acquisition', async t => {
  const f = await fixture(t), limits = join(f.root, 'limits.json');
  await writeFile(limits, bytes({ timeoutMs: 90 }), { mode: 0o600 });
  f.control.mutate = () => new Promise(resolve => setTimeout(resolve, 50));
  const result = await child([...f.args, '--limits', limits]).done;
  assert.equal(result.code, 2, result.stderr); assert.equal(await exists(f.output), false); assert.ok(f.calls.length <= 2);
});
