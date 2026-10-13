// Real operator child process + real filesystem + loopback HTTP. The peer is
// explicit native-schema fixture data, not a Rust node or authority receipt.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { peer, json, TOKEN } from './source_context_fixtures.mjs';
import { symbolInput, nativeSymbols, FILES, DECLARATIONS } from './source_context_symbols_fixtures.mjs';
const cli = fileURLToPath(new URL('../../scripts/fg_source_context.mjs', import.meta.url));
export async function run(args) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [], err = []; let size = 0;
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  child.stdout.on('data', b => { out.push(b); if ((size += b.length) > 1000000) child.kill(); });
  child.stderr.on('data', b => { err.push(b); if ((size += b.length) > 1000000) child.kill(); });
  return new Promise((resolve, reject) => {
    child.once('error', e => { clearTimeout(timer); reject(e); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, out: Buffer.concat(out).toString(), err: Buffer.concat(err).toString() }); });
  });
}
async function privateInputs(t, q) {
  const root = await mkdtemp(join(tmpdir(), 'fg-symbol-export-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const query = join(root, 'query.json'), token = join(root, 'read-token');
  await writeFile(query, JSON.stringify(q), { mode: 0o600 });
  await writeFile(token, TOKEN + '\n', { mode: 0o600 });
  return { root, query, token, args: ['--query-file', query, '--token-file', token] };
}
for (const format of ['sha1', 'sha256']) test(`${format}: CLI capture and offline inspect retain symbol checkpoints and exact bytes`, async t => {
  const q = symbolInput(format), raw = nativeSymbols(q);
  q.minimum_symbol = { token: raw.retrieval.generation_vector.symbols.index_token, number: '4' };
  const p = await peer(t, (_req, res) => json(res, raw)), local = await privateInputs(t, q), bundle = join(local.root, 'capture');
  const captured = await run(['capture', '--endpoint', p.endpoint, ...local.args, '--output', bundle, '--require-complete']);
  assert.equal(captured.code, 0, captured.err); assert.equal(captured.err, '');
  const receipt = JSON.parse(captured.out);
  assert.equal(receipt.symbols.generation.number, '4'); assert.equal(receipt.symbols.state, 'available');
  assert.equal(receipt.lexical_checkpoint.number, '7'); assert.equal(receipt.authority_verified, false);
  const text = await readFile(join(bundle, 'context.txt'), 'utf8'), capture = await readFile(join(bundle, 'capture.json'), 'utf8');
  assert.match(text, /content\/path\/symbol context/); assert.match(text, /"symbol_query"/);
  assert.match(text, /"generation":\{"token":"alg:2:e+/); assert.equal((capture + text + captured.out).includes(TOKEN), false);
  assert.equal((await stat(join(bundle, 'capture.json'))).mode & 0o777, 0o600);
  const inspected = await run(['inspect', '--bundle', bundle, '--expected-sha256', receipt.manifest_sha256]);
  assert.equal(inspected.code, 0, inspected.err); assert.deepEqual(JSON.parse(inspected.out).symbols, receipt.symbols);
  assert.equal(p.calls.length, 1, 'inspection must not acquire or refresh source');
  assert.equal(new URLSearchParams(p.calls[0].body).get('minimum_symbol_number'), '4');
});

test('CLI optional missing symbols export partial receipts; require-complete leaves no bundle', async t => {
  const q = symbolInput('sha1', { symbols: { name: 'Recover', policy: 'optional' } });
  const raw = nativeSymbols(q, FILES, DECLARATIONS, 'stale'), p = await peer(t, (_req, res) => json(res, raw));
  const local = await privateInputs(t, q), bundle = join(local.root, 'partial');
  const partial = await run(['capture', '--endpoint', p.endpoint, ...local.args, '--output', bundle]);
  assert.equal(partial.code, 3, partial.err); assert.equal(JSON.parse(partial.out).symbols.reason, 'stale');
  assert.match(await readFile(join(bundle, 'context.txt'), 'utf8'), /"state":"unavailable","reason":"stale"/);
  const strictBundle = join(local.root, 'strict');
  const strict = await run(['capture', '--endpoint', p.endpoint, ...local.args, '--output', strictBundle, '--require-complete']);
  assert.equal(strict.code, 3, strict.err); assert.equal(JSON.parse(strict.out).exported, false);
  await assert.rejects(stat(strictBundle), { code: 'ENOENT' }); assert.equal(p.calls.length, 2);
});

test('corrupt symbol evidence never writes a local success marker or retries', async t => {
  const q = symbolInput(), raw = nativeSymbols(q); raw.retrieval.symbols.result.matches[0].blob = 'f'.repeat(40);
  const local = await privateInputs(t, q), bundle = join(local.root, 'rejected'), p = await peer(t, (_req, res) => json(res, raw));
  const result = await run(['capture', '--endpoint', p.endpoint, ...local.args, '--output', bundle]);
  assert.equal(result.code, 2); assert.equal(result.out, ''); assert.equal(result.err.includes(TOKEN), false);
  await assert.rejects(stat(bundle), { code: 'ENOENT' }); assert.equal(p.calls.length, 1);
});
