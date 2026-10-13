// Operator processes, sockets and real private bundles; the peer is explicit
// native-schema data, not the Rust server or independently verified authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '../../scripts/operator/source_context.mjs';
import { inspectBundle } from '../../scripts/operator/source_context_export.mjs';
import { peer, json, TOKEN } from './source_context_fixtures.mjs';
import { symbolInput, assemble } from './source_context_symbols_fixtures.mjs';
import { nativeRanked, PROFILE, CORPUS, oracle, hex } from './source_context_ranking_fixtures.mjs';
const cli = fileURLToPath(new URL('../../scripts/fg_source_context.mjs', import.meta.url));
async function run(args) {
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
async function local(t, q) {
  const root = await mkdtemp(join(tmpdir(), 'fg-rank-export-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const query = join(root, 'query.json'), token = join(root, 'token');
  await writeFile(query, JSON.stringify(q), { mode: 0o600 }); await writeFile(token, TOKEN + '\n', { mode: 0o600 });
  return { root, query, token, args: ['--query-file', query, '--token-file', token] };
}
for (const format of ['sha1', 'sha256']) test(`${format}: ranked CLI text uses recomputed priority while capture retains raw source order`, async t => {
  const q = symbolInput(format, { selection: PROFILE }), raw = nativeRanked(q), inputs = await local(t, q);
  const p = await peer(t, (_req, res) => json(res, raw)), output = join(inputs.root, 'result');
  const captured = await run(['capture', '--endpoint', p.endpoint, ...inputs.args, '--output', output, '--require-complete']);
  assert.equal(captured.code, 0, captured.err); const receipt = JSON.parse(captured.out);
  assert.equal(receipt.selection, PROFILE); assert.equal(receipt.symbols.generation.number, '4');
  const capture = JSON.parse(await readFile(join(output, 'capture.json'), 'utf8'));
  assert.deepEqual(capture.native_response.files.map(f => f.path_hex), CORPUS.map(f => hex(f.path)));
  assert.deepEqual(capture.summary.ranking.selected.map(f => f.path_hex), CORPUS.toReversed().map(f => hex(f.path)));
  const text = await readFile(join(output, 'context.txt'), 'utf8');
  const objects = text.trimEnd().split('\n').slice(3).map(line => JSON.parse(line));
  const files = objects.filter(value => Object.hasOwn(value, 'anchors'));
  assert.deepEqual(files.map(f => f.path_hex), CORPUS.toReversed().map(f => hex(f.path)));
  const ranking = objects.find(value => Object.hasOwn(value, 'ranking')).ranking;
  assert.equal(ranking.selected[0].score_q16, 4279); assert.equal(ranking.semantic_relevance, false);
  assert.equal((text + captured.out + JSON.stringify(capture)).includes(TOKEN), false);
  await rm(inputs.token); await rm(inputs.query);
  const before = p.calls.length;
  const inspected = await run(['inspect', '--bundle', output, '--expected-sha256', receipt.manifest_sha256]);
  assert.equal(inspected.code, 0, inspected.err); assert.equal(JSON.parse(inspected.out).selection, PROFILE);
  assert.equal(JSON.parse(inspected.out).manifest_sha256, receipt.manifest_sha256);
  assert.equal(p.calls.length, before);
});

test('ranked partial capture and require-complete retain file-selection omissions', async t => {
  const q = symbolInput('sha1', { selection: PROFILE, limits: { context_max_files: 1 } }), raw = nativeRanked(q);
  const p = await peer(t, (_req, res) => json(res, raw)), inputs = await local(t, q), strict = join(inputs.root, 'strict');
  const refused = await run(['capture', '--endpoint', p.endpoint, ...inputs.args, '--output', strict, '--require-complete']);
  assert.equal(refused.code, 3, refused.err); assert.equal(JSON.parse(refused.out).exported, false);
  await assert.rejects(stat(strict), { code: 'ENOENT' });
  const partial = join(inputs.root, 'partial'), captured = await run(['capture', '--endpoint', p.endpoint, ...inputs.args, '--output', partial]);
  assert.equal(captured.code, 3, captured.err); const receipt = JSON.parse(captured.out);
  assert.equal(receipt.omitted_files, 1); assert.equal(receipt.selection, PROFILE);
  const stored = JSON.parse(await readFile(join(partial, 'capture.json'), 'utf8'));
  assert.equal(stored.summary.ranking.selected[0].path_hex, hex('z/Recover.rs'));
  const inspected = await run(['inspect', '--bundle', partial, '--expected-sha256', receipt.manifest_sha256]);
  assert.equal(inspected.code, 3, inspected.err); assert.equal(JSON.parse(inspected.out).omitted_files, 1);
});

test('a self-consistent lower-ranked substitute cannot produce a bundle or trigger a fallback request', async t => {
  const q = symbolInput('sha1', { selection: PROFILE, limits: { context_max_files: 1 } }), raw = nativeRanked(q);
  const wrong = oracle(raw.retrieval)[1]; assemble(raw, q, CORPUS, [wrong.path_hex]);
  raw.ranking.selected = [{ position: 1, ...wrong }];
  const p = await peer(t, (_req, res) => json(res, raw)), inputs = await local(t, q), output = join(inputs.root, 'bad');
  const result = await run(['capture', '--endpoint', p.endpoint, ...inputs.args, '--output', output]);
  assert.equal(result.code, 2); assert.match(result.err, /context_ranking_selection_changed/);
  assert.equal(result.out, ''); await assert.rejects(stat(output), { code: 'ENOENT' });
  assert.equal(p.calls.length, 1); assert.equal(new URLSearchParams(p.calls[0].body).get('context_selection'), PROFILE);
});

test('offline inspection reruns score verification even with a supplied pin to a rewritten local manifest', async t => {
  const q = symbolInput('sha256', { selection: PROFILE }), raw = nativeRanked(q), inputs = await local(t, q);
  const p = await peer(t, (_req, res) => json(res, raw)), output = join(inputs.root, 'valid');
  const captured = await run(['capture', '--endpoint', p.endpoint, ...inputs.args, '--output', output]);
  assert.equal(captured.code, 0, captured.err);
  const bytes = JSON.parse(await readFile(join(output, 'capture.json'), 'utf8'));
  bytes.native_response.ranking.selected[0].score_q16++;
  bytes.summary.ranking.selected[0].score_q16++;
  const changed = Buffer.from(JSON.stringify(bytes) + '\n');
  await writeFile(join(output, 'capture.json'), changed);
  const manifest = JSON.parse(await readFile(join(output, 'manifest.json'), 'utf8'));
  manifest.files[0].bytes = changed.length; manifest.files[0].sha256 = sha256(changed);
  const replaced = Buffer.from(JSON.stringify(manifest) + '\n'); await writeFile(join(output, 'manifest.json'), replaced);
  // Deliberately supply the NEW pin to exercise semantic revalidation beyond
  // the separately tested original-manifest integrity check.
  await assert.rejects(inspectBundle(output, sha256(replaced)), /ranking_selection_changed/);
  assert.equal(p.calls.length, 1);
});
