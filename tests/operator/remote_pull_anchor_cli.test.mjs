// Real CLI processes retain exact source-comment requests against native-schema
// HTTP peers. These tests do not execute Rust source/permission admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, chmod, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { loadPullIntent, readPullRecord } from '../../scripts/operator/pull_files.mjs';
import { pullCanonical } from '../../scripts/operator/remote_pull.mjs';
import { TOKEN, ROTATED, input, commentAnchor, peer } from './remote_pull_fixture.mjs';

const CLI = resolve('scripts/remote_pull.mjs');
async function cli(t, args) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', completed = false;
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  t.after(() => { if (!completed) child.kill('SIGKILL'); });
  child.stdout.on('data', chunk => { out += chunk; if (out.length > 2 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', chunk => { err += chunk; if (err.length > 2 * 1024 * 1024) child.kill('SIGKILL'); });
  const [code, signal] = await once(child, 'close'); clearTimeout(timer); completed = true;
  return { code, signal, out, err };
}
async function prepared(t, p) {
  const root = await mkdtemp(join(tmpdir(), 'fg-pull-anchor-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const f = { root, token: join(root, 'token'), rotated: join(root, 'rotated'), input: join(root, 'input.json'),
    slot: join(root, 'request'), record: join(root, 'result.json') };
  const value = input(p.endpoint, p.intent.action, p.intent.scope.object_format);
  value.fields.anchor = commentAnchor(p.intent.scope.object_format);
  for (const [path, bytes] of [[f.token, TOKEN], [f.rotated, ROTATED], [f.input, pullCanonical(value)]]) {
    await writeFile(path, bytes, { mode: 0o600 });
  }
  const result = await cli(t, ['prepare', '--input', f.input, '--token-file', f.token, '--request-dir', f.slot]);
  assert.equal(result.code, 0, result.err); p.intent = await loadPullIntent(f.slot); return f;
}
const send = (f, intent, record = f.record) => ['send', '--request-dir', f.slot, '--token-file', f.token,
  '--confirm-key', intent.key, '--record', record];
const recover = (f, record) => ['recover', '--request-dir', f.slot, '--token-file', f.rotated, '--record', record];

for (const action of ['comment', 'append-comment']) test(`${action}: CLI retains raw source coordinates and rejects substituted known receipts before networking`, async t => {
  const p = await peer(t, { action, algorithm: 'sha256' }), f = await prepared(t, p);
  const saved = await readFile(join(f.slot, 'intent.json'));
  const inspected = await cli(t, ['inspect', '--request-dir', f.slot]);
  assert.equal(inspected.code, 0, inspected.err);
  assert.deepEqual(JSON.parse(inspected.out).intent.fields.anchor, commentAnchor('sha256'));
  assert.equal(p.requests.length, 0);
  const sent = await cli(t, send(f, p.intent)); assert.equal(sent.code, 0, sent.err);
  const record = await readPullRecord(f.record, p.intent);
  assert.equal(record.outcome.state, 'committed'); assert.equal(record.publication.anchor.byte_end, '7');
  assert.equal(record.publication.anchor.pull_request_version, '18446744073709551615');
  assert.equal(record.publication.comment_version, action === 'comment' ? '1' : null);
  const forged = structuredClone(record); forged.publication.anchor.path_hex = '6f74686572';
  const foreign = join(f.root, 'changed-source.json'), destination = join(f.root, 'must-not-exist.json');
  await writeFile(foreign, pullCanonical(forged), { mode: 0o600 });
  const calls = p.requests.length;
  const refused = await cli(t, [...send(f, p.intent, destination), '--known', foreign]);
  assert.equal(refused.code, 2, refused.err); assert.equal(p.requests.length, calls);
  await assert.rejects(lstat(destination), { code: 'ENOENT' });
  assert.deepEqual(await readFile(join(f.slot, 'intent.json')), saved);
  const recovered = await cli(t, [...recover(f, join(f.root, 'recovered.json')), '--known', f.record]);
  assert.equal(recovered.code, 0, recovered.err); assert.equal(p.requests.length, calls + 1);
  assert.equal(p.requests.at(-1).url, '/repo.git/api/v1/outcomes');
  assert.equal(p.requests.at(-1).headers.authorization, `Bearer ${ROTATED}`);
});
test('append-comment: a lost source-comment reply survives a fresh CLI process with the same immutable key', async t => {
  const p = await peer(t, { action: 'append-comment', handle(r, res, s) {
    if (!r.url.endsWith('/outcomes')) { s.published = true; res.destroy(); return true; }
  } }), f = await prepared(t, p), saved = await readFile(join(f.slot, 'intent.json'));
  const sent = await cli(t, send(f, p.intent)); assert.equal(sent.code, 3, sent.err);
  const uncertain = await readPullRecord(f.record, p.intent);
  assert.equal(uncertain.outcome, null); assert.equal(uncertain.publication, null); assert.equal(uncertain.dispatched, true);
  const destination = join(f.root, 'recovered.json');
  const result = await cli(t, [...recover(f, destination), '--known', f.record]);
  assert.equal(result.code, 0, result.err);
  assert.equal((await readPullRecord(destination, p.intent)).outcome.state, 'committed');
  assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
  assert.ok(p.requests.every(r => r.headers['idempotency-key'] === p.intent.key));
  assert.deepEqual(await readFile(join(f.slot, 'intent.json')), saved);
});
