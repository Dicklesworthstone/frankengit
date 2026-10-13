// Real operator processes and private files against explicit native HTTP peers.
// This is not an fg/Rust engine, repository durability or native policy suite.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, chmod, mkdir, readdir, lstat, symlink, link, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { run } from '../../scripts/remote_pull.mjs';
import { loadPullIntent, savePullIntent, readPullPrivate, pullRecord, validatePullRecord, readPullRecord,
  savePullRecord, checkPullRecordDestination } from '../../scripts/operator/pull_files.mjs';
import { pullCanonical, preparePull } from '../../scripts/operator/remote_pull.mjs';
import { PULL_ACTIONS } from '../../scripts/operator/pull_command.mjs';
import { TOKEN, ROTATED, input, peer, publication, outcome, respond } from './remote_pull_fixture.mjs';
const CLI = resolve('scripts/remote_pull.mjs');
async function files(t, value) {
  const root = await mkdtemp(join(tmpdir(), 'fg-remote-pull-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const paths = { root, token: join(root, 'token'), rotated: join(root, 'rotated'), input: join(root, 'input.json'),
    slot: join(root, 'request'), record: join(root, 'result.json') };
  for (const [file, bytes] of [[paths.token, TOKEN + '\n'], [paths.rotated, ROTATED], [paths.input, pullCanonical(value)]]) {
    await writeFile(file, bytes, { mode: 0o600 });
  }
  return paths;
}
function launch(t, args, { brokenOutput = false } = {}) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', completed = false;
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  t.after(() => { if (!completed) child.kill('SIGKILL'); });
  if (brokenOutput) child.stdout.destroy();
  else child.stdout.on('data', chunk => { out += chunk; if (out.length > 2 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', chunk => { err += chunk; if (err.length > 2 * 1024 * 1024) child.kill('SIGKILL'); });
  const result = once(child, 'close').then(([code, signal]) => { clearTimeout(timer); completed = true; return { code, signal, out, err }; });
  return { child, result };
}
const cli = (t, args, options) => launch(t, args, options).result;
const prepArgs = f => ['prepare', '--input', f.input, '--token-file', f.token, '--request-dir', f.slot];
const sendArgs = (f, intent, record = f.record) => ['send', '--request-dir', f.slot, '--token-file', f.token,
  '--confirm-key', intent.key, '--record', record, ...(intent.action === 'fast-forward' ? ['--fast-forward-only'] : [])];
const recoveryArgs = (f, record = f.record) => ['recover', '--request-dir', f.slot, '--token-file', f.rotated, '--record', record];
async function prepared(t, p) {
  const f = await files(t, input(p.endpoint, p.intent.action, p.intent.scope.object_format));
  const result = await cli(t, prepArgs(f)); assert.equal(result.code, 0, result.err);
  p.intent = await loadPullIntent(f.slot); return f;
}
for (const action of PULL_ACTIONS) test(`${action}: prepare/inspect/send/recover with real processes`, async t => {
  const p = await peer(t, { action }), f = await prepared(t, p);
  assert.equal(p.requests.length, 0);
  const inspected = await cli(t, ['inspect', '--request-dir', f.slot]);
  assert.equal(inspected.code, 0, inspected.err); assert.deepEqual(JSON.parse(inspected.out).intent, p.intent);
  const sent = await cli(t, sendArgs(f, p.intent)); assert.equal(sent.code, 0, sent.err);
  const record = await readPullRecord(f.record, p.intent); assert.equal(record.outcome.state, 'committed');
  assert.equal(record.outcome.decision.decision_sequence, '18446744073709551615');
  assert.equal((await lstat(f.slot)).mode & 0o777, 0o700);
  assert.equal((await lstat(f.record)).mode & 0o777, 0o600);
  assert.equal((await lstat(f.record)).nlink, 1);
  const again = await cli(t, [...sendArgs(f, p.intent, join(f.root, 'again.json')), '--known', f.record]);
  assert.equal(again.code, 0, again.err); assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
  const recovered = await cli(t, [...recoveryArgs(f, join(f.root, 'rotated.json')), '--known', f.record]);
  assert.equal(recovered.code, 0, recovered.err);
  assert.equal(p.requests.at(-1).headers.authorization, `Bearer ${ROTATED}`);
});
test('SHA-256 fast-forward retains exact tips and version in saved intent and receipt', async t => {
  const p = await peer(t, { action: 'fast-forward', algorithm: 'sha256' }), f = await prepared(t, p);
  const sent = await cli(t, sendArgs(f, p.intent)); assert.equal(sent.code, 0, sent.err);
  const record = await readPullRecord(f.record, p.intent);
  assert.equal(record.publication.source_tip, `sha256:${p.intent.fields.source_tip}`);
  assert.equal(record.publication.pull_request_version, p.intent.fields.pull_request_version);
});
test('a canonical refusal exits 1 and retains its exact evidence', async t => {
  const p = await peer(t, { state: 'refused' }), f = await prepared(t, p);
  const result = await cli(t, sendArgs(f, p.intent)); assert.equal(result.code, 1, result.err);
  assert.equal((await readPullRecord(f.record, p.intent)).outcome.decision.code, 'PolicyDenied');
});
test('lost reply persists unknown status and later recovers without another mutation', async t => {
  const p = await peer(t, { handle(r, res, s) { if (!r.url.endsWith('/outcomes')) { s.published = true; res.destroy(); return true; } } });
  const f = await prepared(t, p), original = await readFile(join(f.slot, 'intent.json'));
  const sent = await cli(t, sendArgs(f, p.intent)); assert.equal(sent.code, 3, sent.err);
  const uncertain = await readPullRecord(f.record, p.intent); assert.equal(uncertain.outcome, null); assert.equal(uncertain.dispatched, true);
  const recovered = await cli(t, [...recoveryArgs(f, join(f.root, 'recovered.json')), '--known', f.record]);
  assert.equal(recovered.code, 0, recovered.err); assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
  assert.deepEqual(await readFile(join(f.slot, 'intent.json')), original);
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`${signal} during publication preserves identity for restart recovery`, async t => {
  let admitted; const reached = new Promise(resolve => admitted = resolve);
  const p = await peer(t, { action: 'fast-forward', handle(r, res, s) {
    if (!r.url.endsWith('/outcomes')) { s.published = true; admitted(); return true; }
  } });
  const f = await prepared(t, p), saved = await readFile(join(f.slot, 'intent.json'));
  const started = launch(t, sendArgs(f, p.intent)); await reached; started.child.kill(signal);
  const terminated = await started.result;
  if (signal === 'SIGTERM') assert.equal(terminated.code, 3, terminated.err); else assert.equal(terminated.signal, signal);
  const recovered = await cli(t, recoveryArgs(f, join(f.root, 'restart.json'))); assert.equal(recovered.code, 0, recovered.err);
  assert.deepEqual(await readFile(join(f.slot, 'intent.json')), saved);
  assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
});
test('closed stdout after commit leaves a complete result record and exits nonzero', async t => {
  const p = await peer(t, { action: 'comment' }), f = await prepared(t, p);
  const sent = await cli(t, sendArgs(f, p.intent), { brokenOutput: true }); assert.equal(sent.code, 3, sent.err);
  const record = await readPullRecord(f.record, p.intent); assert.equal(record.outcome.state, 'committed');
  assert.equal(sent.err.includes(TOKEN), false);
  assert.equal(p.requests.length, 3);
});
test('result-name race never overwrites an unrelated file or discards known terminal evidence', async t => {
  let f;
  const p = await peer(t, { handle: async (r, res, s) => {
    if (!r.url.endsWith('/outcomes')) await writeFile(f.record, 'other writer', { mode: 0o600 });
  } });
  f = await prepared(t, p);
  const sent = await cli(t, sendArgs(f, p.intent)); assert.equal(sent.code, 3, sent.err);
  assert.equal((await readFile(f.record)).toString(), 'other writer');
  const diagnostic = JSON.parse(sent.err); assert.equal(diagnostic.record.outcome.state, 'committed');
  assert.equal(diagnostic.outcome_unknown, false);
});
for (const kind of ['missing', 'changed-key', 'changed-body', 'truncated']) test(`invalid saved intent ${kind} refuses without networking`, async t => {
  const p = await peer(t), f = await prepared(t, p), path = join(f.slot, 'intent.json');
  if (kind === 'missing') { await rm(path); }
  else if (kind === 'truncated') await writeFile(path, '{');
  else { const v = structuredClone(p.intent); v[kind === 'changed-key' ? 'key' : 'body'] += 'different'; await writeFile(path, pullCanonical(v)); }
  const result = await cli(t, sendArgs(f, p.intent)); assert.equal(result.code, 2, result.err); assert.equal(p.requests.length, 0);
});
for (const kind of ['public-token', 'symlink-token', 'hardlink-token', 'directory-token', 'oversized-token', 'aliased-parent', 'worktree']) test(`unsafe local input ${kind}`, async t => {
  const p = await peer(t), f = await files(t, input(p.endpoint));
  if (kind === 'public-token') await chmod(f.token, 0o644);
  if (kind === 'symlink-token') { await symlink(f.token, join(f.root, 'link')); f.token = join(f.root, 'link'); }
  if (kind === 'hardlink-token') await link(f.token, join(f.root, 'hardlink'));
  if (kind === 'directory-token') f.token = f.root;
  if (kind === 'oversized-token') await writeFile(f.token, TOKEN + 'xx');
  if (kind === 'aliased-parent') { await symlink(f.root, join(f.root, 'alias')); f.token = join(f.root, 'alias', 'token'); }
  if (kind === 'worktree') await mkdir(join(f.root, '.git'));
  const result = await cli(t, prepArgs(f)); assert.equal(result.code, 2, result.err); assert.equal(p.requests.length, 0);
});
test('an interrupted preparation slot is retained and cannot be replaced by another key', async t => {
  const p = await peer(t), f = await files(t, input(p.endpoint));
  await mkdir(f.slot, { mode: 0o700 }); await writeFile(join(f.slot, 'intent.json'), '{partial', { mode: 0o600 });
  const result = await cli(t, prepArgs(f)); assert.equal(result.code, 2);
  assert.equal((await readFile(join(f.slot, 'intent.json'))).toString(), '{partial'); assert.equal(p.requests.length, 0);
});
test('concurrent preparation has one immutable winner', async t => {
  const p = await peer(t), f = await files(t, input(p.endpoint));
  const results = await Promise.all([cli(t, prepArgs(f)), cli(t, prepArgs(f))]);
  assert.deepEqual(results.map(v => v.code).sort(), [0, 2]);
  assert.ok((await loadPullIntent(f.slot)).key.startsWith('fgp1-')); assert.equal(p.requests.length, 0);
});
test('wrong confirmation, rotated send, missing merge consent and existing result file stop before I/O', async t => {
  const p = await peer(t, { action: 'fast-forward' }), f = await prepared(t, p);
  for (const args of [sendArgs(f, { ...p.intent, key: 'wrong' }), sendArgs({ ...f, token: f.rotated }, p.intent),
    sendArgs(f, p.intent).filter(v => v !== '--fast-forward-only')]) {
    assert.equal((await cli(t, args)).code, 2);
  }
  await writeFile(f.record, 'occupied', { mode: 0o600 });
  assert.equal((await cli(t, sendArgs(f, p.intent))).code, 2);
  assert.equal(p.requests.length, 0); assert.equal((await readFile(f.record)).toString(), 'occupied');
});
test('retained receipt cross-request substitution and terminal regression are rejected', async t => {
  const p = await peer(t), f = await prepared(t, p);
  const known = pullRecord(p.intent, { outcome: outcome(p.intent, 'committed'), publication: publication(p.intent), dispatched: true });
  await savePullRecord(f.record, known, p.intent);
  const other = preparePull(input(p.endpoint), TOKEN); assert.throws(() => validatePullRecord(known, other));
  const sent = await cli(t, [...sendArgs(f, p.intent, join(f.root, 'regressed.json')), '--known', f.record]);
  assert.equal(sent.code, 3, sent.err); assert.equal(p.requests.length, 1);
  assert.equal(p.requests[0].url, '/repo.git/api/v1/outcomes');
});
test('publication awaiting confirmation is saved and only lookup is attempted next', async t => {
  const p = await peer(t, { handle(r, res, s) { if (r.url.endsWith('/outcomes') && s.published) {
    res.writeHead(503); res.end(); return true;
  } } }), f = await prepared(t, p);
  const sent = await cli(t, sendArgs(f, p.intent)); assert.equal(sent.code, 3, sent.err);
  const record = await readPullRecord(f.record, p.intent); assert.equal(record.publication.outcome, 'committed'); assert.equal(record.outcome, null);
  const next = await cli(t, [...sendArgs(f, p.intent, join(f.root, 'retry.json')), '--known', f.record]);
  assert.equal(next.code, 3); assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
});
test('record output errors preserve native result in the diagnostic, with awaited writes', async t => {
  const p = await peer(t), f = await prepared(t, p); let diagnostic = '';
  const result = await run(sendArgs(f, p.intent), { output: async () => { throw new Error('output closed'); }, errorOutput: async text => { diagnostic += text; } });
  assert.equal(result, 3); assert.equal((await readPullRecord(f.record, p.intent)).outcome.state, 'committed');
  assert.equal(JSON.parse(diagnostic).record_path, f.record);
});
test('offline inspection of a known result does not connect or disclose tokens', async t => {
  const p = await peer(t, { action: 'comment' }), f = await prepared(t, p);
  const record = pullRecord(p.intent, { outcome: outcome(p.intent, 'committed'), publication: publication(p.intent), dispatched: true });
  await savePullRecord(f.record, record, p.intent);
  const result = await cli(t, ['inspect', '--request-dir', f.slot, '--known', f.record]);
  assert.equal(result.code, 0); assert.equal(p.requests.length, 0); assert.equal(result.out.includes(TOKEN), false);
});
for (const extra of [['--force'], ['--method', 'squash'], ['--timeout-ms', '0'], ['--timeout-ms', '300001'], ['--record', 'duplicate']]) test(`closed command grammar: ${extra.join(' ')}`, async t => {
  const p = await peer(t), f = await prepared(t, p);
  assert.equal((await cli(t, [...sendArgs(f, p.intent), ...extra])).code, 2); assert.equal(p.requests.length, 0);
});
