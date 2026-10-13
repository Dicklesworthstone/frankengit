// Complete operator processes and private files with native-schema HTTP peers.
// Candidate bytes are opaque transport fixtures, not real Git bundles or proofs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, chmod, mkdir, readdir, lstat, symlink, link, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { run } from '../../scripts/remote_pull.mjs';
import { preparePull, pullCanonical } from '../../scripts/operator/remote_pull.mjs';
import { PULL_LIMITS, pullHash } from '../../scripts/operator/pull_command.mjs';
import { loadPullIntent, savePullIntent, loadPullBundle, readPullRecord, pullRecord,
  savePullRecord, validatePullRecord } from '../../scripts/operator/pull_files.mjs';
import { ROTATED, BUNDLE, reviewInput, reviewPublication, reviewPeer } from './remote_pull_review_fixture.mjs';
import { outcome } from './remote_pull_fixture.mjs';

// Distinct from every mock SHA-256 OID, so credential-absence assertions do not
// confuse a deliberately repeated object digest with an exposed test token.
const TOKEN = 'e1'.repeat(32);
const CLI = resolve('scripts/remote_pull.mjs');
const cases = [['approve'], ['request-changes'], ['withdraw'], ['merge', 'merge-commit'], ['merge', 'squash']];
async function files(t, value) {
  const root = await mkdtemp(join(tmpdir(), 'fg-reviewed-cli-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const f = { root, input: join(root, 'input.json'), token: join(root, 'token'), rotated: join(root, 'rotated'),
    source: join(root, 'reviewed.bundle'), slot: join(root, 'request'), record: join(root, 'result.json') };
  for (const [path, data] of [[f.input, pullCanonical(value)], [f.token, TOKEN + '\n'], [f.rotated, ROTATED], [f.source, BUNDLE]]) {
    await writeFile(path, data, { mode: 0o600 });
  }
  return f;
}
function launch(t, args, { brokenOutput = false } = {}) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', completed = false;
  const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
  t.after(() => { if (!completed) child.kill('SIGKILL'); });
  if (brokenOutput) child.stdout.destroy();
  else child.stdout.on('data', chunk => { out += chunk; if (out.length > 2 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', chunk => { err += chunk; if (err.length > 2 * 1024 * 1024) child.kill('SIGKILL'); });
  const result = once(child, 'close').then(([code, signal]) => { clearTimeout(timer); completed = true; return { code, signal, out, err }; });
  return { child, result };
}
const cli = (t, args, options) => launch(t, args, options).result;
const prepareArgs = (f, action) => ['prepare', '--input', f.input, '--token-file', f.token, '--request-dir', f.slot,
  ...(action === 'withdraw' ? [] : ['--bundle', f.source])];
const sendArgs = (f, intent, record = f.record) => ['send', '--request-dir', f.slot, '--token-file', f.token,
  '--confirm-key', intent.key, '--record', record, '--confirm-candidate', intent.fields.candidate_commit,
  ...(intent.action === 'merge' ? ['--confirm-merge-method', intent.fields.method] : [])];
const recoverArgs = (f, record = f.record) => ['recover', '--request-dir', f.slot, '--token-file', f.rotated, '--record', record];
const savedBundle = f => join(f.slot, 'candidate.bundle');
async function prepared(t, p) {
  const f = await files(t, reviewInput(p.endpoint, p.intent.action, p.intent.scope.object_format, p.intent.fields.method));
  const ready = await cli(t, prepareArgs(f, p.intent.action)); assert.equal(ready.code, 0, ready.err);
  p.intent = await loadPullIntent(f.slot); return f;
}
for (const format of ['sha1', 'sha256']) for (const [action, method] of cases) {
  test(`${format} ${action}/${method ?? 'review'}: durable prepare, inspect, send, rotated recover`, async t => {
    const p = await reviewPeer(t, { action, method, format }), f = await prepared(t, p);
    assert.equal(p.requests.length, 0);
    const names = await readdir(f.slot);
    assert.deepEqual(names.sort(), action === 'withdraw' ? ['intent.json'] : ['candidate.bundle', 'intent.json']);
    const before = await readFile(join(f.slot, 'intent.json'));
    assert.ok(before.length < PULL_LIMITS.intent); assert.equal(before.includes(Buffer.from(TOKEN)), false);
    assert.equal(before.includes(Buffer.from(f.source)), false);
    if (action !== 'withdraw') {
      assert.deepEqual(await loadPullBundle(f.slot, p.intent), BUNDLE);
      assert.equal((await lstat(savedBundle(f))).mode & 0o777, 0o600);
      assert.equal((await lstat(savedBundle(f))).nlink, 1);
    }
    // The caller's original file can disappear: the private saved copy owns retry bytes.
    await rm(f.source);
    const inspected = await cli(t, ['inspect', '--request-dir', f.slot]);
    assert.equal(inspected.code, 0, inspected.err); assert.deepEqual(JSON.parse(inspected.out).intent, p.intent);
    assert.equal(p.requests.length, 0);
    const sent = await cli(t, sendArgs(f, p.intent)); assert.equal(sent.code, 0, sent.err);
    const record = await readPullRecord(f.record, p.intent);
    assert.equal(record.outcome.state, 'committed'); assert.equal(record.publication.subject.policy_epoch, '18446744073709551615');
    assert.equal(record.publication.subject.pull_request_version, p.intent.fields.pull_request_version);
    assert.equal(record.publication.candidate_commit, `${format}:${p.intent.fields.candidate_commit}`);
    assert.equal((await lstat(f.record)).mode & 0o777, 0o600);
    if (action !== 'withdraw') await rm(savedBundle(f));
    const knownSend = await cli(t, [...sendArgs(f, p.intent, join(f.root, 'known.json')), '--known', f.record]);
    assert.equal(knownSend.code, 0, knownSend.err);
    const recovered = await cli(t, [...recoverArgs(f, join(f.root, 'recovered.json')), '--known', f.record]);
    assert.equal(recovered.code, 0, recovered.err);
    assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
    assert.equal(p.requests.at(-1).headers.authorization, `Bearer ${ROTATED}`);
    assert.deepEqual(await readFile(join(f.slot, 'intent.json')), before);
  });
}
for (const [action, method] of cases) test(`${action}/${method ?? 'review'}: native refusal is retained, never a strategy fallback`, async t => {
  const p = await reviewPeer(t, { action, method, state: 'refused' }), f = await prepared(t, p);
  const result = await cli(t, sendArgs(f, p.intent)); assert.equal(result.code, 1, result.err);
  const record = await readPullRecord(f.record, p.intent);
  assert.equal(record.outcome.decision.code, 'PolicyDenied'); assert.equal(record.publication.refusal_code_point, 17);
  assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
});
for (const kind of ['missing', 'corrupt', 'truncated', 'oversized', 'public', 'symlink', 'hardlink', 'directory']) {
  test(`saved ${kind} bundle blocks new publication before any I/O but cannot block recovery`, async t => {
    const p = await reviewPeer(t, { action: 'merge' }), f = await prepared(t, p), path = savedBundle(f);
    if (kind === 'missing') await rm(path);
    if (kind === 'corrupt') { const changed = Buffer.from(BUNDLE); changed[0] ^= 1; await writeFile(path, changed); }
    if (kind === 'truncated') await writeFile(path, BUNDLE.subarray(0, -1));
    if (kind === 'oversized') await writeFile(path, Buffer.alloc(PULL_LIMITS.bundle + 1));
    if (kind === 'public') await chmod(path, 0o644);
    if (kind === 'symlink') { await rm(path); await symlink(f.source, path); }
    if (kind === 'hardlink') await link(path, join(f.root, 'alias'));
    if (kind === 'directory') { await rm(path); await mkdir(path, { mode: 0o700 }); }
    const result = await cli(t, sendArgs(f, p.intent)); assert.equal(result.code, 2, result.err); assert.equal(p.requests.length, 0);
    // An explicit peer terminal, not inference from the broken local file.
    p.published = true;
    const recovered = await cli(t, recoverArgs(f)); assert.equal(recovered.code, 0, recovered.err);
    assert.equal(p.requests.length, 1); assert.equal(p.requests[0].url, '/repo.git/api/v1/outcomes');
  });
}
test('the 16 MiB bundle limit is accepted exactly; malformed payloads create no request slot', async t => {
  const p = await reviewPeer(t), f = await files(t, reviewInput(p.endpoint)), bytes = Buffer.alloc(PULL_LIMITS.bundle, 0xa5);
  const intent = preparePull(reviewInput(p.endpoint), TOKEN, bytes);
  await savePullIntent(f.slot, intent, bytes);
  assert.deepEqual(await loadPullBundle(f.slot, intent, { sync: true }), bytes);
  assert.equal((await readFile(join(f.slot, 'intent.json'))).length < 8192, true);
  for (const data of [Buffer.alloc(0), Buffer.alloc(PULL_LIMITS.bundle + 1), Buffer.from('wrong')]) {
    const next = join(f.root, 'invalid'); await assert.rejects(savePullIntent(next, intent, data));
    await assert.rejects(lstat(next), { code: 'ENOENT' });
  }
  assert.equal(p.requests.length, 0);
});
test('save snapshots candidate bytes and intent before asynchronous filesystem work', async t => {
  const p = await reviewPeer(t), f = await files(t, reviewInput(p.endpoint)), bytes = Buffer.from(BUNDLE), copy = structuredClone(p.intent);
  const saving = savePullIntent(f.slot, copy, bytes);
  bytes.fill(0); copy.fields.candidate_commit = copy.fields.source_tip; copy.bundle.sha256 = 'f'.repeat(64);
  const selected = await saving;
  assert.deepEqual(await loadPullIntent(f.slot), p.intent); assert.deepEqual(await loadPullBundle(f.slot, selected), BUNDLE);
});
for (const state of ['bundle-only', 'partial-intent', 'intent-without-bundle']) {
  test(`interrupted ${state} slot is retained and never reconstructed`, async t => {
    const p = await reviewPeer(t), f = await files(t, reviewInput(p.endpoint)); await mkdir(f.slot, { mode: 0o700 });
    if (state !== 'intent-without-bundle') await writeFile(savedBundle(f), BUNDLE, { mode: 0o600 });
    if (state !== 'bundle-only') await writeFile(join(f.slot, 'intent.json'), state === 'partial-intent' ? '{partial' : pullCanonical(p.intent), { mode: 0o600 });
    const before = await readdir(f.slot);
    const attempt = await cli(t, prepareArgs(f, 'approve')); assert.equal(attempt.code, 2, attempt.err);
    assert.deepEqual(await readdir(f.slot), before); assert.equal(p.requests.length, 0);
    if (state === 'intent-without-bundle') {
      assert.deepEqual(await loadPullIntent(f.slot), p.intent);
      assert.equal((await cli(t, sendArgs(f, p.intent))).code, 2);
      const recovered = await cli(t, recoverArgs(f)); assert.equal(recovered.code, 3, recovered.err);
      assert.equal((await readPullRecord(f.record, p.intent)).outcome.state, 'key_not_observed');
    } else { await assert.rejects(loadPullIntent(f.slot)); assert.equal(p.requests.length, 0); }
  });
}
test('concurrent candidate preparations produce one complete pair, not mixed intents/bundles', async t => {
  const p = await reviewPeer(t), f = await files(t, reviewInput(p.endpoint)), other = Buffer.from(BUNDLE).fill(7);
  const first = preparePull(reviewInput(p.endpoint), TOKEN, BUNDLE), second = preparePull(reviewInput(p.endpoint), TOKEN, other);
  const results = await Promise.allSettled([savePullIntent(f.slot, first, BUNDLE), savePullIntent(f.slot, second, other)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const winner = await loadPullIntent(f.slot), bytes = await loadPullBundle(f.slot, winner);
  assert.deepEqual(bytes, winner.key === first.key ? BUNDLE : other);
  assert.equal(winner.bundle.sha256, pullHash(bytes));
});
test('exact key, candidate and method consent are all mandatory before I/O', async t => {
  const p = await reviewPeer(t, { action: 'merge', method: 'squash' }), f = await prepared(t, p);
  const good = sendArgs(f, p.intent);
  for (const flag of ['--confirm-key', '--confirm-candidate', '--confirm-merge-method']) {
    const index = good.indexOf(flag);
    for (const missing of [true, false]) {
      const args = [...good]; if (missing) args.splice(index, 2); else args[index + 1] = 'wrong';
      const result = await cli(t, args); assert.equal(result.code, 2, result.err);
    }
  }
  assert.equal((await cli(t, [...good, '--fast-forward-only'])).code, 2);
  assert.equal((await cli(t, sendArgs({ ...f, token: f.rotated }, p.intent))).code, 2);
  assert.equal(p.requests.length, 0);
  assert.equal((await cli(t, good)).code, 0);
});
test('withdraw has no payload and cannot import one; review cannot carry merge-method consent', async t => {
  const p = await reviewPeer(t, { action: 'withdraw' }), f = await files(t, reviewInput(p.endpoint, 'withdraw'));
  const wrong = await cli(t, [...prepareArgs(f, 'withdraw'), '--bundle', f.source]);
  assert.equal(wrong.code, 2); await assert.rejects(lstat(f.slot), { code: 'ENOENT' });
  assert.equal((await cli(t, prepareArgs(f, 'withdraw'))).code, 0); p.intent = await loadPullIntent(f.slot);
  assert.equal((await cli(t, [...sendArgs(f, p.intent), '--confirm-merge-method', 'squash'])).code, 2);
  assert.equal(p.requests.length, 0); assert.equal((await cli(t, sendArgs(f, p.intent))).code, 0);
});
for (const extra of [['--bundle', 'other.bundle'], ['--confirm-candidate', 'other'], ['--confirm-merge-method', 'squash']]) {
  test(`recovery refuses write-oriented options: ${extra[0]}`, async t => {
    const p = await reviewPeer(t), f = await prepared(t, p);
    assert.equal((await cli(t, [...recoverArgs(f), ...extra])).code, 2); assert.equal(p.requests.length, 0);
  });
}
test('lost multipart reply persists responsibility; rotated recovery works after losing bundle', async t => {
  const p = await reviewPeer(t, { action: 'merge', handle(req, res, s) {
    if (!req.url.endsWith('/outcomes')) { s.published = true; res.destroy(); return true; }
  } }), f = await prepared(t, p), before = await readFile(join(f.slot, 'intent.json'));
  const sent = await cli(t, sendArgs(f, p.intent)); assert.equal(sent.code, 3, sent.err);
  const unknown = await readPullRecord(f.record, p.intent); assert.equal(unknown.outcome, null); assert.equal(unknown.dispatched, true);
  await rm(savedBundle(f));
  const result = await cli(t, [...recoverArgs(f, join(f.root, 'recovered.json')), '--known', f.record]);
  assert.equal(result.code, 0, result.err); assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
  assert.deepEqual(await readFile(join(f.slot, 'intent.json')), before);
});
test('explicit retry after an unobserved send reuses exact saved binary and key', async t => {
  let posts = 0;
  const p = await reviewPeer(t, { handle(req, res) { if (!req.url.endsWith('/outcomes') && ++posts === 1) { res.destroy(); return true; } } });
  const f = await prepared(t, p), first = await cli(t, sendArgs(f, p.intent)); assert.equal(first.code, 3);
  const next = await cli(t, [...sendArgs(f, p.intent, join(f.root, 'again.json')), '--known', f.record]); assert.equal(next.code, 0, next.err);
  const writes = p.requests.filter(r => !r.url.endsWith('/outcomes')); assert.equal(writes.length, 2);
  assert.deepEqual(writes[0].bytes, writes[1].bytes); assert.equal(writes[0].headers['idempotency-key'], writes[1].headers['idempotency-key']);
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`${signal} during reviewed merge preserves request for bodyless restart recovery`, async t => {
  let admitted; const reached = new Promise(resolve => admitted = resolve);
  const p = await reviewPeer(t, { action: 'merge', method: 'squash', handle(req, res, s) {
    if (!req.url.endsWith('/outcomes')) { s.published = true; admitted(); return true; }
  } }), f = await prepared(t, p), original = await readFile(join(f.slot, 'intent.json'));
  const started = launch(t, sendArgs(f, p.intent));
  await Promise.race([reached, started.result.then(() => assert.fail('Process exited before upload reached peer'))]);
  started.child.kill(signal); const ended = await started.result;
  if (signal === 'SIGTERM') assert.equal(ended.code, 3, ended.err); else assert.equal(ended.signal, 'SIGKILL');
  await rm(savedBundle(f));
  const result = await cli(t, recoverArgs(f, join(f.root, 'restart.json'))); assert.equal(result.code, 0, result.err);
  assert.deepEqual(await readFile(join(f.slot, 'intent.json')), original);
  assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
});
test('publication awaiting confirmation remains a no-resend witness without its bundle', async t => {
  const p = await reviewPeer(t, { handle(req, res, s) {
    if (req.url.endsWith('/outcomes') && s.published) { res.writeHead(503); res.end(); return true; }
  } }), f = await prepared(t, p);
  const sent = await cli(t, sendArgs(f, p.intent)); assert.equal(sent.code, 3, sent.err);
  const record = await readPullRecord(f.record, p.intent); assert.equal(record.publication.outcome, 'committed'); assert.equal(record.outcome, null);
  await rm(savedBundle(f));
  const again = await cli(t, [...sendArgs(f, p.intent, join(f.root, 'again.json')), '--known', f.record]); assert.equal(again.code, 3, again.err);
  assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
  assert.equal((await readPullRecord(join(f.root, 'again.json'), p.intent)).publication.tx_id, record.publication.tx_id);
});
test('closed stdout after reviewed merge cannot erase the synced result', async t => {
  const p = await reviewPeer(t, { action: 'merge' }), f = await prepared(t, p);
  const result = await cli(t, sendArgs(f, p.intent), { brokenOutput: true }); assert.equal(result.code, 3, result.err);
  const record = await readPullRecord(f.record, p.intent); assert.equal(record.outcome.state, 'committed');
  assert.equal(record.publication.method, 'merge-commit'); assert.equal(result.err.includes(TOKEN), false);
});
test('record-name race keeps the other file and reports an already confirmed reviewed merge', async t => {
  let f;
  const p = await reviewPeer(t, { action: 'merge', handle: async (req) => {
    if (!req.url.endsWith('/outcomes')) await writeFile(f.record, 'other writer', { mode: 0o600 });
  } });
  f = await prepared(t, p); const result = await cli(t, sendArgs(f, p.intent)); assert.equal(result.code, 3, result.err);
  assert.equal((await readFile(f.record)).toString(), 'other writer');
  const diagnostic = JSON.parse(result.err); assert.equal(diagnostic.outcome_unknown, false);
  assert.equal(diagnostic.record.outcome.state, 'committed'); assert.equal(diagnostic.record.publication.method, 'merge-commit');
});
test('candidate records bind the exact bundle and subject; foreign receipts refuse offline', async t => {
  const p = await reviewPeer(t, { action: 'merge' }), f = await prepared(t, p);
  const record = pullRecord(p.intent, { outcome: outcome(p.intent, 'committed'), publication: reviewPublication(p.intent), dispatched: true });
  const other = preparePull(reviewInput(p.endpoint, 'merge'), TOKEN, Buffer.from('different payload'));
  assert.throws(() => validatePullRecord(record, other));
  await savePullRecord(f.record, record, p.intent);
  const inspected = await cli(t, ['inspect', '--request-dir', f.slot, '--known', f.record]);
  assert.equal(inspected.code, 0, inspected.err); assert.equal(p.requests.length, 0);
  const corrupt = structuredClone(record); corrupt.publication.subject.policy_epoch = '1';
  await writeFile(f.record, pullCanonical(corrupt));
  assert.equal((await cli(t, ['inspect', '--request-dir', f.slot, '--known', f.record])).code, 2);
  assert.equal(p.requests.length, 0);
});
test('caller cancellation before preparation starts neither a slot nor a network operation', async t => {
  const p = await reviewPeer(t), f = await files(t, reviewInput(p.endpoint)), controller = new AbortController(); controller.abort();
  const code = await run(prepareArgs(f, 'approve'), { signal: controller.signal, output: async () => {}, errorOutput: async () => {} });
  assert.equal(code, 2); assert.equal(p.requests.length, 0); await assert.rejects(lstat(f.slot), { code: 'ENOENT' });
});
