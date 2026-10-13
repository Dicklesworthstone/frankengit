import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, rm, chmod, link, symlink, mkdir, lstat, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { capturePullReviews, reviewHash, reviewCanonical } from '../../scripts/operator/pull_review_snapshot.mjs';
import { draftPullReview } from '../../scripts/operator/pull_review_draft.mjs';
import { loadReviewCapture, readReviewPrivate, saveReviewJson } from '../../scripts/operator/pull_review_files.mjs';
import { run } from '../../scripts/fg_pull_review.mjs';
import { peer, person, TOKEN, EPOCH, VERSION, NUMBER, HEAD } from './pull_review_snapshot_fixture.mjs';
const CLI = resolve('scripts/fg_pull_review.mjs');
async function files(t, p) {
  const root = await mkdtemp(join(tmpdir(), 'fg-review-cli-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const f = { root, token: join(root, 'token'), input: join(root, 'selection.json'), capture: join(root, 'capture.json'), choice: join(root, 'choice.json'), draft: join(root, 'draft.json') };
  await writeFile(f.input, reviewCanonical(p.selected), { mode: 0o600 }); await writeFile(f.token, TOKEN + '\n', { mode: 0o600 }); return f;
}
function launch(t, args, broken = false) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', done = false;
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  t.after(() => { if (!done) child.kill('SIGKILL'); });
  if (broken) child.stdout.destroy(); else child.stdout.on('data', b => { out += b; if (out.length > 10 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', b => { err += b; if (err.length > 1024 * 1024) child.kill('SIGKILL'); });
  const result = once(child, 'close').then(([code, signal]) => { done = true; clearTimeout(timer); return { code, signal, out, err }; });
  return { child, result };
}
const captureArgs = f => ['capture', '--input', f.input, '--token-file', f.token, '--output', f.capture];
const draftArgs = (f, hash) => ['draft', '--capture', f.capture, '--sha256', hash, '--input', f.choice, '--output', f.draft];
const choice = (action, format = 'sha1', principal = person(12)) => ({ action, principal_id: principal,
  ...(action === 'withdraw' ? {} : { merge_base: 'b'.repeat(format === 'sha1' ? 40 : 64), candidate_commit: 'c'.repeat(format === 'sha1' ? 40 : 64) }),
  ...(action === 'merge' ? { required_reviewers: [person(11), person(10)], method: 'squash' } : { reason: 'An explicit human decision.\n🦀' }) });
async function captured(t, p) {
  const f = await files(t, p), result = await launch(t, captureArgs(f)).result; assert.equal(result.code, 0, result.err);
  return { ...f, receipt: JSON.parse(result.out) };
}
for (const format of ['sha1', 'sha256']) for (const action of ['approve', 'request-changes', 'withdraw', 'merge']) {
  test(`${format} ${action}: actual capture/inspect/draft processes keep native coordinates`, async t => {
    const p = await peer(t, { format }), f = await captured(t, p), count = p.requests.length;
    await writeFile(f.choice, reviewCanonical(choice(action, format)), { mode: 0o600 });
    const inspected = await launch(t, ['inspect', '--capture', f.capture, '--sha256', f.receipt.sha256]).result;
    assert.equal(inspected.code, 0, inspected.err); assert.equal(JSON.parse(inspected.out).pull.snapshot_token, HEAD);
    const result = await launch(t, draftArgs(f, f.receipt.sha256)).result; assert.equal(result.code, 0, result.err);
    assert.equal(JSON.parse(result.out).source_capture_sha256, f.receipt.sha256);
    const draft = JSON.parse(await readFile(f.draft));
    assert.deepEqual(Object.keys(draft), ['endpoint', 'scope', 'number', 'action', 'fields']);
    assert.equal(draft.number, NUMBER); assert.equal(draft.action, action); assert.equal(draft.scope.principal_id, person(12));
    assert.equal(draft.fields.pull_request_version, VERSION); assert.equal(draft.fields.policy_epoch, EPOCH);
    assert.equal(draft.fields.source_tip, 'a'.repeat(format === 'sha1' ? 40 : 64));
    assert.equal(draft.fields.source_ref, 'refs/heads/topic'); assert.equal(draft.fields.target_ref, 'refs/heads/main');
    if (action !== 'merge') assert.equal(draft.fields.expected_version, String(BigInt(VERSION) + 2n));
    else { assert.equal(draft.fields.method, 'squash'); assert.deepEqual(draft.fields.required_reviewers, [person(10), person(11)]); }
    assert.equal(p.requests.length, count); // No network, publication or token read during inspect/draft.
    assert.equal((await lstat(f.capture)).mode & 0o777, 0o600); assert.equal((await lstat(f.draft)).nlink, 1);
    assert.equal(result.out.includes(TOKEN), false); assert.equal(JSON.parse(result.out).publication_attempted, false);
  });
}
test('first review uses zero only after complete pagination; later-page predecessor is exact', async t => {
  const p = await peer(t), capture = await capturePullReviews(p.selected, TOKEN, { pageLimit: 1 });
  assert.equal(capture.review_pages.length, 3);
  assert.equal(draftPullReview(capture, choice('approve', 'sha1', person(101))).fields.expected_version, '0');
  assert.equal(draftPullReview(capture, choice('approve')).fields.expected_version, String(BigInt(VERSION) + 2n));
  const bad = structuredClone(capture); bad.review_pages.pop();
  assert.throws(() => draftPullReview(bad, choice('approve', 'sha1', person(101))));
});
test('withdrawal keeps the exact old candidate/epoch/tips even after PR and policy changes', async t => {
  const p = await peer(t), old = p.native.reviews[2]; old.subject.pull_request_version = '2'; old.subject.policy_epoch = '1';
  old.subject.source_tip = 'sha1:' + 'e'.repeat(40); old.candidate.candidate_commit = 'sha1:' + 'f'.repeat(40); old.freshness = 'pull_request_changed';
  const draft = draftPullReview(await capturePullReviews(p.selected, TOKEN), choice('withdraw'));
  assert.equal(draft.fields.pull_request_version, '2'); assert.equal(draft.fields.policy_epoch, '1');
  assert.equal(draft.fields.source_tip, 'e'.repeat(40)); assert.equal(draft.fields.candidate_commit, 'f'.repeat(40));
  assert.equal(draft.fields.expected_version, old.version);
});
test('merge method/reviewer choices are explicit, detached, and never granted from approval rows', async t => {
  const p = await peer(t), capture = await capturePullReviews(p.selected, TOKEN), selected = choice('merge');
  selected.method = 'merge-commit'; selected.required_reviewers = [person(888)];
  const draft = draftPullReview(capture, selected); selected.required_reviewers.push(person(9));
  assert.deepEqual(draft.fields.required_reviewers, [person(888)]); assert.equal(draft.fields.method, 'merge-commit');
  // A named reviewer need not have an approval: the native sender/admission checks this, not the read client.
  for (const edit of [c => delete c.method, c => c.method = 'fast-forward', c => c.required_reviewers = [],
    c => c.required_reviewers = [c.principal_id], c => c.required_reviewers = [person(1), person(1)],
    c => c.candidate_commit = '0'.repeat(40), c => c.merge_base = 'sha1:' + c.merge_base, c => c.force = true]) {
    const bad = choice('merge'); edit(bad); assert.throws(() => draftPullReview(capture, bad));
  }
});
for (const kind of ['missing', 'closed', 'byte-only', 'no-vote', 'legacy-vote', 'exhausted']) test(`draft refuses unsupported ${kind} without inventing a subject`, async t => {
  const p = await peer(t, { found: kind !== 'missing', state: kind === 'closed' ? 'closed' : 'open', byteOnly: kind === 'byte-only' });
  const action = ['no-vote', 'legacy-vote'].includes(kind) ? 'withdraw' : 'approve';
  if (kind === 'no-vote') p.native.reviews.splice(2, 1);
  if (kind === 'legacy-vote') p.native.reviews[2].candidate = null;
  if (kind === 'exhausted') p.native.reviews[2].version = EPOCH;
  const capture = await capturePullReviews(p.selected, TOKEN); assert.throws(() => draftPullReview(capture, choice(action)));
});
test('changed capture bytes, wrong pin, duplicate keys and partial captures refuse offline', async t => {
  const p = await peer(t), f = await captured(t, p); await writeFile(f.choice, reviewCanonical(choice('approve')), { mode: 0o600 });
  let result = await launch(t, draftArgs(f, '0'.repeat(64))).result; assert.equal(result.code, 2);
  await assert.rejects(readFile(f.draft));
  const bytes = await readFile(f.capture); await writeFile(f.capture, bytes.subarray(0, 25));
  result = await launch(t, draftArgs(f, f.receipt.sha256)).result; assert.equal(result.code, 2);
  assert.equal(p.requests.length, 2);
});
for (const kind of ['public', 'symlink', 'hardlink', 'directory', 'oversized', 'worktree']) test(`private file ${kind} refusal has no network side effects`, async t => {
  const p = await peer(t), f = await files(t, p);
  if (kind === 'public') await chmod(f.token, 0o644);
  if (kind === 'symlink') { await symlink(f.token, join(f.root, 'alias')); f.token = join(f.root, 'alias'); }
  if (kind === 'hardlink') await link(f.token, join(f.root, 'second'));
  if (kind === 'directory') f.token = f.root;
  if (kind === 'oversized') await writeFile(f.token, TOKEN + 'XX');
  if (kind === 'worktree') await mkdir(join(f.root, '.git'));
  const result = await launch(t, captureArgs(f)).result; assert.equal(result.code, 2); assert.equal(p.requests.length, 0);
  await assert.rejects(readFile(f.capture));
});
test('an existing output is never overwritten or used as an implicit resume', async t => {
  const p = await peer(t), f = await files(t, p); await writeFile(f.capture, 'occupied', { mode: 0o600 });
  assert.equal((await launch(t, captureArgs(f)).result).code, 2); assert.equal(p.requests.length, 0);
  assert.equal(await readFile(f.capture, 'utf8'), 'occupied');
});
test('concurrent create-only capture publication has one complete winner', async t => {
  const p = await peer(t), f = await files(t, p), results = await Promise.all([launch(t, captureArgs(f)).result, launch(t, captureArgs(f)).result]);
  assert.equal(results.filter(r => r.code === 0).length, 1);
  const winner = JSON.parse(results.find(r => r.code === 0).out), capture = await loadReviewCapture(f.capture, winner.sha256);
  assert.equal(capture.complete, true); assert.equal((await lstat(f.capture)).nlink, 1);
});
test('a failed final review read publishes no successful prefix', async t => {
  const p = await peer(t, { handle(r, res) { if (r.url.pathname.endsWith('/reviews')) { res.writeHead(503); res.end(); return true; } } });
  const f = await files(t, p), result = await launch(t, captureArgs(f)).result;
  assert.equal(result.code, 3); await assert.rejects(readFile(f.capture));
  assert.deepEqual((await readdir(f.root)).sort(), ['selection.json', 'token']);
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`${signal} during reading leaves no fabricated complete capture`, async t => {
  let reach; const reached = new Promise(r => reach = r);
  const p = await peer(t, { handle(r) { if (r.url.pathname.endsWith('/reviews')) { reach(); return true; } } });
  const f = await files(t, p), job = launch(t, captureArgs(f)); await reached; job.child.kill(signal);
  const result = await job.result; if (signal === 'SIGTERM') assert.equal(result.code, 3); else assert.equal(result.signal, signal);
  await assert.rejects(readFile(f.capture));
});
test('lost stdout preserves the complete named capture and its integrity pin in the diagnostic', async t => {
  const p = await peer(t), f = await files(t, p), result = await launch(t, captureArgs(f), true).result;
  assert.equal(result.code, 3); const err = JSON.parse(result.err);
  assert.equal((await loadReviewCapture(f.capture, err.saved_sha256)).complete, true); assert.equal(err.path, f.capture);
});
test('output-name race cannot overwrite unrelated data after reads', async t => {
  let f;
  const p = await peer(t, { async handle(r) { if (r.url.pathname.endsWith('/reviews')) await writeFile(f.capture, 'other writer', { mode: 0o600 }); } });
  f = await files(t, p); const result = await launch(t, captureArgs(f)).result;
  assert.equal(result.code, 3); assert.equal(await readFile(f.capture, 'utf8'), 'other writer');
});
test('draft/inspect reject credential and publication flags before any access', async t => {
  const p = await peer(t), f = await captured(t, p); await writeFile(f.choice, reviewCanonical(choice('approve')), { mode: 0o600 });
  for (const extra of [['--token-file', f.token], ['--send', 'true'], ['--force', 'true'], ['--sha256', f.receipt.sha256]]) {
    assert.equal((await launch(t, [...draftArgs(f, f.receipt.sha256), ...extra]).result).code, 2);
  }
  assert.equal(p.requests.length, 2);
});
