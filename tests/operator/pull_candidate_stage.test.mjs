// Complete package -> executable staging -> production sender -> recovery.
// HTTP reports model native schemas; Git is only the fixture object oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, chmod, rm, lstat, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { run } from '../../scripts/fg_pull_candidate.mjs';
import { stageCandidateReview } from '../../scripts/operator/pull_candidate_stage.mjs';
import { capturePullCandidate, resolvePullCandidate, candidateCanonical } from '../../scripts/operator/pull_candidate_capture.mjs';
import { saveCandidatePackage, loadCandidatePackage } from '../../scripts/operator/pull_candidate_files.mjs';
import { loadPullIntent, loadPullBundle } from '../../scripts/operator/pull_files.mjs';
import { pullHash, pullCanonical } from '../../scripts/operator/pull_command.mjs';
import { submitPull, recoverPull } from '../../scripts/operator/remote_pull.mjs';
import { resolutionPeer, TOKEN } from './pull_resolution_fixture.mjs';
import { candidatePeer } from './pull_candidate_fixture.mjs';
const CLI = resolve('scripts/fg_pull_candidate.mjs'), ROTATED = 'b'.repeat(64), REVIEWER = '00000000000000000000000000000001';
function choice(p, action = 'approve') {
  return { action, principal_id: action === 'merge' ? 'e'.repeat(32) : REVIEWER, candidate_commit: p.f.candidate,
    ...(action === 'merge' ? { method: p.f.method, required_reviewers: [REVIEWER] } : { reason: 'Reviewed these resolved bytes.' }) };
}
async function setup(t, peerOptions = {}) {
  const p = await resolutionPeer(t, peerOptions), root = await mkdtemp(join(tmpdir(), 'fg-candidate-stage-'));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const original = await capturePullCandidate(p.input, TOKEN), resolved = await resolvePullCandidate(original.capture, p.choices, TOKEN);
  const packagePath = join(root, 'package'), saved = await saveCandidatePackage(packagePath, resolved.capture, resolved.bundle);
  const f = { root, package: packagePath, hash: saved.sha256, request: join(root, 'request'), token: join(root, 'token'), choices: join(root, 'choices.json') };
  await writeFile(f.token, TOKEN + '\n', { mode: 0o600 });
  return { p, f, original, resolved };
}
const selection = (f, choices) => ({ package: f.package, sha256: f.hash, choices, request_dir: f.request });
const args = f => ['stage', '--package', f.package, '--sha256', f.hash, '--choices', f.choices, '--token-file', f.token, '--request-dir', f.request];
async function cli(t, argv, broken = false) {
  const child = spawn(process.execPath, [CLI, ...argv], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  if (broken) child.stdout.destroy(); else child.stdout.on('data', b => { out += b; if (out.length > 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', b => { err += b; if (err.length > 1024 * 1024) child.kill('SIGKILL'); });
  const [code, signal] = await once(child, 'close'); clearTimeout(timer); return { code, signal, out, err };
}
function publication(intent, state) {
  const f = intent.fields, committed = state === 'committed', format = intent.scope.object_format;
  return { type: intent.action === 'merge' ? 'reviewed_merge_publication' : 'candidate_review_publication', schema_version: 1,
    ...intent.scope, action: intent.action, ...(intent.action === 'merge' ? { method: f.method } : {}),
    review_expected_version: intent.action === 'merge' ? null : f.expected_version,
    subject: { number: intent.number, pull_request_version: f.pull_request_version, policy_epoch: f.policy_epoch,
      ...Object.fromEntries(['source', 'target'].flatMap(side => [[`${side}_ref`, f[`${side}_ref`]],
        [`${side}_ref_hex`, Buffer.from(f[`${side}_ref`]).toString('hex')], [`${side}_tip`, `${format}:${f[`${side}_tip`]}`]])) },
    merge_base: `${format}:${f.merge_base}`, candidate_commit: `${format}:${f.candidate_commit}`,
    required_reviewers: intent.action === 'merge' ? f.required_reviewers : null,
    tx_id: 'resolved-command-tx', outcome: state, decision_sequence: '18446744073709551615',
    repository_commit_id: committed ? 'resolved-rcr' : null, refusal_record_id: committed ? null : 'resolved-refusal',
    refusal_code: committed ? null : 'PolicyDenied', refusal_code_point: committed ? null : 17, delivery_acknowledged: null };
}
function outcome(intent, state) {
  const { object_format, ...scope } = intent.scope, terminal = state !== 'key_not_observed';
  const p = publication(intent, state);
  return { type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null, state, terminal,
    transaction: !terminal ? null : { tx_id: p.tx_id, seal_id: 'resolved-seal', request_schema: 'resolved-native-review-v1',
      canonical_request_digest: { algorithm: 1, hex: 'd'.repeat(64) } },
    decision: !terminal ? null : { kind: state, decision_sequence: p.decision_sequence,
      ...(state === 'committed' ? { repository_commit_id: p.repository_commit_id } :
        { code: p.refusal_code, code_point: p.refusal_code_point, refusal_record_id: p.refusal_record_id }) },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
function reply(res, value, status = 200) {
  const counters = ['number', 'pull_request_version', 'policy_epoch', 'review_expected_version', 'decision_sequence'];
  const body = JSON.stringify(value, (key, v) => counters.includes(key) && typeof v === 'string' ? JSON.rawJSON(v) : v);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }); res.end(body);
}
function commands(state = 'committed', drop = false) {
  return (r, res, p) => {
    if (!r.headers['idempotency-key']) return false;
    const intent = p.intent; assert.ok(intent); assert.equal(r.method, 'POST');
    assert.equal(r.headers['idempotency-key'], intent.key);
    assert.ok([`Bearer ${TOKEN}`, `Bearer ${ROTATED}`].includes(r.headers.authorization));
    if (r.url === '/repo.git/api/v1/outcomes') {
      assert.equal(r.body.length, 0); reply(res, outcome(intent, p.sent ? state : 'key_not_observed')); return true;
    }
    assert.equal(r.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(r.url, `/repo.git/api/v1/pulls/7/${intent.action === 'merge' ? 'merge' : `reviews/${intent.action}`}`);
    const boundary = r.headers['content-type'].split('boundary=')[1], marker = Buffer.from('Content-Type: application/x-git-bundle\r\n\r\n');
    const start = r.body.indexOf(marker) + marker.length, end = r.body.length - Buffer.byteLength(`\r\n--${boundary}--\r\n`);
    assert.deepEqual(r.body.subarray(start, end), p.f.bundle);
    const formStart = r.body.indexOf(Buffer.from('\r\n\r\n')) + 4, formEnd = r.body.indexOf(Buffer.from(`\r\n--${boundary}`), formStart);
    assert.equal(r.body.subarray(formStart, formEnd).toString(), intent.body);
    p.sent = (p.sent ?? 0) + 1;
    if (drop) res.destroy(); else reply(res, publication(intent, state), state === 'committed' ? 200 : 409);
    return true;
  };
}
const consent = (intent, bundle) => ({ bundle, confirmKey: intent.key, confirmCandidate: intent.fields.candidate_commit,
  ...(intent.action === 'merge' ? { confirmMergeMethod: intent.fields.method } : {}) });
for (const algorithm of ['sha1', 'sha256']) for (const method of ['merge-commit', 'squash']) {
  for (const action of ['approve', 'request-changes', 'merge']) for (const state of ['committed', 'refused']) {
    test(`${algorithm} ${method} ${action} ${state}: resolved package -> executable stage -> unchanged sender -> recovery`, async t => {
      const { p, f } = await setup(t, { algorithm, method, choice: 'file', bytes: Buffer.from([0, 255, 10]), mode: '100755', commandHandle: commands(state) });
      await writeFile(f.choices, candidateCanonical(choice(p, action)), { mode: 0o600 });
      const result = await cli(t, args(f)); assert.equal(result.code, 0, result.err); assert.equal(p.requests.length, 5);
      const receipt = JSON.parse(result.out); p.intent = await loadPullIntent(f.request, { sync: true });
      const bundle = await loadPullBundle(f.request, p.intent, { sync: true });
      assert.deepEqual(bundle, p.f.bundle); assert.equal(receipt.key, p.intent.key);
      assert.equal(receipt.package_sha256, f.hash); assert.equal(receipt.intent_sha256, pullHash(pullCanonical(p.intent)));
      assert.equal(receipt.publication_attempted, false); assert.equal(result.out.includes(TOKEN), false);
      assert.equal(p.intent.fields.candidate_commit, p.f.candidate);
      if (action !== 'merge') assert.equal(p.intent.fields.expected_version, '2');
      assert.equal((await lstat(f.request)).mode & 0o777, 0o700);
      for (const file of ['intent.json', 'candidate.bundle']) assert.equal((await lstat(join(f.request, file))).mode & 0o777, 0o600);
      const sent = await submitPull(p.intent, TOKEN, consent(p.intent, bundle));
      assert.equal(sent.outcome.state, state); assert.equal(sent.publication.decision_sequence, '18446744073709551615');
      const recovered = await recoverPull(p.intent, ROTATED, { known: sent.outcome, publication: sent.publication });
      assert.equal(recovered.outcome.state, state); assert.equal(p.sent, 1);
      assert.equal((await loadCandidatePackage(f.package, f.hash)).capture.preparation.state, 'resolved');
    });
  }
}
test('lost response recovers with original key after both package and saved bundle are removed', async t => {
  const { p, f } = await setup(t, { commandHandle: commands('committed', true) });
  const staged = await stageCandidateReview(selection(f, choice(p)), TOKEN);
  p.intent = await loadPullIntent(f.request); const bundle = await loadPullBundle(f.request, p.intent);
  await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent, bundle)), e => e.dispatched && e.outcomeUnknown);
  await rm(f.package, { recursive: true }); await rm(join(f.request, 'candidate.bundle'));
  const saved = await loadPullIntent(f.request); assert.equal(saved.key, staged.key);
  assert.equal((await recoverPull(saved, ROTATED)).outcome.state, 'committed'); assert.equal(p.sent, 1);
  await assert.rejects(stageCandidateReview(selection(f, choice(p)), TOKEN));
  assert.equal((await loadPullIntent(f.request)).key, staged.key);
});
test('staging does not waive the production sender key, candidate, method or credential confirmations', async t => {
  const { p, f } = await setup(t, { commandHandle: commands() });
  await stageCandidateReview(selection(f, choice(p, 'merge')), TOKEN);
  p.intent = await loadPullIntent(f.request); const bundle = await loadPullBundle(f.request, p.intent), options = consent(p.intent, bundle);
  for (const [token, bad] of [[ROTATED, options], [TOKEN, { ...options, confirmKey: 'wrong' }],
    [TOKEN, { ...options, confirmCandidate: '0'.repeat(40) }], [TOKEN, { ...options, confirmMergeMethod: 'squash' }]]) {
    await assert.rejects(submitPull(p.intent, token, bad));
  }
  assert.equal(p.requests.length, 5); assert.equal(p.sent, undefined);
  assert.equal((await submitPull(p.intent, TOKEN, options)).outcome.state, 'committed');
});
for (const bad of ['pin', 'bundle', 'choice', 'token-mode', 'occupied']) test(`stage ${bad} refuses without creating or replacing a request`, async t => {
  const { p, f } = await setup(t), original = choice(p);
  await writeFile(f.choices, candidateCanonical(original), { mode: 0o600 });
  if (bad === 'pin') f.hash = '0'.repeat(64);
  if (bad === 'bundle') await writeFile(join(f.package, 'candidate.bundle'), 'changed');
  if (bad === 'choice') await writeFile(f.choices, candidateCanonical({ ...original, candidate_commit: '0'.repeat(40) }));
  if (bad === 'token-mode') await chmod(f.token, 0o644);
  if (bad === 'occupied') { await mkdir(f.request, { mode: 0o700 }); await writeFile(join(f.request, 'intent.json'), '{partial', { mode: 0o600 }); }
  const result = await cli(t, args(f)); assert.equal(result.code, 2, result.err); assert.equal(p.requests.length, 5);
  if (bad === 'occupied') assert.equal(await readFile(join(f.request, 'intent.json'), 'utf8'), '{partial');
  else await assert.rejects(lstat(f.request), { code: 'ENOENT' });
});
test('two executable stagers have one immutable request winner', async t => {
  const { p, f } = await setup(t); await writeFile(f.choices, candidateCanonical(choice(p)), { mode: 0o600 });
  const results = await Promise.all([cli(t, args(f)), cli(t, args(f))]);
  const winner = results.filter(r => r.code === 0); assert.equal(winner.length, 1);
  assert.ok([2, 3].includes(results.find(r => r.code !== 0).code));
  assert.equal((await loadPullIntent(f.request)).key, JSON.parse(winner[0].out).key); assert.equal(p.requests.length, 5);
});
test('closed stdout retains the complete staged request and bounded completion receipt', async t => {
  const { p, f } = await setup(t); await writeFile(f.choices, candidateCanonical(choice(p)), { mode: 0o600 });
  const result = await cli(t, args(f), true); assert.equal(result.code, 3, result.err);
  const intent = await loadPullIntent(f.request), receipt = JSON.parse(result.err).completed;
  assert.equal(receipt.key, intent.key); assert.deepEqual(await loadPullBundle(f.request, intent), p.f.bundle);
  assert.equal(result.err.includes(TOKEN), false); assert.equal(p.requests.length, 5);
});
test('stage input mutation and pre-cancellation cannot select a different action or request', async t => {
  const { p, f } = await setup(t), input = selection(f, choice(p)), expected = structuredClone(input);
  const pending = stageCandidateReview(input, TOKEN); input.choices.action = 'merge'; input.request_dir = join(f.root, 'other');
  const done = await pending; assert.equal(done.action, expected.choices.action); assert.equal(done.request_dir, expected.request_dir);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(stageCandidateReview({ ...expected, request_dir: join(f.root, 'cancelled') }, TOKEN, { signal: controller.signal }), /candidate_cancelled/);
  await assert.rejects(lstat(join(f.root, 'cancelled')), { code: 'ENOENT' }); assert.equal(p.requests.length, 5);
});
for (const extra of [['--bundle', 'other'], ['--ca-file', 'other'], ['--endpoint', 'https://other.invalid/repo'], ['--force', 'true']]) {
  test(`offline staging grammar refuses ${extra[0]}`, async t => {
    const { p, f } = await setup(t); await writeFile(f.choices, candidateCanonical(choice(p)), { mode: 0o600 });
    const result = await cli(t, [...args(f), ...extra]); assert.equal(result.code, 2); assert.equal(p.requests.length, 5);
  });
}
test('stage refuses an output inside its source package and leaves that package loadable', async t => {
  const { p, f } = await setup(t); f.request = join(f.package, 'request');
  await assert.rejects(stageCandidateReview(selection(f, choice(p)), TOKEN), /candidate_output_inside_package/);
  await loadCandidatePackage(f.package, f.hash); assert.equal(p.requests.length, 5);
});
test('resolve refuses an output inside its original conflict package', async t => {
  const { p, f, original } = await setup(t);
  const source = await saveCandidatePackage(join(f.root, 'conflict'), original.capture);
  await writeFile(f.choices, candidateCanonical(p.choices), { mode: 0o600 });
  let err = '';
  const code = await run(['resolve', '--package', source.path, '--sha256', source.sha256,
    '--choices', f.choices, '--token-file', f.token, '--output-dir', join(source.path, 'resolved')],
    { output: () => {}, errorOutput: s => { err += s; } });
  assert.equal(code, 2, err); assert.match(err, /candidate_output_inside_package/);
  await loadCandidatePackage(source.path, source.sha256); assert.equal(p.requests.length, 5);
});
test('draft refuses to invalidate its source package by writing a file inside it', async t => {
  const { p, f } = await setup(t); await writeFile(f.choices, candidateCanonical(choice(p)), { mode: 0o600 });
  const result = await cli(t, ['draft', '--package', f.package, '--sha256', f.hash,
    '--choices', f.choices, '--output', join(f.package, 'draft.json')]);
  assert.equal(result.code, 2, result.err); assert.match(result.err, /candidate_output_inside_package/);
  await loadCandidatePackage(f.package, f.hash); assert.equal(p.requests.length, 5);
});

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: ordinary clean candidates stage through the same CLI without resolution`, async t => {
  const p = await candidatePeer(t, { algorithm, method: algorithm === 'sha256' ? 'squash' : 'merge-commit' });
  const root = await mkdtemp(join(tmpdir(), 'fg-stage-clean-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const captured = await capturePullCandidate(p.input, TOKEN), saved = await saveCandidatePackage(join(root, 'package'), captured.capture, captured.bundle);
  // A sibling that shares the source name's prefix is permitted, not a child.
  const f = { root, package: saved.path, hash: saved.sha256, request: join(root, 'package-staged'),
    token: join(root, 'token'), choices: join(root, 'choices.json') };
  await writeFile(f.token, TOKEN, { mode: 0o600 });
  await writeFile(f.choices, candidateCanonical(choice({ f: p.fixture }, 'merge')), { mode: 0o600 });
  const staged = await cli(t, args(f)); assert.equal(staged.code, 0, staged.err);
  const intent = await loadPullIntent(f.request);
  assert.equal(intent.fields.method, p.fixture.method); assert.equal(intent.fields.candidate_commit, p.fixture.candidate);
  assert.deepEqual(await loadPullBundle(f.request, intent), p.fixture.bundle);
  assert.equal((await loadCandidatePackage(f.package, f.hash)).capture.preparation.state, 'clean');
  assert.equal(p.requests.length, 4);
});
