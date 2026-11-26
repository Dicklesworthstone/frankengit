// Actual durable clients and CLI processes with native-schema peers. Candidate
// bytes are opaque fixtures; these tests do not execute native series admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, writeFile, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { preparePull, preparePullWithIdentity, validatePullIntent, validatePullPublication,
  pullCanonical, pullHash, pullEnvelope } from '../../scripts/operator/pull_command.mjs';
import { submitPull, recoverPull } from '../../scripts/operator/remote_pull.mjs';
import { capturePullReviews, reviewCanonical } from '../../scripts/operator/pull_review_snapshot.mjs';
import { draftPullReview } from '../../scripts/operator/pull_review_draft.mjs';
import { saveReviewJson } from '../../scripts/operator/pull_review_files.mjs';
import { loadPullIntent, readPullRecord } from '../../scripts/operator/pull_files.mjs';
import { TOKEN, ROTATED, outcome } from './remote_pull_fixture.mjs';
import { BUNDLE, reviewInput, reviewConsent, reviewReply } from './remote_pull_review_fixture.mjs';
import { peer, person } from './pull_review_snapshot_fixture.mjs';

const ACTIONS = ['approve', 'request-changes', 'withdraw', 'merge'];
const IDENTITY = { nonce: '0'.repeat(32), credential_fingerprint: pullHash(TOKEN) };
const bundleFor = action => action === 'withdraw' ? null : BUNDLE;
function input(action, format = 'sha1', method = 'rebase') {
  const value = reviewInput('https://forge.example/repo.git', action, format, method);
  if (action !== 'merge' && method !== undefined) value.fields.method = method;
  return value;
}
function publication(intent, state = 'committed') {
  const fields = intent.fields, format = intent.scope.object_format, merge = intent.action === 'merge';
  const committed = state === 'committed';
  const refs = Object.fromEntries(['source', 'target'].flatMap(side => {
    const bytes = Object.hasOwn(fields, side + '_ref_hex') ? Buffer.from(fields[side + '_ref_hex'], 'hex')
      : Buffer.from(fields[side + '_ref']);
    const display = bytes.toString('utf8');
    return [[side + '_ref', Buffer.from(display).equals(bytes) ? display : null],
      [side + '_ref_hex', bytes.toString('hex')], [side + '_tip', format + ':' + fields[side + '_tip']]];
  }));
  return { type: merge ? 'reviewed_merge_publication' : 'candidate_review_publication', schema_version: 1,
    ...intent.scope, action: intent.action, ...(merge || fields.method === 'rebase' ? { method: fields.method } : {}),
    review_expected_version: merge ? null : fields.expected_version,
    subject: { number: intent.number, pull_request_version: fields.pull_request_version, policy_epoch: fields.policy_epoch, ...refs },
    merge_base: format + ':' + fields.merge_base, candidate_commit: format + ':' + fields.candidate_commit,
    required_reviewers: merge ? [...fields.required_reviewers] : null,
    tx_id: 'native-transaction', outcome: state, decision_sequence: '18446744073709551615',
    repository_commit_id: committed ? 'native-rcr' : null, refusal_record_id: committed ? null : 'native-refusal',
    refusal_code: committed ? null : 'PolicyDenied', refusal_code_point: committed ? null : 17, delivery_acknowledged: null };
}
function choice(action, format = 'sha1') {
  const width = format === 'sha1' ? 40 : 64;
  return { action, principal_id: person(10), method: 'rebase',
    ...(action === 'withdraw' ? {} : { merge_base: 'b'.repeat(width), candidate_commit: 'c'.repeat(width) }),
    ...(action === 'merge' ? { required_reviewers: [person(12)] } : { reason: 'Reviewed every rewritten commit in this exact series.' }) };
}
async function workflow(t, action, format = 'sha1', { terminal = 'committed', drop = false, wrongMethod = false } = {}) {
  let intent, writes = 0;
  const p = await peer(t, { format, byteOnly: true, handle(record, res) {
    if (record.method === 'GET') return false;
    assert.equal(record.headers['idempotency-key'], intent.key);
    if (record.url.pathname.endsWith('/outcomes')) { reviewReply(res, outcome(intent, writes ? terminal : 'key_not_observed')); return true; }
    assert.equal(record.url.pathname, '/repo.git/api/v1/pulls/' + intent.number + '/' +
      (action === 'merge' ? 'merge' : 'reviews/' + action));
    assert.equal(record.headers.authorization, 'Bearer ' + TOKEN);
    assert.deepEqual(record.body, pullEnvelope(intent, bundleFor(action)).body);
    assert.equal(new URLSearchParams(intent.body).get('method'), 'rebase');
    writes++;
    if (drop) res.destroy();
    else {
      const reply = publication(intent, terminal); if (wrongMethod) reply.method = 'squash';
      reviewReply(res, reply, terminal === 'committed' ? 200 : 409);
    }
    return true;
  } });
  const target = Buffer.concat([Buffer.from('refs/heads/main'), Buffer.from([254])]).toString('hex');
  for (const row of [p.native.pull.pull_request.data, ...p.native.reviews.map(r => r.subject)]) {
    row.target_ref = null; row.target_ref_hex = target;
  }
  return { p, install(value) { intent = value; }, get writes() { return writes; } };
}

for (const format of ['sha1', 'sha256']) for (const action of ACTIONS) {
  test(format + ' ' + action + ': explicit rebase changes saved identity and survives exact reload', () => {
    const selected = input(action, format), intent = preparePullWithIdentity(selected, IDENTITY, bundleFor(action));
    const body = new URLSearchParams(intent.body);
    assert.deepEqual(body.getAll('method'), ['rebase']); assert.equal(body.get('candidate_commit'), selected.fields.candidate_commit);
    assert.equal(intent.body.endsWith('&method=rebase'), true);
    const saved = pullCanonical(intent);
    assert.equal(pullCanonical(validatePullIntent(JSON.parse(saved))), saved);
    const ordinary = structuredClone(selected);
    if (action === 'merge') ordinary.fields.method = 'merge-commit'; else delete ordinary.fields.method;
    assert.notEqual(preparePullWithIdentity(ordinary, IDENTITY, bundleFor(action)).key, intent.key);
    for (const method of [undefined, 'merge-commit', 'squash']) {
      const changed = structuredClone(intent);
      if (method === undefined) delete changed.fields.method; else changed.fields.method = method;
      assert.throws(() => validatePullIntent(changed));
    }
  });
  for (const terminal of ['committed', 'refused']) test(format + ' ' + action + ' ' + terminal + ': captured raw subject publishes and recovers the original rebase key', async t => {
    const w = await workflow(t, action, format, { terminal });
    const capture = await capturePullReviews(w.p.selected, TOKEN, { pageLimit: 1 });
    const before = reviewCanonical(capture), draft = draftPullReview(capture, choice(action, format));
    assert.equal(draft.fields.method, 'rebase');
    assert.equal(Object.hasOwn(draft.fields, 'source_ref'), false); assert.equal(Object.hasOwn(draft.fields, 'target_ref'), false);
    const intent = preparePull(draft, TOKEN, bundleFor(action)), saved = pullCanonical(intent); w.install(intent);
    const result = await submitPull(intent, TOKEN, reviewConsent(intent));
    assert.equal(result.outcome.state, terminal); assert.equal(result.publication.method, 'rebase');
    const recovered = await recoverPull(JSON.parse(saved), ROTATED, { known: result.outcome });
    assert.equal(recovered.outcome.state, terminal);
    assert.equal((await submitPull(intent, TOKEN, reviewConsent(intent))).dispatched, false);
    assert.equal(w.writes, 1); assert.equal(pullCanonical(intent), saved); assert.equal(reviewCanonical(capture), before);
  });
  test(format + ' ' + action + ': terminal receipt cannot omit or substitute the saved method', () => {
    const intent = preparePullWithIdentity(input(action, format), IDENTITY, bundleFor(action));
    for (const state of ['committed', 'refused']) {
      const receipt = publication(intent, state), status = state === 'committed' ? 200 : 409;
      assert.deepEqual(validatePullPublication(receipt, intent, status), receipt);
      for (const method of [undefined, null, '', 'merge-commit', 'squash', 'Rebase', 'rebase/v1']) {
        const bad = structuredClone(receipt); if (method === undefined) delete bad.method; else bad.method = method;
        assert.throws(() => validatePullPublication(bad, intent, status));
      }
    }
    if (action !== 'merge') {
      const ordinary = input(action, format); delete ordinary.fields.method;
      const old = preparePullWithIdentity(ordinary, IDENTITY, bundleFor(action));
      assert.throws(() => validatePullPublication({ ...publication(old), method: 'rebase' }, old, 200));
    }
  });
}
for (const action of ACTIONS) test(action + ': lost rebase reply recovers without replay or the original bundle', async t => {
  const w = await workflow(t, action, 'sha256', { drop: true });
  const capture = await capturePullReviews(w.p.selected, TOKEN);
  const intent = preparePull(draftPullReview(capture, choice(action, 'sha256')), TOKEN, bundleFor(action)); w.install(intent);
  await assert.rejects(submitPull(intent, TOKEN, reviewConsent(intent)), e => e.dispatched && e.outcomeUnknown);
  const recovered = await recoverPull(intent, ROTATED); assert.equal(recovered.outcome.state, 'committed');
  const { bundle: _, ...consent } = reviewConsent(intent);
  assert.equal((await submitPull(intent, TOKEN, { ...consent, known: recovered.outcome })).dispatched, false);
  assert.equal(w.writes, 1);
});
for (const action of ACTIONS) test(action + ': a foreign method receipt remains unknown until original-key recovery', async t => {
  const w = await workflow(t, action, 'sha1', { wrongMethod: true });
  const capture = await capturePullReviews(w.p.selected, TOKEN);
  const intent = preparePull(draftPullReview(capture, choice(action)), TOKEN, bundleFor(action)); w.install(intent);
  await assert.rejects(submitPull(intent, TOKEN, reviewConsent(intent)), e => e.dispatched && e.outcomeUnknown && e.publication === null);
  assert.equal((await recoverPull(intent, ROTATED)).outcome.state, 'committed');
  assert.equal((await submitPull(intent, TOKEN, reviewConsent(intent))).dispatched, false); assert.equal(w.writes, 1);
});
for (const action of ACTIONS) test(action + ': invalid method choices refuse without changing the ordinary review profile', async t => {
  const p = await peer(t), capture = await capturePullReviews(p.selected, TOKEN);
  for (const method of [null, '', 'Rebase', 'rebase/v1', 'auto', ...(action === 'merge' ? [] : ['merge-commit', 'squash'])]) {
    const selected = input(action); selected.fields.method = method;
    assert.throws(() => preparePull(selected, TOKEN, bundleFor(action)));
    assert.throws(() => draftPullReview(capture, { ...choice(action), method }));
  }
  if (action !== 'merge') {
    const selected = choice(action); delete selected.method;
    const ordinary = draftPullReview(capture, selected);
    assert.equal(Object.hasOwn(ordinary.fields, 'method'), false);
    assert.equal(new URLSearchParams(preparePull(ordinary, TOKEN, bundleFor(action)).body).has('method'), false);
  } else {
    const selected = choice(action); delete selected.method;
    assert.throws(() => draftPullReview(capture, selected));
  }
});
test('a stale withdrawal retains its original series subject and needs an explicit rebase choice', async t => {
  const w = await workflow(t, 'withdraw', 'sha256'), old = w.p.native.reviews[0];
  old.subject.pull_request_version = '2'; old.subject.policy_epoch = '1';
  old.subject.source_tip = 'sha256:' + 'e'.repeat(64); old.candidate.candidate_commit = 'sha256:' + 'f'.repeat(64);
  old.freshness = 'pull_request_changed';
  const capture = await capturePullReviews(w.p.selected, TOKEN), selected = choice('withdraw', 'sha256');
  const draft = draftPullReview(capture, selected);
  assert.equal(draft.fields.method, 'rebase'); assert.equal(draft.fields.pull_request_version, '2');
  assert.equal(draft.fields.policy_epoch, '1'); assert.equal(draft.fields.source_tip, 'e'.repeat(64));
  assert.equal(draft.fields.candidate_commit, 'f'.repeat(64)); assert.equal(draft.fields.expected_version, old.version);
  delete selected.method; assert.equal(Object.hasOwn(draftPullReview(capture, selected).fields, 'method'), false);
  const intent = preparePull(draft, TOKEN); w.install(intent);
  assert.equal((await submitPull(intent, TOKEN, reviewConsent(intent))).outcome.state, 'committed');
});
test('rebase merge requires its exact explicit confirmation before any network operation', async t => {
  const w = await workflow(t, 'merge'), capture = await capturePullReviews(w.p.selected, TOKEN);
  const intent = preparePull(draftPullReview(capture, choice('merge')), TOKEN, BUNDLE); w.install(intent);
  const before = w.p.requests.length;
  for (const method of [undefined, 'merge-commit', 'squash']) {
    const consent = reviewConsent(intent); if (method === undefined) delete consent.confirmMergeMethod; else consent.confirmMergeMethod = method;
    await assert.rejects(submitPull(intent, TOKEN, consent), { code: 'explicit_reviewed_merge_method_required' });
    assert.equal(w.p.requests.length, before);
  }
  assert.equal((await submitPull(intent, TOKEN, reviewConsent(intent))).outcome.state, 'committed');
});

async function cli(script, args) {
  try { return { code: 0, ...await promisify(execFile)(process.execPath, [resolve(script), ...args], { timeout: 10000, maxBuffer: 2 * 1024 * 1024 }) }; }
  catch (error) { return { code: error.code, stdout: error.stdout, stderr: error.stderr }; }
}
for (const action of ACTIONS) test(action + ': private CLI draft, prepare, send and rotated recovery retain exact rebase custody', async t => {
  const w = await workflow(t, action, 'sha256'), capture = await capturePullReviews(w.p.selected, TOKEN);
  const root = await realpath(await mkdtemp(join(tmpdir(), 'fg-rebase-pull-'))); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = name => join(root, name), captured = await saveReviewJson(path('capture.json'), capture);
  for (const [name, data] of [['choice.json', reviewCanonical(choice(action, 'sha256'))], ['token', TOKEN + '\n'],
    ['rotated', ROTATED + '\n'], ['series.bundle', BUNDLE]]) await writeFile(path(name), data, { mode: 0o600 });
  const reads = w.p.requests.length;
  const drafted = await cli('scripts/fg_pull_review.mjs', ['draft', '--capture', path('capture.json'), '--sha256', captured.sha256,
    '--input', path('choice.json'), '--output', path('draft.json')]);
  assert.equal(drafted.code, 0, drafted.stderr); assert.equal(w.p.requests.length, reads);
  assert.equal(JSON.parse(drafted.stdout).publication_attempted, false);
  const ready = await cli('scripts/remote_pull.mjs', ['prepare', '--input', path('draft.json'), '--token-file', path('token'),
    '--request-dir', path('request'), ...(action === 'withdraw' ? [] : ['--bundle', path('series.bundle')])]);
  assert.equal(ready.code, 0, ready.stderr); assert.equal(w.p.requests.length, reads);
  const intent = await loadPullIntent(path('request')), before = await readFile(path('request/intent.json')); w.install(intent);
  assert.equal(intent.fields.method, 'rebase'); await rm(path('series.bundle'));
  const args = ['send', '--request-dir', path('request'), '--token-file', path('token'), '--confirm-key', intent.key,
    '--confirm-candidate', intent.fields.candidate_commit, ...(action === 'merge' ? ['--confirm-merge-method', 'rebase'] : [])];
  const sent = await cli('scripts/remote_pull.mjs', [...args, '--record', path('result.json')]); assert.equal(sent.code, 0, sent.stderr);
  const retained = await readPullRecord(path('result.json'), intent);
  assert.equal(retained.outcome.state, 'committed'); assert.equal(retained.publication.method, 'rebase');
  if (action !== 'withdraw') await rm(path('request/candidate.bundle'));
  const recovered = await cli('scripts/remote_pull.mjs', ['recover', '--request-dir', path('request'), '--token-file', path('rotated'),
    '--known', path('result.json'), '--record', path('recovered.json')]); assert.equal(recovered.code, 0, recovered.stderr);
  assert.equal(JSON.parse(recovered.stdout).outcome.state, 'committed');
  const known = await cli('scripts/remote_pull.mjs', [...args, '--known', path('result.json'), '--record', path('known.json')]);
  assert.equal(known.code, 0, known.stderr); assert.equal(w.writes, 1);
  assert.deepEqual(await readFile(path('request/intent.json')), before);
});
