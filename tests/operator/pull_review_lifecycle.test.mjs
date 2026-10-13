// Complete reader/drafter/sender modules with real sockets and CLI processes.
// The peer below checks wire contracts; it is not native Rust admission/policy.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, chmod, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { capturePullReviews, reviewCanonical } from '../../scripts/operator/pull_review_snapshot.mjs';
import { draftPullReview } from '../../scripts/operator/pull_review_draft.mjs';
import { saveReviewJson } from '../../scripts/operator/pull_review_files.mjs';
import { preparePull, validatePullIntent, pullEnvelope } from '../../scripts/operator/pull_command.mjs';
import { submitPull, recoverPull } from '../../scripts/operator/remote_pull.mjs';
import { peer, TOKEN, person, VERSION, EPOCH } from './pull_review_snapshot_fixture.mjs';
const exec = promisify(execFile), ACTIONS = ['update', 'close', 'reopen', 'fast-forward'];
const CLI = resolve('scripts/fg_pull_review.mjs'), ROTATED = 'f'.repeat(64);
const choice = action => ({ action, principal_id: person(10), ...(action === 'update' ? { title: 'Edited title 🦀' } : {}) });
const wire = value => JSON.stringify(value, (key, data) => ['number', 'expected_version', 'review_expected_version',
  'pull_request_version', 'policy_epoch', 'decision_sequence'].includes(key) && typeof data === 'string' ? JSON.rawJSON(data) : data);
function reply(res, value, status = 200) { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(wire(value)); }
function observation(intent, state = null) {
  const { object_format: _, ...scope } = intent.scope;
  return { type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null,
    state: state ?? 'key_not_observed', terminal: state !== null,
    transaction: state === null ? null : { tx_id: 'peer-tx', seal_id: 'peer-seal', request_schema: 'peer-native-command-v1',
      canonical_request_digest: { algorithm: 1, hex: 'e'.repeat(64) } },
    decision: state === null ? null : { kind: state, decision_sequence: EPOCH,
      ...(state === 'committed' ? { repository_commit_id: 'peer-rcr' } : { code: 'PolicyDenied', code_point: 17, refusal_record_id: 'peer-refusal' }) },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
function nativePublication(intent, form, state) {
  const ff = intent.action === 'fast-forward', review = ['approve', 'request-changes', 'withdraw', 'merge'].includes(intent.action);
  const refs = Object.fromEntries(['source', 'target'].flatMap(side => [[`${side}_ref`, form.get(`${side}_ref`)],
    [`${side}_ref_hex`, Buffer.from(form.get(`${side}_ref`)).toString('hex')],
    [`${side}_tip`, `${intent.scope.object_format}:${form.get(`${side}_tip`)}`]]));
  const coords = review ? { subject: { number: intent.number, pull_request_version: form.get('pull_request_version'),
    policy_epoch: form.get('policy_epoch'), ...refs }, merge_base: `${intent.scope.object_format}:${form.get('merge_base')}`,
    candidate_commit: `${intent.scope.object_format}:${form.get('candidate_commit')}`,
    review_expected_version: intent.action === 'merge' ? null : form.get('expected_version'),
    required_reviewers: intent.action === 'merge' ? form.getAll('required_reviewer') : null,
    ...(intent.action === 'merge' ? { method: form.get('method') } : {}) }
    : { number: intent.number, ...(ff ? { pull_request_version: form.get('pull_request_version'), ...refs }
      : { expected_version: form.get('expected_version') }) };
  return { type: review ? (intent.action === 'merge' ? 'reviewed_merge_publication' : 'candidate_review_publication')
    : ff ? 'fast_forward_merge_publication' : 'pull_request_publication', schema_version: 1, ...intent.scope,
    action: intent.action, ...coords, tx_id: 'peer-tx', outcome: state, decision_sequence: EPOCH,
    repository_commit_id: state === 'committed' ? 'peer-rcr' : null, refusal_record_id: state === 'committed' ? null : 'peer-refusal',
    refusal_code: state === 'committed' ? null : 'PolicyDenied', refusal_code_point: state === 'committed' ? null : 17,
    delivery_acknowledged: null };
}
async function workflow(t, action, format, terminal = 'committed', drop = false) {
  let intent, writes = 0, published = false, posted;
  const p = await peer(t, { format, state: action === 'reopen' ? 'closed' : 'open', handle(record, res) {
    if (record.method === 'GET') return false;
    assert.equal(record.headers['idempotency-key'], intent.key);
    if (record.url.pathname.endsWith('/outcomes')) { assert.equal(record.body.length, 0); reply(res, observation(intent, published ? terminal : null)); return true; }
    const review = ['approve', 'request-changes', 'withdraw'].includes(action);
    assert.equal(record.url.pathname, `/repo.git/api/v1/pulls/${intent.number}/${review ? 'reviews/' : ''}${action}`);
    writes++; published = true; posted = record;
    let body = record.body.toString('utf8');
    if (record.headers['content-type'].startsWith('multipart/')) {
      // Parse just the independently specified command part for the receipt;
      // opaque bundle bytes are not claimed to be a valid Git candidate.
      const start = body.indexOf('\r\n\r\n') + 4, end = body.indexOf('\r\n--', start);
      assert.ok(start >= 4 && end > start); body = body.slice(start, end);
    }
    const form = new URLSearchParams(body);
    assert.equal(form.get('principal_id'), null); assert.equal(form.get('force'), null);
    if (drop) res.destroy(); else reply(res, nativePublication(intent, form, terminal), terminal === 'committed' ? 200 : 409);
    return true;
  } });
  const capture = await capturePullReviews(p.selected, TOKEN, { pageLimit: 2 });
  return { p, capture, install(value) { intent = value; }, get writes() { return writes; }, get posted() { return posted; } };
}
for (const format of ['sha1', 'sha256']) for (const action of ACTIONS) for (const terminal of ['committed', 'refused']) {
  test(`${format} ${action}: capture, draft, real sender ${terminal} and same-key recovery`, async t => {
    const w = await workflow(t, action, format, terminal), before = reviewCanonical(w.capture);
    const draft = draftPullReview(w.capture, choice(action)), intent = preparePull(draft, TOKEN); w.install(intent);
    assert.deepEqual(validatePullIntent(intent), intent);
    const f = new URLSearchParams(intent.body), version = action === 'fast-forward' ? 'pull_request_version' : 'expected_version';
    assert.equal(f.get(version), VERSION); assert.equal(f.get('source_tip'), 'a'.repeat(format === 'sha1' ? 40 : 64));
    assert.equal(f.get('target_tip'), 'b'.repeat(format === 'sha1' ? 40 : 64));
    assert.equal(f.get('object_format'), format); assert.equal(f.get('source_ref'), 'refs/heads/topic');
    if (action !== 'fast-forward') {
      assert.equal(f.get('body'), w.capture.pull.pull_request.data.body);
      assert.equal(f.get('title'), action === 'update' ? choice(action).title : w.capture.pull.pull_request.data.title);
    } else { assert.equal(f.get('title'), null); assert.equal(f.get('body'), null); }
    assert.equal(w.writes, 0); assert.equal(reviewCanonical(w.capture), before);
    const consent = { confirmKey: intent.key, ...(action === 'fast-forward' ? { confirmFastForward: true } : {}) };
    if (action === 'fast-forward') {
      const n = w.p.requests.length; await assert.rejects(submitPull(intent, TOKEN, { confirmKey: intent.key })); assert.equal(w.p.requests.length, n);
    }
    const result = await submitPull(intent, TOKEN, consent);
    assert.equal(result.outcome.state, terminal); assert.equal(w.writes, 1); assert.equal(w.posted.body.toString(), intent.body);
    assert.equal((await recoverPull(intent, ROTATED, { known: result.outcome })).outcome.state, terminal);
    assert.equal((await submitPull(intent, TOKEN, { ...consent, known: result.outcome })).dispatched, false);
    assert.equal(w.writes, 1); assert.equal(reviewCanonical(w.capture), before);
  });
}
for (const format of ['sha1', 'sha256']) for (const action of ['approve', 'request-changes', 'withdraw', 'merge-commit', 'squash']) {
  test(`${format} ${action}: recovered review drafts integrate with unchanged candidate sender`, async t => {
    const merge = ['merge-commit', 'squash'].includes(action), operation = merge ? 'merge' : action;
    const w = await workflow(t, operation, format), length = format === 'sha1' ? 40 : 64;
    const selected = { principal_id: person(10), action: operation,
      ...(operation === 'withdraw' ? {} : { merge_base: 'b'.repeat(length), candidate_commit: 'c'.repeat(length) }),
      ...(merge ? { method: action, required_reviewers: [person(12)] } : { reason: 'Explicit reviewed choice.' }) };
    const draft = draftPullReview(w.capture, selected), bundle = operation === 'withdraw' ? null : Buffer.from('opaque bundle fixture');
    const intent = preparePull(draft, TOKEN, bundle); w.install(intent);
    assert.equal(draft.fields.expected_version, merge ? undefined : VERSION);
    const result = await submitPull(intent, TOKEN, { confirmKey: intent.key, confirmCandidate: draft.fields.candidate_commit,
      ...(merge ? { confirmMergeMethod: action } : {}), ...(bundle ? { bundle } : {}) });
    assert.equal(result.outcome.state, 'committed'); assert.equal(w.writes, 1);
    assert.equal(result.publication.subject.policy_epoch, EPOCH);
    assert.equal((await recoverPull(intent, ROTATED)).outcome.state, 'committed');
  });
}
test('lost reply from a snapshot-derived close recovers with a rotated credential and no duplicate', async t => {
  const w = await workflow(t, 'close', 'sha1', 'committed', true);
  const intent = preparePull(draftPullReview(w.capture, choice('close')), TOKEN); w.install(intent);
  await assert.rejects(submitPull(intent, TOKEN, { confirmKey: intent.key }), e => e.dispatched && e.outcomeUnknown);
  assert.equal((await recoverPull(intent, ROTATED)).outcome.state, 'committed'); assert.equal(w.writes, 1);
});
for (const action of ACTIONS) test(`${action}: wrong lifecycle state and byte-only forms refuse`, async t => {
  const bad = await peer(t, { state: action === 'reopen' ? 'open' : 'closed' });
  const c = await capturePullReviews(bad.selected, TOKEN);
  assert.throws(() => draftPullReview(c, choice(action)), { code: 'pull_draft_state_conflict' });
  const p = await peer(t, { state: action === 'reopen' ? 'closed' : 'open', byteOnly: true });
  const bytes = await capturePullReviews(p.selected, TOKEN);
  assert.throws(() => draftPullReview(bytes, choice(action)), { code: 'byte_only_review_form_unsupported' });
});
test('an edit distinguishes omitted fields from empty replacement and detaches all caller changes', async t => {
  const p = await peer(t), c = await capturePullReviews(p.selected, TOKEN), saved = reviewCanonical(c);
  const selected = { ...choice('update'), title: 'a'.repeat(256), body: '' }, draft = draftPullReview(c, selected);
  assert.equal(draft.fields.body, ''); assert.equal(draft.fields.title.length, 256);
  selected.title = 'changed'; c.pull.pull_request.data.title = 'other';
  assert.equal(draft.fields.title.length, 256); assert.equal(preparePull(draft, TOKEN).fields.body, '');
  const original = JSON.parse(saved);
  const bodyOnly = draftPullReview(original, { action: 'update', principal_id: person(10), body: 'é'.repeat(32768) });
  assert.equal(bodyOnly.fields.title, original.pull.pull_request.data.title); assert.ok(pullEnvelope(preparePull(bodyOnly, TOKEN)).body.length > 65536);
  assert.throws(() => draftPullReview(original, { action: 'update', principal_id: person(10) }));
  assert.throws(() => draftPullReview(original, { ...choice('update'), title: 'a'.repeat(257) }));
  assert.throws(() => draftPullReview(original, { ...choice('update'), body: 'é'.repeat(32769) }));
});
for (const [key, value] of [['source_tip', 'c'.repeat(40)], ['target_ref', 'refs/heads/other'], ['expected_version', '0'],
  ['method', 'squash'], ['force', true], ['body', 'replacement'], ['principal', person(99)]]) {
  test(`close cannot override captured ${key}`, async t => {
    const p = await peer(t), c = await capturePullReviews(p.selected, TOKEN);
    assert.throws(() => draftPullReview(c, { ...choice('close'), [key]: value }));
  });
}
test('missing and merged PRs are not reopened, while exhausted versions and equal FF tips refuse', async t => {
  for (const options of [{ found: false }, { state: 'merged' }, { state: 'merged', legacyMerge: true }]) {
    const p = await peer(t, options), c = await capturePullReviews(p.selected, TOKEN);
    for (const action of ACTIONS) assert.throws(() => draftPullReview(c, choice(action)));
  }
  const p = await peer(t, { count: 0 }), c = await capturePullReviews(p.selected, TOKEN);
  c.pull.pull_request.version = EPOCH; c.review_pages[0].pull_request_version = EPOCH;
  assert.throws(() => draftPullReview(c, choice('close')), { code: 'review_version_exhausted' });
  c.pull.pull_request.version = VERSION; c.review_pages[0].pull_request_version = VERSION;
  c.pull.pull_request.data.source_tip = c.pull.pull_request.data.target_tip;
  assert.throws(() => draftPullReview(c, choice('fast-forward')), { code: 'pull_draft_already_up_to_date' });
  assert.equal(draftPullReview(c, choice('close')).action, 'close');
});
for (const action of ACTIONS) test(`${action}: private offline CLI draft is accepted by the real preparer`, async t => {
  const p = await peer(t, { state: action === 'reopen' ? 'closed' : 'open', format: 'sha256' });
  const c = await capturePullReviews(p.selected, TOKEN), root = await mkdtemp(join(tmpdir(), 'fg-review-lifecycle-'));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const capture = join(root, 'capture.json'), input = join(root, 'choice.json'), output = join(root, 'draft.json');
  const saved = await saveReviewJson(capture, c); await writeFile(input, reviewCanonical(choice(action)), { mode: 0o600 });
  const before = p.requests.length;
  const result = await exec(process.execPath, [CLI, 'draft', '--capture', capture, '--sha256', saved.sha256,
    '--input', input, '--output', output], { timeout: 10000, maxBuffer: 65536 });
  const receipt = JSON.parse(result.stdout), draft = JSON.parse(await readFile(output, 'utf8'));
  assert.equal(receipt.publication_attempted, false); assert.equal(receipt.source_capture_sha256, saved.sha256);
  assert.equal(preparePull(draft, TOKEN).action, action); assert.equal(p.requests.length, before);
  assert.equal(result.stdout.includes(TOKEN), false);
});

for (const [name, body, refused, padding = ''] of [
  ['full ASCII body', 'x'.repeat(65536), false],
  ['full multibyte body', 'é'.repeat(32768), false],
  ['full JSON-escaped body', '\u0001'.repeat(65536), false],
  ['ASCII byte overflow', 'x'.repeat(65537), true],
  ['multibyte byte overflow', 'é'.repeat(32769), true],
  ['oversized choice envelope', 'valid', true, ' '.repeat(512 * 1024)],
]) test(`native-size CLI edit: ${name}`, async t => {
  const w = await workflow(t, 'update', 'sha256');
  const root = await mkdtemp(join(tmpdir(), 'fg-review-body-'));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const capture = join(root, 'capture.json'), input = join(root, 'choice.json'), output = join(root, 'draft.json');
  const saved = await saveReviewJson(capture, w.capture);
  await writeFile(input, padding + reviewCanonical({ action: 'update', principal_id: person(10), body }), { mode: 0o600 });
  const before = w.p.requests.length;
  const execute = () => exec(process.execPath, [CLI, 'draft', '--capture', capture, '--sha256', saved.sha256,
    '--input', input, '--output', output], { timeout: 10000, maxBuffer: 65536 });
  if (refused) {
    await assert.rejects(execute(), e => e.code === 2);
    await assert.rejects(readFile(output), { code: 'ENOENT' });
  } else {
    const result = await execute(), draft = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(JSON.parse(result.stdout).publication_attempted, false);
    assert.equal(draft.fields.body, body);
    assert.equal(draft.fields.title, w.capture.pull.pull_request.data.title);
    assert.equal(draft.fields.expected_version, VERSION);
    assert.equal(w.p.requests.length, before);
    const intent = preparePull(draft, TOKEN); w.install(intent);
    assert.equal((await submitPull(intent, TOKEN, { confirmKey: intent.key })).outcome.state, 'committed');
    assert.equal(new URLSearchParams(w.posted.body.toString()).get('body'), body);
    assert.equal(w.writes, 1);
  }
  if (refused) { assert.equal(w.writes, 0); assert.equal(w.p.requests.length, before); }
});
