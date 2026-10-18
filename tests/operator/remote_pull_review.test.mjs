import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { preparePull, submitPull, recoverPull, validatePullIntent, parsePullJson } from '../../scripts/operator/remote_pull.mjs';
import { PULL_LIMITS, pullCanonical, pullEnvelope, validatePullBundle, validatePullPublication } from '../../scripts/operator/pull_command.mjs';
import { TOKEN, ROTATED, BUNDLE, reviewInput, reviewPublication, reviewWire, reviewReply, reviewConsent, reviewPeer } from './remote_pull_review_fixture.mjs';
import { input as legacyInput, outcome } from './remote_pull_fixture.mjs';

const cases = [['approve'], ['request-changes'], ['withdraw'], ['merge', 'merge-commit'], ['merge', 'squash']];
// Independent literal framing expectations: do not use the production envelope
// to decide whether production encoded the native two-part grammar correctly.
function expectedUpload(intent, bundle) {
  const boundary = `fg-pull-candidate-${intent.nonce}`;
  return Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${intent.body}\r\n--${boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="candidate.bundle"\r\nContent-Type: application/x-git-bundle\r\n\r\n`), bundle, Buffer.from(`\r\n--${boundary}--\r\n`)]);
}
for (const format of ['sha1', 'sha256']) for (const [action, method] of cases) for (const state of ['committed', 'refused']) {
  test(`${format} ${action}/${method ?? 'review'} ${state}: original-key publication and confirmation`, async t => {
    const p = await reviewPeer(t, { format, action, method, state }), original = structuredClone(p.intent);
    const result = await submitPull(p.intent, TOKEN, reviewConsent(p.intent));
    assert.equal(result.outcome.state, state); assert.equal(result.dispatched, true);
    assert.equal(result.publication.subject.number, '9007199254740993');
    assert.equal(result.publication.subject.policy_epoch, '18446744073709551615');
    assert.equal(result.publication.decision_sequence, '18446744073709551615');
    assert.deepEqual(p.intent, original); assert.equal(p.requests.length, 3);
    const [pre, post, confirm] = p.requests;
    for (const request of p.requests) {
      assert.equal(request.method, 'POST'); assert.equal(request.headers.authorization, `Bearer ${TOKEN}`);
      assert.equal(request.headers['idempotency-key'], p.intent.key); assert.equal(request.headers.cookie, undefined);
    }
    assert.equal(pre.bytes.length, 0); assert.equal(confirm.bytes.length, 0);
    assert.equal(post.headers['content-length'], String(post.bytes.length));
    assert.equal(post.url, `/repo.git/api/v1/pulls/${p.intent.number}/${action === 'merge' ? 'merge' : `reviews/${action}`}`);
    if (action === 'withdraw') {
      assert.equal(post.headers['content-type'], 'application/x-www-form-urlencoded'); assert.deepEqual(post.bytes, Buffer.from(p.intent.body));
      assert.equal(p.intent.bundle, null);
    } else {
      assert.equal(post.headers['content-type'], `multipart/form-data; boundary=fg-pull-candidate-${p.intent.nonce}`);
      assert.deepEqual(post.bytes, expectedUpload(p.intent, BUNDLE));
      assert.deepEqual(p.intent.bundle, { size: BUNDLE.length, sha256: createHash('sha256').update(BUNDLE).digest('hex') });
    }
    const fields = new URLSearchParams(p.intent.body);
    assert.equal(fields.get('principal'), null); assert.equal(fields.get('force'), null);
    assert.equal(fields.get('source_tip'), p.intent.fields.source_tip); assert.equal(fields.get('policy_epoch'), p.intent.fields.policy_epoch);
    if (action === 'merge') {
      assert.equal(fields.get('method'), method); assert.deepEqual(fields.getAll('required_reviewer'), ['5'.repeat(32), '6'.repeat(32)]);
    } else { assert.equal(fields.get('reason'), p.intent.fields.reason); assert.equal(fields.has('method'), false); }
    const again = reviewConsent(p.intent); delete again.bundle;
    const known = await submitPull(p.intent, TOKEN, { ...again, known: result.outcome });
    assert.equal(known.dispatched, false); assert.equal(p.requests.length, 4);
  });
}
test('saved candidate schema is separate; original intents and keys are unchanged', () => {
  const legacy = preparePull(legacyInput('https://forge.test/repo.git'), TOKEN);
  assert.equal(legacy.schema, 'frankengit-remote-pull-intent-v1'); assert.equal('bundle' in legacy, false);
  const { key, ...basis } = legacy;
  assert.equal(key, `fgp1-${legacy.nonce}-${createHash('sha256').update(JSON.stringify(basis)).digest('hex')}`);
  const review = preparePull(reviewInput(legacy.endpoint), TOKEN, BUNDLE);
  assert.equal(review.schema, 'frankengit-remote-pull-candidate-intent-v1'); assert.match(review.key, /^fgpc1-/);
  assert.deepEqual(validatePullIntent(JSON.parse(pullCanonical(review))), review);
  assert.equal(pullCanonical(review).includes(TOKEN), false);
  for (const edit of [x => x.bundle.sha256 = 'f'.repeat(64), x => x.bundle.size++, x => x.bundle.path = '/etc/passwd',
    x => x.fields.candidate_commit = x.fields.source_tip, x => x.schema = legacy.schema, x => delete x.bundle]) {
    const bad = structuredClone(review); edit(bad); assert.throws(() => validatePullIntent(bad));
  }
  assert.throws(() => preparePull(legacyInput(legacy.endpoint), TOKEN, BUNDLE));
});
for (const edit of [
  v => v.fields.pull_request_version = '0', v => v.fields.pull_request_version = '18446744073709551615',
  v => v.fields.policy_epoch = 1, v => v.fields.policy_epoch = '0', v => v.fields.policy_epoch = '18446744073709551616',
  v => v.fields.source_ref = 'refs/tags/no', v => v.fields.target_ref = v.fields.source_ref,
  v => v.fields.merge_base = '0'.repeat(40), v => v.fields.candidate_commit = 'd'.repeat(64),
  v => v.fields.expected_version = '18446744073709551615', v => v.fields.reason = ' ',
  v => v.fields.reason = 'x'.repeat(4097), v => v.fields.reviewer = '5'.repeat(32), v => v.fields.force = true,
  v => v.fields.method = 'squash', v => v.fields.required_reviewers = ['5'.repeat(32)],
]) test(`review grammar refuses ${edit.toString()}`, () => {
  const v = reviewInput('https://forge.test/repo.git'); assert.doesNotThrow(() => preparePull(v, TOKEN, BUNDLE));
  edit(v); assert.throws(() => preparePull(v, TOKEN, BUNDLE));
});
test('merge reviewer set and method must be explicit, distinct and not the submitter', () => {
  const v = reviewInput('https://forge.test/repo.git', 'merge');
  assert.doesNotThrow(() => preparePull(v, TOKEN, BUNDLE));
  for (const edit of [x => delete x.fields.method, x => x.fields.method = 'auto', x => x.fields.reason = 'approve',
    x => x.fields.required_reviewers = [], x => x.fields.required_reviewers.push(x.fields.required_reviewers[0]),
    x => x.fields.required_reviewers = [x.scope.principal_id], x => x.fields.required_reviewers = ['5'.repeat(31)],
    x => x.fields.required_reviewers = new Array(33).fill('5'.repeat(32))]) {
    const bad = structuredClone(v); edit(bad); assert.throws(() => preparePull(bad, TOKEN, BUNDLE));
  }
  const w = reviewInput(v.endpoint, 'withdraw'); assert.doesNotThrow(() => preparePull(w, TOKEN));
  assert.throws(() => preparePull(w, TOKEN, BUNDLE)); w.fields.expected_version = '0'; assert.throws(() => preparePull(w, TOKEN));
});
test('finite binary bounds, exact fingerprints and boundary collisions refuse locally', () => {
  const input = reviewInput('https://forge.test/repo.git');
  for (const bad of [null, Buffer.alloc(0), 'bundle', new Uint8Array(4), Buffer.alloc(PULL_LIMITS.bundle + 1), Buffer.from(new SharedArrayBuffer(4))]) {
    assert.throws(() => preparePull(input, TOKEN, bad));
  }
  const full = Buffer.alloc(PULL_LIMITS.bundle, 255), intent = preparePull(input, TOKEN, full);
  assert.equal(pullEnvelope(intent, full).body.length, expectedUpload(intent, full).length);
  const changed = Buffer.from(full); changed[0] ^= 1; assert.throws(() => validatePullBundle(intent, changed));
  const collision = Buffer.from(`--fg-pull-candidate-${intent.nonce}`), crafted = structuredClone(intent);
  crafted.bundle = { size: collision.length, sha256: createHash('sha256').update(collision).digest('hex') };
  const { key: _, ...basis } = crafted; crafted.key = `fgpc1-${crafted.nonce}-${createHash('sha256').update(JSON.stringify(basis)).digest('hex')}`;
  assert.throws(() => pullEnvelope(crafted, collision), /boundary_collision/);
});
for (const edit of [
  p => p.subject.number = '1', p => p.subject.pull_request_version = '1', p => p.subject.policy_epoch = '1',
  p => p.subject.source_ref = 'refs/heads/other', p => p.subject.target_ref_hex += '00', p => p.subject.source_tip = p.subject.target_tip,
  p => p.merge_base = p.candidate_commit, p => p.candidate_commit = p.subject.source_tip,
  p => p.review_expected_version = '1', p => p.required_reviewers = [], p => p.method = 'merge-commit',
  p => p.repository_incarnation = 'f'.repeat(32), p => p.principal_id = 'f'.repeat(32), p => p.delivery_acknowledged = true,
]) test(`reject mismatched native review receipt: ${edit.toString()}`, async t => {
  const p = await reviewPeer(t, { handle(req, res, s) {
    if (req.url.endsWith('/outcomes')) return false;
    const reply = reviewPublication(s.intent); edit(reply); reviewReply(res, reply); return true;
  } });
  await assert.rejects(submitPull(p.intent, TOKEN, reviewConsent(p.intent)), e => e.outcomeUnknown && e.publication === null);
  assert.equal(p.requests.length, 2);
});
test('merge receipt may not change method, reviewers or review-only fields', () => {
  for (const method of ['merge-commit', 'squash']) {
    const intent = preparePull(reviewInput('https://forge.test/repo.git', 'merge', 'sha256', method), TOKEN, BUNDLE);
    const good = reviewPublication(intent); assert.deepEqual(validatePullPublication(good, intent, 200), good);
    for (const edit of [p => p.method = method === 'squash' ? 'merge-commit' : 'squash', p => delete p.method,
      p => p.required_reviewers.reverse(), p => p.required_reviewers.pop(), p => p.review_expected_version = '0']) {
      const bad = structuredClone(good); edit(bad); assert.throws(() => validatePullPublication(bad, intent, 200));
    }
  }
});
test('candidate and strategy consent and original credential are checked before networking', async t => {
  const p = await reviewPeer(t, { action: 'merge', method: 'squash' });
  for (const edit of [v => delete v.confirmCandidate, v => v.confirmCandidate = p.intent.fields.source_tip,
    v => delete v.confirmMergeMethod, v => v.confirmMergeMethod = 'merge-commit', v => v.confirmFastForward = true,
    v => v.confirmKey = 'wrong']) {
    const opts = reviewConsent(p.intent); edit(opts); await assert.rejects(submitPull(p.intent, TOKEN, opts));
  }
  await assert.rejects(submitPull(p.intent, ROTATED, reviewConsent(p.intent)));
  assert.equal(p.requests.length, 0);
  assert.equal((await submitPull(p.intent, TOKEN, reviewConsent(p.intent))).outcome.state, 'committed');
});
test('binary bytes, form fields, scope and reviewers are detached before preflight', async t => {
  let bytes, submitted;
  const p = await reviewPeer(t, { action: 'merge', handle(req, res, s) {
    if (req.url.endsWith('/outcomes') && !s.published) {
      bytes.fill(0); submitted.fields.required_reviewers.reverse(); submitted.fields.method = 'squash';
      submitted.scope.repository_id = 'f'.repeat(32);
    }
  } });
  submitted = structuredClone(p.intent); bytes = Buffer.from(BUNDLE);
  const result = await submitPull(submitted, TOKEN, reviewConsent(p.intent, bytes));
  assert.equal(result.outcome.state, 'committed'); assert.deepEqual(p.requests[1].bytes, expectedUpload(p.intent, BUNDLE));
});
for (const action of ['approve', 'merge']) test(`${action}: lost reply, same-byte retry, then rotated lookup only`, async t => {
  let writes = 0;
  const p = await reviewPeer(t, { action, handle(req, res, s) {
    if (!req.url.endsWith('/outcomes') && ++writes === 1) { res.destroy(); return true; }
  } });
  await assert.rejects(submitPull(p.intent, TOKEN, reviewConsent(p.intent)), e => e.dispatched && e.outcomeUnknown);
  assert.equal(writes, 1);
  const result = await submitPull(p.intent, TOKEN, reviewConsent(p.intent)); assert.equal(result.outcome.state, 'committed');
  const payloads = p.requests.filter(r => !r.url.endsWith('/outcomes')); assert.equal(payloads.length, 2);
  assert.deepEqual(payloads[0].bytes, payloads[1].bytes); assert.equal(payloads[0].headers['idempotency-key'], payloads[1].headers['idempotency-key']);
  assert.equal((await recoverPull(p.intent, ROTATED, { known: result.outcome })).outcome.state, 'committed');
  assert.equal(writes, 2); assert.equal(p.requests.at(-1).headers.authorization, `Bearer ${ROTATED}`);
});
test('retained publication prevents resend even without bundle and with missing outcome', async t => {
  const p = await reviewPeer(t), pub = reviewPublication(p.intent), options = reviewConsent(p.intent); delete options.bundle;
  await assert.rejects(submitPull(p.intent, TOKEN, { ...options, publication: pub }), e => e.publication?.tx_id === pub.tx_id && !e.dispatched);
  assert.equal(p.requests.length, 1);
  await assert.rejects(submitPull(p.intent, TOKEN, options), e => !e.dispatched && e.phase === 'publication');
  assert.equal(p.requests.length, 2);
});
for (const status of [401, 403, 404, 409, 429, 503]) test(`review endpoint HTTP ${status} without terminal evidence stays unknown`, async t => {
  const p = await reviewPeer(t, { handle(req, res) {
    if (req.url.endsWith('/outcomes')) return false;
    res.writeHead(status, { 'Content-Type': 'application/json' }); res.end('{"type":"error"}'); return true;
  } });
  await assert.rejects(submitPull(p.intent, TOKEN, reviewConsent(p.intent)), e => e.dispatched && e.outcomeUnknown && e.publication === null);
  assert.equal(p.requests.length, 2);
});
test('confirmation conflict preserves the exact native publication', async t => {
  const p = await reviewPeer(t, { action: 'merge', handle(req, res, s) {
    if (req.url.endsWith('/outcomes') && s.published) {
      const o = outcome(s.intent, 'committed'); o.transaction.tx_id = 'other'; reviewReply(res, o); return true;
    }
  } });
  await assert.rejects(submitPull(p.intent, TOKEN, reviewConsent(p.intent)), e => e.phase === 'confirmation' && e.publication?.subject.number === p.intent.number);
});
test('full-width review numbers retain raw integer lexemes; duplicate subjects refuse', () => {
  const intent = preparePull(reviewInput('https://forge.test/repo.git'), TOKEN, BUNDLE), good = reviewPublication(intent);
  assert.deepEqual(parsePullJson(Buffer.from(reviewWire(good)), { wire: true }), good);
  const raw = reviewWire(good).replace('"policy_epoch":18446744073709551615', '"policy_epoch":1,"policy_epoch":18446744073709551615');
  assert.throws(() => parsePullJson(Buffer.from(raw), { wire: true }), /duplicate/);
});
test('one deadline and cancellation own stalled multipart submission', async t => {
  const p = await reviewPeer(t, { handle(req) { return !req.url.endsWith('/outcomes'); } });
  await assert.rejects(submitPull(p.intent, TOKEN, { ...reviewConsent(p.intent), timeoutMs: 80 }), e => e.outcomeUnknown && e.dispatched);
  assert.equal(p.requests.length, 2);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(submitPull(p.intent, TOKEN, { ...reviewConsent(p.intent), signal: controller.signal }), e => !e.dispatched);
  assert.equal(p.requests.length, 2);
});
test('multipart uses verified TLS: private CA succeeds; wrong-name and untrusted endpoints refuse', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'fg-review-tls-')); t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, alt] of [['local', 'IP:127.0.0.1'], ['wrong', 'DNS:wrong.test']]) {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, `${name}.key`),
      '-out', join(dir, `${name}.crt`), '-days', '1', '-subj', `/CN=${name}`, '-addext', `subjectAltName=${alt}`], { stdio: 'ignore', timeout: 15000 });
    const cert = await readFile(join(dir, `${name}.crt`)), key = await readFile(join(dir, `${name}.key`));
    const p = await reviewPeer(t, { action: 'merge', method: 'squash', tls: { key, cert } });
    await assert.rejects(submitPull(p.intent, TOKEN, reviewConsent(p.intent))); assert.equal(p.requests.length, 0);
    if (name === 'local') {
      assert.equal((await submitPull(p.intent, TOKEN, { ...reviewConsent(p.intent), ca: cert })).outcome.state, 'committed');
      assert.deepEqual(p.requests[1].bytes, expectedUpload(p.intent, BUNDLE));
    } else { await assert.rejects(submitPull(p.intent, TOKEN, { ...reviewConsent(p.intent), ca: cert })); assert.equal(p.requests.length, 0); }
  }
});
