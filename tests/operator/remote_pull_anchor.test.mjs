// Real sockets and explicit native-schema receipts; native Git/source admission
// is independently responsible for authenticating these original coordinates.
import test from 'node:test';
import assert from 'node:assert/strict';
import { preparePull, submitPull, recoverPull, validatePullIntent, parsePullJson, PullError } from '../../scripts/operator/remote_pull.mjs';
import { preparePullWithIdentity, pullTokenFingerprint, validatePullPublication } from '../../scripts/operator/pull_command.mjs';
import { TOKEN, ROTATED, input, commentAnchor, publication, wire, peer, respond, consent } from './remote_pull_fixture.mjs';

function anchoredInput(endpoint, action = 'append-comment', algorithm = 'sha1') {
  const value = input(endpoint, action, algorithm); value.fields.anchor = commentAnchor(algorithm); return value;
}
async function anchoredPeer(t, options = {}) {
  const p = await peer(t, { action: 'append-comment', ...options });
  p.intent = preparePull(anchoredInput(p.endpoint, p.intent.action, p.intent.scope.object_format), TOKEN);
  return p;
}
for (const algorithm of ['sha1', 'sha256']) for (const action of ['comment', 'append-comment']) for (const state of ['committed', 'refused']) {
  test(`${algorithm} anchored ${action}: exact native form, ${state} receipt and original-key confirmation`, async t => {
    const p = await anchoredPeer(t, { algorithm, action, state }), saved = structuredClone(p.intent);
    const result = await submitPull(p.intent, TOKEN, consent(p.intent));
    assert.equal(result.outcome.state, state); assert.equal(result.dispatched, true);
    assert.equal(result.publication.anchor.pull_request_version, '18446744073709551615');
    assert.equal(result.publication.anchor.source_tip, `${algorithm}:${saved.fields.anchor.source_tip}`);
    assert.equal(result.publication.anchor.byte_start, '2'); assert.equal(result.publication.anchor.byte_end, '7');
    assert.equal(result.publication.anchor.line_start, '1'); assert.equal(result.publication.anchor.line_count, '2');
    const post = p.requests[1], fields = [...new URLSearchParams(post.body)];
    assert.equal(post.url, `/repo.git/api/v1/pulls/${saved.number}/comments${action === 'append-comment' ? '/append' : ''}`);
    assert.deepEqual(fields, [
      ...(action === 'comment' ? [['expected_version', '0']] : []), ['body', saved.fields.body],
      ['anchor_pull_request_version', '18446744073709551615'],
      ['anchor_source_ref_hex', '726566732f68656164732f746f706963ff'], ['anchor_target_ref_hex', '726566732f68656164732f6d61696e'],
      ['anchor_source_tip', 'a'.repeat(algorithm === 'sha1' ? 40 : 64)], ['anchor_target_tip', 'b'.repeat(algorithm === 'sha1' ? 40 : 64)],
      ['anchor_compared_base', 'b'.repeat(algorithm === 'sha1' ? 40 : 64)], ['anchor_comparison', 'direct'],
      ['anchor_path_hex', '7372632fff2e7273'], ['anchor_side', 'after'], ['anchor_blob', 'c'.repeat(algorithm === 'sha1' ? 40 : 64)],
      ['anchor_mode', '100755'], ['anchor_byte_start', '2'], ['anchor_byte_end', '7'], ['anchor_line_start', '1'], ['anchor_line_count', '2'],
    ]);
    assert.equal(result.publication.expected_version, action === 'comment' ? '0' : null);
    assert.equal(result.publication.comment_version, action === 'comment' && state === 'committed' ? '1' : null);
    assert.equal(result.publication.refs_changed, false); assert.deepEqual(p.intent, saved);
    const replay = await submitPull(saved, TOKEN, consent(saved, { known: result.outcome, publication: result.publication }));
    assert.equal(replay.dispatched, false); assert.equal(p.requests.filter(r => !r.url.endsWith('/outcomes')).length, 1);
  });
}
test('native numeric source spans and full u64 PR version parse exactly before receipt validation', () => {
  const intent = preparePull(anchoredInput('https://forge.test/repo.git'), TOKEN), native = wire(publication(intent));
  assert.match(native, /"pull_request_version":18446744073709551615[,}]/);
  for (const [name, value] of [['byte_start', 2], ['byte_end', 7], ['line_start', 1], ['line_count', 2]]) {
    assert.match(native, new RegExp(`"${name}":${value}[,}]`));
  }
  const decoded = parsePullJson(Buffer.from(native), { wire: true });
  assert.equal(decoded.anchor.pull_request_version, '18446744073709551615');
  assert.deepEqual(validatePullPublication(decoded, intent, 200), publication(intent));
});
test('saved anchor coordinates detach caller edits and participate in the original key', () => {
  const value = anchoredInput('https://forge.test/repo.git'), identity = {
    nonce: '01'.repeat(16), credential_fingerprint: pullTokenFingerprint(TOKEN) };
  const original = preparePullWithIdentity(value, identity), saved = structuredClone(original);
  value.fields.anchor.path_hex = '6f74686572';
  assert.deepEqual(original, saved);
  assert.notEqual(preparePullWithIdentity(value, identity).key, original.key);
  for (const change of [a => a.path_hex = '6f74686572', a => a.pull_request_version = '2',
    a => a.blob = 'd'.repeat(40), a => { a.byte_end = '8'; }]) {
    const changed = anchoredInput(original.endpoint); change(changed.fields.anchor);
    const resealed = preparePullWithIdentity(changed, identity);
    assert.notEqual(resealed.key, original.key);
    assert.throws(() => validatePullIntent({ ...resealed, key: original.key }), /pull_intent_changed/);
  }
  const plain = preparePullWithIdentity(input(original.endpoint, 'append-comment'), identity);
  assert.notEqual(plain.key, original.key);
  assert.throws(() => validatePullIntent({ ...plain, key: original.key }), /pull_intent_changed/);
  assert.deepEqual(validatePullIntent(JSON.parse(JSON.stringify(original))), original);
});
test('invalid anchor errors retain the public PullError boundary and cannot enter metadata commands', () => {
  for (const anchor of [null, {}, { ...commentAnchor(), profile: 'unknown' }, { ...commentAnchor(), anchor_status: 'exact' }]) {
    const value = anchoredInput('https://forge.test/repo.git'); value.fields.anchor = anchor;
    assert.throws(() => preparePull(value, TOKEN), e => e instanceof PullError && e.code.startsWith('invalid_pull_anchor_'));
  }
  const value = input('https://forge.test/repo.git', 'open'); value.fields.anchor = commentAnchor();
  assert.throws(() => preparePull(value, TOKEN), /invalid_pull_fields/);
});
for (const action of ['comment', 'append-comment']) test(`${action}: receipt must echo only the complete original source anchor`, async t => {
  let mutation = value => value;
  const p = await anchoredPeer(t, { action, handle(r, res, s) {
    if (!r.url.endsWith('/outcomes')) { respond(res, mutation(publication(s.intent))); return true; }
  } });
  for (const edit of [v => { delete v.anchor; }, v => v.anchor_status = 'exact',
    v => v.anchor.path_hex = '6f74686572', v => v.anchor.pull_request_version = '2',
    v => v.anchor.byte_end = '8', v => v.anchor.blob = `sha1:${'d'.repeat(40)}`,
    v => v.anchor.profile = 'unknown', v => v.anchor.extra = true]) {
    mutation = value => { edit(value); return value; };
    await assert.rejects(submitPull(p.intent, TOKEN, consent(p.intent)), e =>
      e instanceof PullError && e.phase === 'publication' && e.dispatched && e.publication === null && e.outcomeUnknown);
  }
  mutation = value => value;
  // A valid native echo is accepted at the same closed parsing boundary.
  assert.deepEqual(validatePullPublication(publication(p.intent), p.intent, 200), publication(p.intent));
  const plain = preparePull(input(p.endpoint, action), TOKEN);
  assert.throws(() => validatePullPublication(publication(p.intent), plain, 200));
});
for (const action of ['comment', 'append-comment']) test(`${action}: lost anchored response recovers under rotation without refreshing source`, async t => {
  const p = await anchoredPeer(t, { action, algorithm: 'sha256', handle(r, res, s) {
    if (!r.url.endsWith('/outcomes')) { s.published = true; res.destroy(); return true; }
  } });
  const saved = structuredClone(p.intent);
  await assert.rejects(submitPull(saved, TOKEN, consent(saved)), e => e.dispatched && e.outcomeUnknown);
  const result = await recoverPull(saved, ROTATED);
  assert.equal(result.outcome.state, 'committed'); assert.equal(result.dispatched, false); assert.equal(result.publication, null);
  assert.deepEqual(saved, p.intent); assert.equal(p.requests.length, 3);
  assert.equal(p.requests.at(-1).url, '/repo.git/api/v1/outcomes');
  assert.equal(p.requests.at(-1).headers.authorization, `Bearer ${ROTATED}`);
  assert.ok(p.requests.every(r => r.headers['idempotency-key'] === saved.key));
  assert.equal(p.requests[1].body, saved.body);
});
