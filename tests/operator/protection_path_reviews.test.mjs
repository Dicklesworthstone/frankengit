import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { LIMITS, canonical, policy, prepareIntent, snapshotReply, validateIntent } from '../../scripts/operator/review_protection.mjs';
import { loadIntent, saveIntent } from '../../scripts/operator/protection_files.mjs';
import { recoverSavedIntent, sendSavedIntent } from '../../scripts/operator/protection_journal.mjs';
import { intentSummary } from '../../scripts/fg_protection_admin.mjs';
import { ACTOR, REVIEWER, TOKEN, ROTATED, SCOPE, POLICY, NEXT, ref, state, json, peer, files } from './protection_fixtures.mjs';

const OTHER = 'c'.repeat(32);
const rule = (path = Buffer.from('src/security'), scope = 'subtree', extra = {}) => ({
  path_hex: Buffer.from(path).toString('hex'), scope, required_reviewers: [REVIEWER, OTHER], required_approvals: 1, ...extra,
});
const pathPolicy = (rules = [rule()], extra = {}) => ({ administrators: [ACTOR], branches: [{
  reference_hex: ref('refs/heads/main'), required_reviewers: [], path_reviews: rules, ...extra,
}] });
const plan = extra => prepareIntent({ endpoint: 'https://forge.example/team/repo.git', token: TOKEN, principal_id: ACTOR,
  expectedScope: SCOPE, snapshot: state(), replacement: pathPolicy(), nonce: 'e'.repeat(32), ...extra });

test('empty path lists preserve every historical policy, form, key and saved intent byte', () => {
  const old = plan({ replacement: NEXT });
  const before = structuredClone(POLICY), after = structuredClone(NEXT);
  before.branches[0].path_reviews = []; after.branches[0].path_reviews = [];
  const explicit = plan({ snapshot: state({ policy: before }), replacement: after });
  assert.equal(canonical(explicit), canonical(old));
  assert.equal(new URLSearchParams(explicit.request.body).has('required_path_review'), false);
  assert.equal(Object.hasOwn(explicit.replacement.branches[0], 'path_reviews'), false);
});

test('path-only policies retain exact raw bytes and both scopes in forms and canonical intents', () => {
  for (const object_format of ['sha1', 'sha256']) {
    const raw = Buffer.from([0x73, 0x72, 0x63, 0x2f, 0xff]);
    const replacement = pathPolicy([rule(raw, 'subtree'), rule(raw, 'exact', { required_approvals: 2 })]);
    const intent = plan({ expectedScope: { ...SCOPE, object_format }, snapshot: state({ object_format, policy: replacement }), replacement });
    const normalized = policy(replacement);
    assert.deepEqual(snapshotReply(state({ object_format, policy: replacement })).policy, normalized);
    assert.deepEqual(intent.source.policy, normalized); assert.deepEqual(intent.replacement, normalized);
    assert.deepEqual(intent.replacement.branches[0].path_reviews.map(row => row.scope), ['exact', 'subtree']);
    assert.deepEqual(new URLSearchParams(intent.request.body).getAll('required_path_review'), [
      `${ref('refs/heads/main')}:exact:${raw.toString('hex')}:2:${REVIEWER},${OTHER}`,
      `${ref('refs/heads/main')}:subtree:${raw.toString('hex')}:1:${REVIEWER},${OTHER}`,
    ]);
    assert.deepEqual(validateIntent(JSON.parse(canonical(intent))), intent);
    assert.equal(new URLSearchParams(intent.request.body).has('required_reviewer'), false);
    assert.equal(canonical(intent).includes(TOKEN), false);
  }
});

test('path-rule sorting is deterministic and duplicate selectors cannot hide behind other quorums', () => {
  const first = rule('a', 'subtree'), last = rule('z', 'exact');
  const unsorted = pathPolicy([last, { ...first, required_reviewers: [OTHER, REVIEWER] }]);
  assert.deepEqual(plan({ replacement: unsorted }), plan({ replacement: pathPolicy([first, last]) }));
  assert.throws(() => policy(pathPolicy([first, { ...first, required_approvals: 2 }])), /duplicate_path_review_selector/);
  assert.throws(() => policy(pathPolicy([first, { ...first, required_reviewers: [ACTOR] }])), /duplicate_path_review_selector/);
  const input = pathPolicy([first]), intent = plan({ replacement: input });
  input.branches[0].path_reviews[0].required_reviewers.length = 0;
  assert.deepEqual(intent.replacement, pathPolicy([rule('a', 'subtree')]));
});

test('paths reject ambiguous components without normalizing valid native names', () => {
  for (const path of ['', '/', '/src', 'src/', 'src//key', '.', '..', 'src/./key', 'src/../key', 'src\0key']) {
    assert.throws(() => policy(pathPolicy([rule(path)])), /invalid_path_review_path/);
  }
  for (const path_hex of ['0', 'A0', 'xz', null, 1, [], '61'.repeat(LIMITS.path + 1)]) {
    assert.throws(() => policy(pathPolicy([rule('a', 'exact', { path_hex })])));
  }
  // These are distinct literal names, including a star, newline and non-UTF-8.
  const names = [Buffer.from('SRC'), Buffer.from('src'), Buffer.from('a*b'), Buffer.from('a\nb'), Buffer.from([0xff])];
  const selected = policy(pathPolicy(names.map(name => rule(name)))).branches[0].path_reviews;
  assert.equal(selected.length, names.length);
  assert.deepEqual(new Set(selected.map(row => row.path_hex)), new Set(names.map(name => name.toString('hex'))));
});

test('path quorums require explicit bounded counts, known fields, scopes and independent eligible sets', () => {
  for (const scope of ['prefix', 'Exact', '', null, 0, true]) assert.throws(() => policy(pathPolicy([rule('a', scope)])), /invalid_path_review_scope/);
  for (const required_approvals of [0, -0, -1, 3, 1.5, '1', null, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => policy(pathPolicy([rule('a', 'exact', { required_approvals })])), /invalid_path_review_approval_count/);
  }
  for (const required_reviewers of [[], [REVIEWER, REVIEWER], Array.from({ length: 33 }, (_, n) => n.toString(16).padStart(32, '0'))]) {
    assert.throws(() => policy(pathPolicy([rule('a', 'exact', { required_reviewers })])));
  }
  for (const field of ['path_hex', 'scope', 'required_reviewers', 'required_approvals']) {
    const missing = rule(); delete missing[field]; assert.throws(() => policy(pathPolicy([missing])), /invalid_record_fields/);
  }
  assert.throws(() => policy(pathPolicy([rule('a', 'exact', { inferred_owner: true })])), /invalid_record_fields/);
  assert.throws(() => policy(pathPolicy([])), /invalid_principal_count/);
});

test('path count and raw-byte ceilings apply across the whole policy', () => {
  const rules = Array.from({ length: LIMITS.branchPathReviews }, (_, n) => rule(`path-${n}`));
  assert.equal(policy(pathPolicy(rules)).branches[0].path_reviews.length, 32);
  assert.throws(() => policy(pathPolicy([...rules, rule('excess')])), /invalid_path_review_count/);
  const branches = Array.from({ length: 8 }, (_, n) => ({ reference_hex: ref(`refs/heads/p${n}`), required_reviewers: [], path_reviews: rules }));
  assert.equal(policy({ administrators: [ACTOR], branches }).branches.flatMap(row => row.path_reviews).length, 256);
  assert.throws(() => policy({ administrators: [ACTOR], branches: [...branches,
    { reference_hex: ref('refs/heads/p8'), required_reviewers: [], path_reviews: [rule()] }] }), /invalid_path_review_count/);
  const long = Array.from({ length: 16 }, (_, n) => rule(`${n.toString().padStart(2, '0')}${'x'.repeat(LIMITS.path - 2)}`));
  assert.equal(policy(pathPolicy(long)).branches[0].path_reviews.length, 16);
  assert.throws(() => policy(pathPolicy([...long, rule('z')])), /path_review_byte_limit/);
});

test('existing branch approvals, checks and queue requirements remain alongside path rules', () => {
  const required_checks = [{ source_ref_hex: ref('refs/heads/ci'), publisher: ACTOR, graph_root: '1'.repeat(64), job: 'build' }];
  const required_candidate_checks = [{ publisher: OTHER, graph_root: '2'.repeat(64), job: 'test' }];
  const replacement = pathPolicy([rule()], { required_reviewers: [REVIEWER, OTHER], required_approvals: 1,
    required_checks, required_candidate_checks, require_merge_queue: true });
  const intent = plan({ replacement }), form = new URLSearchParams(intent.request.body);
  assert.equal(form.getAll('required_reviewer').length, 2);
  assert.equal(form.getAll('required_check').length, 1); assert.equal(form.getAll('required_candidate_check').length, 1);
  assert.equal(form.getAll('required_path_review').length, 1);
  assert.equal(form.get('required_approvals'), `${ref('refs/heads/main')}:1`);
  assert.equal(form.get('require_merge_queue'), ref('refs/heads/main'));
  assert.deepEqual(validateIntent(intent), intent);
});

test('replacement preview shows full path-rule additions, removals and quorum changes', () => {
  const before = pathPolicy([rule()]), after = pathPolicy([rule('src/security', 'subtree', { required_approvals: 2 }), rule('docs', 'subtree')]);
  const intent = plan({ snapshot: state({ policy: before }), replacement: after });
  const preview = intentSummary(intent).branches[0];
  assert.deepEqual(preview.path_reviews_removed, before.branches[0].path_reviews);
  assert.deepEqual(preview.path_reviews_added, policy(after).branches[0].path_reviews);
  const clear = plan({ snapshot: state({ policy: before }), replacement: { administrators: [ACTOR], branches: [] }, clear: true });
  assert.deepEqual(intentSummary(clear).branches[0].path_reviews_removed, before.branches[0].path_reviews);
  assert.equal(new URLSearchParams(clear.request.body).has('required_path_review'), false);
  assert.equal(intentSummary(plan({ snapshot: state({ policy: before }), replacement: before })).branches.length, 0);
});

test('frozen path-policy intent binds source, every selector field and exact original body', () => {
  const original = plan({ snapshot: state({ policy: pathPolicy() }) });
  for (const side of ['source', 'replacement']) for (const edit of [
    rule => { rule.path_hex += '61'; }, rule => { rule.scope = 'exact'; },
    rule => { rule.required_reviewers[1] = 'd'.repeat(32); }, rule => { rule.required_approvals = 2; },
  ]) {
    const changed = structuredClone(original);
    edit((side === 'source' ? changed.source.policy : changed.replacement).branches[0].path_reviews[0]);
    assert.throws(() => validateIntent(changed), /integrity/);
  }
  for (const edit of [value => { delete value.replacement.branches[0].path_reviews; },
    value => { value.request.body += '&required_path_review=forged'; }, value => { value.request.key += '-fresh'; }]) {
    const changed = structuredClone(original); edit(changed); assert.throws(() => validateIntent(changed));
  }
});

test('saved path intents retry exact original bytes and recover only the original key after an unknown send', async t => {
  const f = await files(t); let intent, sends = 0;
  const p = await peer(t, (call, response) => {
    if (call.url.endsWith('/protection')) {
      if (++sends === 1) { response.destroy(); return; }
      json(response, { type: 'review_protection_publication', schema_version: 1, ...intent.scope,
        principal_id: ACTOR, expected_version: intent.source.version, expected_epoch: intent.source.policy_epoch,
        resulting_epoch: '3', tx_id: 'tx-paths', outcome: 'committed', decision_sequence: '9007199254740993',
        repository_commit_id: 'rcr-paths', refusal_record_id: null, refusal_code: null, refusal_code_point: null, delivery_acknowledged: null });
    } else {
      assert.equal(call.url.endsWith('/outcomes'), true);
      json(response, { type: 'transaction_outcome', schema_version: 1,
        tenant_id: intent.scope.tenant_id, repository_id: intent.scope.repository_id, repository_incarnation: intent.scope.repository_incarnation,
        principal_id: ACTOR, selector: 'transaction', command_index: null, state: 'committed', terminal: true,
        transaction: { tx_id: 'tx-paths', seal_id: 'seal-paths', request_schema: 'native-receive-admission', canonical_request_digest: { algorithm: 2, hex: '5'.repeat(64) } },
        decision: { kind: 'committed', decision_sequence: '9007199254740993', repository_commit_id: 'rcr-paths' },
        read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false });
    }
  });
  intent = plan({ endpoint: p.endpoint, snapshot: state({ policy: pathPolicy() }) });
  await saveIntent(f.intent, intent);
  const original = await readFile(join(f.intent, 'intent.json'));
  const options = { expectedEndpoint: intent.endpoint, confirmation: intent.intent_sha256 };
  await assert.rejects(sendSavedIntent(f.intent, TOKEN, options), error => error.outcomeUnknown === true);
  await assert.rejects(sendSavedIntent(f.intent, TOKEN, options), /explicit_retry_required/);
  const retry = await sendSavedIntent(f.intent, TOKEN, { ...options, retry: true });
  assert.equal(retry.summary.state, 'committed'); assert.equal(sends, 2);
  for (const call of p.calls) {
    assert.equal(call.body, intent.request.body); assert.equal(call.headers['idempotency-key'], intent.request.key);
  }
  assert.deepEqual(await loadIntent(f.intent), intent); assert.deepEqual(await readFile(join(f.intent, 'intent.json')), original);
  const recovered = await recoverSavedIntent(f.intent, ROTATED, { expectedEndpoint: intent.endpoint });
  assert.equal(recovered.summary.state, 'committed'); assert.equal(recovered.request_reexecuted, false);
  assert.equal(p.calls.length, 3); assert.equal(p.calls[2].body, '');
  assert.equal(p.calls[2].headers['idempotency-key'], intent.request.key);
  assert.equal(p.calls[2].headers.authorization, `Bearer ${ROTATED}`);
});
