// Native-schema peers exercise the actual durable client, not Git admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, writeFile, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { preparePullWithIdentity, preparePull, validatePullIntent, validatePullPublication,
  pullCanonical, pullHash, pullEnvelope } from '../../scripts/operator/pull_command.mjs';
import { submitPull, recoverPull } from '../../scripts/operator/remote_pull.mjs';
import { capturePullReviews, reviewCanonical } from '../../scripts/operator/pull_review_snapshot.mjs';
import { draftPullReview } from '../../scripts/operator/pull_review_draft.mjs';
import { saveReviewJson } from '../../scripts/operator/pull_review_files.mjs';
import { input, TOKEN, ROTATED } from './remote_pull_fixture.mjs';
import { reviewInput, BUNDLE } from './remote_pull_review_fixture.mjs';
import { peer, person, EPOCH } from './pull_review_snapshot_fixture.mjs';

const ENDPOINT = 'https://forge.example/repo.git';
const ACTIONS = ['fast-forward', 'approve', 'request-changes', 'withdraw', 'merge-commit', 'squash'];
const IDENTITY = { nonce: '0'.repeat(32), credential_fingerprint: pullHash(TOKEN) };
const rawSource = Buffer.concat([Buffer.from('refs/heads/topic'), Buffer.from([255])]);
const rawTarget = Buffer.concat([Buffer.from('refs/heads/main'), Buffer.from([254])]);
const metadata = action => ['update', 'close', 'reopen'].includes(action);
const operation = action => ['merge-commit', 'squash'].includes(action) ? 'merge' : action;
const payload = action => metadata(action) || ['fast-forward', 'withdraw'].includes(action) ? null : BUNDLE;
function selection(action, format = 'sha1', endpoint = ENDPOINT) {
  return action === 'fast-forward' ? input(endpoint, action, format)
    : reviewInput(endpoint, operation(action), format, action);
}
function rawFields(selected, side = 'both') {
  const out = structuredClone(selected);
  for (const name of ['source', 'target']) if (side === name || side === 'both') {
    delete out.fields[name + '_ref'];
    out.fields[name + '_ref_hex'] = (name === 'source' ? rawSource : rawTarget).toString('hex');
  }
  return out;
}
function nativeReferences(fields, format) {
  return Object.fromEntries(['source', 'target'].flatMap(side => {
    const bytes = Object.hasOwn(fields, side + '_ref_hex') ? Buffer.from(fields[side + '_ref_hex'], 'hex')
      : Buffer.from(fields[side + '_ref']);
    // An independent round trip checks the native UTF-8-or-null display contract.
    const text = bytes.toString('utf8');
    return [[side + '_ref', Buffer.from(text).equals(bytes) ? text : null],
      [side + '_ref_hex', bytes.toString('hex')], [side + '_tip', format + ':' + fields[side + '_tip']]];
  }));
}
function receipt(intent, state = 'committed') {
  const f = intent.fields, ff = intent.action === 'fast-forward', review = !ff && !metadata(intent.action);
  const merge = intent.action === 'merge', committed = state === 'committed';
  const refs = nativeReferences(f, intent.scope.object_format);
  return { type: ff ? 'fast_forward_merge_publication' : !review ? 'pull_request_publication'
    : merge ? 'reviewed_merge_publication' : 'candidate_review_publication', schema_version: 1,
    ...intent.scope, action: intent.action,
    ...(review ? { subject: { number: intent.number, pull_request_version: f.pull_request_version,
      policy_epoch: f.policy_epoch, ...refs }, review_expected_version: merge ? null : f.expected_version,
      merge_base: intent.scope.object_format + ':' + f.merge_base, candidate_commit: intent.scope.object_format + ':' + f.candidate_commit,
      required_reviewers: merge ? [...f.required_reviewers] : null, ...(merge ? { method: f.method } : {}) }
      : { number: intent.number, ...(ff ? { pull_request_version: f.pull_request_version, ...refs } : { expected_version: f.expected_version }) }),
    tx_id: 'native-transaction', outcome: state, decision_sequence: EPOCH,
    repository_commit_id: committed ? 'native-rcr' : null, refusal_record_id: committed ? null : 'native-refusal',
    refusal_code: committed ? null : 'PolicyDenied', refusal_code_point: committed ? null : 17, delivery_acknowledged: null };
}
function observation(intent, state = null) {
  const { object_format: _, ...scope } = intent.scope;
  return { type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null,
    state: state ?? 'key_not_observed', terminal: state !== null,
    transaction: state === null ? null : { tx_id: 'native-transaction', seal_id: 'native-seal', request_schema: 'native-pr-schema-v1',
      canonical_request_digest: { algorithm: 1, hex: 'c'.repeat(64) } },
    decision: state === null ? null : { kind: state, decision_sequence: EPOCH,
      ...(state === 'committed' ? { repository_commit_id: 'native-rcr' }
        : { code: 'PolicyDenied', code_point: 17, refusal_record_id: 'native-refusal' }) },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
function send(res, value, status = 200) {
  const counters = ['number', 'version', 'expected_version', 'pull_request_version', 'policy_epoch', 'review_expected_version', 'decision_sequence'];
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(value, (key, data) => counters.includes(key) && typeof data === 'string' ? JSON.rawJSON(data) : data));
}
function consent(intent, action) {
  return { confirmKey: intent.key, ...(action === 'fast-forward' ? { confirmFastForward: true }
    : metadata(action) ? {} : { confirmCandidate: intent.fields.candidate_commit }),
    ...(operation(action) === 'merge' ? { confirmMergeMethod: action } : {}),
    ...(payload(action) === null ? {} : { bundle: BUNDLE }) };
}
function choice(action, format) {
  return { action: operation(action), principal_id: person(10),
    ...(metadata(action) || ['fast-forward', 'withdraw'].includes(action) ? {}
      : { merge_base: 'b'.repeat(format === 'sha1' ? 40 : 64), candidate_commit: 'c'.repeat(format === 'sha1' ? 40 : 64) }),
    ...(operation(action) === 'merge' ? { method: action, required_reviewers: [person(12)] }
      : metadata(action) || action === 'fast-forward' ? {} : { reason: 'The exact original review subject.' }),
    ...(action === 'update' ? { title: 'An explicit metadata edit' } : {}) };
}
async function workflow(t, action, format, side = 'both', terminal = 'committed', drop = false) {
  let intent, writes = 0;
  const p = await peer(t, { format, state: action === 'reopen' ? 'closed' : 'open', handle(record, res) {
    if (record.method === 'GET') return false;
    assert.equal(record.headers['idempotency-key'], intent.key);
    if (record.url.pathname.endsWith('/outcomes')) { send(res, observation(intent, writes ? terminal : null)); return true; }
    assert.equal(record.url.pathname, '/repo.git/api/v1/pulls/' + intent.number + '/' +
      (['approve', 'request-changes', 'withdraw'].includes(intent.action) ? 'reviews/' : '') + intent.action);
    assert.equal(record.headers.authorization, 'Bearer ' + TOKEN);
    assert.deepEqual(record.body, pullEnvelope(intent, payload(action)).body);
    writes++;
    if (drop) res.destroy(); else send(res, receipt(intent, terminal), terminal === 'committed' ? 200 : 409);
    return true;
  } });
  for (const name of ['source', 'target']) if (side === name || side === 'both') {
    const hex = (name === 'source' ? rawSource : rawTarget).toString('hex');
    for (const row of [p.native.pull.pull_request.data, ...p.native.reviews.map(r => r.subject)]) {
      row[name + '_ref'] = null; row[name + '_ref_hex'] = hex;
    }
  }
  return { p, install(value) { intent = value; }, get writes() { return writes; } };
}

// Captured from unmodified 24337110 before enabling aliases. Whole-intent
// hashes protect historical field order, serialized bodies and saved keys.
const TEXT_GOLDENS = [
  ['sha1', 'fast-forward', 'a207fbbf2025e25a52a402bb029c0c53f8c23cf2a9043279d281af1622a53935'],
  ['sha1', 'approve', '26237ccedccda3bdb945e456786ddf6b337efa11bb5d00ccd0acc3930de64db2'],
  ['sha1', 'request-changes', 'f888f9408e889eb83332582722855269bf624a9d48c9f24c002a73c07e73d20f'],
  ['sha1', 'withdraw', '3c5946b39a0add255ab20f3b79a1168fe43950c094701e9a2e7f760ffa9999e5'],
  ['sha1', 'merge-commit', '60a5e46e6a33c7ea3a86609c6013566635465335444af9add5dec35a13efb3a3'],
  ['sha1', 'squash', 'cee1c8c034c3ca6a24765bd35ecf469a7c410fe0ab60e8f6b7bce124a4c75fae'],
  ['sha256', 'fast-forward', '30000579c3172589854262b71203f52336acbea530eaffe158ed7b6ae0a46d62'],
  ['sha256', 'approve', '623eb8aa2f65a0291ca6c568d17b79c493b7eaca080269ba7e011308373f4aba'],
  ['sha256', 'request-changes', 'b4566b3918428fdef1dc2bf22877267c5c0347bf1889efdb694b80e483bb7961'],
  ['sha256', 'withdraw', '1e00875ad3a57186a7878ef3358b5fe8dcecaac49ef69007a75d48a7962446d5'],
  ['sha256', 'merge-commit', 'e2b927b363585259fa200551f05f848254197501b3f234231d988529348f9202'],
  ['sha256', 'squash', 'e8dce404b739f7a9b14b28bb79f3610330b7fa9283a36df8d834409494e622c6'],
];
for (const [format, action, hash] of TEXT_GOLDENS) test(format + ' ' + action + ': historical text intent is byte-identical', () => {
  const intent = preparePullWithIdentity(selection(action, format), IDENTITY, payload(action));
  assert.equal(pullHash(pullCanonical(intent)), hash);
  assert.equal(pullCanonical(validatePullIntent(JSON.parse(pullCanonical(intent)))), pullCanonical(intent));
});

for (const format of ['sha1', 'sha256']) for (const action of ACTIONS) for (const side of ['source', 'target', 'both']) {
  test(format + ' ' + action + ' ' + side + ': captured raw refs reach publication and original-key recovery', async t => {
    const terminal = side === 'target' ? 'refused' : 'committed';
    const w = await workflow(t, action, format, side, terminal);
    const capture = await capturePullReviews(w.p.selected, TOKEN, { pageLimit: 1 }), original = reviewCanonical(capture);
    const draft = draftPullReview(capture, choice(action, format));
    const prepared = preparePull(draft, TOKEN, payload(action)), saved = pullCanonical(prepared);
    const intent = validatePullIntent(JSON.parse(saved)); w.install(intent);
    const form = new URLSearchParams(intent.body);
    for (const name of ['source', 'target']) {
      const raw = side === name || side === 'both';
      assert.equal(form.get(name + '_ref_hex'), raw ? (name === 'source' ? rawSource : rawTarget).toString('hex') : null);
      assert.equal(form.get(name + '_ref'), raw ? null : 'refs/heads/' + (name === 'source' ? 'topic' : 'main'));
    }
    assert.equal(w.writes, 0);
    const result = await submitPull(intent, TOKEN, consent(intent, action));
    assert.equal(result.outcome.state, terminal); assert.equal(w.writes, 1);
    assert.equal((await recoverPull(JSON.parse(saved), ROTATED, { known: result.outcome })).outcome.state, terminal);
    assert.equal((await submitPull(intent, TOKEN, consent(intent, action))).dispatched, false);
    assert.equal(w.writes, 1); assert.equal(pullCanonical(intent), saved); assert.equal(reviewCanonical(capture), original);
  });
}
for (const action of ACTIONS) test(action + ': raw-ref lost reply recovers without a second publication', async t => {
  const w = await workflow(t, action, 'sha256', 'both', 'committed', true);
  const capture = await capturePullReviews(w.p.selected, TOKEN);
  const intent = preparePull(draftPullReview(capture, choice(action, 'sha256')), TOKEN, payload(action)); w.install(intent);
  await assert.rejects(submitPull(intent, TOKEN, consent(intent, action)), e => e.dispatched && e.outcomeUnknown);
  assert.equal((await recoverPull(intent, ROTATED)).outcome.state, 'committed');
  assert.equal((await submitPull(intent, TOKEN, consent(intent, action))).dispatched, false);
  assert.equal(w.writes, 1);
});

for (const action of ['update', 'close', 'reopen', ...ACTIONS]) test(action + ': captured UTF-8 C1 refs draft as exact bytes', async t => {
  const w = await workflow(t, action, 'sha256');
  const names = { source: 'refs/heads/topic\u0080\u0085', target: 'refs/heads/main\u009f' };
  for (const row of [w.p.native.pull.pull_request.data, ...w.p.native.reviews.map(r => r.subject)]) {
    for (const [side, name] of Object.entries(names)) {
      row[side + '_ref'] = name; row[side + '_ref_hex'] = Buffer.from(name).toString('hex');
    }
  }
  const capture = await capturePullReviews(w.p.selected, TOKEN), draft = draftPullReview(capture, choice(action, 'sha256'));
  for (const [side, name] of Object.entries(names)) {
    assert.equal(draft.fields[side + '_ref_hex'], Buffer.from(name).toString('hex'));
    assert.equal(Object.hasOwn(draft.fields, side + '_ref'), false);
  }
  const intent = preparePull(draft, TOKEN, payload(action)); w.install(intent);
  assert.equal((await submitPull(intent, TOKEN, consent(intent, action))).outcome.state, 'committed');
  assert.equal((await recoverPull(intent, ROTATED)).outcome.state, 'committed'); assert.equal(w.writes, 1);
});

for (const action of ACTIONS) test(action + ': raw aliases reject ambiguous, invalid and aliased-equal branch identities', () => {
  const good = rawFields(selection(action)), make = selected => preparePullWithIdentity(selected, IDENTITY, payload(action));
  assert.equal(make(good).fields.source_ref_hex, rawSource.toString('hex'));
  for (const invalid of ['', 'ffF', '0', rawSource.toString('hex').toUpperCase(), '00',
    ...['refs/tags/topic', 'refs/heads/../other', 'refs/heads/x.lock', 'refs/heads/bad name', 'refs/heads/a\0b'].map(s => Buffer.from(s).toString('hex'))]) {
    const bad = structuredClone(good); bad.fields.source_ref_hex = invalid;
    assert.throws(() => make(bad));
  }
  for (const side of ['source', 'target']) {
    const bad = structuredClone(good); bad.fields[side + '_ref'] = 'refs/heads/duplicate';
    assert.throws(() => make(bad), { code: 'invalid_pull_fields' });
    delete bad.fields[side + '_ref']; delete bad.fields[side + '_ref_hex'];
    assert.throws(() => make(bad), { code: 'invalid_pull_fields' });
  }
  const same = selection(action);
  same.fields.source_ref_hex = Buffer.from(same.fields.target_ref).toString('hex'); delete same.fields.source_ref;
  assert.throws(() => make(same), { code: 'invalid_pull_coordinates' });
  const bounded = rawFields(selection(action), 'source');
  bounded.fields.source_ref_hex = Buffer.concat([Buffer.from('refs/heads/'), Buffer.alloc(1013, 255)]).toString('hex');
  assert.equal(make(bounded).fields.source_ref_hex, bounded.fields.source_ref_hex);
  bounded.fields.source_ref_hex += 'ff'; assert.throws(() => make(bounded), { code: 'invalid_pull_branch' });
});
for (const format of ['sha1', 'sha256']) for (const action of ACTIONS) {
  test(format + ' ' + action + ': receipt refs bind raw bytes and exact UTF-8-or-null display', () => {
    const selected = rawFields(selection(action, format), 'source');
    selected.fields.target_ref_hex = Buffer.from('refs/heads/cafe\u0301').toString('hex'); delete selected.fields.target_ref;
    const intent = preparePullWithIdentity(selected, IDENTITY, payload(action)), publication = receipt(intent);
    const coordinates = value => action === 'fast-forward' ? value : value.subject;
    assert.deepEqual(validatePullPublication(publication, intent, 200), publication);
    for (const [name, value] of [['source_ref', rawSource.toString()], ['source_ref_hex', rawTarget.toString('hex')],
      ['target_ref', null], ['target_ref', 'refs/heads/café'], ['target_ref_hex', Buffer.from('refs/heads/café').toString('hex')]]) {
      const bad = structuredClone(publication); coordinates(bad)[name] = value;
      assert.throws(() => validatePullPublication(bad, intent, 200));
    }
    const alias = structuredClone(intent);
    alias.fields.target_ref = 'refs/heads/cafe\u0301'; delete alias.fields.target_ref_hex;
    assert.throws(() => validatePullIntent(alias), { code: 'pull_intent_changed' });
  });
}
test('withdrawal preserves old raw refs after the PR is retargeted', async t => {
  const w = await workflow(t, 'withdraw', 'sha256');
  const old = w.p.native.reviews[0], oldSource = old.subject.source_ref_hex, oldTarget = old.subject.target_ref_hex;
  old.subject.pull_request_version = '2'; old.subject.policy_epoch = '1'; old.freshness = 'pull_request_changed';
  const data = w.p.native.pull.pull_request.data;
  data.source_ref = 'refs/heads/new-topic'; data.source_ref_hex = Buffer.from(data.source_ref).toString('hex');
  data.target_ref = 'refs/heads/new-main'; data.target_ref_hex = Buffer.from(data.target_ref).toString('hex');
  for (const row of w.p.native.reviews.slice(1)) row.freshness = 'pull_request_changed';
  const capture = await capturePullReviews(w.p.selected, TOKEN), draft = draftPullReview(capture, choice('withdraw', 'sha256'));
  assert.equal(draft.fields.source_ref_hex, oldSource); assert.equal(draft.fields.target_ref_hex, oldTarget);
  assert.equal(draft.fields.pull_request_version, '2'); assert.equal(draft.fields.policy_epoch, '1');
  const intent = preparePull(draft, TOKEN); w.install(intent);
  assert.equal((await submitPull(intent, TOKEN, consent(intent, 'withdraw'))).outcome.state, 'committed');
});
for (const action of ['update', 'close', 'reopen', ...ACTIONS]) test(action + ': private offline CLI drafts raw refs for durable preparation', async t => {
  const w = await workflow(t, action, 'sha256'), capture = await capturePullReviews(w.p.selected, TOKEN);
  const root = await realpath(await mkdtemp(join(tmpdir(), 'fg-raw-review-'))); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const captured = join(root, 'capture.json'), selected = join(root, 'choice.json'), output = join(root, 'draft.json');
  const saved = await saveReviewJson(captured, capture);
  await writeFile(selected, reviewCanonical(choice(action, 'sha256')), { mode: 0o600 });
  const reads = w.p.requests.length;
  const result = await promisify(execFile)(process.execPath, [resolve('scripts/fg_pull_review.mjs'), 'draft', '--capture', captured,
    '--sha256', saved.sha256, '--input', selected, '--output', output], { timeout: 10000, maxBuffer: 65536 });
  assert.equal(JSON.parse(result.stdout).publication_attempted, false); assert.equal(w.p.requests.length, reads);
  const draft = JSON.parse(await readFile(output, 'utf8'));
  assert.equal(draft.fields.source_ref_hex, rawSource.toString('hex')); assert.equal(draft.fields.target_ref_hex, rawTarget.toString('hex'));
  const intent = preparePull(draft, TOKEN, payload(action)); w.install(intent);
  assert.equal((await submitPull(intent, TOKEN, consent(intent, action))).outcome.state, 'committed');
  assert.equal((await recoverPull(intent, ROTATED)).outcome.state, 'committed'); assert.equal(w.writes, 1);
});
