import test from 'node:test';
import assert from 'node:assert/strict';
import { QueueClient } from '../../crates/fgit-node/src/smart_http/server/browser/queues.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { queuePreparationRequest, queuePreparationReply, queueCandidateRequest, queueInspectionReply } from '../../crates/fgit-node/src/smart_http/server/browser/queues-candidate.mjs';
import { queuePublication, CANDIDATE_RECEIPT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/queues-protocol.mjs';
import { BUNDLE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { token, actor, json, webcrypto, deferred, show as prShow, row, data } from './pulls-fixtures.mjs';
import { recovered, terminal } from './pulls-candidate-fixtures.mjs';
import { queueFixture, candidatePublication } from './queues-candidate-fixtures.mjs';

const href = 'https://forge.example/team/repo.git/ui/queues/';
function harness(f = queueFixture(), respond = () => null, extra = {}) {
  const calls = []; let client;
  const fetchImpl = async (url, options) => {
    const call = { path: new URL(url).pathname, ...options }; calls.push(call);
    const result = await respond(call, client); if (result !== null && result !== undefined) return result;
    if (call.path.endsWith('/queues')) return json(f.page);
    if (call.path.endsWith('/prepare')) return f.prepared();
    if (call.path.endsWith('/inspect')) return json(f.inspection);
    if (call.path.endsWith('/land-candidate')) return json(candidatePublication(client.pending));
    throw new Error(`Unexpected request ${call.path}`);
  };
  client = new QueueClient({ href, fetchImpl, cryptoImpl: webcrypto, ...extra });
  const connect = async () => { await client.connect(token); await client.list(); };
  const prepare = () => client.prepareCandidate(7, f.fields, f.commitMetadata);
  const stage = () => client.stageCandidate(7, f.fields);
  return { client, calls, connect, prepare, stage, f };
}
const request = f => queuePreparationRequest(7, f.fields, f.commitMetadata, f.scope);
const response = (f, metadata = f.metadata, bundle = f.bundle) => ({ status: 200, type: f.type, value: f.mixed(metadata, bundle) });

test('selected queue prepare → full native inspection → explicit candidate landing works in both hash domains and raw refs', async () => {
  for (const algorithm of ['sha1', 'sha256']) for (const raw of [false, true]) {
    const h = harness(queueFixture(algorithm, raw)); await h.connect();
    await assert.rejects(h.stage(), /Prepare and inspect/);
    const result = await h.prepare(); assert.equal(h.client.pending, null); assert.equal(h.client.candidateReady, true);
    assert.equal(result.candidate.fields.expected_commit, h.f.fields.candidate_commit ?? h.f.landingFields.expected_commit);
    assert.deepEqual(h.client.exportCandidateBundle(), h.f.bundle);
    const [prepare, inspect] = h.calls.slice(1);
    assert.match(prepare.path, /queues\/7\/prepare$/); assert.match(inspect.path, /pulls\/1\/inspect$/);
    for (const call of [prepare, inspect]) {
      assert.equal(call.method, 'POST'); assert.equal(call.headers['Idempotency-Key'], undefined);
      assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error');
    }
    const command = new URLSearchParams(prepare.body);
    assert.equal(command.get('source_ref_hex'), h.f.refs.source_ref_hex); assert.equal(command.has('source_ref'), false);
    assert.equal(command.get('expected_version'), '3'); assert.equal(command.get('expected_incarnation'), h.f.scope.incarnation);
    const inspectionBody = await inspect.body.text(); assert.ok(inspectionBody.includes(`source_ref_hex=${h.f.refs.source_ref_hex}`));
    assert.equal(inspectionBody.includes('&source_ref='), false);
    const pending = await h.stage(); assert.equal(h.calls.length, 3); assert.equal(pending.action, 'land-candidate');
    assert.equal(pending.body, h.f.commandForm); assert.equal(pending.bundle_bytes, h.f.bundle.length);
    assert.equal(JSON.stringify(pending).includes('bundle_base64'), false);
    result.candidate.fields.expected_version = 99; assert.equal(h.client.pending.fields.expected_version, 3);
    const done = await h.client.send(); assert.equal(done.outcome, 'committed'); assert.equal(done.refsChanged, true);
    assert.equal(h.client.pending, null); assert.equal(h.client.candidateReady, false);
    const write = h.calls.at(-1); assert.equal(write.headers['Idempotency-Key'], pending.key);
    const bytes = new Uint8Array(await write.body.arrayBuffer());
    assert.deepEqual(bytes, queueCandidateRequest(7, h.f.landingFields, h.f.scope, h.f.commandForm, h.f.bundle, pending.nonce).bytes);
  }
});

test('preparation requires the exact recorded first queue entry and preserves explicit metadata', async () => {
  const h = harness(); await h.client.connect(token);
  await assert.rejects(h.prepare(), /Read this repository/);
  await h.client.list();
  for (const change of [{ expected_version: 4 }, { pull_request: 2 }, { source_ref_hex: `${h.f.refs.source_ref_hex}aa` },
    { expected_source_tip: 'd'.repeat(40) }, { target_ref_hex: `${h.f.refs.target_ref_hex}aa` }]) {
    await assert.rejects(h.client.prepareCandidate(7, { ...h.f.fields, ...change }, h.f.commitMetadata));
  }
  assert.equal(h.calls.length, 1);
  const metadata = { ...h.f.commitMetadata, message_hex: 'ff0a', profile: 'exact-renames-v1' }; delete metadata.message;
  const r = queuePreparationRequest(7, h.f.fields, metadata, h.f.scope);
  assert.equal(new URLSearchParams(r.body).get('message_hex'), 'ff0a'); assert.equal(r.profile, 'exact-renames-v1');
  for (const change of [{ message: 'ambiguous' }, { message_hex: '00' }, { timestamp: -0 }, { profile: 'force-ours' }, { method: 'squash' }, { author: 'Name\r\nInjected <e>' }]) {
    assert.throws(() => queuePreparationRequest(7, h.f.fields, { ...metadata, ...change }, h.f.scope));
  }
});

test('conflicted and already-up-to-date native responses stop without inspection, staging or hidden fallback', async () => {
  for (const state of ['conflicted', 'already_up_to_date']) {
    const f = queueFixture(), metadata = { ...f.metadata, state, candidate: null, bundle: null, landing: null,
      conflicts: state === 'conflicted' ? [{ path_hex: '61', kind: 'content', base: null, ours: { mode: 33188, oid: 'a'.repeat(40) }, theirs: null }] : [] };
    if (state === 'conflicted') metadata.merge_base = f.landingFields.merge_base;
    const h = harness(f, call => call.path.endsWith('/prepare') ? json(metadata, state === 'conflicted' ? 409 : 200) : null);
    await h.connect(); const result = await h.prepare();
    assert.equal(result.metadata.state, state); assert.equal(result.candidate, null); assert.equal(h.client.candidateReady, false);
    await assert.rejects(h.stage()); assert.equal(h.calls.length, 2);
  }
});

test('preparation binds queue, raw subject, native command, complete envelope and exact candidate bundle', async () => {
  const f = queueFixture('sha1', true), r = request(f);
  for (const mutate of [m => { m.queue.expected_version++; }, m => { m.queue.number++; }, m => { m.subject.source_ref_hex += 'ee'; },
    m => { m.subject.pull_request_version++; }, m => { m.subject.policy_epoch++; }, m => { m.profile = 'exact-renames-v1'; },
    m => { m.method = 'squash'; }, m => { m.merge_authorized = true; }, m => { m.bundle.sha256 = 'a'.repeat(64); },
    m => { m.bundle.bytes++; }, m => { m.landing.api_path = '/api/v1/pulls/1/merge'; },
    m => { m.landing.command_form += '&force=true'; }, m => { m.landing.command_form += '&expected_version=3'; },
    m => { m.landing.command_form = m.landing.command_form.replace('expected_version=3', 'expected_version=4'); },
    m => { m.candidate.commit = m.subject.source_tip; }, m => { delete m.subject.source_ref; }, m => { m.repository_incarnation = '9'.repeat(32); }]) {
    const metadata = structuredClone(f.metadata); mutate(metadata);
    await assert.rejects(queuePreparationReply(response(f, metadata), r, f.scope, webcrypto));
  }
  const truncated = response(f); truncated.value = truncated.value.subarray(0, truncated.value.length - 1);
  await assert.rejects(queuePreparationReply(truncated, r, f.scope, webcrypto));
  const original = await queuePreparationReply(response(f), r, f.scope, webcrypto);
  assert.equal(original.artifact.commandForm, f.commandForm);
  assert.throws(() => queueCandidateRequest(7, f.landingFields, f.scope, f.commandForm, new Uint8Array(BUNDLE_LIMIT + 1), '1'.repeat(32)));
  assert.throws(() => queueCandidateRequest(7, f.landingFields, f.scope, f.commandForm, new TextEncoder().encode(`--fg-queue-${'1'.repeat(32)}`), '1'.repeat(32)));
});

test('queue inspection retains full native hash, parent order, byte-ref and complete-diff checks', async () => {
  const f = queueFixture('sha256', true), prepared = await queuePreparationReply(response(f), request(f), f.scope, webcrypto);
  for (const mutate of [r => { r.all_changed_paths = false; }, r => { r.subject.target_ref_hex += 'aa'; }, r => { r.subject.policy_epoch++; },
    r => { r.parents.reverse(); }, r => { r.candidate_commit_body_hex += '00'; }, r => { r.bundle.sha256 = 'f'.repeat(64); },
    r => { r.comparison.entry_count = 1; }, r => { r.comparison.before = 'd'.repeat(64); }, r => { r.published = true; }]) {
    const inspected = structuredClone(f.inspection); mutate(inspected);
    await assert.rejects(queueInspectionReply(inspected, prepared.artifact, webcrypto));
  }
  const newer = { ...f.inspection, snapshot_token: `alg:2:${'d'.repeat(64)}`, source_head: 'later-review-event' };
  assert.equal((await queueInspectionReply(newer, prepared.artifact, webcrypto)).head, newer.snapshot_token);
  const h = harness(f, call => call.path.endsWith('/inspect') ? json({ ...f.inspection, all_changed_paths: false }) : null);
  await h.connect(); await assert.rejects(h.prepare()); assert.equal(h.client.candidateReady, false); await assert.rejects(h.stage());
});

test('queue candidates transfer to independent PR inspection/review and retain the exact landing in both hash domains and raw refs', async () => {
  for (const algorithm of ['sha1', 'sha256']) for (const raw of [false, true]) {
    const h = harness(queueFixture(algorithm, raw)); await h.connect(); await h.prepare();
    const serialized = h.client.exportReviewCandidate(), receipt = JSON.parse(serialized), calls = [];
    let reviewer;
    reviewer = new PullClient({ href: href.replace('/queues/', '/pulls/'), cryptoImpl: webcrypto, fetchImpl: async (url, options) => {
      const path = new URL(url).pathname; calls.push({ path, ...options });
      if (path.endsWith('/inspect')) return json(h.f.inspection);
      if (path.endsWith('/approve')) {
        const { pull_request, ...subject } = h.f.inspection.subject;
        return json(terminal(reviewer.pending, { subject: { number: pull_request, ...subject } }));
      }
      return json(prShow({ object_format: algorithm, pull_request: row(1, { version: 4, data: data({ ...h.f.refs,
        object_format: algorithm, source_tip: h.f.fields.expected_source_tip, target_tip: h.f.fields.expected_target_tip }) }) }));
    } });
    await reviewer.connect('d'.repeat(64)); await reviewer.show(1);
    await reviewer.importCandidate(serialized);
    assert.equal(calls.filter(call => call.path.endsWith('/inspect')).length, 1);
    assert.deepEqual(JSON.parse(reviewer.exportCandidate()), receipt);
    const pending = await reviewer.stageReview('approve', 0, 'Independently inspected every candidate path.');
    assert.equal(pending.fields.candidate_commit, h.f.landingFields.expected_commit);
    assert.equal(Object.hasOwn(pending.fields, 'source_ref_hex'), raw);
    assert.equal(Object.hasOwn(pending.fields, 'source_ref'), !raw);
    assert.equal(calls.length, 2, 'export, import and review staging never publish');
    assert.equal((await reviewer.send()).outcome, 'committed');
    assert.equal(calls[2].headers['Idempotency-Key'], pending.key);
    const landing = await h.stage();
    assert.equal(landing.fields.expected_commit, pending.fields.candidate_commit);
    assert.equal(landing.fields.merge_base, pending.fields.merge_base);
    assert.deepEqual(h.client.exportCandidateBundle(), h.f.bundle);
    assert.equal((await h.client.send()).outcome, 'committed');
  }
});

test('lost candidate replies, changed draft and reconnect preserve exact original body/key and historical outcomes', async () => {
  const h = harness(queueFixture(), call => { if (call.path.endsWith('/land-candidate')) throw new Error('lost after commit'); });
  await h.connect(); await h.prepare(); const pending = await h.stage(), receipt = h.client.exportReceipt();
  const decoded = JSON.parse(receipt); assert.equal(decoded.schema, 'frankengit-queue-candidate-retry-v1');
  assert.equal(decoded.request.command_form, h.f.commandForm); assert.equal(receipt.includes(token), false);
  await assert.rejects(h.client.send(), error => error.outcomeUnknown); h.client.invalidateCandidate(); h.client.disconnect();
  assert.equal(h.client.pending.key, pending.key); await assert.rejects(h.client.connect('d'.repeat(64)), /credential/);
  const restored = harness(h.f); await restored.client.connect(token); await restored.client.restoreReceipt(receipt);
  assert.equal(restored.calls.length, 0); assert.equal(restored.client.candidateReady, false);
  const done = await restored.client.send(); assert.equal(done.outcome, 'committed'); assert.equal(restored.calls.length, 1);
  const before = h.calls.at(-1), after = restored.calls[0];
  assert.equal(before.headers['Idempotency-Key'], after.headers['Idempotency-Key']);
  assert.deepEqual(new Uint8Array(await before.body.arrayBuffer()), new Uint8Array(await after.body.arrayBuffer()));
  assert.equal(done.reply.expected_version, 3); // No reread or present-day queue reconstruction.
});

test('candidate recovery receipts reject altered bytes, guards, route, principal and missing original identity', async () => {
  const h = harness(); await h.connect(); await h.prepare(); await h.stage(); const receipt = JSON.parse(h.client.exportReceipt());
  for (const mutate of [r => { r.origin = 'https://other.example'; }, r => { r.request.command_form += '&force=1'; },
    r => { r.request.bundle_base64 = btoa('different bundle'); }, r => { r.request.fields.expected_version++; },
    r => { r.request.nonce = '1'.repeat(32); }, r => { r.request.key += 'a'; }, r => { r.request.observedPrincipal = 'no'; },
    r => { r.schema = 'frankengit-queue-retry-v1'; }, r => { delete r.request.bundle_base64; }]) {
    const altered = structuredClone(receipt); mutate(altered); const next = harness(); await next.client.connect(token);
    await assert.rejects(next.client.restoreReceipt(JSON.stringify(altered))); assert.equal(next.client.pending, null); assert.equal(next.calls.length, 0);
  }
  const next = harness(); await next.client.connect(token);
  await assert.rejects(next.client.restoreReceipt(' '.repeat(CANDIDATE_RECEIPT_LIMIT + 1)));
});

test('rotated outcome-only credential recovers the original candidate without queue reads, inspection or resend', async () => {
  const h = harness(); await h.connect(); await h.prepare(); await h.stage(); const receipt = h.client.exportReceipt();
  const r = harness(h.f, call => call.path.endsWith('/outcomes') ? json(recovered({ state: 'committed', terminal: true,
    decision: { kind: 'committed', decision_sequence: 8, repository_commit_id: 'original-candidate-rcr' } })) : null);
  await r.client.connect('d'.repeat(64), { recoveryOnly: true, originalPrincipal: actor }); await r.client.restoreReceipt(receipt);
  for (const operation of [() => r.client.list(), r.prepare, r.stage, () => r.client.send()]) await assert.rejects(operation());
  const outcome = await r.client.recover(); assert.equal(outcome.rcr, 'original-candidate-rcr'); assert.equal(r.calls.length, 1);
  assert.equal(r.calls[0].body, undefined); assert.equal(r.client.pending, null);
});

test('cancel, credential loss, total read deadline and draft changes reject late candidate completion', async () => {
  for (const cancel of ['read', 'disconnect', 'deadline']) {
    const late = deferred(), entered = deferred();
    const h = harness(queueFixture(), call => { if (call.path.endsWith('/inspect')) { entered.resolve(call); return late.promise; } },
      cancel === 'deadline' ? { operationTimeoutMs: 100 } : {});
    await h.connect(); const preparing = h.prepare(); const call = await entered.promise;
    if (cancel === 'read') h.client.cancelReads();
    else if (cancel === 'disconnect') h.client.disconnect();
    else await new Promise(resolve => setTimeout(resolve, 130));
    assert.equal(call.signal.aborted, true); late.resolve(json(h.f.inspection));
    await assert.rejects(preparing); assert.equal(h.client.candidateReady, false); assert.equal(h.client.pending, null);
  }
  const h = harness(); await h.connect(); await h.prepare();
  await assert.rejects(h.client.stageCandidate(7, { ...h.f.fields, expected_policy_epoch: 2 }), /selection changed/);
  h.client.invalidateCandidate(); await assert.rejects(h.stage());
});

test('cancellation during bundle/commit/key hashing cannot install a candidate or staged request', async () => {
  for (const phase of ['bundle', 'commit', 'key']) {
    const f = queueFixture(), entered = deferred(), release = deferred(); let holding = false;
    const cryptoImpl = { getRandomValues: values => webcrypto.getRandomValues(values), subtle: { async digest(algorithm, bytes) {
      const actual = webcrypto.subtle.digest(algorithm, bytes);
      const selected = phase === 'bundle' ? bytes.length === f.bundle.length : phase === 'commit' ? algorithm === 'SHA-1' : true;
      if (holding && selected) { holding = false; entered.resolve(); await release.promise; }
      return actual;
    } } };
    const h = harness(f, () => null, { cryptoImpl }); await h.connect();
    if (phase === 'key') await h.prepare();
    holding = true; const pending = phase === 'key' ? h.stage() : h.prepare();
    await entered.promise; h.client.cancelReads(); release.resolve();
    await assert.rejects(pending, /cancelled|changed|superseded/);
    assert.equal(h.client.candidateReady, false); assert.equal(h.client.pending, null);
  }
});

test('candidate canonical receipts bind actual merge identity and historical terminal state', async () => {
  const h = harness(); await h.connect(); await h.prepare(); const p = await h.stage();
  const refused = candidatePublication(p, false); assert.equal(queuePublication(refused, p, 409).outcome, 'refused');
  for (const mutate of [r => { r.proposed_action.method = 'fast-forward-only'; }, r => { r.proposed_action.expected_commit = 'd'.repeat(40); },
    r => { r.proposed_action.merge_base = 'f'.repeat(40); }, r => { r.historical_outcome = false; }, r => { r.refs_changed = false; }]) {
    const reply = candidatePublication(p); mutate(reply); assert.throws(() => queuePublication(reply, p, 200));
  }
});

test('new queue routes retain independent read, binary body, method, status and publication envelopes', async () => {
  let calls = 0;
  const t = new Transport({ href, pageSuffix: '/ui/queues/', cryptoImpl: webcrypto, fetchImpl: async () => { calls++; return json({}); } });
  await t.connect(token);
  const read = { method: 'POST', body: 'guard=1', binary: true, statuses: [200, 409] };
  const binary = { method: 'POST', body: new Blob(['candidate']), contentType: 'multipart/form-data; boundary=x' };
  for (const [path, options] of [['queues/7/prepare', { ...read, key: 'grant' }], ['queues/7/prepare', { ...read, read: false }],
    ['queues/7/prepare', { ...read, binary: false }], ['queues/7/prepare-prefix', read],
    ['pulls/1/inspect', { ...binary, key: 'grant' }], ['pulls/1/inspect', { ...binary, read: false }], ['pulls/1/inspect', { ...binary, statuses: [200, 409] }],
    ['queues/7/land-candidate', binary], ['queues/7/land-candidate', { ...binary, key: 'original', read: true }],
    ['pulls/1/merge', { ...binary, key: 'original', read: false }], ['queues/7/land-candidate?force=1', { ...binary, key: 'original', read: false, statuses: [200, 409] }]]) {
    await assert.rejects(t.request(path, options));
  }
  assert.equal(calls, 0);
});
