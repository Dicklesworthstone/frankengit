import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { collaborationCommand, publication, recovery } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { preparationCommand, preparationReply, inspectionReply, multipart, findBytes, BUNDLE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { token, actor, reviewer, scope, head, page, metadata, json, options, webcrypto, deferred } from './pulls-fixtures.mjs';
import { fixture, terminal, recovered } from './pulls-candidate-fixtures.mjs';
const f = fixture(), commitMetadata = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 1, message: 'Exact candidate\n' };
async function clientWith(handler, algorithm = 'sha1') {
  const calls = [], client = new PullClient(options((url, options) => {
    calls.push({ url: String(url), ...options });
    if (new URL(url).pathname.endsWith('/api/v1/pulls')) return json(page({ object_format: algorithm, pull_requests: [] }));
    return handler(url, options, client);
  }));
  await client.connect(token); await client.list(); return { client, calls };
}
async function inspected(handler = () => { throw new Error('Unexpected request'); }) {
  const result = await clientWith((url, options, client) => String(url).endsWith('/inspect') ? json(f.inspection) : handler(url, options, client));
  await result.client.inspect(1, f.fields, f.bundle); return result;
}

test('preparation has complete explicit commit metadata and subject, never a transaction key', async () => {
  const { client, calls } = await clientWith((url) => String(url).endsWith('/prepare') ? new Response(f.mixed(), { headers: { 'Content-Type': f.type } }) : json(f.inspection));
  const result = await client.prepareAndInspect(1, f.selected, commitMetadata);
  assert.equal(result.metadata.state, 'clean'); assert.equal(client.candidate.fields.candidate_commit, f.fields.candidate_commit);
  assert.equal(calls.length, 3);
  for (const call of calls) assert.equal(call.headers['Idempotency-Key'], undefined);
  assert.equal(new URLSearchParams(calls[1].body).get('timestamp'), '1');
  assert.match(calls[2].headers['Content-Type'], /^multipart\/form-data;/);
});
test('candidate preparation grammar refuses inferred coordinates and unsafe metadata', () => {
  for (const [selected, meta] of [[{ ...f.selected, policy_epoch: undefined }, commitMetadata], [f.selected, { ...commitMetadata, timestamp: -1 }],
    [f.selected, { ...commitMetadata, author: 'bad\nparent fake' }], [f.selected, { ...commitMetadata, message: '' }],
    [{ ...f.selected, force: true }, commitMetadata], [f.selected, { ...commitMetadata, principal: 'admin' }]]) assert.throws(() => preparationCommand(selected, meta));
});
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm} mixed candidate and native commit identity verify without lossy byte decoding`, async () => {
  const sample = fixture(algorithm);
  const result = await preparationReply({ status: 200, type: sample.type, value: sample.mixed() }, 1, sample.selected, sample.artifact.scope, webcrypto);
  assert.deepEqual(result.artifact.bundle, sample.bundle);
  assert.equal((await inspectionReply(sample.inspection, sample.artifact, webcrypto)).reply.candidate_commit, sample.fields.candidate_commit);
});
test('truncated MIME, changed bundle commitment, extra epilogue and wrong subject cannot yield a candidate', async () => {
  const mixed = f.mixed(), cases = [mixed.slice(0, -1), new Uint8Array([...mixed, 0])];
  for (const value of cases) await assert.rejects(preparationReply({ status: 200, type: f.type, value }, 1, f.selected, scope, webcrypto));
  for (const metadata of [{ ...f.metadata, bundle: { ...f.metadata.bundle, sha256: '0'.repeat(64) } },
    { ...f.metadata, subject: { ...f.metadata.subject, source_tip: 'c'.repeat(40) } }, { ...f.metadata, published: true }]) {
    await assert.rejects(preparationReply({ status: 200, type: f.type, value: f.mixed(metadata) }, 1, f.selected, scope, webcrypto));
  }
});
test('conflicted and already-up-to-date reads never become prepared reviews or terminal writes', async () => {
  for (const [state, status] of [['conflicted', 409], ['already_up_to_date', 200]]) {
    const report = { ...f.metadata, state, candidate: null, bundle: null, merge_base: f.fields.merge_base,
      conflicts: state === 'conflicted' ? [{ path_hex: '61ff', kind: 'binary', base: null, ours: null, theirs: null }] : [] };
    const { client } = await clientWith(() => json(report, status));
    assert.equal((await client.prepareAndInspect(1, f.selected, commitMetadata)).inspection, null);
    assert.equal(client.candidate, null); assert.equal(client.pending, null);
    await assert.rejects(client.stageReview('approve', 0, 'reason'));
  }
});
test('multipart framing is byte-exact and collision-safe, with no filename path authority', () => {
  const result = multipart('a=b', f.bundle, 'fixed-boundary');
  assert.notEqual(findBytes(result.bytes, f.bundle), -1);
  assert.throws(() => multipart('a=b', new Uint8Array(Buffer.from('--fixed-boundary')), 'fixed-boundary'));
  assert.throws(() => multipart('a=b', f.bundle, 'bad\r\n'));
  assert.throws(() => multipart('a=b', new Uint8Array(BUNDLE_LIMIT + 1), 'fixed-boundary'));
  assert.equal(findBytes(new Uint8Array(Buffer.from('aaaabaaaac')), new Uint8Array(Buffer.from('aaaac'))), 5);
});
test('inspection rejects changed native commit bytes, parents, bundle and comparison endpoints', async () => {
  for (const extra of [{ candidate_commit_body_hex: f.inspection.candidate_commit_body_hex + '20' }, { parents: [...f.inspection.parents].reverse() },
    { bundle: { ...f.inspection.bundle, sha256: '0'.repeat(64) } }, { all_changed_paths: false },
    { comparison: { ...f.inspection.comparison, before: 'e'.repeat(40) } }, { published: true }]) await assert.rejects(inspectionReply({ ...f.inspection, ...extra }, f.artifact, webcrypto));
});
test('inspection validates byte-exact text hunk spans and preserves binary/object-only distinctions', async () => {
  const entries = [
    { path_hex: '61ff', kind: 'modified', before: null, after: null, content: { type: 'text', algorithm: 'Myers', additions: 1, deletions: 1, before_bytes: 2, after_bytes: 2,
      hunks: [{ old: { byte_start: 0, byte_end: 2, line_start: 0, line_count: 1 }, new: { byte_start: 0, byte_end: 2, line_start: 0, line_count: 1 }, before_hex: '610a', after_hex: 'ff0a' }] } },
    { path_hex: '62', kind: 'modified', before: null, after: null, content: { type: 'binary', before_bytes: 5, after_bytes: 7, body_included: false } },
    { path_hex: '63', kind: 'mode_changed', before: null, after: null, content: { type: 'object_only', content_read: false } },
  ];
  const report = { ...f.inspection, comparison: { ...f.inspection.comparison, entry_count: 3, entries } };
  assert.equal((await inspectionReply(report, f.artifact, webcrypto)).reply.comparison.entries[1].content.type, 'binary');
  entries[0].content.hunks[0].old.line_count = 2; await assert.rejects(inspectionReply(report, f.artifact, webcrypto));
});
test('review grammar keeps independent reviewer-stream versions and explicit nonempty merge requirements', () => {
  assert.equal(collaborationCommand('approve', { ...f.fields, expected_version: 0, reason: 'exact' }).expected_version, 0);
  for (const [action, fields] of [['approve', { ...f.fields, expected_version: 0, reason: 'exact', reviewer }],
    ['withdraw', { ...f.fields, expected_version: 0, reason: 'withdraw' }], ['merge', { ...f.fields, required_reviewer: [] }],
    ['merge', { ...f.fields, required_reviewer: [reviewer, reviewer] }], ['merge', { ...f.fields, required_reviewer: [reviewer], expected_version: 1 }]]) assert.throws(() => collaborationCommand(action, fields));
});
test('metadata staging is network-free and later editor changes cannot alter its sealed request', async () => {
  const { client, calls } = await clientWith(() => { throw new Error('No HTTP expected'); });
  const fields = metadata(); await client.stageMetadata(1, 'update', fields); fields.title = 'changed later';
  const external = client.pending; external.fields.body = 'changed getter';
  assert.equal(client.pending.fields.title, metadata().title); assert.equal(client.pending.fields.body, metadata().body); assert.equal(calls.length, 1);
  client.discardUnsent(); assert.equal(client.pending, null);
});
test('dispatched exact retry preserves key, content type and every multipart byte after lost response', async () => {
  let sends = 0; const { client, calls } = await inspected((_url, _options, owner) => {
    sends += 1; if (sends === 1) throw new Error('connection lost after possible CAS'); return json(terminal(owner.pending));
  });
  await client.stageReview('approve', 0, 'Reviewed exact candidate'); const key = client.pending.key;
  await assert.rejects(client.send(), error => error.outcomeUnknown === true); assert.equal(client.pending.key, key);
  assert.throws(() => client.discardUnsent()); await assert.rejects(client.stageMerge([reviewer]));
  const result = await client.send(); assert.equal(result.outcome, 'committed'); assert.equal(client.pending, null);
  const writes = calls.filter(call => call.headers['Idempotency-Key']); assert.equal(writes.length, 2);
  assert.equal(writes[0].headers['Idempotency-Key'], writes[1].headers['Idempotency-Key']);
  assert.equal(writes[0].headers['Content-Type'], writes[1].headers['Content-Type']);
  assert.deepEqual(await writes[0].body.arrayBuffer(), await writes[1].body.arrayBuffer());
});
test('HTTP 409 canonical refusal settles, but ordinary conflict or contradictory status retains uncertainty', async () => {
  for (const kind of ['terminal', 'ordinary', 'wrong-status']) {
    const { client } = await clientWith((_url, _options, owner) => kind === 'ordinary' ? json({ type: 'pull_request_error', code: 'idempotency_key_reused' }, 409) :
      json(terminal(owner.pending, { outcome: 'refused', repository_commit_id: null, refusal_record_id: 'refusal-1', refusal_code: 'Conflict', refusal_code_point: 1 }), kind === 'wrong-status' ? 200 : 409));
    await client.stageMetadata(1, 'close', metadata());
    if (kind === 'terminal') { assert.equal((await client.send()).outcome, 'refused'); assert.equal(client.pending, null); }
    else { await assert.rejects(client.send()); assert.ok(client.pending); }
  }
});
test('terminal review results must match candidate, policy, PR and reviewer-stream coordinates', async () => {
  const { client } = await inspected(); await client.stageReview('approve', 2, 'exact'); const pending = client.pending;
  assert.equal(publication(terminal(pending), pending, 200).outcome, 'committed');
  for (const extra of [{ candidate_commit: 'c'.repeat(40) }, { review_expected_version: 1 },
    { subject: { ...terminal(pending).subject, policy_epoch: 2 } }, { type: 'reviewed_merge_publication' }, { delivery_acknowledged: true }]) assert.throws(() => publication(terminal(pending, extra), pending, 200));
});
test('merge sends explicitly chosen reviewers, never automatically promotes displayed approvals', async () => {
  const { client } = await inspected(); await client.stageMerge(['6'.repeat(32), reviewer]);
  assert.deepEqual(client.pending.fields.required_reviewer, [reviewer, '6'.repeat(32)]);
  assert.equal(publication(terminal(client.pending), client.pending, 200).outcome, 'committed');
  assert.throws(() => publication(terminal(client.pending, { required_reviewers: [reviewer] }), client.pending, 200));
});
test('withdrawal is an exact form command with no candidate bytes, not a merge grant', async () => {
  const { client, calls } = await inspected((_url, _options, owner) => json(terminal(owner.pending)));
  await client.stageReview('withdraw', 1, 'withdraw exact prior vote'); assert.equal(client.pending.bundle_bytes, 0);
  await client.send(); const call = calls.at(-1); assert.equal(call.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.match(await call.body.text(), /expected_version=1/); assert.match(call.url, /reviews\/withdraw$/);
});
test('candidate sharing never exports credentials and imported candidates must pass native inspection', async () => {
  const { client } = await inspected(); const saved = client.exportCandidate(); assert.equal(saved.includes(token), false);
  const { client: other, calls } = await clientWith(() => json(f.inspection));
  await other.importCandidate(saved); assert.match(calls.at(-1).url, /\/inspect$/); assert.equal(other.pending, null); assert.ok(other.candidate);
  const bad = JSON.parse(saved); bad.sha256 = '0'.repeat(64); await assert.rejects(other.importCandidate(JSON.stringify(bad)));
  const foreign = JSON.parse(saved); foreign.scope.incarnation = 'foreign'; await assert.rejects(other.importCandidate(JSON.stringify(foreign)));
});
test('saved retry is credential-bound, token-free, and imports as possibly dispatched', async () => {
  const { client } = await inspected(); await client.stageReview('approve', 0, 'exact'); const saved = client.exportReceipt(), pending = client.pending;
  assert.equal(saved.includes(token), false); assert.throws(() => client.discardUnsent());
  const { client: restored, calls } = await clientWith(() => json(recovered()));
  await restored.restoreReceipt(saved); assert.equal(restored.pending.key, pending.key); assert.equal(restored.pending.sent, true); assert.throws(() => restored.discardUnsent());
  const result = await restored.recover(); assert.equal(result.terminal, false); assert.ok(restored.pending);
  const lookup = calls.at(-1); assert.equal(lookup.body, undefined); assert.equal(lookup.headers['Content-Type'], undefined); assert.match(lookup.url, /\/outcomes$/);
  assert.equal(lookup.headers['Idempotency-Key'], pending.key);
});
for (const field of ['number', 'body', 'policy', 'bundle', 'incarnation', 'key', 'origin']) test(`recovery tampering with ${field} cannot reuse the original request identity`, async () => {
  const { client } = await inspected(); await client.stageReview('approve', 0, 'exact'); const receipt = JSON.parse(client.exportReceipt());
  switch (field) {
    case 'number': receipt.request.number = 2; break;
    case 'body': receipt.request.fields.reason = 'changed'; break;
    case 'policy': receipt.request.fields.policy_epoch = 2; break;
    case 'bundle': receipt.request.bundle_base64 = Buffer.from('changed').toString('base64'); break;
    case 'incarnation': receipt.request.scope.incarnation = 'another'; break;
    case 'key': receipt.request.key = receipt.request.key.slice(0, -1) + (receipt.request.key.endsWith('0') ? '1' : '0'); break;
    case 'origin': receipt.origin = 'https://other.example'; break;
  }
  const { client: restored, calls } = await clientWith(() => { throw new Error('No mutation'); });
  await assert.rejects(restored.restoreReceipt(JSON.stringify(receipt))); assert.equal(restored.pending, null); assert.equal(calls.length, 1);
});
test('restoring the wrong credential cannot reassign a pending transaction to another principal', async () => {
  const { client } = await clientWith(() => { throw new Error('unused'); }); await client.stageMetadata(1, 'update', metadata()); const saved = client.exportReceipt();
  client.disconnect(); await assert.rejects(client.connect('d'.repeat(64))); assert.ok(client.pending);
  const other = new PullClient(options(() => { throw new Error('unused'); })); await other.connect('d'.repeat(64)); await assert.rejects(other.restoreReceipt(saved));
});
test('absence and undecided recovery never settle a write; only an exact terminal result does', async () => {
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    const { client } = await clientWith(() => json(recovered({ state, transaction: state === 'undecided' ? recovered().transaction : null })));
    await client.stageMetadata(1, 'close', metadata()); assert.equal((await client.recover()).terminal, false); assert.ok(client.pending);
  }
  const { client } = await clientWith(() => json(recovered({ terminal: true, state: 'committed', decision: { kind: 'committed', decision_sequence: 2, repository_commit_id: 'rcr-1' } })));
  await client.stageMetadata(1, 'close', metadata()); assert.equal((await client.recover()).outcome, 'committed'); assert.equal(client.pending, null);
});
test('recovery refuses different incarnation, principal, transaction, and false non-commit claims', async () => {
  const { client } = await clientWith(() => json(recovered())); await client.stageMetadata(1, 'update', metadata()); await client.recover();
  const pending = client.pending;
  for (const extra of [{ repository_incarnation: 'other' }, { principal_id: reviewer }, { absence_proves_non_commit: true },
    { transaction: { ...recovered().transaction, tx_id: 'other' } }, { terminal: true }]) assert.throws(() => recovery(recovered(extra), pending));
});
test('one in-flight mutation cannot be replaced, discarded, or duplicated by concurrent clicks', async () => {
  const wait = deferred(), { client } = await clientWith(() => wait.promise); await client.stageMetadata(1, 'close', metadata());
  const sending = client.send(); assert.equal(client.busy, true); await assert.rejects(client.send()); await assert.rejects(client.stageMetadata(1, 'update', metadata()));
  assert.throws(() => client.discardUnsent()); client.disconnect(); wait.resolve(json(terminal(client.pending))); await assert.rejects(sending);
  assert.ok(client.pending); assert.equal(client.busy, false);
});
test('late candidate inspections cannot overwrite a newly selected or disconnected view', async () => {
  const wait = deferred(), { client } = await clientWith(() => wait.promise);
  const reading = client.inspect(1, f.fields, f.bundle);
  // Allow hashing and dispatch to enter the transport before invalidating.
  for (let i = 0; i < 10; i += 1) await new Promise(setImmediate);
  client.invalidateCandidate(); wait.resolve(json(f.inspection)); await assert.rejects(reading); assert.equal(client.candidate, null);
});

test('recovery cannot forget a previously observed transaction after an absence response', async () => {
  const { client } = await clientWith(() => json(recovered()));
  await client.stageMetadata(1, 'update', metadata()); await client.recover();
  const pending = client.pending;
  for (const state of ['key_not_observed', 'seal_not_observed']) assert.throws(() => recovery(recovered({ state, transaction: null }), pending));
  assert.equal(client.pending.observedTx, 'transaction-1');
});

test('replacing a credential with malformed input disconnects the old token rather than silently retaining it', async () => {
  const client = new PullClient(options(() => json(page())));
  await client.connect(token); await client.list();
  await assert.rejects(client.connect('invalid'));
  assert.equal(client.connected, false); assert.equal(client.binding, null);
});
