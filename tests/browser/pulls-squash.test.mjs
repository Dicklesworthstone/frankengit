// Browser contract tests use the production modules and WebCrypto. HTTP replies
// and the DOM are controlled fixtures; native admission is covered by node tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { candidateMethod, mergeMethod, preparationCommand, preparationReply, inspectionReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { collaborationCommand, requestBody, requestKey, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { fixture, terminal } from './pulls-candidate-fixtures.mjs';
import { token, reviewer, page, show, json, options, webcrypto } from './pulls-fixtures.mjs';
import { fakeDocument, until } from './helpers/pulls-workflow-fixture.mjs';

const commitMetadata = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 1, message: 'Exact candidate\n' };
function squashFixture(algorithm = 'sha1', identityReuse = false) {
  const old = fixture(algorithm), width = algorithm === 'sha1' ? 40 : 64;
  const body = Buffer.from('tree ' + 'f'.repeat(width) + '\nparent ' + old.fields.target_tip +
    '\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nExact candidate\n');
  const commit = createHash(algorithm).update('commit ' + body.length + '\0').update(body).digest('hex');
  const selected = { ...old.selected, source_tip: identityReuse ? commit : old.fields.source_tip };
  const fields = { ...selected, merge_base: identityReuse ? selected.target_tip : old.fields.merge_base, candidate_commit: commit };
  const bundle = new Uint8Array(Buffer.concat([Buffer.from('# ' + (algorithm === 'sha1' ? 'v2' : 'v3') +
    ' git bundle\n' + commit + ' refs/heads/candidate\n\nPACK'), Buffer.from([0, 255, 13, 10])]));
  const sha256 = createHash('sha256').update(bundle).digest('hex');
  const subject = { ...old.metadata.subject, source_tip: selected.source_tip };
  const metadata = { ...old.metadata, method: 'squash', subject,
    candidate: { ...old.metadata.candidate, merge_base: fields.merge_base, commit }, bundle: { bytes: bundle.length, sha256 } };
  const artifact = { ...old.artifact, method: 'squash', fields, bundle, sha256 };
  const inspection = { ...old.inspection, subject, merge_base: fields.merge_base, candidate_commit: commit,
    parents: [selected.target_tip], candidate_commit_body_hex: body.toString('hex'),
    bundle: { ...old.inspection.bundle, bytes: bundle.length, sha256, expanded_bytes: body.length },
    comparison: { ...old.inspection.comparison, after: commit } };
  return { ...old, selected, fields, bundle, artifact, metadata, inspection, commitBody: body,
    mixed: (meta = metadata) => old.mixed(meta, bundle) };
}
async function clientWith(sample, handler) {
  const calls = [], client = new PullClient(options((url, init) => {
    const call = { url: String(url), ...init }; calls.push(call);
    if (new URL(url).pathname.endsWith('/api/v1/pulls')) return json(page({ object_format: sample.fields.object_format, pull_requests: [] }));
    if (String(url).endsWith('/inspect')) return json(sample.inspection);
    return handler(call, client);
  }));
  await client.connect(token); await client.list(); return { client, calls };
}
async function inspected(sample = squashFixture(), handler = () => { throw new Error('Unexpected request'); }) {
  const result = await clientWith(sample, handler);
  await result.client.inspect(1, sample.fields, sample.bundle, 'squash'); return result;
}
function responseFor(sample, metadata = sample.metadata) {
  return { status: 200, type: sample.type, value: sample.mixed(metadata) };
}
function conflictReport(sample) {
  const entry = digit => ({ mode: 0o100644, oid: digit.repeat(sample.fields.target_tip.length) });
  return { ...sample.metadata, state: 'conflicted', candidate: null, bundle: null, merge_base: sample.fields.merge_base,
    conflicts: [{ path_hex: '61', kind: 'content', base: entry('1'), ours: entry('2'), theirs: entry('3') }] };
}

for (const algorithm of ['sha1', 'sha256']) {
  test(algorithm + ': explicit squash inspection binds the sole parent to exact target bytes', async () => {
    const sample = squashFixture(algorithm);
    const result = await inspectionReply(sample.inspection, sample.artifact, webcrypto);
    assert.deepEqual(result.reply.parents, [sample.fields.target_tip]);
    assert.notEqual(sample.fields.candidate_commit, sample.fields.source_tip);
    assert.equal(candidateMethod(sample.artifact), 'squash');
    for (const parents of [[], [sample.fields.source_tip], [sample.fields.target_tip, sample.fields.source_tip]]) {
      await assert.rejects(inspectionReply({ ...sample.inspection, parents }, sample.artifact, webcrypto), /parent identities/);
    }
    await assert.rejects(inspectionReply({ ...sample.inspection,
      candidate_commit_body_hex: sample.inspection.candidate_commit_body_hex + '20' }, sample.artifact, webcrypto), /object identity/);
    const legacy = { ...sample.artifact }; delete legacy.method;
    await assert.rejects(inspectionReply(sample.inspection, legacy, webcrypto), /parent identities/);
    await assert.rejects(inspectionReply(sample.inspection, { ...sample.artifact, method: 'merge-commit' }, webcrypto), /parent identities/);
    const twoParent = fixture(algorithm);
    await assert.rejects(inspectionReply(twoParent.inspection, { ...twoParent.artifact, method: 'squash' }, webcrypto), /parent identities/);
    assert.deepEqual((await inspectionReply(twoParent.inspection, twoParent.artifact, webcrypto)).reply.parents, twoParent.inspection.parents);
  });

  test(algorithm + ': a one-commit squash retains its explicit method when source identity is reused', async () => {
    const sample = squashFixture(algorithm, true);
    assert.equal(sample.fields.candidate_commit, sample.fields.source_tip);
    assert.equal(sample.fields.merge_base, sample.fields.target_tip);
    await inspectionReply(sample.inspection, sample.artifact, webcrypto);
    const { client, calls } = await inspected(sample);
    assert.equal(candidateMethod(client.candidate), 'squash');
    await assert.rejects(client.stageInspectedFastForward(), /Fast-forward requires/);
    const serialized = client.exportCandidate();
    assert.equal(JSON.parse(serialized).method, 'squash');
    client.invalidateCandidate(); await client.importCandidate(serialized);
    assert.equal(candidateMethod(client.candidate), 'squash');
    assert.equal(calls.filter(call => call.url.endsWith('/inspect')).length, 2, 'shared bytes always undergo native reinspection');
    await client.stageMerge([reviewer]);
    assert.equal(client.pending.action, 'merge'); assert.equal(client.pending.fields.method, 'squash');
    client.discardUnsent();
    const oldReceipt = JSON.parse(serialized); delete oldReceipt.method;
    await client.importCandidate(JSON.stringify(oldReceipt));
    assert.equal(candidateMethod(client.candidate), 'fast-forward-only', 'old source-tip receipts keep their established meaning');
    await client.stageInspectedFastForward(); assert.equal(client.pending.action, 'fast-forward');
    client.disconnect();
  });

  test(algorithm + ': preparation freezes explicit squash and refuses method substitutions', async () => {
    const sample = squashFixture(algorithm);
    const result = await preparationReply(responseFor(sample), 1, sample.selected, sample.artifact.scope, webcrypto, false, 'squash');
    assert.equal(result.artifact.method, 'squash'); assert.deepEqual(result.artifact.bundle, sample.bundle);
    for (const method of [undefined, 'merge-commit', 'rebase']) {
      await assert.rejects(preparationReply(responseFor(sample, { ...sample.metadata, method }), 1,
        sample.selected, sample.artifact.scope, webcrypto, false, 'squash'));
    }
    await assert.rejects(preparationReply(responseFor(sample), 1, sample.selected, sample.artifact.scope, webcrypto), /method changed/);
    const old = fixture(algorithm);
    const legacy = await preparationReply(responseFor(old), 1, old.selected, old.artifact.scope, webcrypto);
    assert.equal(legacy.artifact.method, 'merge-commit', 'missing method remains the legacy two-parent default');
  });
}

test('only preparation and merge commands accept squash; reviewer coordinates stay unchanged', () => {
  const sample = squashFixture();
  assert.equal(Object.hasOwn(preparationCommand(sample.selected, commitMetadata), 'method'), false);
  assert.equal(preparationCommand(sample.selected, commitMetadata, 'squash').method, 'squash');
  assert.equal(collaborationCommand('merge', { ...sample.fields, required_reviewer: [reviewer], method: 'squash' }).method, 'squash');
  for (const method of [null, '', 'rebase', 'fast-forward-only']) {
    assert.throws(() => mergeMethod(method));
    assert.throws(() => preparationCommand(sample.selected, commitMetadata, method));
    assert.throws(() => collaborationCommand('merge', { ...sample.fields, required_reviewer: [reviewer], method }));
  }
  for (const action of ['approve', 'request-changes', 'withdraw']) {
    assert.throws(() => collaborationCommand(action, { ...sample.fields, expected_version: 1, reason: 'Exact candidate', method: 'squash' }));
  }
});

test('squash preparation, inspection, review and merge keep distinct explicit wire contracts', async () => {
  const sample = squashFixture('sha256');
  const { client, calls } = await clientWith(sample, () => new Response(sample.mixed(), { headers: { 'Content-Type': sample.type } }));
  await client.prepareAndInspect(1, sample.selected, commitMetadata, 'squash');
  assert.equal(new URLSearchParams(calls[1].body).get('method'), 'squash');
  assert.equal(calls.length, 3); assert.equal(calls[2].url.endsWith('/inspect'), true);
  assert.doesNotMatch(await calls[2].body.text(), /(?:&|\r\n)method=/);
  assert.ok(calls.every(call => call.headers['Idempotency-Key'] === undefined));
  const reads = calls.length;
  await client.stageReview('approve', 0, 'Reviewed exact squash bytes');
  assert.equal(Object.hasOwn(client.pending.fields, 'method'), false);
  assert.equal(client.pending.fields.candidate_commit, sample.fields.candidate_commit);
  client.discardUnsent();
  await assert.rejects(client.stageMerge([]), /explicit required reviewers/);
  await client.stageMerge([reviewer]);
  const frozen = client.pending; client.pending.fields.method = 'merge-commit'; client.candidate.method = 'merge-commit';
  client.invalidateCandidate();
  assert.deepEqual(client.pending, frozen); assert.equal(client.pending.fields.method, 'squash');
  assert.equal(calls.length, reads, 'review and merge staging cannot publish');
  client.disconnect();
});

test('merge method participates in exact request bytes and the recovery key', async () => {
  const sample = squashFixture(), nonce = '1'.repeat(32), fields = { ...sample.fields, required_reviewer: [reviewer] };
  const legacy = requestBody('merge', fields, sample.bundle, nonce);
  const squash = requestBody('merge', { ...fields, method: 'squash' }, sample.bundle, nonce);
  assert.doesNotMatch(Buffer.from(legacy.bytes).toString(), /method=/);
  assert.match(Buffer.from(squash.bytes).toString(), /&method=squash\r\n/);
  assert.notDeepEqual(legacy.bytes, squash.bytes);
  const root = { origin: 'https://forge.example', route: '/team/repo.git/' }, fingerprint = 'a'.repeat(64);
  const key = body => requestKey(root, fingerprint, sample.artifact.scope, 1, 'merge', nonce, body, webcrypto);
  assert.notEqual(await key(legacy), await key(squash));
  assert.deepEqual(requestBody('merge', fields, sample.bundle, nonce).bytes, legacy.bytes);
});

test('squash candidate import rejects unknown methods and contradictory native parent shapes', async () => {
  const sample = squashFixture(), { client, calls } = await inspected(sample), saved = JSON.parse(client.exportCandidate());
  for (const method of ['rebase', null, 'fast-forward-only']) {
    await assert.rejects(client.importCandidate(JSON.stringify({ ...saved, method })));
    assert.equal(client.candidate, null);
  }
  assert.equal(calls.length, 2, 'unsupported receipt methods never reach native inspection');
  await assert.rejects(client.importCandidate(JSON.stringify({ ...saved, method: 'merge-commit' })), /parent identities/);
  assert.equal(client.candidate, null);
  await client.importCandidate(JSON.stringify(saved)); assert.equal(client.candidate.method, 'squash');
  client.disconnect();
});

test('lost squash replies can be retried from a receipt with unchanged method, bundle and key', async () => {
  const sample = squashFixture(); let writes = 0;
  const handler = (_call, client) => {
    if (++writes === 1) throw new Error('Reply lost after possible publication');
    return json(terminal(client.pending, { method: 'squash' }));
  };
  const first = await inspected(sample, handler); await first.client.stageMerge([reviewer]);
  const frozen = first.client.pending;
  await assert.rejects(first.client.send(), error => error.outcomeUnknown === true);
  const saved = first.client.exportReceipt(); assert.equal(JSON.parse(saved).request.fields.method, 'squash');
  assert.equal(saved.includes(token), false); first.client.disconnect();
  const second = await clientWith(sample, handler), tampered = JSON.parse(saved);
  tampered.request.fields.method = 'merge-commit';
  await assert.rejects(second.client.restoreReceipt(JSON.stringify(tampered)), /Recovery key/);
  assert.equal(second.client.pending, null);
  await second.client.restoreReceipt(saved); assert.equal(second.client.pending.key, frozen.key);
  assert.equal(writes, 1, 'receipt restoration does not send');
  assert.equal((await second.client.send()).outcome, 'committed');
  const sent = [...first.calls, ...second.calls].filter(call => call.headers['Idempotency-Key']);
  assert.equal(sent.length, 2); assert.equal(sent[0].headers['Idempotency-Key'], sent[1].headers['Idempotency-Key']);
  assert.equal(sent[0].headers['Content-Type'], sent[1].headers['Content-Type']);
  assert.deepEqual(await sent[0].body.arrayBuffer(), await sent[1].body.arrayBuffer());
  assert.equal(second.client.pending, null); second.client.disconnect();
});

test('a terminal method contradiction preserves the squash request for exact recovery or retry', async () => {
  for (const method of [undefined, 'merge-commit', 'rebase']) {
    const sample = squashFixture(); let replyMethod = method;
    const { client, calls } = await inspected(sample, (_call, owner) => json(terminal(owner.pending, { method: replyMethod })));
    await client.stageMerge([reviewer]); const frozen = client.pending;
    assert.throws(() => publication(terminal(frozen, { method }), frozen, 200));
    await assert.rejects(client.send(), error => error.outcomeUnknown === true);
    assert.equal(client.pending.key, frozen.key); assert.equal(client.pending.fields.method, 'squash');
    assert.throws(() => client.discardUnsent());
    replyMethod = 'squash'; assert.equal((await client.send()).outcome, 'committed');
    const sent = calls.filter(call => call.headers['Idempotency-Key']);
    assert.equal(sent.length, 2); assert.equal(sent[0].headers['Idempotency-Key'], sent[1].headers['Idempotency-Key']);
    assert.deepEqual(await sent[0].body.arrayBuffer(), await sent[1].body.arrayBuffer());
    client.disconnect();
  }
});

test('conflicted squash cannot silently use the existing two-parent resolver', async () => {
  const sample = squashFixture(), report = conflictReport(sample);
  const { client, calls } = await clientWith(sample, () => json(report, 409));
  const result = await client.prepareAndInspect(1, sample.selected, commitMetadata, 'squash');
  assert.equal(result.inspection, null); assert.equal(client.conflict.method, 'squash');
  await assert.rejects(client.resolveAndInspect([{ path_hex: '61', choice: 'ours' }]), /source branch/);
  await assert.rejects(client.stageMerge([reviewer]));
  assert.equal(client.pending, null); assert.equal(client.candidate, null);
  assert.equal(calls.length, 2); assert.equal(calls.some(call => call.url.endsWith('/resolve')), false);
  client.disconnect();
});

async function mountedSquash(sample, { conflicted = false } = {}) {
  const doc = fakeDocument(), calls = [];
  const observed = show({ object_format: sample.fields.object_format });
  observed.pull_request.data = { ...observed.pull_request.data, object_format: sample.fields.object_format,
    source_tip: sample.fields.source_tip, target_tip: sample.fields.target_tip };
  const ui = mountPulls(doc, { cryptoImpl: webcrypto, downloadImpl: () => {}, fetchImpl: (url, init) => {
    const call = { url: String(url), ...init }; calls.push(call);
    if (url.pathname.endsWith('/pulls/1')) return json(observed);
    if (url.pathname.endsWith('/prepare')) return conflicted ? json(conflictReport(sample), 409)
      : new Response(sample.mixed(), { headers: { 'Content-Type': sample.type } });
    if (url.pathname.endsWith('/inspect')) return json(sample.inspection);
    assert.ok(url.pathname.endsWith('/merge'), 'squash must keep its reviewed-merge endpoint');
    return json(terminal(ui.client.pending, { method: 'squash' }));
  } });
  const node = id => { const value = doc.getElementById(id); assert.ok(value); return value; };
  const submit = id => node(id).dispatchEvent(new Event('submit', { cancelable: true }));
  await ui.client.connect(token); await ui.loadPr(1);
  assert.equal(node('candidate-method').value, 'merge-commit');
  node('candidate-method').value = 'squash'; node('candidate-method').dispatchEvent(new Event('change'));
  for (const [id, value] of Object.entries({ 'policy-epoch': '1', ...commitMetadata })) node(id).value = String(value);
  submit('prepare');
  await until(() => !node('prepare-candidate').disabled && (ui.client.candidate || ui.client.conflict));
  return { ...ui, node, submit, calls };
}

for (const algorithm of ['sha1', 'sha256']) test(algorithm + ': page prepares and explicitly publishes squash without a fast-forward substitution', async () => {
  const sample = squashFixture(algorithm, true), ui = await mountedSquash(sample);
  assert.equal(ui.client.candidate.method, 'squash'); assert.equal(ui.node('merge-heading').textContent, 'Reviewed squash');
  assert.equal(ui.node('merge-stage').textContent, 'Prepare squash — do not send');
  assert.equal(ui.node('merge-reviewer-fields').hidden, false); assert.equal(ui.node('required-reviewers').required, true);
  assert.match(ui.node('merge-method-guidance').textContent, /target as its only parent/);
  assert.equal(new URLSearchParams(ui.calls.find(call => call.url.endsWith('/prepare')).body).get('method'), 'squash');
  ui.node('required-reviewers').value = reviewer; ui.node('confirm').checked = true;
  const reads = ui.calls.length; ui.submit('merge');
  await until(() => ui.client.pending && !ui.client.busy);
  const frozen = ui.client.pending;
  assert.equal(frozen.action, 'merge'); assert.equal(frozen.fields.method, 'squash'); assert.equal(frozen.sent, false);
  assert.equal(ui.calls.length, reads); assert.equal(ui.node('confirm').checked, false); assert.equal(ui.node('send').disabled, true);
  ui.node('candidate-method').value = 'merge-commit'; ui.node('candidate-method').dispatchEvent(new Event('change'));
  assert.equal(ui.client.candidate, null); assert.deepEqual(ui.client.pending, frozen);
  assert.equal(ui.node('merge-stage').disabled, true);
  ui.node('send').click(); assert.equal(ui.calls.length, reads, 'editing method cannot confirm or dispatch a pending request');
  ui.node('confirm').checked = true; ui.node('confirm').dispatchEvent(new Event('change')); ui.node('send').click();
  await until(() => /Canonical committed/.test(ui.node('status').textContent));
  const writes = ui.calls.filter(call => call.headers['Idempotency-Key']);
  assert.equal(writes.length, 1); assert.equal(writes[0].headers['Idempotency-Key'], frozen.key);
  assert.match(await writes[0].body.text(), /&method=squash\r\n/);
  assert.equal(ui.client.pending, null); ui.disconnect();
});

test('page leaves conflicted squash read-only and directs resolution to the source branch', async () => {
  const ui = await mountedSquash(squashFixture(), { conflicted: true });
  assert.equal(ui.node('resolution').hidden, true); assert.equal(ui.node('resolve-candidate').disabled, true);
  assert.equal(ui.node('merge-stage').disabled, true); assert.equal(ui.client.pending, null);
  assert.match(ui.node('status').textContent, /Squash has conflicts.*source branch/);
  ui.node('resolve-candidate').click();
  assert.equal(ui.calls.some(call => call.url.endsWith('/resolve')), false); ui.disconnect();
});
