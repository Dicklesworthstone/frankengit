// Production browser protocol and WebCrypto checks against controlled HTTP/DOM
// peers. Real native TCP/authority coverage lives in native_pull_rebase_http.rs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { mountPulls, renderInspection } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { rebasePreparationCommand, rebasePreparationReply, rebaseInspectionReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-rebase.mjs';
import { inspectionReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { requestBody, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { terminal } from './pulls-candidate-fixtures.mjs';
import { sample, metadata } from './pulls-rebase-fixtures.mjs';
import { token, reviewer, page, show, json, options, webcrypto, deferred } from './pulls-fixtures.mjs';
import { fakeDocument, until } from './helpers/pulls-workflow-fixture.mjs';


async function connected(value, dispatch = null) {
  const calls = []; let client;
  client = new PullClient(options(async (url, init) => {
    const call = { url: String(url), ...init }; calls.push(call);
    if (url.pathname.endsWith('/pulls')) return json(page({ object_format: value.fields.object_format, pull_requests: [] }));
    if (dispatch) { const result = await dispatch(call, client); if (result) return result; }
    if (url.pathname.endsWith('/prepare-rebase')) return new Response(value.mixed(), { headers: { 'Content-Type': value.type } });
    if (url.pathname.endsWith('/inspect-rebase')) return json(value.inspection);
    if (url.pathname.endsWith('/inspect')) return json(value.inspection);
    return json(terminal(client.pending, { method: 'rebase' }));
  }));
  await client.connect(token); await client.list();
  return { client, calls };
}

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: prepare, independently inspect every commit, review and merge keep the exact rebase method`, async () => {
  const value = sample(algorithm), { client, calls } = await connected(value);
  const result = await client.prepareRebaseAndInspect(1, value.selected, { ...metadata, upstream: value.fields.merge_base });
  assert.equal(result.inspection.commits.length, 2); assert.equal(client.candidate.method, 'rebase');
  const command = new URLSearchParams(calls[1].body);
  assert.equal(command.get('profile'), 'path-v1'); assert.equal(command.get('upstream'), value.fields.merge_base);
  assert.equal(command.has('author'), false); assert.equal(command.has('message'), false);
  assert.ok(calls[2].url.endsWith('/inspect-rebase')); assert.ok(calls.every(call => !call.headers['Idempotency-Key']));
  assert.match(await calls[2].body.text(), new RegExp(value.fields.candidate_commit));
  await client.stageReview('approve', 0, 'Inspected both commits, including the temporary protected path');
  assert.equal(client.pending.fields.method, 'rebase'); assert.equal(client.pending.sent, false); assert.equal(calls.length, 3);
  assert.equal((await client.send()).outcome, 'committed'); assert.match(await calls[3].body.text(), /method=rebase/);
  await client.inspect(1, value.fields, value.bundle, 'rebase');
  await client.stageMerge([reviewer]); assert.equal(client.pending.fields.method, 'rebase');
  assert.equal((await client.send()).outcome, 'committed');
  assert.ok(calls.at(-1).url.endsWith('/merge')); assert.match(await calls.at(-1).body.text(), /method=rebase/);
  client.disconnect();
});

test('rebase command requires explicit upstream and empty policy, and never accepts invented authors or messages', () => {
  const value = sample();
  for (const changed of [{ upstream: value.fields.source_tip }, { empty: 'automatic' }, { committer: 'bad' }, { timestamp: -1 },
    { author: 'Other <other@example.invalid>' }, { message: 'replace authorship' }, { upstream: '0'.repeat(40) }]) {
    assert.throws(() => rebasePreparationCommand(value.selected, { ...metadata, upstream: value.fields.merge_base, ...changed }));
  }
});

test('the client refuses missing, reordered, substituted or partly inspected series before enabling any action', async () => {
  const mutations = [
    report => { report.complete = false; },
    report => { report.scope = 'final_tree_only'; },
    report => { report.commits.shift(); },
    report => { report.commits.reverse(); },
    report => { report.commits[0].commit_hex += '00'; },
    report => { report.commits[1].parent = report.subject.target_tip; },
    report => { report.commits[0].tree = report.commits[1].tree; },
    report => { report.commits[0].comparison.entries = []; },
    report => { report.commits[1].comparison.before_tree = '6'.repeat(40); },
    report => { report.source_comparison.after = report.subject.source_tip; },
    report => { report.bundle.sha256 = '0'.repeat(64); },
    report => { report.subject.policy_epoch += 1; },
    report => { report.method = 'squash'; },
  ];
  for (const mutate of mutations) {
    const value = sample(); mutate(value.inspection);
    const { client, calls } = await connected(value);
    await assert.rejects(client.prepareRebaseAndInspect(1, value.selected, { ...metadata, upstream: value.fields.merge_base }));
    assert.equal(client.candidate, null); assert.equal(client.pending, null);
    await assert.rejects(client.stageReview('approve', 0, 'Cannot approve')); await assert.rejects(client.stageMerge([reviewer]));
    assert.ok(calls.every(call => !call.headers['Idempotency-Key'])); client.disconnect();
  }
});

test('ordinary inspection cannot substitute its final-tree receipt for rebase inspection', async () => {
  const value = sample();
  await assert.rejects(inspectionReply(value.inspection, value.artifact, webcrypto), /every rewritten commit/);
  const { client, calls } = await connected(value);
  await client.inspect(1, value.fields, value.bundle, 'rebase'); const exported = JSON.parse(client.exportCandidate());
  await client.importCandidate(JSON.stringify(exported)); assert.ok(calls.at(-1).url.endsWith('/inspect-rebase'));
  await assert.rejects(client.importCandidate(JSON.stringify({ ...exported, method: 'squash' })));
  assert.equal(client.candidate, null); assert.equal(client.pending, null); client.disconnect();
});

test('series counts, completeness, prerequisites and aggregate inspection budgets fail closed', async () => {
  const value = sample();
  for (const mutate of [
    report => { report.commit_count += 1; },
    report => { report.all_rewritten_commits = false; },
    report => { report.replay_equivalence_verified = true; },
    report => { report.prerequisites.push(value.fields.source_tip); },
    report => { report.bundle.pack_bytes = report.bundle.bytes + 1; },
    report => { report.bundle.transport_only_objects = report.bundle.pack_objects + 1; },
    report => {
      const delta = report.commits[0].comparison, entry = delta.entries[0];
      delta.entries = Array.from({ length: 65 }, (_, index) => ({ ...structuredClone(entry), path_hex: Buffer.from(`p${String(index).padStart(3, '0')}`).toString('hex') }));
      delta.entry_count = delta.entries.length;
    },
  ]) {
    const report = structuredClone(value.inspection); mutate(report);
    await assert.rejects(rebaseInspectionReply(report, value.artifact, webcrypto));
  }
  for (const mutate of [
    report => { report.step_count += 1; },
    report => { report.series_complete = false; },
    report => { report.provisional_steps = true; },
    report => { report.committer = 'Other <other@example.invalid>'; },
    report => { report.steps[1].original = report.steps[0].original; },
    report => { report.steps[1].rewritten = report.steps[0].rewritten; },
  ]) {
    const report = structuredClone(value.metadata); mutate(report);
    await assert.rejects(rebasePreparationReply({ status: 200, type: value.type, value: value.mixed(report) }, 1,
      value.command, value.artifact.scope, webcrypto));
  }
});

test('a newly empty or conflicted step returns a stopped preparation with no partial bundle or review authority', async () => {
  for (const state of ['became_empty', 'conflicted']) {
    const value = sample(), stopped = { ...value.metadata, state, candidate_commit: null, root_tree: null,
      bundle: null, stopped_commit: value.fields.source_tip, steps: [value.metadata.steps[0]], step_count: 1,
      series_complete: false, provisional_steps: true,
      conflicts: state === 'conflicted' ? [{ path_hex: '61', kind: 'content', base: null, ours: null, theirs: null }] : [] };
    const { client, calls } = await connected(value, call => call.url.endsWith('/prepare-rebase') ? json(stopped, 409) : null);
    const result = await client.prepareRebaseAndInspect(1, value.selected, { ...metadata, upstream: value.fields.merge_base });
    assert.equal(result.inspection, null); assert.equal(client.candidate, null); assert.equal(client.conflict === null, state !== 'conflicted'); assert.equal(calls.length, 2);
    await assert.rejects(client.stageMerge([reviewer])); client.disconnect();
    const forged = { status: 200, type: value.type, value: value.mixed(stopped) };
    await assert.rejects(rebasePreparationReply(forged, 1, value.command, value.artifact.scope, webcrypto));
  }
});

test('editing selection while inspection is in flight never selects the old rebase artifact', async () => {
  const value = sample(), waiting = deferred(); let inspecting = false;
  const { client } = await connected(value, call => { if (call.url.endsWith('/inspect-rebase')) { inspecting = true; return waiting.promise; } return null; });
  const attempt = client.prepareRebaseAndInspect(1, value.selected, { ...metadata, upstream: value.fields.merge_base });
  const rejected = assert.rejects(attempt, /superseded/); await until(() => inspecting);
  client.invalidateCandidate(); waiting.resolve(json(value.inspection)); await rejected;
  assert.equal(client.candidate, null); assert.equal(client.pending, null); client.disconnect();
});

test('lost rebase publication replies retain exact method, bundle and key across receipt export and restart', async () => {
  const value = sample('sha256'); let writes = 0;
  const dispatch = (call, client) => {
    if (!call.headers['Idempotency-Key']) return null;
    if (++writes === 1) throw new Error('reply lost after possible commit');
    return json(terminal(client.pending, { method: 'rebase' }));
  };
  const first = await connected(value, dispatch); await first.client.inspect(1, value.fields, value.bundle, 'rebase');
  await first.client.stageMerge([reviewer]); const pending = first.client.pending;
  await assert.rejects(first.client.send(), /reply lost/); const receipt = first.client.exportReceipt();
  assert.equal(receipt.includes(token), false); first.client.disconnect();
  const second = await connected(value, dispatch); await second.client.restoreReceipt(receipt);
  assert.equal(second.client.pending.key, pending.key); assert.equal(writes, 1);
  assert.equal((await second.client.send()).outcome, 'committed');
  const sent = [...first.calls, ...second.calls].filter(call => call.headers['Idempotency-Key']);
  assert.equal(sent.length, 2); assert.equal(sent[0].headers['Idempotency-Key'], sent[1].headers['Idempotency-Key']);
  assert.deepEqual(await sent[0].body.arrayBuffer(), await sent[1].body.arrayBuffer()); second.client.disconnect();
});

test('terminal review method cannot be replaced after sending a whole-series rebase review', () => {
  const value = sample(), body = requestBody('approve', { ...value.fields, method: 'rebase', expected_version: 0, reason: 'both commits' }, value.bundle, '1'.repeat(32));
  const pending = { action: 'approve', number: 1, fields: body.fields, scope: value.artifact.scope };
  const result = terminal(pending, { method: 'rebase' }); assert.equal(publication(result, pending, 200).outcome, 'committed');
  for (const method of [undefined, 'squash', 'merge-commit']) assert.throws(() => publication({ ...result, method }, pending, 200));
});

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: browser page renders temporary paths and explicitly stages rebase publication`, async () => {
  const value = sample(algorithm), doc = fakeDocument(), calls = [], observed = show({ object_format: algorithm });
  observed.pull_request.data.object_format = algorithm;
  observed.pull_request.data.source_tip = value.fields.source_tip; observed.pull_request.data.target_tip = value.fields.target_tip;
  let ui;
  ui = mountPulls(doc, { cryptoImpl: webcrypto, downloadImpl() {}, fetchImpl: async (url, init) => {
    calls.push({ url: String(url), ...init });
    if (url.pathname.endsWith('/pulls/1')) return json(observed);
    if (url.pathname.endsWith('/prepare-rebase')) return new Response(value.mixed(), { headers: { 'Content-Type': value.type } });
    if (url.pathname.endsWith('/inspect-rebase')) return json(value.inspection);
    assert.ok(url.pathname.endsWith('/merge')); return json(terminal(ui.client.pending, { method: 'rebase' }));
  } });
  const node = id => doc.getElementById(id), submit = id => node(id).dispatchEvent(new Event('submit', { cancelable: true }));
  await ui.client.connect(token); await ui.loadPr(1);
  node('candidate-method').value = 'rebase'; node('candidate-method').dispatchEvent(new Event('change'));
  assert.equal(node('rebase-fields').hidden, false); assert.equal(node('author').required, false); assert.equal(node('message').disabled, true);
  node('policy-epoch').value = '1'; node('committer').value = metadata.committer; node('timestamp').value = '7'; node('rebase-upstream').value = value.fields.merge_base;
  submit('prepare'); await until(() => ui.client.candidate && !node('review-stage').disabled);
  assert.match(node('candidate').textContent, /Commit 1 of 2/); assert.match(node('candidate').textContent, /Commit 2 of 2/);
  assert.match(node('candidate').textContent, /added: protected\/settings/); assert.match(node('candidate').textContent, /deleted: protected\/settings/);
  assert.equal(node('merge-heading').textContent, 'Reviewed rebase'); assert.equal(node('resolution').hidden, true);
  node('required-reviewers').value = reviewer; node('confirm').checked = true; const reads = calls.length; submit('merge');
  await until(() => ui.client.pending && !ui.client.busy);
  assert.equal(ui.client.pending.fields.method, 'rebase'); assert.equal(calls.length, reads); assert.equal(node('confirm').checked, false);
  assert.equal(node('send').disabled, true); node('confirm').checked = true; node('confirm').dispatchEvent(new Event('change')); node('send').click();
  await until(() => /Canonical committed/.test(node('status').textContent));
  assert.equal(calls.filter(call => call.headers['Idempotency-Key']).length, 1); ui.disconnect();
});

test('series rendering uses one aggregate display budget and keeps every commit and changed path label', () => {
  const value = sample(), doc = fakeDocument(), parent = doc.createElement('div');
  value.inspection.commits[0].commit_hex = '61'.repeat(600 * 1024);
  const rendered = renderInspection(doc, parent, value.inspection);
  assert.equal(rendered.clipped, true); assert.match(parent.textContent, /Commit 2 of 2/);
  assert.match(parent.textContent, /deleted: protected\/settings/); assert.match(parent.textContent, /DISPLAY CLIPPED/);
  assert.ok(parent.textContent.length < 530 * 1024);
});
