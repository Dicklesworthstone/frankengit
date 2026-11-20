// Production browser protocol and WebCrypto checks against controlled HTTP/DOM
// peers. Real native TCP/authority coverage lives in native_pull_rebase_http.rs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { mountPulls, renderInspection } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { rebasePreparationCommand, rebasePreparationReply, rebaseInspectionReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-rebase.mjs';
import { inspectionReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { requestBody, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { fixture, terminal } from './pulls-candidate-fixtures.mjs';
import { token, reviewer, page, show, json, options, webcrypto, deferred } from './pulls-fixtures.mjs';
import { fakeDocument, until } from './helpers/pulls-workflow-fixture.mjs';

const metadata = { committer: 'Maintainer <maintainer@example.invalid>', timestamp: 7, empty: 'stop' };
function sample(algorithm = 'sha1') {
  const old = fixture(algorithm), width = algorithm === 'sha1' ? 40 : 64;
  const hash = (kind, bytes) => createHash(algorithm).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
  const firstTree = '8'.repeat(width), lastTree = '9'.repeat(width), initialTree = '7'.repeat(width);
  const body = (parent, tree, message) => Buffer.from(`tree ${tree}\nparent ${parent}\nauthor Author <author@example.invalid> 1 +0000\ncommitter ${metadata.committer} 7 +0000\n\n${message}\n`);
  const firstBody = body(old.selected.target_tip, firstTree, 'Add protected configuration'), first = hash('commit', firstBody);
  const lastBody = body(first, lastTree, 'Remove temporary configuration'), last = hash('commit', lastBody);
  const blob = Buffer.from('secret\n'), blobId = hash('blob', blob), path_hex = Buffer.from('protected/settings').toString('hex');
  const entry = added => ({ path_hex, kind: added ? 'added' : 'deleted', before: added ? null : { mode: 0o100644, oid: blobId },
    after: added ? { mode: 0o100644, oid: blobId } : null, content: { type: 'text', algorithm: 'myers-v1',
      before_bytes: added ? 0 : blob.length, after_bytes: added ? blob.length : 0, additions: added ? 1 : 0, deletions: added ? 0 : 1,
      hunks: [{ old: { byte_start: 0, byte_end: added ? 0 : blob.length, line_start: 0, line_count: added ? 0 : 1 },
        new: { byte_start: 0, byte_end: added ? blob.length : 0, line_start: 0, line_count: added ? 1 : 0 },
        before_hex: added ? '' : blob.toString('hex'), after_hex: added ? blob.toString('hex') : '' }] } });
  const comparison = (before, after, before_tree, after_tree, entries) => ({ mode: 'direct', before, after, before_tree, after_tree, entry_count: entries.length, entries });
  const bundle = new Uint8Array(Buffer.concat([Buffer.from(`rebase-fixture:${algorithm}:${last}\n`), Buffer.from([0, 255, 13, 10])]));
  const sha256 = createHash('sha256').update(bundle).digest('hex');
  const fields = { ...old.fields, candidate_commit: last }, command = rebasePreparationCommand(old.selected, { ...metadata, upstream: fields.merge_base });
  const preparation = { ...old.metadata, type: 'pull_request_rebase_preparation', profile: 'path-v1', method: 'rebase',
    candidate_commit: last, root_tree: lastTree, merge_base: fields.merge_base, committer: metadata.committer, timestamp: metadata.timestamp,
    empty_policy: metadata.empty, stopped_commit: null, step_count: 2, series_complete: true, provisional_steps: false,
    steps: [{ original: '6'.repeat(width), rewritten: first, tree: firstTree, kind: 'replayed' },
      { original: fields.source_tip, rewritten: last, tree: lastTree, kind: 'replayed' }], bundle: { bytes: bundle.length, sha256 } };
  delete preparation.candidate;
  const inspection = { ...old.inspection, type: 'pull_request_rebase_inspection', profile: 'verified-linear-series-v1', method: 'rebase',
    scope: 'all_paths_all_commits', complete: true, all_rewritten_commits: true, replay_equivalence_verified: false,
    candidate_commit: last, commit_count: 2,
    bundle: { ...old.inspection.bundle, bytes: bundle.length, sha256, pack_objects: 4, expanded_bytes: firstBody.length + lastBody.length },
    source_comparison: comparison(fields.source_tip, last, lastTree, lastTree, []),
    commits: [{ commit: first, parent: fields.target_tip, tree: firstTree, commit_hex: firstBody.toString('hex'),
      comparison: comparison(fields.target_tip, first, initialTree, firstTree, [entry(true)]) },
    { commit: last, parent: first, tree: lastTree, commit_hex: lastBody.toString('hex'),
      comparison: comparison(first, last, firstTree, lastTree, [entry(false)]) }] };
  for (const field of ['comparison', 'parents', 'candidate_commit_body_hex']) delete inspection[field];
  const artifact = { ...old.artifact, method: 'rebase', fields, bundle, sha256 };
  return { ...old, fields, command, artifact, bundle, metadata: preparation, inspection,
    mixed: (meta = preparation) => old.mixed(meta, bundle) };
}

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
    assert.equal(result.inspection, null); assert.equal(client.candidate, null); assert.equal(client.conflict, null); assert.equal(calls.length, 2);
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
