// Cumulative operator continuations over controlled native-schema HTTP peers.
// Real private files, CLI processes and complete validators; no native replay or
// independent bundle-admission claim is made by these opaque bundle fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, realpath, writeFile, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { capturePullCandidate, resolveRebaseCandidate, validateCandidateCapture, candidateCanonical,
  REBASE_CONTINUATION_CAPTURE_SCHEMA, CANDIDATE_CAPTURE_SCHEMA, RESOLVED_CAPTURE_SCHEMA } from '../../scripts/operator/pull_candidate_capture.mjs';
import { REBASE_HISTORY_SCHEMA } from '../../scripts/operator/pull_candidate_rebase_history.mjs';
import { saveCandidatePackage, loadCandidatePackage } from '../../scripts/operator/pull_candidate_files.mjs';
import { draftCandidateReview } from '../../scripts/operator/pull_candidate_draft.mjs';
import { stageCandidateReview } from '../../scripts/operator/pull_candidate_stage.mjs';
import { loadPullIntent, loadPullBundle } from '../../scripts/operator/pull_files.mjs';
import { run } from '../../scripts/fg_pull_candidate.mjs';
import { continuationFixture, continuationPeer } from './pull_candidate_rebase_continuation_fixture.mjs';
import { token, actor, reviewer, reply, mixed } from './pull_candidate_rebase_fixture.mjs';

async function directory(t) {
  const path = await realpath(await mkdtemp(join(tmpdir(), 'fg-rebase-continuation-'))); await chmod(path, 0o700);
  t.after(() => rm(path, { recursive: true, force: true })); return path;
}
function finished(algorithm = 'sha1', flow = 'conflicts') {
  const f = continuationFixture(algorithm, flow);
  return { capture: { ...f.capture, schema: REBASE_CONTINUATION_CAPTURE_SCHEMA, preparation_status: 200,
    preparation: f.complete, inspection: f.inspection, history: { schema: REBASE_HISTORY_SCHEMA,
      rounds: f.actions.map((action, i) => ({ preparation: i ? f.reports[i - 1] : f.initial, action })) } }, bundle: Buffer.from(f.bundle) };
}
const decision = (value, action = 'approve') => ({ action, principal_id: action === 'merge' ? actor : reviewer,
  method: 'rebase', candidate_commit: value.capture.preparation.candidate_commit,
  ...(action === 'merge' ? { required_reviewers: [reviewer] } : { reason: 'Reviewed the complete resolved series.' }) });
async function cli(t, args) {
  const child = spawn(process.execPath, [resolve('scripts/fg_pull_candidate.mjs'), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  child.stdout.on('data', bytes => { out += bytes; if (out.length > 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', bytes => { err += bytes; if (err.length > 1024 * 1024) child.kill('SIGKILL'); });
  const [code, signal] = await once(child, 'close'); clearTimeout(timer); return { code, signal, out, err };
}

for (const algorithm of ['sha1', 'sha256']) for (const flow of ['conflicts', 'initial-keep', 'initial-drop', 'resolved-keep', 'resolved-drop']) {
  test(`${algorithm} ${flow}: explicit original-bound continuations retain full custody and never rediscover`, async t => {
    const p = await continuationPeer(t, { algorithm, flow }), root = await directory(t);
    let value = await capturePullCandidate(p.input, token);
    const originalRequest = structuredClone(value.capture.request), originalPull = structuredClone(value.capture.pull);
    const originalReviews = structuredClone(value.capture.review_pages);
    const initial = await saveCandidatePackage(join(root, 'initial'), value.capture, value.bundle);
    const retained = await readFile(join(initial.path, 'capture.json'));
    for (let i = 0; i < p.fixture.actions.length; i++) {
      const previousRequests = p.requests.length;
      value = await resolveRebaseCandidate(value.capture, p.fixture.actions[i], token);
      assert.equal(value.capture.schema, REBASE_CONTINUATION_CAPTURE_SCHEMA);
      assert.equal(value.capture.history.schema, REBASE_HISTORY_SCHEMA); assert.equal(value.capture.history.rounds.length, i + 1);
      assert.deepEqual(value.capture.request, originalRequest); assert.deepEqual(value.capture.pull, originalPull);
      assert.deepEqual(value.capture.review_pages, originalReviews);
      const clean = value.capture.preparation.state === 'clean';
      assert.equal(value.usage.requests, clean ? 2 : 1); assert.equal(p.requests.length - previousRequests, clean ? 2 : 1);
      assert.equal(value.capture.preparation.empty_policy, p.fixture.reports[i].empty_policy);
      assert.equal(value.capture.request.metadata.empty, 'stop');
      assert.equal(p.requests.slice(previousRequests).every(r => r.method === 'POST'), true);
      const saved = await saveCandidatePackage(join(root, `continued-${i}`), value.capture, value.bundle);
      value = await loadCandidatePackage(saved.path, saved.sha256);
      if (!clean) {
        assert.equal(value.bundle, null); assert.equal(value.capture.inspection, null);
        await assert.rejects(draftCandidateReview(value.capture, null, { ...decision(value), candidate_commit: p.fixture.complete.candidate_commit }),
          { code: 'candidate_draft_requires_clean_inspection' });
      }
    }
    assert.equal(value.capture.preparation.state, 'clean'); assert.deepEqual(value.bundle, p.fixture.bundle);
    assert.equal(value.capture.inspection.commits.length, flow.endsWith('drop') ? 1 : 2);
    const beforeDraft = p.requests.length;
    for (const action of ['approve', 'request-changes', 'merge']) {
      const draft = await draftCandidateReview(value.capture, value.bundle, decision(value, action));
      assert.equal(draft.fields.method, 'rebase'); assert.equal(draft.fields.candidate_commit, p.fixture.complete.candidate_commit);
      if (action !== 'merge') assert.equal(draft.fields.expected_version, '5');
    }
    const staged = await stageCandidateReview({ package: value.path, sha256: value.sha256,
      choices: decision(value), request_dir: join(root, 'request') }, token);
    const intent = await loadPullIntent(staged.request_dir, { sync: true });
    assert.deepEqual(await loadPullBundle(staged.request_dir, intent, { sync: true }), p.fixture.bundle);
    assert.equal(intent.fields.method, 'rebase'); assert.equal(staged.publication_attempted, false);
    assert.equal(p.requests.length, beforeDraft); assert.deepEqual(await readFile(join(initial.path, 'capture.json')), retained);
    assert.equal(p.requests.filter(r => r.method === 'GET').length, 2);
    if (flow === 'conflicts') {
      assert.deepEqual(p.continuations[1].files.get('file_0'), p.fixture.replacement);
      assert.equal(p.continuations[1].command.getAll('resolution').length, 2);
      assert.equal(value.capture.inspection.source_comparison.entries.length, 0);
      assert.equal(value.capture.inspection.commits[0].comparison.entries[0].kind, 'added');
      assert.equal(value.capture.inspection.commits[1].comparison.entries[0].kind, 'deleted');
    }
  });
}

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: executable resolve-rebase restarts from each pinned package`, async t => {
  const p = await continuationPeer(t, { algorithm }), root = await directory(t), file = name => join(root, name);
  const initial = await capturePullCandidate(p.input, token);
  let saved = await saveCandidatePackage(file('initial'), initial.capture, initial.bundle);
  await writeFile(file('token'), token + '\n', { mode: 0o600 });
  for (let i = 0; i < p.fixture.actions.length; i++) {
    await writeFile(file(`choices-${i}.json`), candidateCanonical(p.fixture.actions[i]), { mode: 0o600 });
    const result = await cli(t, ['resolve-rebase', '--package', saved.path, '--sha256', saved.sha256,
      '--choices', file(`choices-${i}.json`), '--token-file', file('token'), '--output-dir', file(`continued-${i}`)]);
    assert.equal(result.code, i === 0 ? 1 : 0, result.err); const receipt = JSON.parse(result.out);
    assert.equal(receipt.type, 'pull_candidate_rebase_continued'); assert.equal(receipt.source_package_sha256, saved.sha256);
    assert.equal(receipt.published, false); assert.equal(receipt.usage.requests, i === 0 ? 1 : 2); saved = receipt;
  }
  const inspected = await cli(t, ['inspect', '--package', saved.path, '--sha256', saved.sha256]);
  assert.equal(inspected.code, 0, inspected.err); const value = JSON.parse(inspected.out).capture;
  assert.equal(value.history.rounds.length, 2); assert.equal(value.inspection.commits.length, 2);
  assert.equal(value.history.rounds[0].action.choices[0].content_hex, p.fixture.replacement.toString('hex'));
  assert.equal(p.requests.length, 6);
});

const corruptions = [
  ['changed original metadata', v => v.capture.request.metadata.empty = 'keep'],
  ['removed first original recipe', v => v.capture.history.rounds.shift()],
  ['mutated retained file bytes', v => v.capture.history.rounds[0].action.choices[0].content_hex = '01'],
  ['wrong explicit original', v => v.capture.history.rounds[1].action.original = v.capture.history.rounds[0].action.original],
  ['empty history', v => v.capture.history.rounds = []],
  ['unversioned history', v => delete v.capture.history.schema],
  ['nested capture history', v => v.capture.history.rounds[0].capture = {}],
  ['ordinary resolved schema substitution', v => v.capture.schema = RESOLVED_CAPTURE_SCHEMA],
  ['original capture schema substitution', v => v.capture.schema = CANDIDATE_CAPTURE_SCHEMA],
  ['lost cumulative receipt', v => v.capture.preparation.resolutions.shift()],
  ['changed file result', v => v.capture.preparation.resolutions[0].paths[0].result.oid = '1'.repeat(40)],
  ['changed final resolution mode', v => v.capture.preparation.resolutions[0].paths[0].result.mode = 0o100644],
  ['injected receipt field', v => v.capture.preparation.resolutions[0].paths[0].approved = true],
  ['changed earlier conflict', v => v.capture.history.rounds[0].preparation.conflicts[0].ours.oid = '1'.repeat(40)],
  ['changed completed prefix', v => v.capture.preparation.steps[0].rewritten = '1'.repeat(40)],
  ['changed historical snapshot', v => v.capture.history.rounds[0].preparation.snapshot_token = `alg:1:${'d'.repeat(64)}`],
  ['changed historical source head', v => v.capture.history.rounds[1].preparation.source_head = 'different-head'],
  ['omitted intermediate inspection', v => { v.capture.inspection.commits.shift(); v.capture.inspection.commit_count--; }],
  ['changed bundle bytes', v => v.bundle[0] ^= 1],
];
for (const [name, change] of corruptions) test(`offline continuation refuses ${name}`, async () => {
  const value = finished(); change(value); await assert.rejects(validateCandidateCapture(value.capture, value.bundle));
});
test('empty-policy history must explicitly bind its original and transition from stop', async () => {
  for (const change of [r => r.action.from_empty = 'drop', r => r.action.empty = 'stop', r => delete r.action.from_empty,
    r => r.action.original = '2'.repeat(40), r => r.preparation.state = 'conflicted']) {
    const value = finished('sha1', 'initial-keep'); change(value.capture.history.rounds[0]);
    await assert.rejects(validateCandidateCapture(value.capture, value.bundle));
  }
});
test('wrong original, cancellation, and input-only overrides refuse before any continuation request', async t => {
  const p = await continuationPeer(t), initial = await capturePullCandidate(p.input, token), before = p.requests.length;
  for (const action of [{ ...p.fixture.actions[0], original: '2'.repeat(40) },
    { ...p.fixture.actions[0], expected_head: 'override' }, { ...p.fixture.actions[0], empty: 'keep' }]) {
    await assert.rejects(resolveRebaseCandidate(initial.capture, action, token));
  }
  const controller = new AbortController(); controller.abort();
  await assert.rejects(resolveRebaseCandidate(initial.capture, p.fixture.actions[0], token, { signal: controller.signal }), { code: 'candidate_cancelled' });
  assert.equal(p.requests.length, before);
});
test('changed authority snapshot rejects a continued report without rediscovery or inspection', async t => {
  const p = await continuationPeer(t, { handle: (r, response, _p, f) => {
    if (!r.url.endsWith('/resolve-rebase')) return false;
    reply(response, { ...f.reports[0], snapshot_token: `alg:1:${'d'.repeat(64)}` }, 409); return true;
  } });
  const initial = await capturePullCandidate(p.input, token);
  await assert.rejects(resolveRebaseCandidate(initial.capture, p.fixture.actions[0], token), error => error.phase === 'resolution');
  assert.equal(p.requests.length, 4); assert.equal(p.requests.filter(r => r.method === 'GET').length, 2);
});
test('completed-prefix substitution is refused before full-series inspection', async t => {
  let count = 0;
  const p = await continuationPeer(t, { handle: (r, response, _p, f) => {
    if (!r.url.endsWith('/resolve-rebase') || ++count !== 2) return false;
    const forged = structuredClone(f.complete); forged.steps[0].tree = '1'.repeat(40);
    // Both cumulative receipts and the complete bundle are valid; only the
    // previously completed step's tree was substituted in this response.
    const body = mixed(forged, f.bundle);
    response.writeHead(200, { 'Content-Type': body.type, 'Content-Length': body.body.length }); response.end(body.body); return true;
  } });
  const initial = await capturePullCandidate(p.input, token), first = await resolveRebaseCandidate(initial.capture, p.fixture.actions[0], token);
  await assert.rejects(resolveRebaseCandidate(first.capture, p.fixture.actions[1], token),
    { code: 'candidate_rebase_completed_prefix_changed', phase: 'resolution' });
  assert.equal(p.requests.length, 5); assert.equal(p.requests.some(r => r.url.endsWith('/inspect-rebase')), false);
});
test('continuation action and previous reports detach before asynchronous file identity checks', async t => {
  const p = await continuationPeer(t), initial = await capturePullCandidate(p.input, token), action = structuredClone(p.fixture.actions[0]);
  const pending = resolveRebaseCandidate(initial.capture, action, token);
  action.choices[0].content_hex = '01'; initial.capture.preparation.conflicts[0].ours.oid = '1'.repeat(40);
  const result = await pending;
  assert.equal(result.capture.history.rounds[0].action.choices[0].content_hex, p.fixture.replacement.toString('hex'));
  assert.deepEqual(p.continuations[0].files.get('file_0'), p.fixture.replacement);
});
test('a clean package refuses continuation before reading credentials or writing output', async t => {
  const value = finished(), root = await directory(t), saved = await saveCandidatePackage(join(root, 'clean'), value.capture, value.bundle);
  const errors = [], code = await run(['resolve-rebase', '--package', saved.path, '--sha256', saved.sha256,
    '--choices', join(root, 'missing-choice'), '--token-file', join(root, 'missing-token'), '--output-dir', join(root, 'new')],
  { output: async () => {}, errorOutput: async text => errors.push(JSON.parse(text)) });
  assert.equal(code, 2); assert.equal(errors[0].code, 'candidate_rebase_original_stop_required');
  assert.deepEqual(await readdir(root), ['clean']);
});
test('native continuation refusal never fabricates an all-dropped candidate or tries another method', async t => {
  let prepares = 0;
  const p = await continuationPeer(t, { flow: 'initial-drop', handle: (r, response) => {
    if (!r.url.endsWith('/prepare-rebase') || ++prepares === 1) return false;
    reply(response, { type: 'error', code: 'no_retained_rebase_candidate' }, 422); return true;
  } });
  p.capture.preparation.stopped_commit = p.capture.preparation.steps[0].original;
  p.fixture.actions[0].original = p.capture.preparation.stopped_commit;
  p.capture.preparation.steps = []; p.capture.preparation.step_count = 0;
  const initial = await capturePullCandidate(p.input, token);
  await assert.rejects(resolveRebaseCandidate(initial.capture, p.fixture.actions[0], token),
    { code: 'candidate_http_refused', phase: 'resolution', status: 422 });
  assert.equal(p.requests.length, 4); assert.equal(p.requests.some(r => r.url.endsWith('/inspect-rebase')), false);
});
test('an entirely dropped series cannot be substituted for a clean inspected continuation', async () => {
  const value = finished('sha1', 'initial-drop'), report = value.capture.preparation;
  report.candidate_commit = report.subject.target_tip;
  report.root_tree = value.capture.inspection.commits[0].comparison.before_tree;
  for (const step of report.steps) Object.assign(step, { kind: 'dropped_empty', rewritten: report.candidate_commit, tree: report.root_tree });
  await assert.rejects(validateCandidateCapture(value.capture, value.bundle));
});
