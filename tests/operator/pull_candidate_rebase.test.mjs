// Real HTTP/private-file/CLI/sender modules with controlled native-schema peers.
// Commit hashes are real; opaque bundles exercise custody, not native admission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, chmod, writeFile, readFile, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { capturePullCandidate, validateCandidateCapture, resolvePullCandidate, candidateInput, candidateCanonical } from '../../scripts/operator/pull_candidate_capture.mjs';
import { draftCandidateReview } from '../../scripts/operator/pull_candidate_draft.mjs';
import { rebaseCommitterMatches } from '../../scripts/operator/pull_candidate_commit.mjs';
import { saveCandidatePackage, loadCandidatePackage } from '../../scripts/operator/pull_candidate_files.mjs';
import { stageCandidateReview } from '../../scripts/operator/pull_candidate_stage.mjs';
import { loadPullIntent, loadPullBundle } from '../../scripts/operator/pull_files.mjs';
import { preparePull, pullEnvelope, validatePullIntent } from '../../scripts/operator/pull_command.mjs';
import { run } from '../../scripts/fg_pull_candidate.mjs';
import { fixture as ordinaryFixture } from '../browser/pulls-candidate-fixtures.mjs';
import { localRebase, rebasePeer, rawReferences, reply, sha, token, actor, reviewer } from './pull_candidate_rebase_fixture.mjs';

function choice(value, action = 'approve', principal = action === 'merge' ? actor : reviewer) {
  return { action, principal_id: principal, candidate_commit: value.capture.preparation.candidate_commit,
    method: 'rebase', ...(action === 'merge' ? { required_reviewers: [reviewer] } : { reason: 'Reviewed every intermediate commit and exact saved bytes.' }) };
}
async function directory(t) {
  const path = await realpath(await mkdtemp(join(tmpdir(), 'fg-rebase-candidate-'))); await chmod(path, 0o700);
  t.after(() => rm(path, { recursive: true, force: true })); return path;
}
async function cli(t, args) {
  const child = spawn(process.execPath, [resolve('scripts/fg_pull_candidate.mjs'), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  child.stdout.on('data', b => { out += b; if (out.length > 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', b => { err += b; if (err.length > 1024 * 1024) child.kill('SIGKILL'); });
  const [code, signal] = await once(child, 'close'); clearTimeout(timer); return { code, signal, out, err };
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: acquire exact native rebase series and transient protected paths`, async t => {
    const p = await rebasePeer(t, { algorithm }), value = await capturePullCandidate(p.input, token);
    assert.equal(value.capture.schema, 'frankengit-pull-candidate-capture-v1');
    assert.equal(value.capture.request.method, 'rebase'); assert.deepEqual(value.bundle, p.bundle);
    assert.equal(value.usage.requests, 4); assert.equal(p.requests.length, 4);
    assert.deepEqual(p.requests.slice(2).map(r => new URL(r.url, p.input.endpoint).pathname), [
      '/repo.git/api/v1/pulls/1/prepare-rebase', '/repo.git/api/v1/pulls/1/inspect-rebase',
    ]);
    const inspection = value.capture.inspection;
    assert.equal(inspection.commit_count, 2); assert.equal(inspection.source_comparison.entry_count, 0);
    assert.deepEqual(inspection.commits.map(c => c.comparison.entries[0].kind), ['added', 'deleted']);
    assert.equal(Buffer.from(inspection.commits[0].comparison.entries[0].path_hex, 'hex').toString(), 'protected/settings');
    assert.equal((await validateCandidateCapture(value.capture, value.bundle)).artifact.method, 'rebase');
    assert.equal(candidateCanonical(value.capture).includes(token), false);
  });
  for (const action of ['approve', 'request-changes', 'merge']) {
    test(`${algorithm} ${action}: whole-series package drafts and stages explicit durable rebase identity`, async t => {
      const v = localRebase(algorithm), root = await directory(t), selected = choice(v, action);
      const saved = await saveCandidatePackage(join(root, 'candidate'), v.capture, v.bundle);
      const checked = await loadCandidatePackage(saved.path, saved.sha256);
      assert.deepEqual(checked.capture.inspection.commits, v.capture.inspection.commits);
      const draft = await draftCandidateReview(checked.capture, checked.bundle, selected);
      assert.equal(draft.fields.method, 'rebase'); assert.equal(draft.fields.candidate_commit, selected.candidate_commit);
      if (action !== 'merge') assert.equal(draft.fields.expected_version, '5');
      const prepared = preparePull(draft, token, checked.bundle);
      assert.deepEqual(validatePullIntent(prepared), prepared);
      assert.equal(new URLSearchParams(prepared.body).get('method'), 'rebase');
      assert.ok(pullEnvelope(prepared, checked.bundle).body.includes(checked.bundle));
      const staged = await stageCandidateReview({ package: saved.path, sha256: saved.sha256, choices: selected,
        request_dir: join(root, 'request') }, token);
      assert.equal(staged.method, 'rebase'); assert.equal(staged.publication_attempted, false);
      const intent = await loadPullIntent(staged.request_dir, { sync: true });
      assert.equal(intent.fields.method, 'rebase'); assert.equal(intent.key, staged.key);
      assert.equal(intent.fields.candidate_commit, selected.candidate_commit);
      assert.deepEqual(await loadPullBundle(staged.request_dir, intent, { sync: true }), v.bundle);
    });
  }
  for (const state of ['conflicted', 'became_empty']) {
    test(`${algorithm} ${state}: retain original stopped identity without a reviewable candidate`, async t => {
      const p = await rebasePeer(t, { algorithm, state }), value = await capturePullCandidate(p.input, token);
      assert.equal(value.capture.preparation.state, state); assert.equal(value.bundle, null); assert.equal(value.capture.inspection, null);
      assert.equal(value.usage.requests, 3); assert.equal(value.capture.preparation.steps.length, 1);
      assert.equal(value.capture.preparation.stopped_commit, value.capture.pull.pull_request.data.source_tip);
      const root = await directory(t), saved = await saveCandidatePackage(join(root, 'stopped'), value.capture);
      assert.equal(saved.bundle_path, null); assert.equal((await loadCandidatePackage(saved.path, saved.sha256)).artifact, null);
      await assert.rejects(draftCandidateReview(value.capture, null, { ...choice(value), candidate_commit: 'a'.repeat(algorithm === 'sha1' ? 40 : 64) }),
        { code: 'candidate_draft_requires_clean_inspection' });
      await assert.rejects(resolvePullCandidate(value.capture, [{ path_hex: '66696c65ff', choice: 'ours' }], token),
        { code: 'candidate_rebase_resolution_requires_original_commit_recipes' });
      assert.equal(p.requests.length, 3);
      const errors = [];
      const exit = await run(['resolve', '--package', saved.path, '--sha256', saved.sha256, '--choices', join(root, 'missing-choices'),
        '--token-file', join(root, 'missing-token'), '--output-dir', join(root, 'resolved')],
      { output: async () => {}, errorOutput: async text => errors.push(JSON.parse(text)) });
      assert.equal(exit, 2); assert.equal(errors[0].code, 'candidate_rebase_resolution_requires_original_commit_recipes');
    });
  }
  test(`${algorithm}: actual CLI capture, offline inspection and staging preserve the package`, async t => {
    const p = await rebasePeer(t, { algorithm }), root = await directory(t), file = name => join(root, name);
    await writeFile(file('input.json'), candidateCanonical(p.input), { mode: 0o600 });
    await writeFile(file('token'), token + '\n', { mode: 0o600 });
    const acquired = await cli(t, ['capture', '--input', file('input.json'), '--token-file', file('token'), '--output-dir', file('package')]);
    assert.equal(acquired.code, 0, acquired.err); const saved = JSON.parse(acquired.out);
    assert.equal(saved.state, 'clean'); assert.equal(saved.published, false); assert.equal(saved.usage.requests, 4);
    const inspected = await cli(t, ['inspect', '--package', saved.path, '--sha256', saved.sha256]);
    assert.equal(inspected.code, 0, inspected.err); const observed = JSON.parse(inspected.out);
    assert.equal(observed.capture.inspection.commits.length, 2); assert.equal(observed.capture.inspection.source_comparison.entries.length, 0);
    await writeFile(file('choices.json'), candidateCanonical(choice(p)), { mode: 0o600 });
    const staged = await cli(t, ['stage', '--package', saved.path, '--sha256', saved.sha256, '--choices', file('choices.json'),
      '--token-file', file('token'), '--request-dir', file('request')]);
    assert.equal(staged.code, 0, staged.err); assert.equal(JSON.parse(staged.out).method, 'rebase'); assert.equal(p.requests.length, 4);
    assert.deepEqual(await readFile(join(file('request'), 'candidate.bundle')), p.bundle);
  });
}

const corruptions = [
  ['missing original mapping', v => { v.capture.preparation.steps.shift(); v.capture.preparation.step_count--; }],
  ['substituted intermediate mapping', v => v.capture.preparation.steps[0].rewritten = '1'.repeat(40)],
  ['changed intermediate tree', v => v.capture.preparation.steps[0].tree = '1'.repeat(40)],
  ['reordered mapping', v => v.capture.preparation.steps.reverse()],
  ['upstream masquerading as original', v => v.capture.preparation.steps[0].original = v.capture.request.metadata.upstream],
  ['missing inspected commit', v => { v.capture.inspection.commits.shift(); v.capture.inspection.commit_count--; }],
  ['final-tree-only report', v => { v.capture.inspection.commits = []; v.capture.inspection.commit_count = 0; }],
  ['changed native commit bytes', v => v.capture.inspection.commits[0].commit_hex += '0a'],
  ['unrequested committer', v => { v.capture.request.metadata.committer = 'Other <other@example.invalid>'; v.capture.preparation.committer = v.capture.request.metadata.committer; }],
  ['unrequested timestamp', v => { v.capture.request.metadata.timestamp = '9'; v.capture.preparation.timestamp = 9; }],
  ['missing preserved author report', v => delete v.capture.preparation.original_authors_preserved],
  ['false preserved message report', v => v.capture.preparation.original_messages_preserved = false],
  ['copied signature claim', v => v.capture.preparation.original_signatures_copied = true],
  ['author authority claim', v => v.capture.preparation.author_identity_verified = true],
  ['changed pack accounting', v => v.capture.preparation.pack_objects++],
  ['partial series label', v => v.capture.inspection.complete = false],
  ['missing intermediate coverage', v => v.capture.inspection.all_rewritten_commits = false],
  ['changed source snapshot', v => v.capture.inspection.source_head = 'different-head'],
  ['changed pinned token', v => v.capture.preparation.snapshot_token = `alg:1:${'d'.repeat(64)}`],
  ['wrong prerequisite', v => v.capture.inspection.prerequisites[0] = v.capture.inspection.subject.source_tip],
  ['missing review completion', v => v.capture.review_pages[0].next_after = reviewer],
  ['wrong method', v => v.capture.inspection.method = 'squash'],
  ['unsolicited resolution receipt', v => v.capture.preparation.resolution_profile = 'original-commit-path-v1'],
  ['foreign bundle', v => v.bundle[0] ^= 1],
];
for (const [name, change] of corruptions) test(`offline rebase validation rejects ${name}`, async () => {
  const value = localRebase(); change(value); await assert.rejects(validateCandidateCapture(value.capture, value.bundle));
});
test('corrupt online inspection never reaches a reviewable capture', async t => {
  const p = await rebasePeer(t, { mutate: v => v.capture.preparation.steps[0].rewritten = '1'.repeat(40) });
  await assert.rejects(capturePullCandidate(p.input, token), { code: 'candidate_rebase_series_changed', phase: 'inspection' });
  assert.equal(p.requests.length, 4);
});
test('dropping empty originals retains the complete retained chain and exact initial tree', async () => {
  const value = localRebase(), preparation = value.capture.preparation;
  value.capture.request.metadata.empty = 'drop'; preparation.empty_policy = 'drop';
  preparation.steps.unshift({ original: '2'.repeat(40), rewritten: value.capture.inspection.subject.target_tip,
    tree: value.capture.inspection.commits[0].comparison.before_tree, kind: 'dropped_empty' }); preparation.step_count++;
  assert.equal((await validateCandidateCapture(value.capture, value.bundle)).artifact.method, 'rebase');
  preparation.steps[0].tree = '1'.repeat(40);
  await assert.rejects(validateCandidateCapture(value.capture, value.bundle), { code: 'candidate_rebase_dropped_tree_changed' });
});
test('explicit keep policy still requires the complete native body chain', async () => {
  const value = localRebase(); value.capture.request.metadata.empty = 'keep'; value.capture.preparation.empty_policy = 'keep';
  assert.equal((await validateCandidateCapture(value.capture, value.bundle)).artifact.method, 'rebase');
});
test('stopped commit cannot be the excluded original upstream', async () => {
  const value = localRebase('sha1', 'conflicted');
  value.capture.preparation.stopped_commit = value.capture.request.metadata.upstream;
  await assert.rejects(validateCandidateCapture(value.capture), { code: 'candidate_rebase_original_outside_suffix' });
});
for (const method of [undefined, 'merge-commit', 'squash', '', null]) test(`rebase review requires explicit method, refusing ${JSON.stringify(method)}`, async () => {
  const value = localRebase(), selected = choice(value);
  if (method === undefined) delete selected.method; else selected.method = method;
  await assert.rejects(draftCandidateReview(value.capture, value.bundle, selected), { code: 'candidate_draft_method_changed' });
});
test('raw branch byte selectors survive online acquisition and durable drafts', async t => {
  const p = await rebasePeer(t, { algorithm: 'sha256', mutate: v => rawReferences(v.capture,
    Buffer.concat([Buffer.from('refs/heads/source-'), Buffer.from([255])]), Buffer.from('refs/heads/target-\u0085')) });
  const value = await capturePullCandidate(p.input, token), draft = await draftCandidateReview(value.capture, value.bundle, choice(value));
  assert.equal(draft.fields.source_ref_hex, p.capture.pull.pull_request.data.source_ref_hex);
  assert.equal(draft.fields.target_ref_hex, p.capture.pull.pull_request.data.target_ref_hex);
  assert.equal(Object.hasOwn(draft.fields, 'source_ref'), false); assert.equal(Object.hasOwn(draft.fields, 'target_ref'), false);
});
test('complete reviewer paging binds a stale predecessor without refreshing series identity', async t => {
  const p = await rebasePeer(t, { reviewCount: 51 });
  p.reviews[50].version = 17; p.reviews[50].freshness = 'source_moved'; p.reviews[50].subject.source_tip = '1'.repeat(40);
  const value = await capturePullCandidate(p.input, token), count = p.requests.length;
  const draft = await draftCandidateReview(value.capture, value.bundle, choice(value, 'approve', p.reviews[50].reviewer));
  assert.equal(draft.fields.expected_version, '17'); assert.equal(draft.fields.source_tip, value.capture.preparation.subject.source_tip);
  assert.equal(p.requests.length, count); assert.equal(count, 5);
});
test('metadata, choice and bundle inputs detach before asynchronous series hashing', async () => {
  const value = localRebase(), selected = choice(value), expected = selected.candidate_commit;
  const pending = draftCandidateReview(value.capture, value.bundle, selected);
  value.bundle.fill(0); value.capture.inspection.commits = []; value.capture.request.metadata.empty = 'drop';
  selected.method = 'squash'; selected.reason = 'changed';
  const result = await pending;
  assert.equal(result.fields.method, 'rebase'); assert.equal(result.fields.candidate_commit, expected);
  assert.equal(result.fields.reason, 'Reviewed every intermediate commit and exact saved bytes.');
});
test('rebase metadata rejects ordinary fields, defaults and unknown policies before requests', () => {
  for (const change of [v => delete v.metadata.upstream, v => v.metadata.empty = 'auto', v => delete v.metadata.empty,
    v => v.metadata.author = 'Author <author@example.invalid>', v => v.metadata.message = 'replacement',
    v => v.metadata.timestamp = '01', v => v.metadata.timestamp = '9007199254740992']) {
    const value = localRebase(); change(value.capture.request); assert.throws(() => candidateInput(value.capture.request));
  }
});
test('rebase acquisition respects wire, paging, cancellation and snapshot bounds', async t => {
  const p = await rebasePeer(t, { reviewCount: 51 });
  await assert.rejects(capturePullCandidate(p.input, token, { maxReviewPages: 1 }), { code: 'candidate_review_page_limit' });
  await assert.rejects(capturePullCandidate(p.input, token, { maxWireBytes: 1 }), { code: 'candidate_response_limit' });
  const controller = new AbortController(); controller.abort(); const before = p.requests.length;
  await assert.rejects(capturePullCandidate(p.input, token, { signal: controller.signal }), { code: 'candidate_cancelled' });
  assert.equal(p.requests.length, before); p.input.expected_head = `alg:1:${'e'.repeat(64)}`;
  await assert.rejects(capturePullCandidate(p.input, token));
});
test('rebase preparation refusal never falls back to ordinary preparation or a mutation route', async t => {
  const p = await rebasePeer(t, { handle: (r, response) => {
    if (!r.url.endsWith('/prepare-rebase')) return false;
    reply(response, { type: 'refusal' }, 403); return true;
  } });
  await assert.rejects(capturePullCandidate(p.input, token), { code: 'candidate_http_refused', phase: 'preparation', status: 403 });
  assert.equal(p.requests.length, 3);
});
test('committer binding ignores preserved non-UTF-8 messages and continuation text', () => {
  const value = localRebase(), metadata = value.capture.request.metadata;
  const body = Buffer.from(value.capture.inspection.commits[0].commit_hex, 'hex'), split = body.indexOf(Buffer.from('\n\n'));
  const headers = body.subarray(0, split), withBytes = Buffer.concat([headers,
    Buffer.from('\nencoding ISO-8859-1\nx-custom value\n committer this is continuation data\n\n'), Buffer.from([255, 0, 13, 10]),
    Buffer.from('committer Wrong <wrong@example.invalid> 9 +0000\n')]);
  assert.equal(rebaseCommitterMatches(withBytes.toString('hex'), metadata), true);
  assert.equal(rebaseCommitterMatches(Buffer.concat([headers, Buffer.from(`\ncommitter ${metadata.committer} 7 +0000\n\n`)]).toString('hex'), metadata), false);
});

// Preserve both ordinary parent styles and the omitted legacy review method
// without claiming the independent, presently unavailable Git-oracle lane.
for (const algorithm of ['sha1', 'sha256']) for (const method of ['merge-commit', 'squash']) {
  test(`${algorithm} ${method}: existing capture and legacy review grammar stay unchanged`, async () => {
    const f = ordinaryFixture(algorithm), capture = localRebase(algorithm).capture;
    const body = method === 'squash' ? Buffer.from(f.commitBody.toString().replace(`parent ${f.selected.source_tip}\n`, '')) : f.commitBody;
    const commit = createHash(algorithm).update(`commit ${body.length}\0`).update(body).digest('hex');
    const bundle = Buffer.from(`opaque ordinary custody fixture ${algorithm} ${method} ${commit}`);
    capture.request.method = method; capture.request.metadata = { author: 'Test <test@example.invalid>',
      committer: 'Test <test@example.invalid>', timestamp: '1', message: 'Exact candidate\n' };
    capture.preparation = { ...f.metadata, method, candidate: { ...f.metadata.candidate, commit }, bundle: { bytes: bundle.length, sha256: sha(bundle) } };
    capture.inspection = { ...f.inspection, candidate_commit: commit, candidate_commit_body_hex: body.toString('hex'),
      parents: method === 'squash' ? [f.selected.target_tip] : [f.selected.target_tip, f.selected.source_tip],
      bundle: { ...f.inspection.bundle, bytes: bundle.length, sha256: sha(bundle), expanded_bytes: body.length },
      comparison: { ...f.inspection.comparison, after: commit } };
    capture.review_pages[0].reviews[0].candidate = { merge_base: f.fields.merge_base, candidate_commit: commit };
    const checked = await validateCandidateCapture(capture, bundle);
    assert.equal(checked.artifact.method, method); assert.deepEqual(candidateInput(capture.request), capture.request);
    const selection = { action: 'approve', principal_id: reviewer, candidate_commit: commit, reason: 'Legacy review shape.' };
    const draft = await draftCandidateReview(capture, bundle, selection); assert.equal(Object.hasOwn(draft.fields, 'method'), false);
    await assert.rejects(draftCandidateReview(capture, bundle, { ...selection, method: 'rebase' }), { code: 'candidate_draft_method_changed' });
  });
}
