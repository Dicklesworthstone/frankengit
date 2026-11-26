// Explicit native-schema protocol fixtures. Commit/blob identities are real
// hashes; these tests do not run native replay, Git, pack admission or authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { sample } from '../browser/pulls-rebase-fixtures.mjs';
import { rebaseRecipeUpload } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-rebase-resolution.mjs';
import { candidateRebaseAction, replayRebaseHistory, extendRebaseHistory, verifyRebaseHistoryResult,
  REBASE_HISTORY_SCHEMA, REBASE_HISTORY_MAX_ROUNDS, REBASE_CHOICE_BYTES } from '../../scripts/operator/pull_candidate_rebase_history.mjs';
import { CandidateError } from '../../scripts/operator/pull_candidate_io.mjs';

const clone = value => structuredClone(value);
const hex = value => Buffer.from(value).toString('hex');
const blob = (format, bytes, mode = 0o100644) => ({ mode,
  oid: createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex') });
const receipts = values => ({ resolution_profile: 'original-commit-path-v1', resolution_input_commits: values.length,
  resolution_consumed_commits: values.length, resolutions: clone(values) });
function fixture(format = 'sha1') {
  const f = sample(format), replacement = Buffer.from([0, 255, 13, 10]), native = blob(format, replacement, 0o100755);
  const conflict = (ours, theirs) => ({ path_hex: 'ff', kind: 'binary', base: null,
    ours: clone(ours), theirs: blob(format, Buffer.from(theirs)) });
  const firstConflict = conflict(blob(format, Buffer.from('onto\n')), 'first\n');
  const secondConflict = conflict(native, 'second\n');
  const metadata = { ...clone(f.metadata), original_authors_preserved: true, original_messages_preserved: true,
    original_signatures_copied: false, author_identity_verified: false };
  const stop = (index, conflicts, state = 'conflicted') => ({ ...clone(metadata), state, series_complete: false,
    provisional_steps: true, candidate_commit: null, root_tree: null, bundle: null,
    stopped_commit: metadata.steps[index].original, steps: clone(metadata.steps.slice(0, index)), step_count: index,
    conflicts: clone(conflicts) });
  const original1 = metadata.steps[0].original, original2 = metadata.steps[1].original;
  const firstReceipt = { original: original1, paths: [{ conflict: clone(firstConflict), choice: 'file', result: native }] };
  const secondReceipt = { original: original2, paths: [{ conflict: clone(secondConflict), choice: 'theirs', result: clone(secondConflict.theirs) }] };
  const first = stop(0, [firstConflict]);
  const second = { ...stop(1, [secondConflict]), ...receipts([firstReceipt]) };
  const complete = { ...metadata, generated_objects: 4, pack_objects: 4, borrowed_objects: 0,
    ...receipts([firstReceipt, secondReceipt]) };
  const firstAction = { action: 'resolve', original: original1,
    choices: [{ path_hex: 'ff', choice: 'file', mode: '100755', content_hex: hex(replacement) }] };
  const secondAction = { action: 'resolve', original: original2, choices: [{ path_hex: 'ff', choice: 'theirs' }] };
  const context = { number: 1, command: clone(f.command), scope: clone(f.artifact.scope),
    head: metadata.snapshot_token, sourceHead: metadata.source_head };
  return { ...f, first, second, complete, firstAction, secondAction, context, firstReceipt, secondReceipt, stop, replacement };
}
function decode(upload) {
  const bytes = Buffer.from(upload.bytes);
  if (upload.contentType === 'application/x-www-form-urlencoded') return { command: new URLSearchParams(bytes.toString()), files: new Map() };
  const boundary = /boundary=([^;]+)$/.exec(upload.contentType)[1], marker = Buffer.from(`\r\n--${boundary}`);
  const files = new Map(); let offset = Buffer.byteLength(`--${boundary}\r\n`), command;
  for (;;) {
    const split = bytes.indexOf('\r\n\r\n', offset), end = bytes.indexOf(marker, split + 4);
    assert.ok(split >= offset && end >= split + 4);
    const header = bytes.subarray(offset, split).toString(), name = /name="([^"]+)"/.exec(header)[1];
    const value = bytes.subarray(split + 4, end);
    if (name === 'command') command = new URLSearchParams(value.toString()); else files.set(name, value);
    offset = end + marker.length;
    if (bytes.subarray(offset, offset + 4).equals(Buffer.from('--\r\n'))) { assert.equal(offset + 4, bytes.length); break; }
    assert.equal(bytes.subarray(offset, offset + 2).toString(), '\r\n'); offset += 2;
  }
  return { command, files };
}
const code = wanted => error => error instanceof CandidateError && error.code === wanted;

for (const format of ['sha1', 'sha256']) test(`${format}: serialized stops replay every prior original-bound recipe and exact file`, async () => {
  const f = fixture(format), first = await extendRebaseHistory(null, f.first, f.firstAction, f.context);
  assert.equal(first.operation, 'resolve-rebase'); assert.equal(first.history.schema, REBASE_HISTORY_SCHEMA);
  assert.equal(first.history.rounds.length, 1); assert.equal(first.recipes[0].original, f.first.stopped_commit);
  assert.deepEqual(first.recipes[0].paths[0].result, f.firstReceipt.paths[0].result);
  const retained = JSON.parse(JSON.stringify(first.history)), restored = await replayRebaseHistory(retained, f.context);
  assert.deepEqual(restored.recipes, first.recipes); assert.deepEqual(restored.command, first.command);
  verifyRebaseHistoryResult(f.second, restored);
  const second = await extendRebaseHistory(retained, f.second, f.secondAction, f.context);
  assert.equal(second.history.rounds.length, 2);
  const sent = decode(second.upload);
  assert.deepEqual(sent.command.getAll('resolution'), [
    `${f.first.stopped_commit}:ff:file:100755:file_0`, `${f.second.stopped_commit}:ff:theirs`,
  ]);
  assert.equal(sent.command.get('expected_head'), f.context.head);
  assert.equal(sent.command.get('upstream'), f.context.command.upstream);
  assert.deepEqual(sent.files.get('file_0'), f.replacement);
  assert.doesNotThrow(() => verifyRebaseHistoryResult(f.complete, second));
  assert.deepEqual(first.history, retained, 'extending a new package leaves the old history unchanged');
  const offline = await replayRebaseHistory(JSON.parse(JSON.stringify(second.history)), f.context);
  assert.deepEqual(offline.recipes, second.recipes);
  assert.doesNotThrow(() => verifyRebaseHistoryResult(f.complete, offline));
});

test('choices explicitly confirm the current original commit and cannot revise prior resolutions', async () => {
  const f = fixture(), first = await extendRebaseHistory(null, f.first, f.firstAction, f.context);
  for (const original of [f.first.stopped_commit, f.context.command.upstream, f.metadata.steps[1].rewritten]) {
    await assert.rejects(extendRebaseHistory(first.history, f.second, { ...f.secondAction, original }, f.context),
      code('candidate_rebase_wrong_original'));
  }
  await assert.rejects(extendRebaseHistory(first.history, f.first, f.firstAction, f.context));
  for (const mutate of [
    h => { h.rounds[0].action.original = f.second.stopped_commit; },
    h => { h.rounds[0].action.choices[0].content_hex = 'ff'; },
    h => { h.rounds[0].preparation.conflicts[0].ours.oid = '8'.repeat(40); },
  ]) {
    const history = clone(first.history); mutate(history);
    await assert.rejects(extendRebaseHistory(history, f.second, f.secondAction, f.context));
  }
});

test('each consumed receipt must preserve the original conflict, choice, result and path set', async () => {
  const f = fixture(), first = await extendRebaseHistory(null, f.first, f.firstAction, f.context);
  const mutations = [
    r => { delete r.resolution_profile; }, r => { r.resolution_input_commits++; },
    r => { r.resolution_consumed_commits = 0; }, r => { r.resolutions.length = 0; },
    r => { r.resolutions[0].original = r.steps[0].rewritten; },
    r => { r.resolutions[0].paths[0].conflict.path_hex = '61'; },
    r => { r.resolutions[0].paths[0].conflict.kind = 'content'; },
    r => { r.resolutions[0].paths[0].choice = 'ours'; },
    r => { r.resolutions[0].paths[0].result.oid = '8'.repeat(40); },
    r => { r.resolutions[0].paths[0].result.mode = 0o100644; },
    r => { r.resolutions[0].paths.push(clone(r.resolutions[0].paths[0])); },
  ];
  for (const mutate of mutations) {
    const report = clone(f.second); mutate(report);
    await assert.rejects(extendRebaseHistory(first.history, report, f.secondAction, f.context));
  }
});

test('unchanged completed original mappings and trees are required across every later stop', async () => {
  const f = fixture(), first = await extendRebaseHistory(null, f.first, f.firstAction, f.context);
  const second = await extendRebaseHistory(first.history, f.second, f.secondAction, f.context);
  for (const key of ['original', 'rewritten', 'tree', 'kind']) {
    const changed = clone(f.complete); changed.steps[0][key] = key === 'kind' ? 'preserved_empty' : 'c'.repeat(40);
    assert.throws(() => verifyRebaseHistoryResult(changed, second));
  }
  const swapped = clone(f.second); swapped.steps[0].original = '9'.repeat(40);
  await assert.rejects(extendRebaseHistory(first.history, swapped, f.secondAction, f.context));
  const truncated = clone(f.complete); truncated.steps.length = 0;
  assert.throws(() => verifyRebaseHistoryResult(truncated, second));
});

test('final clean receipts are closed at every nested record as well as during history replay', async () => {
  const f = fixture(), first = await extendRebaseHistory(null, f.first, f.firstAction, f.context);
  const second = await extendRebaseHistory(first.history, f.second, f.secondAction, f.context);
  for (const mutate of [
    r => { r.resolutions[0].published = true; },
    r => { r.resolutions[0].paths[0].bytes = 'forged'; },
    r => { r.resolutions[0].paths[0].conflict.authorized = true; },
    r => { r.resolutions[0].paths[0].conflict.ours.extra = 1; },
    r => { r.resolutions[0].paths[0].result.extra = 1; },
    r => { r.resolutions[0].paths[0].result.oid = `sha1:${r.resolutions[0].paths[0].result.oid}`; },
    r => { r.resolutions[0].paths[0].choice = 'automatic'; },
  ]) {
    const report = clone(f.complete); mutate(report);
    assert.throws(() => verifyRebaseHistoryResult(report, second));
  }
});

for (const format of ['sha1', 'sha256']) for (const empty of ['keep', 'drop'])
  test(`${format}: ${empty} after a resolved empty stop preserves recipes and changes only explicit policy`, async () => {
    const f = fixture(format), first = await extendRebaseHistory(null, f.first, f.firstAction, f.context);
    const stopped = { ...f.stop(0, [], 'became_empty'), ...receipts([f.firstReceipt]) };
    verifyRebaseHistoryResult(stopped, first);
    const action = { action: 'continue-empty', original: stopped.stopped_commit, from_empty: 'stop', empty };
    const continued = await extendRebaseHistory(first.history, stopped, action, f.context);
    assert.equal(continued.operation, 'resolve-rebase');
    assert.deepEqual(continued.command, { ...first.command, empty });
    assert.deepEqual(continued.recipes, first.recipes);
    const sent = decode(continued.upload);
    assert.equal(sent.command.get('empty'), empty); assert.equal(sent.command.get('expected_head'), f.context.head);
    assert.deepEqual(sent.command.getAll('resolution'), [`${f.first.stopped_commit}:ff:file:100755:file_0`]);
    assert.deepEqual(sent.files.get('file_0'), f.replacement);
    const next = clone(f.second); next.empty_policy = empty;
    if (empty === 'drop') {
      next.steps[0].kind = 'dropped_empty'; next.steps[0].rewritten = f.context.command.target_tip;
    }
    assert.doesNotThrow(() => verifyRebaseHistoryResult(next, continued));
    const replayed = await replayRebaseHistory(JSON.parse(JSON.stringify(continued.history)), f.context);
    assert.deepEqual(replayed.command, continued.command); assert.deepEqual(replayed.recipes, continued.recipes);
    const wrong = clone(next); wrong.steps[0].kind = empty === 'drop' ? 'replayed' : 'dropped_empty';
    assert.throws(() => verifyRebaseHistoryResult(wrong, continued), code('candidate_rebase_empty_outcome_changed'));
    await assert.rejects(extendRebaseHistory(continued.history, stopped, action, f.context));
  });

test('empty continuation with no recipes uses native prepare grammar and pins the returned snapshot', async () => {
  const f = fixture(), stopped = f.stop(0, [], 'became_empty');
  const continued = await extendRebaseHistory(null, stopped,
    { action: 'continue-empty', original: stopped.stopped_commit, from_empty: 'stop', empty: 'keep' }, f.context);
  assert.equal(continued.operation, 'prepare-rebase'); assert.equal(continued.recipes.length, 0);
  const fields = decode(continued.upload).command;
  assert.equal(fields.get('empty'), 'keep'); assert.equal(fields.has('expected_head'), false);
  assert.equal(fields.has('resolution'), false);
  const changed = { ...clone(f.second), empty_policy: 'keep', snapshot_token: `alg:2:${'8'.repeat(64)}` };
  assert.throws(() => verifyRebaseHistoryResult(changed, continued));
  assert.throws(() => candidateRebaseAction({ action: 'continue-empty', original: stopped.stopped_commit,
    from_empty: 'drop', empty: 'keep' }, 'sha1'), code('candidate_rebase_explicit_empty_transition_required'));
});

test('a policy continuation cannot rewrite an already completed prefix', async () => {
  const f = fixture(), stopped = f.stop(1, [], 'became_empty');
  const state = await extendRebaseHistory(null, stopped,
    { action: 'continue-empty', original: stopped.stopped_commit, from_empty: 'stop', empty: 'drop' }, f.context);
  const reply = clone(f.complete); reply.empty_policy = 'drop';
  for (const name of ['resolution_profile', 'resolution_input_commits', 'resolution_consumed_commits', 'resolutions']) delete reply[name];
  reply.steps[1] = { ...reply.steps[1], rewritten: reply.steps[0].rewritten, tree: reply.steps[0].tree, kind: 'dropped_empty' };
  assert.doesNotThrow(() => verifyRebaseHistoryResult(reply, state));
  reply.steps[0].tree = '9'.repeat(40);
  assert.throws(() => verifyRebaseHistoryResult(reply, state), code('candidate_rebase_completed_prefix_changed'));
});

test('incomplete choices, unsafe paths, file modes and malformed histories fail before file hashing', async () => {
  const f = fixture(); let hashes = 0;
  const crypto = { getRandomValues: bytes => webcrypto.getRandomValues(bytes), subtle: { digest() { hashes++; throw Error('unexpected hash'); } } };
  for (const action of [
    { ...f.firstAction, choices: [] },
    { ...f.firstAction, original: `sha1:${f.first.stopped_commit}` },
    { ...f.firstAction, choices: [{ path_hex: '2e6769742f636f6e666967', choice: 'delete' }] },
    { ...f.firstAction, choices: [{ path_hex: 'ff', choice: 'file', mode: '120000', content_hex: '' }] },
    { ...f.firstAction, choices: [{ path_hex: '61', choice: 'theirs' }] },
    { ...f.firstAction, choices: [{ path_hex: 'ff', choice: 'base' }] },
  ]) await assert.rejects(extendRebaseHistory(null, f.first, action, f.context, { crypto }));
  for (const history of [{ schema: REBASE_HISTORY_SCHEMA, rounds: Array(REBASE_HISTORY_MAX_ROUNDS + 1).fill({}) },
    { schema: 'unknown', rounds: [] }, { schema: REBASE_HISTORY_SCHEMA, rounds: [], token: 'secret' }]) {
    await assert.rejects(replayRebaseHistory(history, f.context, { crypto }));
  }
  assert.equal(hashes, 0);
});

test('whole-series raw content budget is cumulative before a new file hash', async () => {
  const f = fixture(), bytes = Buffer.alloc(REBASE_CHOICE_BYTES / 4, 65);
  const first = await extendRebaseHistory(null, f.first, f.firstAction, f.context);
  const report = clone(f.second), choices = [];
  report.conflicts = Array.from({ length: 4 }, (_, i) => ({ ...clone(report.conflicts[0]), path_hex: hex(`p${i}`) }));
  for (const row of report.conflicts) choices.push({ path_hex: row.path_hex, choice: 'file', mode: '100644', content_hex: hex(bytes) });
  let hashes = 0;
  const crypto = { getRandomValues: bytes => webcrypto.getRandomValues(bytes), subtle: { digest(...args) { hashes++; return webcrypto.subtle.digest(...args); } } };
  await assert.rejects(extendRebaseHistory(first.history, report, { ...f.secondAction, choices }, f.context, { crypto }),
    code('candidate_rebase_resolution_budget'));
  assert.equal(hashes, 0, 'oversized new action fails before replay or hashing its files');
});

test('caller edits during hashing cannot change retained observations, actions, pins or file bytes', async () => {
  const f = fixture(); let enter, release;
  const entered = new Promise(resolve => { enter = resolve; }), waiting = new Promise(resolve => { release = resolve; });
  const crypto = { getRandomValues: bytes => webcrypto.getRandomValues(bytes), subtle: { async digest(...args) {
    enter(); await waiting; return webcrypto.subtle.digest(...args);
  } } };
  const original = clone({ first: f.first, firstAction: f.firstAction, context: f.context, replacement: f.replacement });
  const work = extendRebaseHistory(null, f.first, f.firstAction, f.context, { crypto });
  await entered;
  f.first.conflicts[0].ours.oid = '8'.repeat(40); f.firstAction.choices[0].content_hex = '77';
  f.context.command.committer = 'Changed <changed@example.invalid>'; f.context.head = `alg:2:${'8'.repeat(64)}`;
  release(); const result = await work;
  assert.deepEqual(result.history.rounds[0].preparation, original.first);
  assert.deepEqual(result.history.rounds[0].action, original.firstAction);
  assert.deepEqual(result.context, original.context);
  assert.deepEqual(decode(result.upload).files.get('file_0'), Buffer.from(original.replacement));
});

test('cancellation interrupts historical replay without returning a reusable partial state', async () => {
  const f = fixture(), first = await extendRebaseHistory(null, f.first, f.firstAction, f.context);
  let checks = 0;
  await assert.rejects(replayRebaseHistory(first.history, f.context, { check() {
    if (++checks === 5) throw new CandidateError('candidate_cancelled');
  } }), code('candidate_cancelled'));
  const restored = await replayRebaseHistory(first.history, f.context);
  assert.deepEqual(restored.history, first.history);
});

test('shared serializer refuses empty recipes and preserves exact file framing after policy changes', async () => {
  const f = fixture(), first = await extendRebaseHistory(null, f.first, f.firstAction, f.context);
  assert.throws(() => rebaseRecipeUpload(first.command, f.context.head, [], webcrypto));
  const upload = rebaseRecipeUpload({ ...first.command, empty: 'drop' }, f.context.head, first.recipes, webcrypto);
  assert.equal(decode(upload).command.get('empty'), 'drop');
  assert.deepEqual(decode(upload).files.get('file_0'), f.replacement);
});
