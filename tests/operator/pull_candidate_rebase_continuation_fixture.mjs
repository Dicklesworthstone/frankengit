// Native-schema read peers, not a replay engine. Hashes and exact binary custody
// are checked independently; bundle bytes remain explicitly opaque fixtures.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { localRebase, rebasePeer, mixed, reply, sha, head } from './pull_candidate_rebase_fixture.mjs';

const clone = value => structuredClone(value);
const blob = (algorithm, bytes, mode = 0o100644) => ({ mode,
  oid: createHash(algorithm).update(`blob ${bytes.length}\0`).update(bytes).digest('hex') });
const receipts = rows => rows.length ? { resolution_profile: 'original-commit-path-v1', resolution_input_commits: rows.length,
  resolution_consumed_commits: rows.length, resolutions: clone(rows) } : {};
export function continuationFixture(algorithm = 'sha1', flow = 'conflicts') {
  const value = localRebase(algorithm), complete = clone(value.capture.preparation), inspection = clone(value.capture.inspection);
  const replacement = Buffer.from([0, 255, 13, 10]), result = blob(algorithm, replacement, 0o100755);
  const firstConflict = { path_hex: 'ff', kind: 'binary', base: null,
    ours: blob(algorithm, Buffer.from('onto\n')), theirs: blob(algorithm, Buffer.from('first\n')) };
  const secondConflict = { path_hex: 'ff', kind: 'binary', base: null,
    ours: clone(result), theirs: blob(algorithm, Buffer.from('second\n')) };
  const stop = (index, conflicts, state = 'conflicted', rows = []) => {
    const report = { ...clone(complete), state, series_complete: false, provisional_steps: true,
      candidate_commit: null, root_tree: null, bundle: null, stopped_commit: complete.steps[index].original,
      steps: clone(complete.steps.slice(0, index)), step_count: index, conflicts: clone(conflicts), ...receipts(rows) };
    for (const key of ['generated_objects', 'pack_objects', 'borrowed_objects']) delete report[key];
    return report;
  };
  const firstOriginal = complete.steps[flow === 'conflicts' ? 0 : 1].original, lastOriginal = complete.steps[1].original;
  const firstAction = { action: 'resolve', original: firstOriginal,
    choices: [{ path_hex: 'ff', choice: 'file', mode: '100755', content_hex: replacement.toString('hex') }] };
  const secondAction = { action: 'resolve', original: lastOriginal, choices: [{ path_hex: 'ff', choice: 'theirs' }] };
  const emptyAction = { action: 'continue-empty', original: lastOriginal, from_empty: 'stop', empty: flow.endsWith('drop') ? 'drop' : 'keep' };
  const firstReceipt = { original: firstOriginal, paths: [{ conflict: clone(firstConflict), choice: 'file', result: clone(result) }] };
  const secondReceipt = { original: lastOriginal, paths: [{ conflict: clone(secondConflict), choice: 'theirs', result: clone(secondConflict.theirs) }] };
  let initial, actions, reports;
  if (flow === 'conflicts') {
    initial = stop(0, [firstConflict]); actions = [firstAction, secondAction];
    reports = [stop(1, [secondConflict], 'conflicted', [firstReceipt])];
    Object.assign(complete, receipts([firstReceipt, secondReceipt]));
  } else if (flow.startsWith('resolved-')) {
    initial = stop(1, [firstConflict]); actions = [firstAction, emptyAction];
    reports = [stop(1, [], 'became_empty', [firstReceipt])];
    Object.assign(complete, receipts([firstReceipt]));
  } else {
    initial = stop(1, [], 'became_empty'); actions = [emptyAction]; reports = [];
  }
  if (flow !== 'conflicts') complete.empty_policy = emptyAction.empty;
  if (flow.endsWith('drop')) {
    const first = complete.steps[0], retained = inspection.commits[0];
    Object.assign(complete.steps[1], { rewritten: first.rewritten, tree: first.tree, kind: 'dropped_empty' });
    Object.assign(complete, { candidate_commit: first.rewritten, root_tree: first.tree, generated_objects: 2, pack_objects: 2 });
    Object.assign(inspection, { candidate_commit: first.rewritten, commits: [retained], commit_count: 1 });
    Object.assign(inspection.source_comparison, { after: first.rewritten, after_tree: first.tree,
      entries: clone(retained.comparison.entries), entry_count: retained.comparison.entry_count });
    Object.assign(inspection.bundle, { pack_objects: 2, expanded_bytes: retained.commit_hex.length / 2 });
  }
  const bundle = Buffer.from(`opaque continued series fixture ${algorithm} ${flow} ${complete.candidate_commit}\n\0`);
  complete.bundle = { bytes: bundle.length, sha256: sha(bundle) };
  Object.assign(inspection.bundle, complete.bundle);
  reports.push(complete);
  value.capture.preparation = clone(initial); value.capture.preparation_status = 409; value.capture.inspection = null; value.bundle = null;
  return { ...value, initial, actions, reports, complete, inspection, bundle, replacement, firstReceipt, secondReceipt, flow };
}
function decode(type, bytes) {
  if (type === 'application/x-www-form-urlencoded') return { command: new URLSearchParams(bytes.toString()), files: new Map() };
  const boundary = /boundary=([^;]+)$/.exec(type)[1], marker = Buffer.from(`\r\n--${boundary}`), files = new Map();
  let offset = Buffer.byteLength(`--${boundary}\r\n`), command;
  for (;;) {
    const split = bytes.indexOf('\r\n\r\n', offset), end = bytes.indexOf(marker, split + 4);
    assert.ok(split >= offset && end >= split + 4);
    const name = /name="([^"]+)"/.exec(bytes.subarray(offset, split).toString())[1], value = bytes.subarray(split + 4, end);
    if (name === 'command') command = new URLSearchParams(value.toString()); else files.set(name, value);
    offset = end + marker.length;
    if (bytes.subarray(offset, offset + 4).toString() === '--\r\n') { assert.equal(offset + 4, bytes.length); break; }
    assert.equal(bytes.subarray(offset, offset + 2).toString(), '\r\n'); offset += 2;
  }
  return { command, files };
}
export async function continuationPeer(t, { algorithm = 'sha1', flow = 'conflicts', handle } = {}) {
  const fixture = continuationFixture(algorithm, flow); let initialPreparation = false, at = 0;
  const p = await rebasePeer(t, { algorithm, mutate: p => {
    p.capture = clone(fixture.capture); p.bundle = null; p.continuations = [];
  }, handle: async (request, response, p) => {
    if (handle && await handle(request, response, p, fixture)) return true;
    const preparing = request.url.endsWith('/prepare-rebase'), resolving = request.url.endsWith('/resolve-rebase');
    if (preparing && !initialPreparation) { initialPreparation = true; return false; }
    if (!preparing && !resolving) return false;
    assert.ok(at < fixture.reports.length); assert.equal(request.method, 'POST');
    const decoded = decode(request.headers['content-type'], request.body), command = decoded.command;
    assert.equal(command.get('profile'), 'path-v1');
    assert.equal(command.get('upstream'), p.input.metadata.upstream);
    assert.equal(command.get('committer'), p.input.metadata.committer); assert.equal(command.get('timestamp'), p.input.metadata.timestamp);
    assert.equal(command.get('empty'), fixture.reports[at].empty_policy);
    const resolutions = fixture.actions.slice(0, at + 1).filter(action => action.action === 'resolve');
    assert.equal(preparing, resolutions.length === 0);
    assert.equal(command.get('expected_head'), preparing ? null : head);
    assert.deepEqual(command.getAll('resolution'), resolutions.map(action => {
      const path = action.choices[0]; return `${action.original}:${path.path_hex}:${path.choice}` +
        (path.choice === 'file' ? ':100755:file_0' : '');
    }));
    if (resolutions.length) assert.deepEqual(decoded.files.get('file_0'), fixture.replacement);
    else assert.equal(decoded.files.size, 0);
    p.continuations.push({ request, command, files: decoded.files });
    const report = fixture.reports[at++]; p.capture.preparation = clone(report);
    if (report.state === 'clean') {
      p.bundle = Buffer.from(fixture.bundle); p.capture.inspection = clone(fixture.inspection);
      const body = mixed(report, p.bundle);
      response.writeHead(200, { 'Content-Type': body.type, 'Content-Length': body.body.length }); response.end(body.body);
    } else reply(response, report, 409);
    return true;
  } });
  p.fixture = fixture; return p;
}
