// Controlled HTTP/DOM peers exercise the production browser client, editor and
// WebCrypto verification. Native Git/authority execution is a separate lane.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { mountPulls, displayBytes } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { ResolutionEditor } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution-view.mjs';
import { rebaseResolutionUpload, verifyRebaseResolutions } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-rebase-resolution.mjs';
import { RESOLUTION_FILE_LIMIT, RESOLUTION_CONTENT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution.mjs';
import { sample, metadata } from './pulls-rebase-fixtures.mjs';
import { terminal } from './pulls-candidate-fixtures.mjs';
import { token, reviewer, page, show, json, options, webcrypto, deferred } from './pulls-fixtures.mjs';
import { fakeDocument, until } from './helpers/pulls-workflow-fixture.mjs';

const hex = bytes => Buffer.from(bytes).toString('hex');
const clone = value => structuredClone(value);
const hash = (algorithm, kind, bytes) => createHash(algorithm).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
const nativeBlob = (algorithm, bytes, mode = 0o100644) => ({ mode, oid: hash(algorithm, 'blob', bytes) });
const binary = new Uint8Array([0, 255, 13, 10, 60, 115, 99, 114, 105, 112, 116, 62]);

function resolutionSample(algorithm = 'sha1') {
  const value = sample(algorithm), original = value.metadata.steps[0].original;
  const row = (path_hex, kind = 'content') => ({ path_hex, kind, base: null,
    ours: nativeBlob(algorithm, Buffer.from('target conflict\n')),
    theirs: nativeBlob(algorithm, Buffer.from('original conflict\n')) });
  const firstConflict = row(hex('protected/settings'));
  firstConflict.theirs = nativeBlob(algorithm, Buffer.from('secret\n'));
  const finalConflicts = [row(hex('empty')), row('ff', 'binary')];
  const receipt = { original, paths: [{ conflict: clone(firstConflict), choice: 'theirs', result: clone(firstConflict.theirs) }] };
  const fileReceipt = { original: value.fields.source_tip, paths: finalConflicts.map((conflict, index) => ({
    conflict: clone(conflict), choice: 'file', result: nativeBlob(algorithm, index === 0 ? new Uint8Array() : binary,
      index === 0 ? 0o100644 : 0o100755),
  })) };
  const receipts = resolutions => ({ resolution_profile: 'original-commit-path-v1', resolution_input_commits: resolutions.length,
    resolution_consumed_commits: resolutions.length, resolutions: clone(resolutions) });
  const stop = (stopped_commit, steps, conflicts) => ({ ...clone(value.metadata), state: 'conflicted', candidate_commit: null,
    root_tree: null, bundle: null, stopped_commit, steps: clone(steps), step_count: steps.length,
    series_complete: false, provisional_steps: true, conflicts: clone(conflicts) });
  const first = stop(original, [], [firstConflict]);
  const second = { ...stop(value.fields.source_tip, [value.metadata.steps[0]], finalConflicts), ...receipts([receipt]) };
  const complete = { ...clone(value.metadata), ...receipts([receipt, fileReceipt]) };
  const fileEntries = fileReceipt.paths.map((path, index) => ({ path_hex: path.conflict.path_hex, kind: 'added', before: null,
    after: clone(path.result), content: index === 0
      ? { type: 'text', algorithm: 'myers-v1', before_bytes: 0, after_bytes: 0, additions: 0, deletions: 0, hunks: [] }
      : { type: 'binary', before_bytes: 0, after_bytes: binary.length, body_included: false } }));
  value.inspection.source_comparison.before_tree = '5'.repeat(algorithm === 'sha1' ? 40 : 64);
  value.inspection.source_comparison.entries = clone(fileEntries);
  value.inspection.source_comparison.entry_count = fileEntries.length;
  const comparison = value.inspection.commits[1].comparison;
  comparison.entries = [...comparison.entries, ...clone(fileEntries)].sort((a, b) => a.path_hex.localeCompare(b.path_hex));
  comparison.entry_count = comparison.entries.length;
  return { ...value, first, second, complete, receipt, fileReceipt,
    initialChoices: [{ path_hex: firstConflict.path_hex, choice: 'theirs' }],
    finalChoices: [
      { path_hex: 'ff', choice: 'file', mode: '100755', bytes: binary.slice() },
      { path_hex: hex('empty'), choice: 'file', mode: '100644', bytes: new Uint8Array() },
    ] };
}

const preparedResponse = (value, report = value.complete) => new Response(value.mixed(report), { headers: { 'Content-Type': value.type } });
async function decoded(call) {
  const type = call.headers['Content-Type'], bytes = Buffer.from(await new Response(call.body).arrayBuffer());
  if (type === 'application/x-www-form-urlencoded') return { parts: new Map(), form: new URLSearchParams(bytes.toString('utf8')) };
  const match = /^multipart\/form-data; boundary=([A-Za-z0-9._-]+)$/.exec(type);
  assert.ok(match, 'one explicit multipart boundary');
  const boundary = match[1], start = Buffer.from(`--${boundary}\r\n`), delimiter = Buffer.from(`\r\n--${boundary}`);
  assert.ok(bytes.subarray(0, start.length).equals(start));
  const parts = new Map(); let offset = start.length;
  for (;;) {
    const split = bytes.indexOf('\r\n\r\n', offset); assert.ok(split >= offset, 'complete MIME part headers');
    const headers = bytes.subarray(offset, split).toString('ascii');
    const name = /Content-Disposition: form-data; name="([^"]+)"/.exec(headers)?.[1];
    assert.ok(name); assert.equal(parts.has(name), false);
    const end = bytes.indexOf(delimiter, split + 4); assert.ok(end >= split + 4, 'complete MIME body');
    const body = bytes.subarray(split + 4, end);
    // Filename-free octet-stream parts are bytes, not browser FormData strings.
    // A generic FormData decoder would corrupt the binary test payload here.
    parts.set(name, name === 'command' ? body.toString('utf8') : new Uint8Array(body));
    offset = end + delimiter.length;
    if (bytes.subarray(offset, offset + 4).equals(Buffer.from('--\r\n'))) {
      assert.equal(offset + 4, bytes.length); break;
    }
    assert.ok(bytes.subarray(offset, offset + 2).equals(Buffer.from('\r\n'))); offset += 2;
  }
  assert.equal(typeof parts.get('command'), 'string');
  return { parts, form: new URLSearchParams(parts.get('command')) };
}
async function connected(value, dispatch = null, cryptoImpl = webcrypto) {
  const calls = []; let client, resolutions = 0;
  client = new PullClient({ ...options(async (url, init) => {
    const call = { url: String(url), path: url.pathname, ...init }; calls.push(call);
    if (url.pathname.endsWith('/pulls')) return json(page({ object_format: value.fields.object_format, pull_requests: [] }));
    if (dispatch) { const custom = await dispatch(call, client); if (custom) return custom; }
    if (url.pathname.endsWith('/prepare-rebase')) return json(value.first, 409);
    if (url.pathname.endsWith('/resolve-rebase')) return ++resolutions === 1 ? json(value.second, 409) : preparedResponse(value);
    if (url.pathname.endsWith('/inspect-rebase')) return json(value.inspection);
    if (call.headers['Idempotency-Key']) return json(terminal(client.pending, { method: 'rebase' }));
    throw new Error(`Unexpected browser request ${url}`);
  }), cryptoImpl });
  await client.connect(token); await client.list();
  await client.prepareRebaseAndInspect(1, value.selected, { ...metadata, upstream: value.fields.merge_base });
  return { client, calls };
}
async function noAuthority(client) {
  assert.equal(client.candidate, null); assert.equal(client.pending, null);
  await assert.rejects(client.stageReview('approve', 0, 'No complete inspection'));
  await assert.rejects(client.stageMerge([reviewer]));
}

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: successive conflicts retain original recipes and head until complete inspection permits explicit review and merge`, async () => {
  const value = resolutionSample(algorithm), inspection = deferred(); let inspecting = false;
  const { client, calls } = await connected(value, call => {
    if (call.path.endsWith('/inspect-rebase') && !inspecting) { inspecting = true; return inspection.promise; }
    return null;
  });
  assert.equal(client.conflict.stopped_commit, value.first.stopped_commit); await noAuthority(client);
  const stopped = await client.resolveAndInspect(value.initialChoices);
  assert.equal(stopped.inspection, null); assert.equal(client.conflict.stopped_commit, value.fields.source_tip);
  assert.equal(stopped.metadata.resolution_consumed_commits, 1); await noAuthority(client);
  const firstRequest = await decoded(calls.find(call => call.path.endsWith('/resolve-rebase')));
  assert.equal(firstRequest.form.get('expected_head'), value.first.snapshot_token);
  assert.deepEqual(firstRequest.form.getAll('resolution'), [`${value.first.stopped_commit}:${value.initialChoices[0].path_hex}:theirs`]);
  assert.equal(firstRequest.form.get('profile'), 'path-v1'); assert.equal(firstRequest.form.get('upstream'), value.fields.merge_base);
  for (const forbidden of ['method', 'author', 'message', 'principal']) assert.equal(firstRequest.form.has(forbidden), false);

  const completing = client.resolveAndInspect(value.finalChoices);
  await until(() => inspecting); await noAuthority(client);
  assert.equal(calls.some(call => call.path.endsWith('/inspect')), false);
  const request = await decoded(calls.filter(call => call.path.endsWith('/resolve-rebase')).at(-1));
  assert.equal(request.form.get('expected_head'), value.first.snapshot_token);
  assert.equal(request.form.get('pull_request_version'), '1'); assert.equal(request.form.get('source_tip'), value.fields.source_tip);
  assert.deepEqual(request.form.getAll('resolution'), [
    `${value.first.stopped_commit}:${value.initialChoices[0].path_hex}:theirs`,
    `${value.fields.source_tip}:${hex('empty')}:file:100644:file_0`, `${value.fields.source_tip}:ff:file:100755:file_1`,
  ]);
  assert.equal(request.parts.get('file_0').byteLength, 0);
  assert.deepEqual(request.parts.get('file_1'), binary);
  assert.equal([...request.parts.keys()].length, 3);
  assert.ok(calls.every(call => !call.headers['Idempotency-Key']));
  inspection.resolve(json(value.inspection)); const result = await completing;
  assert.equal(result.inspection.commit_count, 2); assert.equal(client.conflict, null);
  assert.equal(client.candidate.method, 'rebase'); assert.equal(client.pending, null);
  assert.equal(result.metadata.resolutions[1].paths[1].result.oid, hash(algorithm, 'blob', binary));
  const reads = calls.length;
  await client.stageReview('approve', 0, 'Both original resolutions and every rewritten commit inspected');
  assert.equal(calls.length, reads); assert.equal(client.pending.fields.method, 'rebase');
  assert.equal((await client.send()).outcome, 'committed');
  await client.inspect(1, value.fields, value.bundle, 'rebase');
  await client.stageMerge([reviewer]); assert.equal(client.pending.fields.method, 'rebase');
  assert.equal((await client.send()).outcome, 'committed');
  const writes = calls.filter(call => call.headers['Idempotency-Key']);
  assert.equal(writes.length, 2);
  for (const call of writes) assert.match(await call.body.text(), /method=rebase/);
  client.disconnect();
});

test('resolution request inputs reject wrong snapshots, subjects, methods, paths and incomplete choices before dispatch', async () => {
  const value = resolutionSample();
  const mutations = [
    report => { report.snapshot_token = `alg:1:${'0'.repeat(64)}`; },
    report => { report.subject.source_tip = '7'.repeat(40); },
    report => { report.subject.policy_epoch += 1; },
    report => { report.method = 'squash'; },
    report => { report.profile = 'linear-v1'; },
    report => { report.state = 'clean'; },
    report => { report.published = true; },
    report => { report.stopped_commit = value.fields.merge_base; },
    report => { report.conflicts[0].ours.mode = 0o100600; },
    report => { report.conflicts[0].path_hex = hex('.GiT/config'); },
    report => { report.conflicts.push({ ...report.conflicts[0] }); },
  ];
  for (const mutate of mutations) {
    const report = clone(value.first); mutate(report);
    await assert.rejects(rebaseResolutionUpload(report, value.command, value.first.snapshot_token, [], value.initialChoices, webcrypto));
  }
  const { client, calls } = await connected(value);
  for (const choices of [[], [...value.initialChoices, ...value.initialChoices],
    [{ ...value.initialChoices[0], path_hex: 'ff' }], [{ ...value.initialChoices[0], choice: 'automatic' }],
    [{ ...value.initialChoices[0], choice: 'base' }], [{ ...value.initialChoices[0], author: 'forged' }],
    [{ ...value.initialChoices[0], choice: 'file', mode: '120000', bytes: new Uint8Array() }],
  ]) {
    await assert.rejects(client.resolveAndInspect(choices)); await noAuthority(client);
    assert.equal(calls.length, 2);
  }
  client.disconnect();
});

test('a server refusal preserves the observed stop and exact original pin without an automatic reprepare', async () => {
  const value = resolutionSample(), { client, calls } = await connected(value, call => call.path.endsWith('/resolve-rebase')
    ? json({ type: 'pull_request_error', code: 'preparation_subject_moved' }, 409) : null);
  const exposed = client.conflict; exposed.subject.policy_epoch = 99; exposed.snapshot_token = `alg:1:${'0'.repeat(64)}`;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(client.resolveAndInspect(value.initialChoices)); await noAuthority(client);
    assert.deepEqual(client.conflict, value.first);
  }
  const writes = calls.filter(call => call.path.endsWith('/resolve-rebase'));
  assert.equal(writes.length, 2); assert.equal(await writes[0].body.text(), await writes[1].body.text());
  assert.equal(calls.filter(call => call.path.endsWith('/prepare-rebase')).length, 1);
  assert.equal(calls.some(call => call.path.endsWith('/inspect-rebase')), false); client.disconnect();
});

test('substituted resolution receipts never reach the whole-series inspector or enable a candidate', async () => {
  const changes = [
    report => { delete report.resolution_profile; },
    report => { report.resolution_profile = 'exact-path-resolutions-v1'; },
    report => { report.resolution_input_commits += 1; },
    report => { report.resolution_consumed_commits = 1; },
    report => { report.resolutions.pop(); },
    report => { report.resolutions.reverse(); },
    report => { report.resolutions[1].original = report.steps[1].rewritten; },
    report => { report.resolutions[1].paths.reverse(); },
    report => { report.resolutions[1].paths[0].conflict.path_hex = '61'; },
    report => { report.resolutions[1].paths[0].conflict.kind = 'binary'; },
    report => { report.resolutions[1].paths[0].conflict.ours.oid = '7'.repeat(40); },
    report => { report.resolutions[1].paths[0].choice = 'ours'; },
    report => { report.resolutions[1].paths[1].result.mode = 0o100644; },
    report => { report.resolutions[1].paths[1].result.oid = '7'.repeat(40); },
    report => { report.subject.pull_request = 2; },
    report => { report.subject.policy_epoch += 1; },
    report => { report.snapshot_token = `alg:1:${'7'.repeat(64)}`; },
    report => { report.method = 'merge-commit'; },
    report => { report.bundle.sha256 = '7'.repeat(64); },
  ];
  for (const change of changes) {
    const value = resolutionSample(), report = clone(value.complete); change(report); let resolutions = 0;
    const { client, calls } = await connected(value, call => call.path.endsWith('/resolve-rebase')
      ? ++resolutions === 1 ? json(value.second, 409) : preparedResponse(value, report) : null);
    await client.resolveAndInspect(value.initialChoices);
    await assert.rejects(client.resolveAndInspect(value.finalChoices)); await noAuthority(client);
    assert.equal(calls.some(call => call.path.endsWith('/inspect-rebase')), false);
    assert.deepEqual(client.conflict, value.second); client.disconnect();
  }
});

test('a resolved series still needs a complete independently verified intermediate chain', async () => {
  for (const change of [
    report => { report.commits[0].commit_hex += '00'; },
    report => { report.commits[0].comparison.entries = []; },
    report => { report.commits[1].parent = report.subject.target_tip; },
    report => { report.commit_count = 1; },
    report => { report.method = 'squash'; },
  ]) {
    const value = resolutionSample(); change(value.inspection);
    const { client, calls } = await connected(value);
    await client.resolveAndInspect(value.initialChoices);
    await assert.rejects(client.resolveAndInspect(value.finalChoices)); await noAuthority(client);
    assert.equal(calls.filter(call => call.path.endsWith('/inspect-rebase')).length, 1);
    assert.equal(calls.some(call => call.headers['Idempotency-Key']), false); client.disconnect();
  }
});

test('consumed recipes remain diagnostic when their resolved step becomes empty', async () => {
  const value = resolutionSample(), choices = [{ ...value.initialChoices[0], choice: 'ours' }];
  const upload = await rebaseResolutionUpload(value.first, value.command, value.first.snapshot_token, [], choices, webcrypto);
  const empty = { ...clone(value.first), state: 'became_empty', conflicts: [],
    resolution_profile: 'original-commit-path-v1', resolution_input_commits: 1, resolution_consumed_commits: 1,
    resolutions: [{ original: value.first.stopped_commit, paths: [{ conflict: clone(value.first.conflicts[0]),
      choice: 'ours', result: clone(value.first.conflicts[0].ours) }] }] };
  verifyRebaseResolutions(empty, upload.recipes, 'sha1');
  const { client } = await connected(value, call => call.path.endsWith('/resolve-rebase') ? json(empty, 409) : null);
  const result = await client.resolveAndInspect(choices); assert.equal(result.inspection, null);
  assert.equal(client.conflict, null); await noAuthority(client); client.disconnect();
});

test('recipe budgets accumulate across original commits before any new file hash or request', async () => {
  const value = resolutionSample(), initial = await rebaseResolutionUpload(value.first, value.command, value.first.snapshot_token,
    [], value.initialChoices, webcrypto);
  let hashes = 0;
  const crypto = { getRandomValues: bytes => webcrypto.getRandomValues(bytes), subtle: { digest() { hashes += 1; throw new Error('Unexpected unbounded hash'); } } };
  const previous = clone(initial.recipes);
  previous[0].paths = Array.from({ length: 128 }, (_, index) => ({ ...clone(previous[0].paths[0]),
    conflict: { ...clone(previous[0].paths[0].conflict), path_hex: hex(`p${String(index).padStart(3, '0')}`) } }));
  await assert.rejects(rebaseResolutionUpload(value.second, value.command, value.first.snapshot_token,
    previous, value.finalChoices, crypto), /budget/);
  const retained = clone(initial.recipes);
  retained[0].paths = Array.from({ length: 16 }, (_, index) => ({ ...clone(initial.recipes[0].paths[0]), choice: 'file', mode: '100644',
    conflict: { ...clone(initial.recipes[0].paths[0].conflict), path_hex: hex(`p${index}`) }, bytes: new Uint8Array(RESOLUTION_FILE_LIMIT) }));
  assert.equal(RESOLUTION_CONTENT_LIMIT, 16 * RESOLUTION_FILE_LIMIT);
  await assert.rejects(rebaseResolutionUpload(value.second, value.command, value.first.snapshot_token,
    retained, value.finalChoices, crypto), /budget/);
  const oversized = clone(value.finalChoices); oversized[0].bytes = new Uint8Array(RESOLUTION_FILE_LIMIT + 1);
  await assert.rejects(rebaseResolutionUpload(value.second, value.command, value.first.snapshot_token,
    initial.recipes, oversized, crypto), /bounded exact bytes/);
  assert.equal(hashes, 0);
  const many = clone(value.first);
  many.conflicts = Array.from({ length: 128 }, (_, index) => ({ ...clone(many.conflicts[0]),
    path_hex: hex(`${String(index).padStart(3, '0')}${'x'.repeat(4090)}`) }));
  await assert.rejects(rebaseResolutionUpload(many, value.command, value.first.snapshot_token, [],
    many.conflicts.map(row => ({ path_hex: row.path_hex, choice: 'delete' })), crypto), /256 KiB/);
  assert.equal(hashes, 0);
});

test('current and retained file recipes are frozen before asynchronous WebCrypto work', async () => {
  const value = resolutionSample(), first = await rebaseResolutionUpload(value.first, value.command, value.first.snapshot_token,
    [], [{ path_hex: value.initialChoices[0].path_hex, choice: 'file', mode: '100644', bytes: new Uint8Array(Buffer.from('secret\n')) }],
    webcrypto), waiting = deferred(); let hashing = false;
  const crypto = { getRandomValues: bytes => webcrypto.getRandomValues(bytes), subtle: { async digest(...args) {
    hashing = true; await waiting.promise; return webcrypto.subtle.digest(...args);
  } } };
  const command = clone(value.command), choices = clone(value.finalChoices), previous = clone(first.recipes);
  const future = rebaseResolutionUpload(value.second, command, value.first.snapshot_token, previous, choices, crypto);
  assert.equal(hashing, true);
  command.committer = 'Changed <changed@example.invalid>'; choices[0].bytes.fill(7); choices[0].mode = '100644';
  previous[0].paths[0].choice = 'delete'; previous[0].paths[0].bytes.fill(9); previous[0].original = value.fields.source_tip;
  waiting.resolve(); const upload = await future;
  assert.equal(upload.recipes[0].original, value.first.stopped_commit);
  assert.equal(upload.recipes[0].paths[0].choice, 'file');
  assert.equal(upload.recipes[1].paths[1].result.oid, hash('sha1', 'blob', binary));
  const { form, parts } = await decoded({ body: upload.bytes, headers: { 'Content-Type': upload.contentType } });
  assert.equal(form.get('committer'), metadata.committer);
  assert.deepEqual(parts.get('file_0'), new Uint8Array(Buffer.from('secret\n')));
  assert.deepEqual(parts.get('file_2'), binary);
});

test('a replacement file cannot collide with a multipart boundary after the bounded retries', async () => {
  const value = resolutionSample(); let attempts = 0;
  const crypto = { subtle: webcrypto.subtle, getRandomValues(bytes) { attempts += 1; return bytes.fill(0); } };
  const bytes = new Uint8Array(Buffer.from(`--fg-pr-rebase-resolve-${'0'.repeat(48)}`));
  await assert.rejects(rebaseResolutionUpload(value.first, value.command, value.first.snapshot_token, [],
    [{ path_hex: value.initialChoices[0].path_hex, choice: 'file', mode: '100644', bytes }], crypto), /unambiguous/);
  assert.equal(attempts, 16);
});

for (const change of ['invalidate', 'disconnect']) for (const phase of ['resolution', 'inspection']) test(`${change} during ${phase} cannot restore a stale resolution candidate`, async () => {
  const value = resolutionSample(), waiting = deferred(); let waitingNow = false, resolutions = 0;
  const { client, calls } = await connected(value, call => {
    if (call.path.endsWith('/resolve-rebase')) {
      if (++resolutions === 1) return json(value.second, 409);
      if (phase === 'resolution') { waitingNow = true; return waiting.promise; }
      return preparedResponse(value);
    }
    if (phase === 'inspection' && call.path.endsWith('/inspect-rebase')) { waitingNow = true; return waiting.promise; }
    return null;
  });
  await client.resolveAndInspect(value.initialChoices);
  const attempt = client.resolveAndInspect(value.finalChoices), rejected = assert.rejects(attempt);
  await until(() => waitingNow);
  if (change === 'disconnect') client.disconnect(); else client.invalidateCandidate();
  waiting.resolve(phase === 'resolution' ? preparedResponse(value) : json(value.inspection));
  await rejected; assert.equal(client.candidate, null); assert.equal(client.conflict, null); assert.equal(client.pending, null);
  if (phase === 'resolution') assert.equal(calls.some(call => call.path.endsWith('/inspect-rebase')), false);
  assert.equal(calls.some(call => call.headers['Idempotency-Key']), false); client.disconnect();
});

test('invalidation during file hashing prevents resolution dispatch', async () => {
  const value = resolutionSample(), waiting = deferred(); let hashing = false, armed = false;
  const crypto = { getRandomValues: bytes => webcrypto.getRandomValues(bytes), subtle: { async digest(...args) {
    if (armed) { hashing = true; await waiting.promise; }
    return webcrypto.subtle.digest(...args);
  } } };
  const { client, calls } = await connected(value, null, crypto);
  await client.resolveAndInspect(value.initialChoices);
  armed = true;
  const attempt = client.resolveAndInspect(value.finalChoices), rejected = assert.rejects(attempt);
  await until(() => hashing); client.invalidateCandidate(); waiting.resolve(); await rejected;
  assert.equal(calls.filter(call => call.path.endsWith('/resolve-rebase')).length, 1);
  assert.equal(client.candidate, null); assert.equal(client.conflict, null); client.disconnect();
});

const descendants = node => [node, ...node.children.flatMap(descendants)];
const widgets = parent => descendants(parent).filter(node => ['SELECT', 'TEXTAREA', 'INPUT'].includes(node.tagName));
const select = (node, value) => { node.value = value; node.dispatchEvent(new Event('change')); };
const bytesFile = (bytes, extra = {}) => ({ size: bytes.length, arrayBuffer: async () => bytes.slice().buffer, ...extra });
async function mounted(value, dispatch = null) {
  const doc = fakeDocument(), calls = [], observed = show({ object_format: value.fields.object_format }); let ui, resolutions = 0;
  observed.pull_request.data.object_format = value.fields.object_format;
  observed.pull_request.data.source_tip = value.fields.source_tip; observed.pull_request.data.target_tip = value.fields.target_tip;
  ui = mountPulls(doc, { cryptoImpl: webcrypto, downloadImpl() {}, fetchImpl: async (url, init) => {
    const call = { path: url.pathname, ...init }; calls.push(call);
    if (url.pathname.endsWith('/pulls/1')) return json(observed);
    if (dispatch) { const custom = await dispatch(call, ui); if (custom) return custom; }
    if (url.pathname.endsWith('/prepare-rebase')) return json(value.first, 409);
    if (url.pathname.endsWith('/resolve-rebase')) return ++resolutions === 1 ? json(value.second, 409) : preparedResponse(value);
    if (url.pathname.endsWith('/inspect-rebase')) return json(value.inspection);
    throw new Error(`Unexpected DOM request ${url}`);
  } });
  const node = id => doc.getElementById(id), submit = id => node(id).dispatchEvent(new Event('submit', { cancelable: true }));
  await ui.client.connect(token); await ui.loadPr(1);
  select(node('candidate-method'), 'rebase'); node('policy-epoch').value = '1'; node('committer').value = metadata.committer;
  node('timestamp').value = String(metadata.timestamp); node('rebase-upstream').value = value.fields.merge_base;
  submit('prepare'); await until(() => ui.client.conflict && !node('resolve-candidate').disabled);
  return { ...ui, doc, node, submit, calls, controls: () => widgets(node('resolution-paths')) };
}

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: page renders original and accumulated parent labels and retains recipes between successive conflict editors`, async () => {
  const value = resolutionSample(algorithm), h = await mounted(value);
  assert.equal(h.node('resolution').hidden, false);
  assert.match(h.node('candidate').textContent, new RegExp('Stopped at original commit ' + value.first.stopped_commit));
  for (const label of ['Original parent', 'Current rebased parent', 'Original commit']) assert.ok(h.node('resolution-paths').textContent.includes(label));
  assert.equal(h.node('resolution-paths').textContent.includes('Ours (target)'), false);
  assert.equal(h.controls()[0].value, ''); assert.equal(h.controls()[0].children.find(option => option.value === 'base').disabled, true);
  assert.equal(h.node('review-stage').disabled, true); assert.equal(h.node('merge-stage').disabled, true);
  select(h.controls()[0], 'theirs'); h.submit('resolution');
  await until(() => h.client.conflict?.stopped_commit === value.fields.source_tip && !h.node('resolve-candidate').disabled);
  assert.match(h.node('status').textContent, /Earlier resolutions are retained/);
  assert.match(h.node('candidate').textContent, new RegExp(value.fields.source_tip));
  const rows = h.controls(); assert.equal(rows.length, 10);
  for (const offset of [0, 5]) { select(rows[offset], 'file'); select(rows[offset + 1], offset === 0 ? '100644' : '100755'); }
  select(rows[2], 'text'); rows[3].value = '';
  select(rows[7], 'upload'); rows[9].files = [bytesFile(binary)]; h.submit('resolution');
  await until(() => h.client.candidate && !h.node('review-stage').disabled);
  assert.equal(h.node('resolution').hidden, true); assert.equal(h.client.pending, null);
  assert.match(h.node('candidate').textContent, /Commit 1 of 2/); assert.match(h.node('candidate').textContent, /Commit 2 of 2/);
  assert.match(h.node('candidate').textContent, /protected\/settings/); assert.match(h.node('candidate').textContent, /\\xff/);
  assert.equal(h.node('merge-heading').textContent, 'Reviewed rebase');
  assert.equal(h.calls.filter(call => call.path.endsWith('/resolve-rebase')).length, 2);
  assert.equal(h.calls.filter(call => call.path.endsWith('/inspect-rebase')).length, 1);
  assert.ok(h.calls.every(call => !call.headers['Idempotency-Key'])); h.disconnect();
});

for (const change of ['editor', 'file', 'metadata', 'disconnect']) test(`${change} changes during an asynchronous file read cannot submit stale PR rebase choices`, async () => {
  const value = resolutionSample(), h = await mounted(value), waiting = deferred(); let reading = false;
  const [choice, mode, source, content, upload] = h.controls();
  select(choice, 'file'); select(mode, '100755'); select(source, 'upload');
  upload.files = [bytesFile(binary, { arrayBuffer: () => { reading = true; return waiting.promise; } })];
  h.submit('resolution'); await until(() => reading);
  if (change === 'editor') { content.value = 'changed'; content.dispatchEvent(new Event('input')); }
  if (change === 'file') { upload.files = [bytesFile(new Uint8Array([7]))]; upload.dispatchEvent(new Event('change')); }
  if (change === 'metadata') { h.node('timestamp').value = '99'; h.node('prepare').dispatchEvent(new Event('input')); }
  if (change === 'disconnect') h.disconnect();
  waiting.resolve(binary.slice().buffer);
  await until(() => change === 'disconnect' ? !h.client.connected : /changed|superseded/i.test(h.node('status').textContent));
  await new Promise(setImmediate);
  assert.equal(h.calls.some(call => call.path.endsWith('/resolve-rebase')), false);
  assert.equal(h.client.candidate, null); assert.equal(h.client.pending, null);
  if (change === 'metadata' || change === 'disconnect') assert.equal(h.client.conflict, null);
  if (change === 'disconnect') assert.equal(h.node('resolution-paths').textContent, ''); h.disconnect();
});

test('the rebase editor rejects changed file sizes and preserves ordinary merge-side labels', async () => {
  const value = resolutionSample(), doc = fakeDocument(), parent = doc.createElement('div');
  const editor = new ResolutionEditor(doc, parent, displayBytes); editor.show(value.first); editor.setDisabled(false);
  const [choice, mode, source, , upload] = widgets(parent);
  select(choice, 'file'); select(mode, '100644'); select(source, 'upload'); upload.files = [bytesFile(binary, { size: binary.length + 1 })];
  await assert.rejects(editor.collect(), /size changed/);
  editor.show({ ...value.first, method: 'merge-commit' });
  assert.match(parent.textContent, /Ours \(target\)/); assert.match(parent.textContent, /Theirs \(source\)/);
  assert.equal(parent.textContent.includes('Current rebased parent'), false);
});
