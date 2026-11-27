// Client/view contract coverage; native merge algorithms are tested by the forge.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { mergeProfile, preparationCommand, preparationReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { resolutionUpload } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution.mjs';
import { fixture } from './pulls-candidate-fixtures.mjs';
import { token, reviewer, page, show, json, options, webcrypto, deferred } from './pulls-fixtures.mjs';
import { fakeDocument, until } from './helpers/pulls-workflow-fixture.mjs';

const recursiveProfile = 'recursive-path-merge-v1';
const profiles = ['path-merge-v1', 'exact-renames-v1', 'builtin-attributes-v1', recursiveProfile];
const commitMetadata = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 1, message: 'Exact candidate\n' };
const response = (f, metadata) => ({ status: 200, type: f.type, value: f.mixed(metadata) });
function preparationMetadata(f, profile, singleton = false) {
  return { ...f.metadata, profile, ...(profile === recursiveProfile ? { recursive_base: {
    bases: [f.fields.merge_base, ...(singleton ? [] : ['f'.repeat(f.fields.merge_base.length)])], tree: 'c'.repeat(f.fields.merge_base.length),
  } } : {}) };
}
function conflictReport(f, profile) {
  return { ...preparationMetadata(f, profile), state: 'conflicted', candidate: null, bundle: null, merge_base: f.fields.merge_base,
    conflicts: [{ path_hex: '61', kind: 'attributes_require_driver', base: null,
      ours: { mode: 0o100644, oid: f.selected.target_tip }, theirs: { mode: 0o100644, oid: f.selected.source_tip } }] };
}
async function connected(f, prepare) {
  const calls = [], client = new PullClient(options((url, init) => {
    const call = { path: url.pathname, ...init }; calls.push(call);
    if (call.path.endsWith('/pulls')) return json(page({ object_format: f.fields.object_format, pull_requests: [] }));
    if (call.path.endsWith('/prepare')) return prepare(call);
    if (call.path.endsWith('/inspect')) return json(f.inspection);
    throw new Error(`Unexpected request ${call.path}`);
  }));
  await client.connect(token); await client.list(); return { client, calls };
}

test('profile selection is closed and independent of method without changing the legacy command', () => {
  const f = fixture(), legacy = preparationCommand(f.selected, commitMetadata);
  assert.equal(Object.hasOwn(legacy, 'profile'), false);
  assert.deepEqual(preparationCommand(f.selected, commitMetadata, 'merge-commit', 'path-merge-v1'), legacy);
  for (const method of ['merge-commit', 'squash']) for (const profile of profiles) {
    const command = preparationCommand(f.selected, commitMetadata, method, profile);
    assert.equal(command.profile ?? 'path-merge-v1', profile);
    assert.equal(command.method ?? 'merge-commit', method);
    const original = { ...command }; delete original.profile; delete original.method;
    assert.deepEqual(original, legacy);
  }
  for (const invalid of [null, '', 'builtin-attributes-v2', 'BuiltinAttributesV1', 'recursive-path-merge-v2', 'recursive', 'automatic']) {
    assert.throws(() => mergeProfile(invalid));
    assert.throws(() => preparationCommand(f.selected, commitMetadata, 'merge-commit', invalid));
  }
});

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: selected profiles require matching preparation and complete inspection`, async () => {
  for (const method of ['merge-commit', 'squash']) for (const profile of profiles) {
    const f = fixture(algorithm, method), metadata = preparationMetadata(f, profile);
    const { client, calls } = await connected(f, () => new Response(f.mixed(metadata), { headers: { 'Content-Type': f.type } }));
    const prepared = await client.prepareAndInspect(1, f.selected, commitMetadata, method, profile);
    assert.equal(prepared.metadata.profile, profile); assert.ok(prepared.inspection);
    assert.equal(client.candidate.method, method);
    if (profile === recursiveProfile) {
      assert.deepEqual(client.candidate.preparation, metadata);
      prepared.metadata.recursive_base.bases[0] = '1'.repeat(f.fields.merge_base.length);
      assert.deepEqual(client.candidate.preparation, metadata, 'retained preparation cannot be rewritten through a returned report');
    } else assert.equal(Object.hasOwn(client.candidate, 'preparation'), false);
    assert.ok(client.candidate); assert.equal(client.pending, null); assert.equal(client.conflict, null);
    const command = new URLSearchParams(calls.find(call => call.path.endsWith('/prepare')).body);
    assert.equal(command.get('profile') ?? 'path-merge-v1', profile);
    assert.equal(calls.filter(call => call.path.endsWith('/inspect')).length, 1);
    assert.ok(calls.every(call => call.headers['Idempotency-Key'] === undefined));
    for (const other of profiles.filter(value => value !== profile)) {
      await assert.rejects(preparationReply(response(f, { ...metadata, profile: other }), 1, f.selected,
        f.artifact.scope, webcrypto, false, method, profile), /profile changed/);
    }
    if (profile === recursiveProfile) {
      const count = calls.length, review = await client.stageReview('approve', 0, 'Reviewed exact candidate');
      assert.equal(review.fields.merge_base, f.fields.merge_base); assert.equal(review.fields.candidate_commit, f.fields.candidate_commit);
      client.discardUnsent();
      const merge = await client.stageMerge([reviewer]);
      assert.equal(merge.fields.merge_base, f.fields.merge_base); assert.equal(merge.fields.method ?? 'merge-commit', method);
      assert.equal(calls.length, count, 'preparation and inspection never send the staged review or merge');
      client.discardUnsent();
    }
    client.disconnect();
  }
});

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: recursive preparation requires exact bounded real bases and the effective tree`, async () => {
  const f = fixture(algorithm), metadata = preparationMetadata(f, recursiveProfile);
  const parse = value => preparationReply(response(f, value), 1, f.selected, f.artifact.scope, webcrypto, false, 'merge-commit', recursiveProfile);
  const singleton = await parse(preparationMetadata(f, recursiveProfile, true));
  assert.equal(singleton.artifact.preparation.recursive_base.bases.length, 1);
  const mutations = [
    m => { delete m.recursive_base; }, m => { m.recursive_base = null; }, m => { m.recursive_base = []; },
    m => { delete m.recursive_base.bases; }, m => { delete m.recursive_base.tree; },
    m => { m.recursive_base.bases = []; }, m => { m.recursive_base.bases = [m.recursive_base.bases[0], m.recursive_base.bases[0]]; },
    m => { m.recursive_base.bases.reverse(); }, m => { m.recursive_base.bases[0] = 'd'.repeat(f.fields.merge_base.length); },
    m => { m.recursive_base.bases = Array(4097).fill(f.fields.merge_base); },
    m => { m.recursive_base.bases[0] = 'e'.repeat(algorithm === 'sha1' ? 64 : 40); },
    m => { m.recursive_base.tree = 'c'.repeat(algorithm === 'sha1' ? 64 : 40); },
    m => { m.recursive_base.tree = '0'.repeat(f.fields.merge_base.length); },
    m => { m.recursive_base.synthetic_commit = f.fields.merge_base; },
    m => { m.candidate.merge_base = 'd'.repeat(f.fields.merge_base.length); },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(metadata); mutate(changed);
    await assert.rejects(parse(changed));
  }
  for (const profile of profiles.filter(value => value !== recursiveProfile)) {
    await assert.rejects(preparationReply(response(f, { ...metadata, profile }), 1, f.selected, f.artifact.scope, webcrypto, false, 'merge-commit', profile), /Unexpected recursive/);
  }
  const current = { ...metadata, state: 'already_up_to_date', candidate: null, bundle: null };
  const currentResponse = value => ({ status: 200, type: 'application/json', value: new TextEncoder().encode(JSON.stringify(value)) });
  await assert.rejects(preparationReply(currentResponse(current), 1, f.selected, f.artifact.scope, webcrypto, false, 'merge-commit', recursiveProfile), /Unexpected recursive/);
  delete current.recursive_base;
  assert.equal((await preparationReply(currentResponse(current), 1, f.selected, f.artifact.scope, webcrypto, false, 'merge-commit', recursiveProfile)).artifact, null);
});

test('missing or substituted recursive base witnesses fail before inspection or conflict installation', async () => {
  for (const conflicted of [false, true]) for (const missing of [false, true]) {
    const f = fixture(), metadata = conflicted ? conflictReport(f, recursiveProfile) : preparationMetadata(f, recursiveProfile);
    if (missing) delete metadata.recursive_base; else metadata.recursive_base.bases[0] = 'd'.repeat(40);
    const { client, calls } = await connected(f, () => conflicted ? json(metadata, 409)
      : new Response(f.mixed(metadata), { headers: { 'Content-Type': f.type } }));
    await assert.rejects(client.prepareAndInspect(1, f.selected, commitMetadata, 'merge-commit', recursiveProfile), /recursive|Recursive/);
    assert.equal(client.candidate, null); assert.equal(client.conflict, null); assert.equal(client.pending, null);
    assert.equal(calls.some(call => call.path.endsWith('/inspect')), false); client.disconnect();
  }
});

test('a native recursive-base conflict is an explicit preparation stop without candidate or resolver', async () => {
  const f = fixture(), report = { type: 'pull_request_error', schema_version: 1, code: 'recursive_merge_base_conflict', outcome_unknown: false };
  const { client, calls } = await connected(f, () => json(report, 409));
  await assert.rejects(client.prepareAndInspect(1, f.selected, commitMetadata, 'merge-commit', recursiveProfile), {
    code: 'recursive_merge_base_conflict', status: 409,
  });
  assert.equal(client.candidate, null); assert.equal(client.conflict, null); assert.equal(client.pending, null);
  assert.equal(calls.some(call => call.path.endsWith('/inspect')), false); client.disconnect();
  for (const change of [{ type: 'merge_queue_error' }, { schema_version: 2 }, { outcome_unknown: true }, { candidate: {} }]) {
    const response = { status: 409, type: 'application/json', value: new TextEncoder().encode(JSON.stringify({ ...report, ...change })) };
    await assert.rejects(preparationReply(response, 1, f.selected, f.artifact.scope, webcrypto, false, 'merge-commit', recursiveProfile), error => error.code === undefined);
  }
});

test('a substituted profile cannot install either a candidate or a resolver or trigger inspection', async () => {
  const f = fixture();
  for (const conflicted of [false, true]) {
    const metadata = conflicted ? conflictReport(f, 'path-merge-v1') : f.metadata;
    const { client, calls } = await connected(f, () => conflicted ? json(metadata, 409)
      : new Response(f.mixed(metadata), { headers: { 'Content-Type': f.type } }));
    await assert.rejects(client.prepareAndInspect(1, f.selected, commitMetadata, 'merge-commit', 'builtin-attributes-v1'), /profile changed/);
    assert.equal(client.candidate, null); assert.equal(client.conflict, null); assert.equal(client.pending, null);
    assert.equal(calls.some(call => call.path.endsWith('/inspect')), false); client.disconnect();
  }
});

test('non-path conflicts stay diagnostic and cannot enter direct-path resolution', async () => {
  for (const profile of profiles.slice(1)) {
    const f = fixture(), report = conflictReport(f, profile);
    const { client, calls } = await connected(f, () => json(report, 409));
    const result = await client.prepareAndInspect(1, f.selected, commitMetadata, 'merge-commit', profile);
    assert.equal(result.metadata.state, 'conflicted'); assert.equal(result.inspection, null);
    assert.equal(client.candidate, null); assert.equal(client.conflict, null);
    const count = calls.length;
    await assert.rejects(client.resolveAndInspect([{ path_hex: '61', choice: 'ours' }]));
    await assert.rejects(resolutionUpload(report, f.selected, commitMetadata, [{ path_hex: '61', choice: 'ours' }], webcrypto));
    await assert.rejects(preparationReply(response(f, { ...f.metadata, profile, state: 'resolved' }), 1, f.selected,
      f.artifact.scope, webcrypto, true, 'merge-commit', profile), /direct path/);
    assert.equal(calls.length, count); client.disconnect();
  }
});

async function mounted({ conflicted = false, inspection = null } = {}) {
  const f = fixture(), doc = fakeDocument(), calls = [], downloads = [], observed = show();
  const ui = mountPulls(doc, { cryptoImpl: webcrypto, downloadImpl: (name, text) => downloads.push({ name, text }), fetchImpl: (url, init) => {
    const call = { path: url.pathname, ...init }; calls.push(call);
    if (call.path.endsWith('/pulls/1')) return json(observed);
    if (call.path.endsWith('/prepare')) {
      const profile = new URLSearchParams(call.body).get('profile') ?? 'path-merge-v1';
      return conflicted ? json(conflictReport(f, profile), 409)
        : new Response(f.mixed(preparationMetadata(f, profile)), { headers: { 'Content-Type': f.type } });
    }
    if (call.path.endsWith('/inspect')) return inspection ? inspection(call, f) : json(f.inspection);
    throw new Error(`Unexpected request ${call.path}`);
  } });
  const node = id => doc.getElementById(id);
  const select = profile => { node('candidate-profile').value = profile; node('candidate-profile').dispatchEvent(new Event('change')); };
  const submit = () => node('prepare').dispatchEvent(new Event('submit', { cancelable: true }));
  await ui.client.connect(token); await ui.loadPr(1);
  for (const [id, value] of Object.entries({ 'policy-epoch': '1', ...commitMetadata })) node(id).value = String(value);
  return { ui, node, select, submit, calls, downloads, f };
}

test('recursive profile is selectable in both served pages and retains preparation evidence for display and download', async () => {
  for (const name of ['pulls', 'queues']) {
    const html = await readFile(new URL(`../../crates/fgit-node/src/smart_http/server/browser/${name}.html`, import.meta.url), 'utf8');
    assert.match(html, /<option value="recursive-path-merge-v1">Recursive path merge \(multiple merge bases\)<\/option>/);
  }
  const h = await mounted(); h.select(recursiveProfile); h.submit();
  await until(() => h.ui.client.candidate && !h.node('prepare-candidate').disabled);
  assert.match(h.node('candidate').textContent, /Recursive merge preparation/);
  assert.match(h.node('candidate').textContent, /Real best bases \(2\)/);
  assert.match(h.node('candidate').textContent, /Effective base tree:/);
  h.node('inspection-download').dispatchEvent(new Event('click', { cancelable: true }));
  await until(() => h.downloads.length === 1);
  const report = JSON.parse(h.downloads[0].text);
  assert.deepEqual(report.preparation, preparationMetadata(h.f, recursiveProfile));
  assert.deepEqual(report.inspection, h.f.inspection);
  assert.equal(JSON.parse(h.ui.client.exportCandidate()).schema, 'frankengit-browser-candidate-v1');
  h.select('path-merge-v1');
  assert.equal(h.ui.client.candidate, null); assert.equal(h.node('review-stage').disabled, true); h.ui.disconnect();
});

test('mounted selector sends the chosen profile and changing it invalidates inspected work', async () => {
  const h = await mounted(); assert.equal(h.node('candidate-profile').value, 'path-merge-v1');
  h.select('builtin-attributes-v1'); h.submit();
  await until(() => h.ui.client.candidate && !h.node('prepare-candidate').disabled);
  assert.equal(new URLSearchParams(h.calls.find(call => call.path.endsWith('/prepare')).body).get('profile'), 'builtin-attributes-v1');
  assert.equal(h.node('review-stage').disabled, false); assert.equal(h.ui.client.pending, null);
  h.select('path-merge-v1');
  assert.equal(h.ui.client.candidate, null); assert.equal(h.node('review-stage').disabled, true);
  h.ui.disconnect();
});

test('mounted non-path conflicts hide resolution until a new direct-path preparation is requested', async () => {
  const h = await mounted({ conflicted: true }); h.select('builtin-attributes-v1'); h.submit();
  await until(() => h.node('candidate').textContent.includes('Preparation: conflicted') && !h.node('prepare-candidate').disabled);
  assert.equal(h.ui.client.conflict, null); assert.equal(h.node('resolution').hidden, true);
  assert.equal(h.node('resolve-candidate').disabled, true); assert.equal(h.node('resolution-paths').textContent, '');
  assert.match(h.node('status').textContent, /resolution is unavailable/);
  h.select('path-merge-v1'); assert.equal(h.ui.client.conflict, null); h.submit();
  await until(() => h.ui.client.conflict && !h.node('prepare-candidate').disabled);
  assert.equal(h.node('resolution').hidden, false); assert.equal(h.node('resolve-candidate').disabled, false);
  assert.equal(h.calls.filter(call => call.path.endsWith('/prepare')).length, 2);
  assert.equal(h.calls.some(call => call.path.endsWith('/resolve')), false); h.ui.disconnect();
});

test('changing the mounted profile aborts pending inspection and rejects its late completion', async () => {
  const wait = deferred(), h = await mounted({ inspection: () => wait.promise });
  let preparation;
  const prepare = h.ui.client.prepareAndInspect.bind(h.ui.client);
  h.ui.client.prepareAndInspect = (...args) => { preparation = prepare(...args); return preparation; };
  h.select('builtin-attributes-v1'); h.submit();
  await until(() => h.calls.some(call => call.path.endsWith('/inspect')));
  const call = h.calls.find(value => value.path.endsWith('/inspect'));
  h.select('path-merge-v1'); assert.equal(call.signal.aborted, true);
  wait.resolve(json(h.f.inspection));
  await assert.rejects(preparation);
  await until(() => !h.node('prepare-candidate').disabled);
  assert.equal(h.ui.client.candidate, null); assert.equal(h.ui.client.conflict, null); assert.equal(h.ui.client.pending, null);
  assert.equal(h.node('review-stage').disabled, true); h.ui.disconnect();
});
