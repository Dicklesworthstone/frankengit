// Client/view contract coverage; native attribute merging is tested by the forge.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { mergeProfile, preparationCommand, preparationReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { resolutionUpload } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution.mjs';
import { fixture } from './pulls-candidate-fixtures.mjs';
import { token, page, show, json, options, webcrypto, deferred } from './pulls-fixtures.mjs';
import { fakeDocument, until } from './helpers/pulls-workflow-fixture.mjs';

const profiles = ['path-merge-v1', 'exact-renames-v1', 'builtin-attributes-v1'];
const commitMetadata = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 1, message: 'Exact candidate\n' };
const response = (f, metadata) => ({ status: 200, type: f.type, value: f.mixed(metadata) });
function conflictReport(f, profile) {
  return { ...f.metadata, profile, state: 'conflicted', candidate: null, bundle: null, merge_base: f.fields.merge_base,
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
  for (const invalid of [null, '', 'builtin-attributes-v2', 'BuiltinAttributesV1', 'automatic']) {
    assert.throws(() => mergeProfile(invalid));
    assert.throws(() => preparationCommand(f.selected, commitMetadata, 'merge-commit', invalid));
  }
});

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: selected profiles require matching preparation and complete inspection`, async () => {
  for (const profile of profiles) {
    const f = fixture(algorithm), metadata = { ...f.metadata, profile };
    const { client, calls } = await connected(f, () => new Response(f.mixed(metadata), { headers: { 'Content-Type': f.type } }));
    const prepared = await client.prepareAndInspect(1, f.selected, commitMetadata, 'merge-commit', profile);
    assert.equal(prepared.metadata.profile, profile); assert.ok(prepared.inspection);
    assert.ok(client.candidate); assert.equal(client.pending, null); assert.equal(client.conflict, null);
    const command = new URLSearchParams(calls.find(call => call.path.endsWith('/prepare')).body);
    assert.equal(command.get('profile') ?? 'path-merge-v1', profile);
    assert.equal(calls.filter(call => call.path.endsWith('/inspect')).length, 1);
    assert.ok(calls.every(call => call.headers['Idempotency-Key'] === undefined));
    for (const other of profiles.filter(value => value !== profile)) {
      await assert.rejects(preparationReply(response(f, { ...metadata, profile: other }), 1, f.selected,
        f.artifact.scope, webcrypto, false, 'merge-commit', profile), /profile changed/);
    }
    client.disconnect();
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
  const f = fixture(), doc = fakeDocument(), calls = [], observed = show();
  const ui = mountPulls(doc, { cryptoImpl: webcrypto, downloadImpl: () => {}, fetchImpl: (url, init) => {
    const call = { path: url.pathname, ...init }; calls.push(call);
    if (call.path.endsWith('/pulls/1')) return json(observed);
    if (call.path.endsWith('/prepare')) {
      const profile = new URLSearchParams(call.body).get('profile') ?? 'path-merge-v1';
      return conflicted ? json(conflictReport(f, profile), 409)
        : new Response(f.mixed({ ...f.metadata, profile }), { headers: { 'Content-Type': f.type } });
    }
    if (call.path.endsWith('/inspect')) return inspection ? inspection(call, f) : json(f.inspection);
    throw new Error(`Unexpected request ${call.path}`);
  } });
  const node = id => doc.getElementById(id);
  const select = profile => { node('candidate-profile').value = profile; node('candidate-profile').dispatchEvent(new Event('change')); };
  const submit = () => node('prepare').dispatchEvent(new Event('submit', { cancelable: true }));
  await ui.client.connect(token); await ui.loadPr(1);
  for (const [id, value] of Object.entries({ 'policy-epoch': '1', ...commitMetadata })) node(id).value = String(value);
  return { ui, node, select, submit, calls, f };
}

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
