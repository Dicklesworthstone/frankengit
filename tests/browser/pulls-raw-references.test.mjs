// Browser protocol and DOM contracts. HTTP admission is a test double; actual
// commit-body hashes, request bytes, credential keys and browser modules run here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { subject, subjectReferences, matchSubject, form, rootFor, metadataCommand } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { preparationCommand, inspectionReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { collaborationCommand, fastForwardCommand, publication, requestBody, requestKey } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { resolutionUpload } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution.mjs';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { fixture, terminal, recovered } from './pulls-candidate-fixtures.mjs';
import { token, actor, reviewer, hex, page, show, row, data, metadata, json, options, webcrypto, deferred } from './pulls-fixtures.mjs';
import { fakeDocument, until } from './helpers/pulls-workflow-fixture.mjs';

const href = 'https://forge.example/team/repo.git/ui/pulls/';
const commitMetadata = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 1, message: 'Exact candidate\n' };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function sample(algorithm = 'sha1', source = 'hex', target = 'hex') {
  const original = fixture(algorithm), refs = {}, aliases = {};
  for (const [side, encoding, suffix] of [['source', source, 'ff'], ['target', target, 'fe']]) {
    const name = `${side}_ref`, label = original.selected[name], encoded = hex(label) + (encoding === 'hex' ? suffix : '');
    refs[name] = encoding === 'hex' ? null : label; refs[`${name}_hex`] = encoded;
    aliases[encoding === 'hex' ? `${name}_hex` : name] = encoding === 'hex' ? encoded : label;
  }
  const selected = { object_format: algorithm, pull_request_version: 1, policy_epoch: 1, ...aliases,
    source_tip: original.selected.source_tip, target_tip: original.selected.target_tip };
  const fields = { ...selected, merge_base: original.fields.merge_base, candidate_commit: original.fields.candidate_commit };
  const nativeSubject = { ...original.metadata.subject, ...refs };
  const metadata = { ...original.metadata, subject: nativeSubject }, inspection = { ...original.inspection, subject: nativeSubject };
  return { ...original, selected, fields, refs, metadata, inspection,
    artifact: { ...original.artifact, fields }, mixed: (meta = metadata, bytes = original.bundle) => original.mixed(meta, bytes) };
}
function candidateReceipt(f) {
  return JSON.stringify({ schema: 'frankengit-browser-candidate-v1', number: 1, scope: f.artifact.scope,
    ...(Object.hasOwn(f.artifact, 'method') ? { method: f.artifact.method } : {}), fields: f.fields,
    bundle_base64: Buffer.from(f.bundle).toString('base64'), sha256: f.artifact.sha256 });
}
function nativeTerminal(pending, f, extra = {}) {
  const { pull_request, ...subject } = f.inspection.subject;
  return terminal(pending, { subject: { number: pull_request, ...subject }, ...extra });
}
function harness(f = sample(), respond = () => null) {
  const calls = []; let client;
  client = new PullClient(options(async (url, init) => {
    const call = { path: new URL(url).pathname, url: String(url), ...init }; calls.push(call);
    const override = await respond(call, client); if (override !== null && override !== undefined) return override;
    if (call.path.endsWith('/pulls')) return json(page({ object_format: f.fields.object_format, pull_requests: [] }));
    if (call.path.endsWith('/inspect')) return json(f.inspection);
    if (call.path.endsWith('/prepare')) return new Response(f.mixed(), { headers: { 'Content-Type': f.type } });
    if (/\/(approve|request-changes|withdraw|merge)$/.test(call.path)) return json(nativeTerminal(client.pending, f));
    throw new Error(`Unexpected request ${call.path}`);
  }));
  const connect = async () => { await client.connect(token); await client.list(); };
  const inspect = () => client.importCandidate(candidateReceipt(f));
  return { client, calls, connect, inspect, f };
}
const stage = (client, action) => action === 'merge' ? client.stageMerge([reviewer])
  : client.stageReview(action, action === 'withdraw' ? 1 : 0, 'Independently inspected exact reference bytes and candidate.');

for (const algorithm of ['sha1', 'sha256']) for (const source of ['text', 'hex']) for (const target of ['text', 'hex']) {
  test(`${algorithm} ${source}/${target}: review subjects preserve exactly one alias per side in legacy field order`, () => {
    const f = sample(algorithm, source, target), normalized = subject(f.selected), sourceKey = source === 'hex' ? 'source_ref_hex' : 'source_ref',
      targetKey = target === 'hex' ? 'target_ref_hex' : 'target_ref';
    assert.deepEqual(Object.keys(normalized), ['object_format', 'pull_request_version', 'policy_epoch', sourceKey, targetKey, 'source_tip', 'target_tip']);
    assert.deepEqual(normalized, f.selected);
    assert.deepEqual(subjectReferences(f.inspection.subject), { [sourceKey]: f.selected[sourceKey], [targetKey]: f.selected[targetKey] });
    matchSubject(f.inspection.subject, normalized, 1, algorithm, 'pull_request');
    const prepare = new URLSearchParams(form(preparationCommand(f.selected, commitMetadata)));
    const approve = new URLSearchParams(form(collaborationCommand('approve', { ...f.fields, expected_version: 0, reason: 'Exact bytes' })));
    const squash = new URLSearchParams(form(preparationCommand(f.selected, commitMetadata, 'squash')));
    const merge = new URLSearchParams(form(collaborationCommand('merge', { ...f.fields, required_reviewer: [reviewer], method: 'squash' })));
    assert.equal(squash.get('method'), 'squash'); assert.equal(merge.get('method'), 'squash');
    for (const encoded of [prepare, approve, squash, merge]) {
      assert.equal(encoded.get(sourceKey), f.selected[sourceKey]); assert.equal(encoded.get(targetKey), f.selected[targetKey]);
      assert.equal(encoded.has(source === 'hex' ? 'source_ref' : 'source_ref_hex'), false);
      assert.equal(encoded.has(target === 'hex' ? 'target_ref' : 'target_ref_hex'), false);
    }
  });
}

test('reference aliases reject ambiguity, missing encodings, invalid Git branch bytes and unsafe sizes before transport', () => {
  const f = sample();
  for (const side of ['source', 'target']) {
    const name = `${side}_ref`, encoded = `${name}_hex`;
    const changed = [fields => { fields[name] = 'refs/heads/another'; }, fields => { delete fields[encoded]; },
      ...['', null, undefined, '6', 'FF', 'gg', hex('refs/heads/'), hex('refs/tags/topic'), hex('refs/heads/a..b'),
        hex('refs/heads/a@{b'), hex('refs/heads/.hidden'), hex('refs/heads/a.lock'), hex('refs/heads/a/'), hex('refs/heads/a.'),
        hex('refs/heads/a\0b'), hex('refs/heads/a b'), hex('refs/heads/a\nb'), hex('refs/heads/a?b'), hex('refs/heads/a\\b'),
        hex('refs/heads/') + '61'.repeat(1014)].map(value => fields => { fields[encoded] = value; })];
    for (const mutate of changed) {
      const fields = { ...f.selected }; mutate(fields);
      assert.throws(() => subject(fields)); assert.throws(() => preparationCommand(fields, commitMetadata));
      assert.throws(() => collaborationCommand('approve', { ...fields, merge_base: f.fields.merge_base,
        candidate_commit: f.fields.candidate_commit, expected_version: 0, reason: 'Exact bytes' }));
    }
  }
  const maximum = hex('refs/heads/') + 'ff'.repeat(1013);
  assert.equal(subject({ ...f.selected, source_ref_hex: maximum }).source_ref_hex, maximum);
  const same = { ...f.selected, source_ref: 'refs/heads/main', target_ref_hex: hex('refs/heads/main') }; delete same.source_ref_hex;
  assert.throws(() => subject(same), /must differ/);
  assert.throws(() => metadataCommand('update', { ...metadata(), source_ref_hex: f.selected.source_ref_hex }));
  const { policy_epoch, ...fastForward } = f.selected;
  assert.throws(() => fastForwardCommand(fastForward));
});

test('raw branch bytes are native bytes, including valid UTF-8 which is not a lossy display label', () => {
  const f = sample(), label = 'refs/heads/topic\u00a0suffix';
  const selected = { ...f.selected, source_ref_hex: hex(label) };
  const observed = { ...f.inspection.subject, source_ref: label, source_ref_hex: hex(label) };
  matchSubject(observed, selected, 1, 'sha1', 'pull_request');
  assert.equal(subject({ ...f.selected, source_ref_hex: hex('refs/heads/topic') }).source_ref_hex, hex('refs/heads/topic'));
  assert.deepEqual(subjectReferences(observed), { source_ref: label, target_ref_hex: f.selected.target_ref_hex });
});

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: identical display labels cannot hide a changed native review subject`, async () => {
  const f = sample(algorithm), expected = f.selected;
  for (const name of ['source_ref', 'target_ref']) {
    const changed = structuredClone(f.inspection);
    changed.subject[`${name}_hex`] += '80'; // Both old and new display labels are null.
    assert.equal(changed.subject[name], f.inspection.subject[name]);
    assert.throws(() => matchSubject(changed.subject, expected, 1, algorithm, 'pull_request'), /subject changed/);
    await assert.rejects(inspectionReply(changed, f.artifact, webcrypto), /subject changed/);
    const forged = { ...f.inspection.subject, [name]: 'refs/heads/printable' };
    assert.throws(() => matchSubject(forged, expected, 1, algorithm, 'pull_request'), /disagree/);
  }
  const text = sample(algorithm, 'text', 'text'), changed = { ...text.inspection.subject, source_ref_hex: hex('refs/heads/different') };
  assert.throws(() => matchSubject(changed, text.selected, 1, algorithm, 'pull_request'), /disagree/);
});

for (const algorithm of ['sha1', 'sha256']) for (const action of ['approve', 'request-changes', 'withdraw', 'merge']) {
  test(`${algorithm} ${action}: legacy text command bytes and v1 keys retain their independent pre-alias encoding`, async () => {
    const f = fixture(algorithm), nonce = '1'.repeat(32), fields = { ...f.fields, source_ref: 'refs/heads/topic+%🦀',
      ...(action === 'merge' ? { required_reviewer: [reviewer] } : { expected_version: action === 'withdraw' ? 1 : 0, reason: 'Exact %2f + 🦀\nbytes' }) };
    const pairs = [['object_format', algorithm], ['pull_request_version', '1'], ['policy_epoch', '1'],
      ['source_ref', fields.source_ref], ['target_ref', fields.target_ref], ['source_tip', fields.source_tip], ['target_tip', fields.target_tip],
      ['merge_base', fields.merge_base], ['candidate_commit', fields.candidate_commit],
      ...(action === 'merge' ? [['required_reviewer', reviewer]] : [['expected_version', String(fields.expected_version)], ['reason', fields.reason]])];
    const encoded = new URLSearchParams(pairs).toString(), boundary = `fg-browser-${nonce}`;
    const bytes = action === 'withdraw' ? Buffer.from(encoded) : Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${encoded}\r\n--${boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="candidate.bundle"\r\nContent-Type: application/x-git-bundle\r\n\r\n`),
      f.bundle, Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    const body = requestBody(action, fields, action === 'withdraw' ? null : f.bundle, nonce);
    assert.deepEqual(Buffer.from(body.bytes), bytes);
    const contentType = action === 'withdraw' ? 'application/x-www-form-urlencoded' : `multipart/form-data; boundary=${boundary}`;
    assert.equal(body.contentType, contentType);
    const fingerprint = sha256(token), scope = f.artifact.scope;
    const key = `fgpr1-${nonce}-${sha256(JSON.stringify(['https://forge.example', '/team/repo.git', fingerprint,
      [scope.tenant, scope.repository, scope.incarnation, algorithm], 1, action, nonce, contentType, sha256(bytes)]))}`;
    assert.equal(await requestKey(rootFor(href), fingerprint, scope, 1, action, nonce, body, webcrypto), key);
  });
}

test('legacy text candidate receipts retain their complete v1 serialization on import/export', async () => {
  const h = harness(sample('sha1', 'text', 'text')); await h.connect();
  const serialized = candidateReceipt(h.f); await h.client.importCandidate(serialized);
  assert.equal(h.client.exportCandidate(), serialized);
});

test('raw-reference import requires independent native inspection before it can expose review or merge controls', async () => {
  const entered = deferred(), response = deferred();
  const h = harness(sample(), call => {
    if (call.path.endsWith('/inspect')) { entered.resolve(call); return response.promise; }
    return null;
  });
  await h.connect(); const importing = h.inspect(), call = await entered.promise;
  assert.equal(h.client.candidate, null); assert.equal(h.client.pending, null);
  await assert.rejects(stage(h.client, 'approve'), /Inspect/); await assert.rejects(stage(h.client, 'merge'), /Inspect/);
  assert.equal(call.headers['Idempotency-Key'], undefined);
  const bytes = await call.body.text();
  assert.ok(bytes.includes(`source_ref_hex=${h.f.refs.source_ref_hex}&target_ref_hex=${h.f.refs.target_ref_hex}`));
  assert.equal(bytes.includes('&source_ref='), false); assert.equal(bytes.includes('&target_ref='), false);
  response.resolve(json(h.f.inspection)); await importing;
  assert.equal(h.client.candidate.fields.source_ref_hex, h.f.refs.source_ref_hex);
  assert.equal(h.client.exportCandidate(), candidateReceipt(h.f));
});

for (const algorithm of ['sha1', 'sha256']) for (const action of ['approve', 'request-changes', 'withdraw', 'merge']) {
  test(`${algorithm} ${action}: raw-reference candidates stage and publish the exact inspected subject`, async () => {
    const h = harness(sample(algorithm)); await h.connect(); await h.inspect();
    const pending = await stage(h.client, action);
    assert.equal(h.calls.length, 2); assert.equal(pending.fields.source_ref_hex, h.f.refs.source_ref_hex);
    assert.equal(pending.fields.target_ref_hex, h.f.refs.target_ref_hex); assert.equal(pending.fields.source_ref, undefined);
    assert.equal(pending.fields.target_ref, undefined); assert.equal(pending.fields.candidate_commit, h.f.fields.candidate_commit);
    const body = requestBody(action, pending.fields, action === 'withdraw' ? null : h.f.bundle, pending.nonce);
    const done = await h.client.send(); assert.equal(done.outcome, 'committed'); assert.equal(h.client.pending, null);
    const sent = h.calls.at(-1); assert.equal(sent.headers['Idempotency-Key'], pending.key);
    assert.deepEqual(new Uint8Array(await sent.body.arrayBuffer()), body.bytes);
    assert.equal(h.client.candidate, null);
  });
}

test('a terminal raw-reference contradiction retains the original review for recovery', async () => {
  const h = harness(sample(), (call, client) => {
    if (!call.path.endsWith('/approve')) return null;
    const reply = nativeTerminal(client.pending, h.f); reply.subject.source_ref_hex += '80'; return json(reply);
  });
  await h.connect(); await h.inspect(); const pending = await stage(h.client, 'approve');
  await assert.rejects(h.client.send(), error => error.outcomeUnknown && /subject changed/.test(error.message));
  assert.equal(h.client.pending.key, pending.key); assert.deepEqual(h.client.pending.fields, pending.fields);
  const reply = nativeTerminal(pending, h.f); reply.subject.target_ref = 'refs/heads/false-display-label';
  assert.throws(() => publication(reply, pending, 200), /disagree/);
});

for (const algorithm of ['sha1', 'sha256']) for (const action of ['approve', 'request-changes', 'withdraw', 'merge']) {
  test(`${algorithm} ${action}: portable retries and replacement-credential outcomes retain original raw-reference bytes and key`, async () => {
    const f = sample(algorithm), first = harness(f, call => {
      if (/\/(approve|request-changes|withdraw|merge)$/.test(call.path)) throw new Error('Reply lost after native dispatch.');
      return null;
    });
    await first.connect(); await first.inspect(); const pending = await stage(first.client, action), receipt = first.client.exportReceipt();
    await assert.rejects(first.client.send(), error => error.outcomeUnknown);
    first.client.disconnect(); assert.equal(first.client.pending.key, pending.key);
    const retry = harness(f); await retry.client.connect(token); await retry.client.restoreReceipt(receipt);
    assert.equal(retry.calls.length, 0); assert.deepEqual(retry.client.pending.fields, pending.fields);
    assert.equal(retry.client.exportReceipt(), receipt);
    assert.equal((await retry.client.send()).outcome, 'committed'); assert.equal(retry.calls.length, 1);
    assert.equal(retry.calls[0].headers['Idempotency-Key'], pending.key);
    assert.deepEqual(new Uint8Array(await retry.calls[0].body.arrayBuffer()), new Uint8Array(await first.calls.at(-1).body.arrayBuffer()));

    const rotated = harness(f, call => {
      assert.ok(call.path.endsWith('/outcomes'));
      return json(recovered({ object_format: algorithm, state: 'committed', terminal: true,
        decision: { kind: 'committed', decision_sequence: 8, repository_commit_id: 'original-review-rcr' } }));
    });
    await rotated.client.connect('d'.repeat(64), { recoveryOnly: true, originalPrincipal: actor });
    await rotated.client.restoreReceipt(receipt);
    assert.equal(rotated.client.exportReceipt(), receipt); assert.equal(rotated.calls.length, 0);
    await assert.rejects(rotated.client.list(), /Recovery-only/);
    await assert.rejects(rotated.client.prepareAndInspect(1, f.selected, commitMetadata), /Recovery-only/);
    await assert.rejects(rotated.client.send(), /Recovery-only/);
    const outcome = await rotated.client.recover(); assert.equal(outcome.rcr, 'original-review-rcr'); assert.equal(rotated.calls.length, 1);
    assert.equal(rotated.calls[0].headers['Idempotency-Key'], pending.key); assert.equal(rotated.calls[0].body, undefined);
    assert.equal(rotated.client.pending, null);
  });
}

test('a receipt cannot switch reference aliases, bytes or subject version while reusing the original key', async () => {
  const f = sample('sha1', 'text', 'text');
  delete f.selected.source_ref; delete f.fields.source_ref;
  f.selected.source_ref_hex = f.refs.source_ref_hex; f.fields.source_ref_hex = f.refs.source_ref_hex;
  f.artifact.fields = f.fields;
  const h = harness(f); await h.connect(); await h.inspect(); await stage(h.client, 'approve');
  const original = JSON.parse(h.client.exportReceipt());
  for (const mutate of [fields => { fields.source_ref = f.refs.source_ref; delete fields.source_ref_hex; },
    fields => { fields.source_ref = f.refs.source_ref; }, fields => { fields.source_ref_hex += '80'; },
    fields => { fields.target_ref = 'refs/heads/other'; }, fields => { fields.pull_request_version++; }]) {
    const altered = structuredClone(original); mutate(altered.request.fields);
    const other = harness(f); await other.client.connect(token);
    await assert.rejects(other.client.restoreReceipt(JSON.stringify(altered)));
    assert.equal(other.client.pending, null); assert.equal(other.calls.length, 0);
  }
});

function conflictReport(f) {
  return { ...f.metadata, state: 'conflicted', merge_base: f.fields.merge_base, candidate: null, bundle: null,
    conflicts: [{ path_hex: 'ff', kind: 'binary', base: null, ours: { mode: 0o100644, oid: '1'.repeat(f.fields.source_tip.length) },
      theirs: { mode: 0o100755, oid: '2'.repeat(f.fields.source_tip.length) } }] };
}
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: an existing raw-reference PR prepares, resolves binary conflict choices and re-inspects before review`, async () => {
  const f = sample(algorithm), report = conflictReport(f), bytes = Uint8Array.of(0, 255, 13, 10, 128);
  const choices = [{ path_hex: 'ff', choice: 'file', mode: '100755', bytes }];
  const upload = await resolutionUpload(report, f.selected, commitMetadata, choices, webcrypto);
  const resolved = { ...f.metadata, state: 'resolved', resolution_profile: 'exact-path-resolutions-v1', resolutions: upload.expected.rows };
  const h = harness(f, call => call.path.endsWith('/prepare') ? json(report, 409)
    : call.path.endsWith('/resolve') ? new Response(f.mixed(resolved), { headers: { 'Content-Type': f.type } }) : null);
  await h.connect(); const stopped = await h.client.prepareAndInspect(1, f.selected, commitMetadata);
  assert.equal(stopped.metadata.state, 'conflicted'); assert.equal(h.client.candidate, null); assert.equal(h.calls.length, 2);
  const prepared = new URLSearchParams(h.calls[1].body);
  assert.equal(prepared.get('source_ref_hex'), f.refs.source_ref_hex); assert.equal(prepared.get('target_ref_hex'), f.refs.target_ref_hex);
  const result = await h.client.resolveAndInspect(choices);
  assert.equal(result.metadata.state, 'resolved'); assert.equal(h.client.conflict, null); assert.equal(h.calls.length, 4);
  const body = Buffer.from(await h.calls[2].body.arrayBuffer()), text = body.toString('latin1');
  assert.ok(body.includes(bytes)); assert.ok(text.includes(`source_ref_hex=${f.refs.source_ref_hex}&target_ref_hex=${f.refs.target_ref_hex}`));
  assert.ok(text.includes('resolution=ff%3Afile%3A100755%3Afile_0')); assert.equal(text.includes('&source_ref='), false);
  assert.ok(h.calls[3].path.endsWith('/inspect')); assert.equal(h.calls.some(call => call.headers['Idempotency-Key']), false);
  assert.equal((await stage(h.client, 'request-changes')).fields.source_ref_hex, f.refs.source_ref_hex);
  assert.equal(h.calls.length, 4);
});

test('a resolved raw-reference mismatch leaves conflicts available and never exposes a candidate', async () => {
  const f = sample(), report = conflictReport(f), choices = [{ path_hex: 'ff', choice: 'ours' }];
  const upload = await resolutionUpload(report, f.selected, commitMetadata, choices, webcrypto);
  const resolved = { ...f.metadata, state: 'resolved', resolution_profile: 'exact-path-resolutions-v1', resolutions: upload.expected.rows,
    subject: { ...f.metadata.subject, source_ref_hex: f.refs.source_ref_hex + '80' } };
  const h = harness(f, call => call.path.endsWith('/prepare') ? json(report, 409)
    : call.path.endsWith('/resolve') ? new Response(f.mixed(resolved), { headers: { 'Content-Type': f.type } }) : null);
  await h.connect(); await h.client.prepareAndInspect(1, f.selected, commitMetadata);
  await assert.rejects(h.client.resolveAndInspect(choices), /subject changed/);
  assert.equal(h.client.candidate, null); assert.equal(h.client.pending, null); assert.equal(h.client.conflict.state, 'conflicted');
  assert.equal(h.calls.some(call => call.path.endsWith('/inspect')), false);
});

async function mounted(f = sample()) {
  const doc = fakeDocument(), calls = [], downloads = []; let app;
  const record = row(1, { data: data({ ...f.refs, object_format: f.fields.object_format,
    source_tip: f.fields.source_tip, target_tip: f.fields.target_tip }) });
  app = mountPulls(doc, { href, cryptoImpl: webcrypto, downloadImpl: (name, text) => downloads.push({ name, text }),
    fetchImpl: async (url, init) => {
      const call = { path: new URL(url).pathname, ...init }; calls.push(call);
      if (call.path.endsWith('/pulls/1')) return json(show({ object_format: f.fields.object_format, pull_request: record }));
      if (call.path.endsWith('/prepare')) return new Response(f.mixed(), { headers: { 'Content-Type': f.type } });
      if (call.path.endsWith('/inspect')) return json(f.inspection);
      if (call.path.endsWith('/approve')) return json(nativeTerminal(app.client.pending, f));
      throw new Error(`Unexpected view request ${call.path}`);
    } });
  await app.client.connect(token); await app.loadPr(1);
  const node = id => { const element = doc.getElementById(id); assert.ok(element, `missing ${id}`); return element; };
  const submit = id => node(id).dispatchEvent(new Event('submit', { cancelable: true }));
  const importCandidate = async () => {
    const bytes = Buffer.from(candidateReceipt(f));
    node('candidate-import-file').files = [{ size: bytes.length, arrayBuffer: async () => Uint8Array.from(bytes).buffer }];
    submit('candidate-import'); await until(() => app.client.candidate !== null, 'raw-reference candidate imported');
    await until(() => !node('review-stage').disabled, 'review controls enabled after native inspection');
  };
  return { app, calls, downloads, node, submit, importCandidate };
}

for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: the PR view prepares and explicitly approves observed raw references without copying display labels into forms`, async () => {
  const f = sample(algorithm), h = await mounted(f);
  assert.equal(h.node('prepare-candidate').disabled, false); assert.equal(h.node('fast-forward-stage').disabled, true);
  assert.equal(h.node('source-ref').value, ''); assert.equal(h.node('target-ref').value, '');
  assert.equal(h.node('title').value, ''); assert.equal(h.node('pr-number').value, '');
  for (const [name, value] of Object.entries({ 'policy-epoch': '1', ...commitMetadata })) h.node(name).value = String(value);
  h.submit('prepare'); await until(() => h.app.client.candidate !== null, 'raw-reference preparation and native inspection completed');
  await until(() => !h.node('review-stage').disabled);
  assert.equal(h.calls.length, 3); assert.equal(h.calls.some(call => call.headers['Idempotency-Key']), false);
  assert.ok(h.node('candidate').textContent.includes(`Source reference bytes: ${f.refs.source_ref_hex}`));
  assert.ok(h.node('candidate').textContent.includes(`Target reference bytes: ${f.refs.target_ref_hex}`));
  assert.ok(h.node('candidate').textContent.includes(`Source tip: ${f.fields.source_tip}`));
  const prepared = new URLSearchParams(h.calls[1].body);
  assert.equal(prepared.get('source_ref_hex'), f.refs.source_ref_hex); assert.equal(prepared.get('source_ref'), null);
  h.node('review-action').value = 'approve'; h.node('review-version').value = '0'; h.node('reason').value = 'Reviewed exact native references and candidate.';
  h.submit('review'); await until(() => h.app.client.pending !== null && !h.app.client.busy);
  assert.equal(h.calls.length, 3); assert.equal(h.node('send').disabled, true);
  const pending = h.app.client.pending;
  h.node('confirm').checked = true; h.node('confirm').dispatchEvent(new Event('change')); h.node('send').click();
  await until(() => h.app.client.pending === null && !h.app.client.busy, 'raw-reference review published');
  assert.equal(h.calls.length, 4); assert.equal(h.calls[3].headers['Idempotency-Key'], pending.key);
  assert.ok((await h.calls[3].body.text()).includes(`source_ref_hex=${f.refs.source_ref_hex}&target_ref_hex=${f.refs.target_ref_hex}`));
});

test('portable raw-reference candidate files are imported through the PR view, re-inspected and exported without rewriting identity', async () => {
  const f = sample('sha256'), h = await mounted(f); await h.importCandidate();
  assert.equal(h.calls.filter(call => call.path.endsWith('/inspect')).length, 1);
  assert.equal(h.calls.some(call => call.headers['Idempotency-Key']), false); assert.equal(h.app.client.pending, null);
  h.node('candidate-download').click(); await until(() => h.downloads.length === 1);
  assert.equal(h.downloads[0].text, candidateReceipt(f));
  assert.equal(h.node('merge-stage').disabled, false);
});

test('raw-reference source-tip review remains available while the separate text-only fast-forward publication is explicitly unavailable', async () => {
  const f = sample();
  f.fields = { ...f.fields, source_tip: f.fields.candidate_commit, merge_base: f.fields.target_tip };
  f.artifact = { ...f.artifact, fields: f.fields };
  f.inspection = { ...f.inspection, subject: { ...f.inspection.subject, source_tip: f.fields.source_tip }, merge_base: f.fields.merge_base };
  const h = await mounted(f); await h.importCandidate();
  assert.equal(h.node('review-stage').disabled, false); assert.equal(h.node('merge-stage').disabled, true);
  assert.match(h.node('merge-method-guidance').textContent, /requires text branch references/);
  await assert.rejects(h.app.client.stageInspectedFastForward(), /requires text branch references/);
  await assert.rejects(h.app.client.stageMerge([reviewer]), /explicit fast-forward/);
  assert.equal((await stage(h.app.client, 'approve')).fields.source_ref_hex, f.refs.source_ref_hex);
});
