import test from 'node:test';
import assert from 'node:assert/strict';
import { capturePullCandidate, resolvePullCandidate, validateCandidateCapture, candidateResolutionChoices,
  candidateCanonical, candidateJson, RESOLVED_CAPTURE_SCHEMA, RESOLUTION_CHOICE_BYTES } from '../../scripts/operator/pull_candidate_capture.mjs';
import { resolutionPeer, TOKEN, HEAD } from './pull_resolution_fixture.mjs';
import { candidatePeer, mixed } from './pull_candidate_fixture.mjs';
import { candidateRequest } from '../../scripts/operator/pull_candidate_io.mjs';
const capture = async p => (await capturePullCandidate(p.input, TOKEN)).capture;

for (const algorithm of ['sha1', 'sha256']) for (const method of ['merge-commit', 'squash']) {
  for (const choice of ['base', 'ours', 'theirs', 'delete', 'file']) test(`${algorithm} ${method} ${choice}: conflict -> resolved -> inspected, exact native bytes`, async t => {
    const p = await resolutionPeer(t, { algorithm, method, choice }), original = await capture(p), before = candidateCanonical(original);
    const result = await resolvePullCandidate(original, p.choices, TOKEN);
    assert.equal(result.capture.schema, RESOLVED_CAPTURE_SCHEMA); assert.equal(result.capture.preparation.state, 'resolved');
    assert.equal(result.capture.inspection.candidate_commit, `${algorithm}:${p.f.candidate}`);
    assert.equal(result.capture.inspection.merge_authorized, false); assert.deepEqual(result.bundle, p.f.bundle);
    assert.equal(result.usage.requests, 2); assert.equal(p.requests.length, 5);
    assert.equal(p.requests[3].url, '/repo.git/api/v1/pulls/7/resolve'); assert.equal(p.requests[4].url, '/repo.git/api/v1/pulls/7/inspect');
    const r = p.requests[3];
    let body = r.body.toString();
    if (choice === 'file') {
      const boundary = r.headers['content-type'].split('boundary=')[1];
      const start = r.body.indexOf(Buffer.from('\r\n\r\n')) + 4, end = r.body.indexOf(Buffer.from(`\r\n--${boundary}`), start);
      body = r.body.subarray(start, end).toString(); assert.ok(r.body.includes(Buffer.from('resolved\n')));
    } else assert.equal(r.headers['content-type'], 'application/x-www-form-urlencoded');
    const fields = new URLSearchParams(body);
    assert.equal(fields.get('source_tip'), p.f.source); assert.equal(fields.get('target_tip'), p.f.target);
    assert.equal(fields.get('merge_base'), p.f.base); assert.equal(fields.get('policy_epoch'), '3');
    assert.equal(fields.get('pull_request_version'), '9'); assert.equal(fields.get('profile'), null);
    assert.equal(fields.get('method'), method === 'squash' ? 'squash' : null);
    assert.equal(fields.get('resolution'), `${p.choices[0].path_hex}:${choice}${choice === 'file' ? ':100644:file_0' : ''}`);
    const reopened = await validateCandidateCapture(candidateJson(Buffer.from(candidateCanonical(result.capture))), result.bundle);
    assert.equal(reopened.artifact.fields.candidate_commit, p.f.candidate); assert.equal(p.requests.length, 5);
    assert.equal(candidateCanonical(original), before); assert.deepEqual(result.capture.resolution.preparation, original.preparation);
    assert.equal(result.capture.preparation.snapshot_token, HEAD);
  });
  test(`${algorithm} ${method}: ordinary clean capture is unchanged`, async t => {
    const p = await candidatePeer(t, { algorithm, method }), r = await capturePullCandidate(p.input, TOKEN);
    assert.equal(r.capture.schema, 'frankengit-pull-candidate-capture-v1'); assert.equal(r.capture.preparation.state, 'clean');
    assert.equal(r.capture.resolution, undefined); assert.deepEqual((await validateCandidateCapture(r.capture, r.bundle)).bundle, r.bundle);
  });
}
for (const bytes of [Buffer.alloc(0), Buffer.from([0, 255, 10, 13, 45, 45, 0]), Buffer.alloc(1024 * 1024, 0)]) {
  test(`explicit executable replacement preserves ${bytes.length} binary bytes including empty files`, async t => {
    const p = await resolutionPeer(t, { choice: 'file', bytes, mode: '100755', algorithm: 'sha256' });
    const r = await resolvePullCandidate(await capture(p), p.choices, TOKEN);
    assert.equal(r.capture.preparation.resolutions[0].result.mode, 0o100755);
    assert.equal(r.capture.preparation.resolutions[0].result.oid, `sha256:${p.f.newBlob}`);
    assert.equal(r.capture.resolution.choices[0].content_hex, bytes.toString('hex'));
  });
}
for (const edit of [
  c => c.pop(), c => c.push({ ...c[0] }), c => c[0].path_hex = '6f74686572', c => c[0].choice = 'auto',
  c => c[0].principal = 'f'.repeat(32), c => c[0].content_hex = '00',
  c => { c[0].choice = 'file'; c[0].mode = '120000'; c[0].content_hex = ''; },
  c => { c[0].choice = 'file'; c[0].mode = '100644'; c[0].content_hex = '0'; },
  c => { c[0].choice = 'file'; c[0].mode = '100644'; c[0].content_hex = 'ff'.repeat(1048577); },
]) test(`invalid choices refuse before networking: ${edit.toString()}`, async t => {
  const p = await resolutionPeer(t), original = await capture(p), choices = structuredClone(p.choices); edit(choices);
  await assert.rejects(resolvePullCandidate(original, choices, TOKEN)); assert.equal(p.requests.length, 3);
});
test('cumulative bytes include every path, exact ceiling and one-over', () => {
  const choices = Array.from({ length: 4 }, (_, i) => ({ path_hex: (i + 1).toString(16).padStart(2, '0'), choice: 'file', mode: '100644',
    content_hex: '00'.repeat(1048575) }));
  assert.equal(RESOLUTION_CHOICE_BYTES, 4 * 1024 * 1024);
  assert.equal(candidateResolutionChoices(choices).length, 4);
  choices[0].content_hex += '00'; assert.throws(() => candidateResolutionChoices(choices), /content_limit/);
});
for (const state of ['clean', 'already_up_to_date']) test(`${state} is not a conflict resolution input`, async t => {
  const p = await candidatePeer(t, { state }), r = await capturePullCandidate(p.input, TOKEN), count = p.requests.length;
  await assert.rejects(resolvePullCandidate(r.capture, [{ path_hex: '61', choice: 'delete' }], TOKEN)); assert.equal(p.requests.length, count);
});
for (const edit of [
  r => r.resolved.source_head = 'moved', r => r.resolved.snapshot_token = `alg:1:${'c'.repeat(64)}`,
  r => r.resolved.repository_incarnation = 'f'.repeat(32), r => r.resolved.state = 'clean',
  r => r.resolved.subject.policy_epoch++, r => r.resolved.method = 'squash',
  r => r.resolved.candidate.merge_base = `sha1:${'d'.repeat(40)}`, r => r.resolved.resolutions = [],
  r => r.resolved.resolutions[0].choice = 'ours', r => r.resolved.resolutions[0].result.oid = `sha1:${'e'.repeat(40)}`,
  r => r.resolved.resolutions[0].theirs.oid = `sha1:${'e'.repeat(40)}`, r => r.resolved.resolutions[0].path_hex = '61',
  r => r.resolved.resolutions[0].result.mode = 0o100755,
]) test(`changed resolution result refuses before inspection: ${edit.toString()}`, async t => {
  const p = await resolutionPeer(t), original = await capture(p); edit(p);
  await assert.rejects(resolvePullCandidate(original, p.choices, TOKEN)); assert.equal(p.requests.length, 4);
});
for (const edit of [p => p.inspection.source_head = 'moved', p => p.inspection.candidate_commit_body_hex += '20',
  p => p.inspection.parents.reverse(), p => p.inspection.comparison.after_tree = `sha1:${'e'.repeat(40)}`,
  p => p.inspection.all_changed_paths = false]) test(`inspection remains mandatory: ${edit.toString()}`, async t => {
  const p = await resolutionPeer(t), original = await capture(p); edit(p);
  await assert.rejects(resolvePullCandidate(original, p.choices, TOKEN)); assert.equal(p.requests.length, 5);
});
test('offline replay rejects changed original conflicts, choices and resolved/automatic schema substitution', async t => {
  const p = await resolutionPeer(t), result = await resolvePullCandidate(await capture(p), p.choices, TOKEN);
  for (const edit of [r => r.resolution.choices[0].choice = 'ours', r => r.resolution.preparation.merge_base = `sha1:${'f'.repeat(40)}`,
    r => r.schema = 'frankengit-pull-candidate-capture-v1', r => r.resolution.preparation.state = 'clean',
    r => r.resolution.choices.push({ path_hex: '61', choice: 'delete' }), r => r.review_pages[0].next_after = 'f'.repeat(32)]) {
    const bad = structuredClone(result.capture); edit(bad); await assert.rejects(validateCandidateCapture(bad, result.bundle));
  }
  assert.equal(p.requests.length, 5);
});
for (const status of [401, 403, 409, 429, 503, 307]) test(`resolution HTTP ${status}: no refresh or retry`, async t => {
  const p = await resolutionPeer(t, { handle(r, res) { if (r.url.endsWith('/resolve')) { res.writeHead(status); res.end(); return true; } } });
  await assert.rejects(resolvePullCandidate(await capture(p), p.choices, TOKEN), e => e.status === status && e.phase === 'resolution');
  assert.equal(p.requests.length, 4);
});
for (const bad of ['digest', 'duplicate', 'truncated', 'encoding']) test(`binary resolution response ${bad} refuses`, async t => {
  const p = await resolutionPeer(t, { handle(r, res, s) {
    if (!r.url.endsWith('/resolve')) return;
    let { type, bytes } = mixed(s.resolved, s.f.bundle);
    if (bad === 'digest') bytes[bytes.length - 100] ^= 1;
    if (bad === 'duplicate') bytes = Buffer.from(bytes.toString('latin1').replace('"schema_version":1', '"schema_version":1,"schema_version":1'), 'latin1');
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': bytes.length + Number(bad === 'truncated'),
      ...(bad === 'encoding' ? { 'Content-Encoding': 'gzip' } : {}) }); res.end(bytes); return true;
  } });
  await assert.rejects(resolvePullCandidate(await capture(p), p.choices, TOKEN, { timeoutMs: 1000 })); assert.equal(p.requests.length, 4);
});
test('one response budget is shared by resolution and inspection, with an exact permitted twin', async t => {
  const p = await resolutionPeer(t), original = await capture(p), r = await resolvePullCandidate(original, p.choices, TOKEN);
  assert.equal((await resolvePullCandidate(original, p.choices, TOKEN, { maxWireBytes: r.usage.response_bytes })).usage.response_bytes, r.usage.response_bytes);
  await assert.rejects(resolvePullCandidate(original, p.choices, TOKEN, { maxWireBytes: r.usage.response_bytes - 1 }));
});
test('one deadline owns a stalled inspection; a cancelled call never yields an artifact', async t => {
  const p = await resolutionPeer(t, { handle(r) { return r.url.endsWith('/inspect'); } });
  await assert.rejects(resolvePullCandidate(await capture(p), p.choices, TOKEN, { timeoutMs: 100 }), /candidate_timeout/);
  assert.equal(p.requests.length, 5);
  const c = new AbortController(); c.abort();
  await assert.rejects(resolvePullCandidate({}, p.choices, TOKEN, { signal: c.signal }), /candidate_cancelled/);
  assert.equal(p.requests.length, 5);
});
test('caller edits after invocation cannot change detached conflict observations or choices', async t => {
  const p = await resolutionPeer(t), original = await capture(p), choices = structuredClone(p.choices);
  const promise = resolvePullCandidate(original, choices, TOKEN);
  choices[0].choice = 'ours'; original.request.scope.repository_id = 'f'.repeat(32);
  assert.equal((await promise).capture.resolution.choices[0].choice, 'theirs');
});
test('transport allows only the exact bounded resolve envelope, not a publication operation', async t => {
  const p = await resolutionPeer(t);
  for (const change of [r => r.kind = 'merge', r => r.key = 'key', r => r.body = Buffer.alloc(5 * 1024 * 1024 + 1),
    r => r.type = 'text/plain', r => r.number = 0]) {
    const r = { kind: 'resolve', number: 7, body: Buffer.from('x=y'), type: 'application/x-www-form-urlencoded' }; change(r);
    await assert.rejects(candidateRequest(p.input.endpoint, TOKEN, r));
  }
  assert.equal(p.requests.length, 0);
});
