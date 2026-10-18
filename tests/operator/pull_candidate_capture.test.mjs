import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { capturePullCandidate, validateCandidateCapture, candidateInput, candidateCanonical, candidateJson,
  candidateHash, CandidateError, CANDIDATE_IO_LIMITS } from '../../scripts/operator/pull_candidate_capture.mjs';
import { candidateRequest } from '../../scripts/operator/pull_candidate_io.mjs';
import { candidatePeer, TOKEN, SCOPE, META, HEAD, mixed, sendJson } from './pull_candidate_fixture.mjs';

for (const algorithm of ['sha1', 'sha256']) for (const method of ['merge-commit', 'squash']) {
  test(`${algorithm} ${method}: actual Git bundle through discovery, preparation and native-schema inspection`, async t => {
    const p = await candidatePeer(t, { algorithm, method }), saved = structuredClone(p.input);
    const result = await capturePullCandidate(p.input, TOKEN);
    t.diagnostic(`Independent fixture oracle: ${p.fixture.version}; HTTP peer is not Rust fg.`);
    assert.deepEqual(p.input, saved); assert.equal(result.capture.preparation.state, 'clean');
    assert.equal(result.capture.inspection.candidate_commit, `${algorithm}:${p.fixture.candidate}`);
    assert.deepEqual(result.bundle, p.fixture.bundle); assert.equal(result.usage.requests, 4);
    assert.equal(result.capture.inspection.comparison.entries[0].path_hex.endsWith('ff'), true);
    assert.equal(result.capture.inspection.parents.length, method === 'squash' ? 1 : 2);
    const reopened = await validateCandidateCapture(JSON.parse(candidateCanonical(result.capture)), result.bundle);
    assert.deepEqual(reopened.bundle, result.bundle);
    assert.equal(reopened.artifact.fields.candidate_commit, p.fixture.candidate);
    assert.equal(candidateCanonical(result.capture).includes(TOKEN), false);
    for (const request of p.requests) {
      assert.equal(request.headers['idempotency-key'], undefined); assert.equal(request.headers['accept-encoding'], 'identity');
      assert.equal(request.headers.cookie, undefined); assert.ok(!/\/(?:merge|approve|apply|outcomes)$/.test(request.url));
    }
    assert.equal(result.capture.inspection.merge_authorized, false);
  });
}
for (const count of [0, 50, 51, 103, 400]) test(`complete review discovery with ${count} rows retains one snapshot and exact continuation`, async t => {
  const p = await candidatePeer(t, { reviewCount: count });
  const result = await capturePullCandidate(p.input, TOKEN), pages = result.capture.review_pages;
  assert.equal(pages.length, Math.max(1, Math.ceil(count / 50)));
  assert.equal(pages.flatMap(page => page.reviews).length, count); assert.equal(pages.at(-1).next_after, null);
  for (const page of pages) assert.equal(page.snapshot_token, HEAD);
  assert.equal(result.usage.requests, 3 + pages.length);
});
for (const state of ['conflicted', 'already_up_to_date']) test(`${state} remains a typed noncandidate, not empty successful inspection`, async t => {
  const p = await candidatePeer(t, { state }), result = await capturePullCandidate(p.input, TOKEN);
  assert.equal(result.capture.preparation.state, state); assert.equal(result.bundle, null); assert.equal(result.capture.inspection, null);
  assert.equal(result.usage.requests, 3); assert.equal(p.requests.some(r => r.url.endsWith('/inspect')), false);
  await validateCandidateCapture(result.capture);
});
test('a retained expected head is sent on the first request and cannot silently refresh', async t => {
  const p = await candidatePeer(t); p.input.expected_head = HEAD;
  await capturePullCandidate(p.input, TOKEN); assert.equal(new URL(p.requests[0].url, p.endpoint).searchParams.get('expected_head'), HEAD);
  p.input.expected_head = `alg:1:${'c'.repeat(64)}`;
  await assert.rejects(capturePullCandidate(p.input, TOKEN), e => e.phase === 'discovery');
  assert.equal(p.requests.length, 5);
});
for (const change of [
  p => p.pull.repository_id = 'e'.repeat(32), p => p.pull.repository_incarnation = 'e'.repeat(32),
  p => p.pull.object_format = 'sha256', p => p.pull.pull_request.version = Number.MAX_SAFE_INTEGER + 1,
  p => p.pull.pull_request.state = 'closed', p => p.pull.pull_request.data.source_ref = null,
  p => p.pull.pull_request.data.source_ref_hex = 'ff', p => p.pull.number = 8,
]) test(`invalid discovery stops before candidate construction: ${change.toString()}`, async t => {
  const p = await candidatePeer(t); change(p);
  await assert.rejects(capturePullCandidate(p.input, TOKEN), CandidateError);
  assert.ok(!p.requests.some(r => r.url.endsWith('/prepare')));
});
test('unsafe lexical numbers are rejected before shared validators can round them', async t => {
  const p = await candidatePeer(t, { handle(r, res, p) { if (!r.url.endsWith('/prepare') && !r.url.includes('/reviews')) {
    const body = JSON.stringify(p.pull).replace('"version":9', '"version":9007199254740993');
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(body); return true;
  } } });
  await assert.rejects(capturePullCandidate(p.input, TOKEN), e => e.code === 'unsupported_candidate_json_integer');
  assert.equal(p.requests.length, 1);
});
test('review page caps refuse instead of inferring an absent reviewer from a prefix', async t => {
  const p = await candidatePeer(t, { reviewCount: 51 });
  await assert.rejects(capturePullCandidate(p.input, TOKEN, { maxReviewPages: 1 }), e => e.code === 'candidate_review_page_limit');
  assert.equal(p.requests.length, 2);
  assert.equal((await capturePullCandidate(p.input, TOKEN, { maxReviewPages: 2 })).capture.review_pages.length, 2);
});
for (const edit of [
  v => v.snapshot_token = `alg:1:${'f'.repeat(64)}`, v => v.source_head = 'other-head', v => v.pull_request_version = 10,
  v => v.policy_epoch = 4, v => v.after = 'f'.repeat(32), v => v.next_after = 'f'.repeat(32),
  v => v.merge_authorized = true, v => v.reviews[0].subject.source_tip = 'sha1:' + 'e'.repeat(40),
]) test(`mixed or inconsistent review observation refuses: ${edit.toString()}`, async t => {
  const p = await candidatePeer(t, { reviewCount: 51, handle(r, res, p) {
    if (!r.url.includes('/reviews?') || !r.url.includes('after=')) return false;
    const value = { type: 'review_page', schema_version: 1, ...SCOPE, object_format: 'sha1', source_head: p.pull.source_head,
      snapshot_token: HEAD, number: 7, found: true, pull_request_version: 9, policy_epoch: 3,
      after: p.reviews[49].reviewer, limit: 50, next_after: null, merge_authorized: false, reviews: [structuredClone(p.reviews[50])] };
    edit(value); sendJson(res, value); return true;
  } });
  await assert.rejects(capturePullCandidate(p.input, TOKEN)); assert.equal(p.requests.length, 3);
});
for (const edit of [
  v => v.snapshot_token = `alg:1:${'f'.repeat(64)}`, v => v.source_head = 'other-head',
  v => v.subject.pull_request_version++, v => v.subject.policy_epoch++, v => v.subject.source_tip = 'sha1:' + 'e'.repeat(40),
  v => v.profile = 'exact-renames-v1', v => v.method = 'squash', v => v.published = true,
  v => v.merge_authorized = true, v => v.objects_staged = true, v => v.bundle.sha256 = '0'.repeat(64),
  v => v.bundle.bytes++, v => v.state = 'resolved', v => v.candidate.new_object_count = 10001,
]) test(`changed preparation never reaches inspection: ${edit.toString()}`, async t => {
  const p = await candidatePeer(t); edit(p.preparation);
  await assert.rejects(capturePullCandidate(p.input, TOKEN)); assert.equal(p.requests.length, 3);
});
for (const edit of [
  v => v.snapshot_token = `alg:1:${'f'.repeat(64)}`, v => v.source_head = 'other-head',
  v => v.candidate_commit = 'sha1:' + 'e'.repeat(40), v => v.subject.policy_epoch++,
  v => v.bundle.sha256 = '0'.repeat(64), v => v.candidate_commit_body_hex += '20',
  v => v.parents.reverse(), v => v.comparison.after_tree = 'sha1:' + 'e'.repeat(40),
  v => v.all_changed_paths = false, v => v.merge_authorized = true, v => v.comparison.entry_count = 0,
  v => v.comparison.entries[0].content.hunks[0].old.byte_end++,
  v => v.comparison.entries[0].content.type = 'unsupported',
]) test(`invalid native inspection withholds candidate: ${edit.toString()}`, async t => {
  const p = await candidatePeer(t); edit(p.inspection);
  await assert.rejects(capturePullCandidate(p.input, TOKEN)); assert.equal(p.requests.length, 4);
});
for (const kind of ['boundary', 'trailing', 'duplicate-json', 'foreign-part', 'digest', 'truncated']) test(`hostile multipart response ${kind}`, async t => {
  const p = await candidatePeer(t, { handle(r, res, p) {
    if (!r.url.endsWith('/prepare')) return false;
    let { type, bytes } = mixed(p.preparation, p.fixture.bundle);
    if (kind === 'boundary') type += 'x';
    if (kind === 'trailing') bytes = Buffer.concat([bytes, Buffer.from('unexpected')]);
    if (kind === 'foreign-part') bytes = Buffer.from(bytes.toString('latin1').replace('name="metadata"', 'name="wrong"'), 'latin1');
    if (kind === 'duplicate-json') bytes = Buffer.from(bytes.toString('latin1').replace('"schema_version":1', '"schema_version":1,"schema_version":1'), 'latin1');
    if (kind === 'digest') { const changed = Buffer.from(p.fixture.bundle); changed[changed.length - 1] ^= 1; bytes = mixed(p.preparation, changed).bytes; type = mixed(p.preparation, changed).type; }
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': bytes.length + Number(kind === 'truncated') }); res.end(bytes); return true;
  } });
  await assert.rejects(capturePullCandidate(p.input, TOKEN, { timeoutMs: 1000 })); assert.equal(p.requests.length, 3);
});
for (const status of [401, 403, 404, 429, 503, 307]) test(`HTTP ${status} never becomes a candidate or a retry`, async t => {
  const p = await candidatePeer(t, { handle(r, res) { res.writeHead(status, { Location: 'https://unrelated.invalid/' }); res.end('private server prose'); return true; } });
  await assert.rejects(capturePullCandidate(p.input, TOKEN), e => e instanceof CandidateError && !e.message.includes('private'));
  assert.equal(p.requests.length, 1);
});
test('declared/streamed limits, unsupported encoding, and duplicate headers refuse', async t => {
  for (const kind of ['declared', 'streamed', 'encoded', 'headers']) {
    const p = await candidatePeer(t, { handle(r, res) {
      if (kind === 'declared') res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 300000 });
      if (kind === 'streamed') res.writeHead(200, { 'Content-Type': 'application/json' });
      if (kind === 'encoded') res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' });
      if (kind === 'headers') res.writeHead(200, ['Content-Type', 'application/json', 'Content-Type', 'application/json']);
      res.end(kind === 'streamed' ? ' '.repeat(256 * 1024 + 1) : '{}'); return true;
    } });
    await assert.rejects(capturePullCandidate(p.input, TOKEN)); assert.equal(p.requests.length, 1);
  }
});
test('exact aggregate response budget passes and one byte below refuses', async t => {
  const p = await candidatePeer(t), result = await capturePullCandidate(p.input, TOKEN);
  const exact = await capturePullCandidate(p.input, TOKEN, { maxWireBytes: result.usage.response_bytes });
  assert.equal(exact.usage.response_bytes, result.usage.response_bytes);
  await assert.rejects(capturePullCandidate(p.input, TOKEN, { maxWireBytes: result.usage.response_bytes - 1 }));
});
test('one deadline covers discovery through inspection, including a stalled last request', async t => {
  const p = await candidatePeer(t, { handle(r) { return r.url.endsWith('/inspect'); } });
  await assert.rejects(capturePullCandidate(p.input, TOKEN, { timeoutMs: 200 }), e => e.code === 'candidate_timeout');
  assert.equal(p.requests.length, 4);
});
test('abort before I/O and during candidate construction does not produce a partial artifact', async t => {
  const controller = new AbortController();
  const p = await candidatePeer(t, { handle(r) { if (r.url.endsWith('/prepare')) { controller.abort(); return true; } } });
  await assert.rejects(capturePullCandidate(p.input, TOKEN, { signal: controller.signal })); assert.equal(p.requests.length, 3);
  await assert.rejects(capturePullCandidate(p.input, TOKEN, { signal: controller.signal })); assert.equal(p.requests.length, 3);
});
test('caller edits during discovery cannot alter the detached request', async t => {
  let original;
  const p = await candidatePeer(t, { handle() { original.metadata.message = 'changed'; original.scope.repository_id = 'e'.repeat(32); } });
  original = p.input;
  const result = await capturePullCandidate(original, TOKEN);
  assert.equal(result.capture.request.metadata.message, META.message); assert.equal(result.capture.request.scope.repository_id, SCOPE.repository_id);
});
test('offline revalidation catches changed artifacts and does no network work', async t => {
  const p = await candidatePeer(t), result = await capturePullCandidate(p.input, TOKEN), count = p.requests.length;
  for (const edit of [c => c.request.number = '8', c => c.preparation.method = 'squash', c => c.review_pages = [],
    c => c.review_pages[0].next_after = 'f'.repeat(32), c => c.inspection = null, c => c.preparation_status = 409]) {
    const bad = structuredClone(result.capture); edit(bad); await assert.rejects(validateCandidateCapture(bad, result.bundle));
  }
  const badBundle = Buffer.from(result.bundle); badBundle[0] ^= 1;
  await assert.rejects(validateCandidateCapture(result.capture, badBundle)); await assert.rejects(validateCandidateCapture(result.capture));
  assert.equal(p.requests.length, count);
});
for (const change of [v => v.number = '9007199254740993', v => v.number = '01', v => v.number = 7,
  v => v.metadata.timestamp = '0', v => v.metadata.message = '', v => v.metadata.author = ' <address>',
  v => v.method = 'rebase', v => v.profile = 'exact-renames-v1', v => v.endpoint = 'http://localhost/repo.git',
  v => v.endpoint = 'https://forge.invalid/repo.git?secret=1', v => v.scope.principal_id = '4'.repeat(32)]) {
  test(`input grammar rejects ${change.toString()}`, () => {
    const value = { endpoint: 'https://forge.invalid/repo.git', scope: { ...SCOPE, object_format: 'sha1' }, number: '7', metadata: { ...META }, method: 'merge-commit' };
    change(value); assert.throws(() => candidateInput(value));
  });
}
test('JSON intake refuses duplicate aliases, unsafe numbers, invalid UTF-8 and deep nesting', () => {
  for (const raw of ['{"x":1,"x":2}', '{"x":1,"\\u0078":2}', '{"x":1e0}', '{"x":-0}', '{"x":9007199254740993}', '['.repeat(33) + ']'.repeat(33)]) {
    assert.throws(() => candidateJson(Buffer.from(raw)));
  }
  assert.throws(() => candidateJson(Buffer.from([255])));
  assert.deepEqual(candidateJson(Buffer.from('{"x":1,"text":"{\\\"x\\\":1}"}')), { x: 1, text: '{"x":1}' });
});
test('the transport cannot target publication, review submission, outcome lookup or arbitrary paths', async t => {
  const p = await candidatePeer(t);
  for (const kind of ['merge', 'approve', 'outcomes', '../prepare', 'source/apply']) {
    await assert.rejects(candidateRequest(p.endpoint, TOKEN, { kind, number: 7, body: 'x' }));
  }
  assert.equal(p.requests.length, 0);
});
test('TLS private CA works; untrusted certificates and wrong hostnames refuse before disclosure', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'fg-candidate-tls-')); t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, alt] of [['local', 'IP:127.0.0.1'], ['wrong', 'DNS:wrong.invalid']]) {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, name + '.key'),
      '-out', join(dir, name + '.crt'), '-days', '1', '-subj', '/CN=' + name, '-addext', 'subjectAltName=' + alt], { stdio: 'ignore', timeout: 10000 });
    const cert = await readFile(join(dir, name + '.crt')), key = await readFile(join(dir, name + '.key'));
    const p = await candidatePeer(t, { tls: { cert, key } });
    await assert.rejects(capturePullCandidate(p.input, TOKEN)); assert.equal(p.requests.length, 0);
    if (name === 'local') assert.equal((await capturePullCandidate(p.input, TOKEN, { ca: cert })).capture.preparation.state, 'clean');
    else { await assert.rejects(capturePullCandidate(p.input, TOKEN, { ca: cert })); assert.equal(p.requests.length, 0); }
  }
});
