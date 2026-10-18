// Complete acquisition/package/draft/sender/recovery modules over real sockets.
// The read peer is the existing Git-bundle-backed native-schema fixture. The
// publication peer is a contract fixture, not native policy/admission execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as forward } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { capturePullCandidate } from '../../scripts/operator/pull_candidate_capture.mjs';
import { saveCandidatePackage, loadCandidatePackage } from '../../scripts/operator/pull_candidate_files.mjs';
import { draftCandidateReview } from '../../scripts/operator/pull_candidate_draft.mjs';
import { preparePull, submitPull, recoverPull } from '../../scripts/operator/remote_pull.mjs';
import { candidatePeer, TOKEN, REVIEWER } from './pull_candidate_fixture.mjs';
const ROTATED = 'b'.repeat(64), ACTOR = 'e'.repeat(32), SEQUENCE = '18446744073709551615';

function publication(intent, state) {
  const f = intent.fields, format = intent.scope.object_format, merge = intent.action === 'merge', committed = state === 'committed';
  return { type: merge ? 'reviewed_merge_publication' : 'candidate_review_publication', schema_version: 1,
    ...intent.scope, action: intent.action, ...(merge ? { method: f.method } : {}),
    review_expected_version: merge ? null : Number(f.expected_version),
    subject: { number: Number(intent.number), pull_request_version: Number(f.pull_request_version), policy_epoch: Number(f.policy_epoch),
      ...Object.fromEntries(['source', 'target'].flatMap(side => [[`${side}_ref`, f[`${side}_ref`]],
        [`${side}_ref_hex`, Buffer.from(f[`${side}_ref`]).toString('hex')], [`${side}_tip`, `${format}:${f[`${side}_tip`]}`]])) },
    merge_base: `${format}:${f.merge_base}`, candidate_commit: `${format}:${f.candidate_commit}`,
    required_reviewers: merge ? f.required_reviewers : null,
    tx_id: 'fixture-native-candidate-transaction', outcome: state, decision_sequence: JSON.rawJSON(SEQUENCE),
    repository_commit_id: committed ? 'fixture-native-rcr' : null, refusal_record_id: committed ? null : 'fixture-native-refusal',
    refusal_code: committed ? null : 'PolicyDenied', refusal_code_point: committed ? null : 17, delivery_acknowledged: null };
}
function outcome(intent, state) {
  const { object_format: _, ...scope } = intent.scope, terminal = state !== 'key_not_observed';
  return { type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null, state, terminal,
    transaction: terminal ? { tx_id: 'fixture-native-candidate-transaction', seal_id: 'fixture-native-seal', request_schema: 'fixture-candidate-v1',
      canonical_request_digest: { algorithm: 1, hex: 'c'.repeat(64) } } : null,
    decision: terminal ? { kind: state, decision_sequence: JSON.rawJSON(SEQUENCE), ...(state === 'committed'
      ? { repository_commit_id: 'fixture-native-rcr' } : { code: 'PolicyDenied', code_point: 17, refusal_record_id: 'fixture-native-refusal' }) } : null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
const json = (res, value, status = 200) => { const bytes = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': bytes.length }); res.end(bytes); };
async function workflow(t, config) {
  const native = await candidatePeer(t, config), sockets = new Set(), errors = [];
  const p = { native, intent: null, writes: [], lookups: 0, accepted: false, state: config.state ?? 'committed', drop: false };
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; assert.ok(size <= 19 * 1024 * 1024); chunks.push(chunk); }
      const bytes = Buffer.concat(chunks, size), key = req.headers['idempotency-key'];
      if (key === undefined) {
        // Preserve the entire native-schema read peer, including its assertions.
        assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
        assert.match(req.url, /^\/repo\.git\/api\/v1\/pulls\/7(?:\?|\/reviews\?|\/prepare$|\/inspect$|$)/);
        const upstream = forward(new URL(req.url, native.endpoint), { method: req.method, headers: { ...req.headers, host: new URL(native.endpoint).host } }, response => {
          res.writeHead(response.statusCode, response.headers); response.pipe(res);
        });
        upstream.on('error', error => { errors.push(error); res.destroy(); }); upstream.end(bytes); return;
      }
      assert.ok(p.intent); assert.equal(req.method, 'POST'); assert.equal(key, p.intent.key); assert.equal(req.headers.cookie, undefined);
      if (req.url === '/repo.git/api/v1/outcomes') {
        assert.ok([`Bearer ${TOKEN}`, `Bearer ${ROTATED}`].includes(req.headers.authorization)); assert.equal(size, 0);
        p.lookups++; json(res, outcome(p.intent, p.accepted ? p.state : 'key_not_observed')); return;
      }
      assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
      const action = p.intent.action, suffix = action === 'merge' ? 'merge' : `reviews/${action}`;
      assert.equal(req.url, `/repo.git/api/v1/pulls/7/${suffix}`);
      const boundary = req.headers['content-type'].split('boundary=')[1]; assert.match(boundary, /^fg-pull-candidate-[0-9a-f]{32}$/);
      const marker = Buffer.from('Content-Type: application/x-git-bundle\r\n\r\n');
      const start = bytes.indexOf(marker) + marker.length, end = bytes.length - Buffer.byteLength(`\r\n--${boundary}--\r\n`);
      assert.deepEqual(bytes.subarray(start, end), native.fixture.bundle, 'the native-inspected Git bundle reaches publication unchanged');
      const formStart = bytes.indexOf(Buffer.from('\r\n\r\n')) + 4, formEnd = bytes.indexOf(Buffer.from(`\r\n--${boundary}\r\n`), formStart);
      const form = new URLSearchParams(bytes.subarray(formStart, formEnd).toString('utf8'));
      assert.equal(form.get('candidate_commit'), native.fixture.candidate); assert.equal(form.get('source_tip'), native.fixture.source);
      assert.equal(form.get('target_tip'), native.fixture.target); assert.equal(form.get('merge_base'), native.fixture.base);
      assert.equal(form.get('policy_epoch'), '3'); assert.equal(form.get('pull_request_version'), '9'); assert.equal(form.get('principal'), null);
      if (action === 'merge') { assert.equal(form.get('method'), native.fixture.method); assert.deepEqual(form.getAll('required_reviewer'), [REVIEWER]); }
      else assert.equal(form.get('expected_version'), '2');
      p.writes.push({ bytes, key, url: req.url }); p.accepted = true;
      if (p.drop) res.destroy(); else json(res, publication(p.intent, p.state), p.state === 'committed' ? 200 : 409);
    } catch (error) { errors.push(error); res.destroy(); }
  });
  server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); assert.deepEqual(errors, []); });
  p.input = { ...native.input, endpoint: `http://127.0.0.1:${server.address().port}/repo.git` }; return p;
}
async function prepared(t, config, action) {
  // Candidate state and canonical terminal state are independent fixture values.
  const p = await workflow(t, { ...config, state: 'clean' }); p.state = config.state ?? 'committed';
  const root = await mkdtemp(join(tmpdir(), 'fg-candidate-workflow-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const captured = await capturePullCandidate(p.input, TOKEN), receipt = await saveCandidatePackage(join(root, 'candidate'), captured.capture, captured.bundle);
  const saved = await loadCandidatePackage(receipt.path, receipt.sha256);
  const choices = { action, principal_id: action === 'merge' ? ACTOR : REVIEWER, candidate_commit: p.native.fixture.candidate,
    ...(action === 'merge' ? { method: p.native.fixture.method, required_reviewers: [REVIEWER] } : { reason: 'Explicit review of the saved native candidate.' }) };
  const draft = await draftCandidateReview(saved.capture, saved.bundle, choices);
  p.intent = preparePull(draft, TOKEN, saved.bundle);
  p.consent = { confirmKey: p.intent.key, confirmCandidate: p.native.fixture.candidate, bundle: saved.bundle,
    ...(action === 'merge' ? { confirmMergeMethod: p.native.fixture.method } : {}) };
  return p;
}
for (const algorithm of ['sha1', 'sha256']) for (const method of ['merge-commit', 'squash']) for (const action of ['approve', 'request-changes', 'merge']) {
  test(`${algorithm} ${method} ${action}: actual candidate-to-sender-to-recovery workflow`, async t => {
    const p = await prepared(t, { algorithm, method }, action);
    assert.equal(p.writes.length, 0, 'drafting and preparation are not publication');
    const result = await submitPull(p.intent, TOKEN, p.consent);
    assert.equal(result.outcome.state, 'committed'); assert.equal(result.outcome.decision.decision_sequence, SEQUENCE);
    assert.equal(p.writes.length, 1); assert.equal(p.lookups, 2); assert.equal(p.native.requests.length, 4);
    const recovered = await recoverPull(p.intent, ROTATED, { known: result.outcome, publication: result.publication });
    assert.equal(recovered.outcome.state, 'committed'); assert.equal(recovered.dispatched, false); assert.equal(p.writes.length, 1);
  });
}
for (const method of ['merge-commit', 'squash']) test(`${method}: exact method consent remains required and refusal never falls back`, async t => {
  const p = await prepared(t, { method, state: 'refused' }, 'merge');
  await assert.rejects(submitPull(p.intent, TOKEN, { ...p.consent, confirmMergeMethod: method === 'squash' ? 'merge-commit' : 'squash' }));
  assert.equal(p.lookups, 0); assert.equal(p.writes.length, 0);
  const result = await submitPull(p.intent, TOKEN, p.consent); assert.equal(result.outcome.state, 'refused');
  assert.equal(result.outcome.decision.code, 'PolicyDenied'); assert.equal(p.writes.length, 1);
  const retry = await submitPull(p.intent, TOKEN, { ...p.consent, known: result.outcome });
  assert.equal(retry.dispatched, false); assert.equal(p.writes.length, 1);
});
test('a dropped publication reply recovers with the same principal and key without another bundle upload', async t => {
  const p = await prepared(t, { algorithm: 'sha256', method: 'squash' }, 'merge'); p.drop = true;
  await assert.rejects(submitPull(p.intent, TOKEN, p.consent), e => e.dispatched && e.outcomeUnknown);
  assert.equal(p.writes.length, 1); const observed = await recoverPull(p.intent, ROTATED);
  assert.equal(observed.outcome.state, 'committed'); assert.equal(observed.dispatched, false); assert.equal(p.writes.length, 1);
});
