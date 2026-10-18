// Actual operator contract and private-file checks. Native replies are schema
// fixtures; this does not claim Rust execution, attestation or merge permission.
import test from 'node:test';
import assert from 'node:assert/strict';
import { conclusion, journalConclusion, encode, sha256, jobKey, validateJob, publication, validateTerminal } from '../../scripts/operator/workflow_check_protocol.mjs';

const id = '1'.repeat(64);
function fixture(format = 'sha1', result = 'success') {
  const config = { watch: { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
    object_format: format, ref_hex: Buffer.from('refs/heads/main').toString('hex') }, principal_id: '4'.repeat(32) };
  const job = { directory: '/private/run', journal_id: '5'.repeat(64), minimum_pin: `72:${'6'.repeat(64)}`,
    batch_sha256: '7'.repeat(64), fact_index: 0, job: 'test', source_commit: '8'.repeat(format === 'sha1' ? 40 : 64),
    run_id: '9'.repeat(64), attempt_id: 'a'.repeat(64), graph_root: 'b'.repeat(64), evidence_sha256: 'c'.repeat(64), conclusion: result };
  job.key = jobKey(sha256(encode(config)), id, job);
  const reply = { type: 'workflow_check_publication', schema_version: 1, trusted_local: true, ...config.watch,
    source_ref_hex: config.watch.ref_hex, principal_id: config.principal_id,
    source_commit: job.source_commit, job: job.job, journal_id: job.journal_id, batch_sha256: job.batch_sha256,
    fact_index: job.fact_index, run_id: job.run_id, attempt_id: job.attempt_id, graph_root: job.graph_root,
    conclusion: result, evidence_sha256: job.evidence_sha256, scope: 'trusted_workflow_observations',
    merge_permission: null, delivery_acknowledged: null, evidence_payload_included: false, authoritative_check: false,
    execution_retried: false, journal_acknowledged: false, refs_changed: false, current_refs_asserted: false,
    historical_outcome: true, check_id: `check/${'0'.repeat(52)}`, evidence_bytes: 100,
    decision_sequence: '18446744073709551615', tx_id: 'original-transaction', outcome: 'committed', command_committed: true,
    repository_commit_id: 'original-rcr', refusal_record_id: null, refusal_code: null, node_closed: true, cleanup_error: null };
  return { config, job, reply };
}

test('only succeeded maps to native success; skipped and every negative remain distinct', () => {
  for (const [input, expected] of Object.entries({ succeeded: 'success', skipped: 'action_required', failed: 'failure',
    refused: 'failure', output_limit: 'failure', cancelled: 'cancelled', timed_out: 'timed_out' })) assert.equal(conclusion(input), expected);
  for (const [input, expected] of Object.entries({ succeeded: 'action_required', skipped: 'action_required', failed: 'failure',
    refused: 'failure', output_limit: 'failure', cancelled: 'cancelled', timed_out: 'timed_out' })) assert.equal(journalConclusion(input), expected);
  for (const input of ['success', 'pending', 'toString', '__proto__', '', null, undefined, 0, {}]) {
    assert.throws(() => conclusion(input)); assert.throws(() => journalConclusion(input));
  }
});

for (const format of ['sha1', 'sha256']) {
  test(`${format}: successful publication retains the exact historical terminal without granting merge authority`, () => {
    const { config, job, reply } = fixture(format);
    validateJob(job, config, id);
    const saved = publication(reply, config, job, 0);
    assert.equal(saved.decision_sequence, '18446744073709551615');
    assert.deepEqual(validateTerminal(JSON.parse(encode(saved)), job), saved);
    assert.equal(saved.request_sha256, sha256(encode(job)));
    assert.equal(Object.hasOwn(saved, 'merge_permission'), false);
    for (const field of ['authoritative_check', 'refs_changed', 'execution_retried', 'current_refs_asserted', 'journal_acknowledged']) {
      assert.throws(() => publication({ ...reply, [field]: true }, config, job, 0));
    }
    assert.throws(() => publication({ ...reply, merge_permission: true }, config, job, 0));
  });
  test(`${format}: a new success cannot rewrite an original action-required request or terminal`, () => {
    const { config, job, reply } = fixture(format, 'action_required');
    validateJob(job, config, id);
    const oldBytes = encode(job), saved = publication(reply, config, job, 0);
    const changed = { ...job, conclusion: 'success' };
    assert.notEqual(jobKey(sha256(encode(config)), id, changed), job.key);
    assert.throws(() => validateJob(changed, config, id));
    assert.throws(() => publication({ ...reply, conclusion: 'success' }, config, job, 0));
    assert.throws(() => validateTerminal(saved, changed));
    assert.deepEqual(encode(job), oldBytes);
    assert.deepEqual(validateTerminal(saved, job), saved);
  });
  test(`${format}: success still binds source, publisher, graph, run, attempt and evidence`, () => {
    const { config, job, reply } = fixture(format);
    for (const field of ['source_commit', 'source_ref_hex', 'principal_id', 'job', 'journal_id', 'batch_sha256', 'run_id', 'attempt_id', 'graph_root', 'evidence_sha256']) {
      assert.throws(() => publication({ ...reply, [field]: 'f'.repeat(64) }, config, job, 0), field);
    }
    for (const result of ['action_required', 'failure', 'cancelled', 'timed_out']) {
      assert.throws(() => publication({ ...reply, conclusion: result }, config, job, 0));
    }
  });
  test(`${format}: a refused success observation and failed cleanup remain terminal facts, not job failures`, () => {
    const { config, job, reply } = fixture(format);
    const refused = { ...reply, outcome: 'refused', command_committed: false, repository_commit_id: null,
      refusal_record_id: 'original-refusal', refusal_code: 'TargetRefMoved' };
    assert.equal(publication(refused, config, job, 3).outcome, 'refused');
    assert.throws(() => publication(refused, config, job, 0));
    assert.equal(publication({ ...reply, node_closed: false, cleanup_error: 'close failed' }, config, job, 2).outcome, 'committed');
    assert.throws(() => publication({ ...reply, node_closed: false, cleanup_error: 'close failed' }, config, job, 0));
  });
}
