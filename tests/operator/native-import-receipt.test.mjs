// Literal native receipt contracts, independent of the fake process adapter.
// Source: bundle.rs::finish_import / transaction_outcome.rs::render at 6f20ee29.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readNativeImportReceipt, readNativeOutcomeReceipt } from '../../scripts/lib/native-import-receipt.mjs';
import { importJson } from '../../scripts/lib/native-import-process.mjs';
const digest = { algorithm: 1, hex: 'a'.repeat(64) };
const intent = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), principal_id: '3'.repeat(32),
  object_format: 'sha256', key_digest: digest, content: { declared_refs: 1 } };
const scope = { schema_version: 1, tenant_id: intent.tenant_id, repository_id: intent.repository_id,
  principal_id: intent.principal_id, object_format: intent.object_format };
const transaction = { tx_id: 'tx:original', seal_id: 'seal:original', canonical_request_digest: digest, request_schema: 'native-schema' };
function outcome(state = 'key_not_observed') {
  return { type: 'transaction_outcome', ...scope, key_digest: digest, selector: 'transaction', command_index: null,
    state, terminal: false, transaction: state === 'undecided' ? transaction : null, decision: null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
    node_closed: true, cleanup_error: null };
}
function imported() {
  return { type: 'git_bundle_import', ...scope, outcome: 'committed', command_committed: true, atomic: true,
    tx_id: 'tx:original', decision_sequence: 1, repository_commit_id: 'rcr:original', refusal_code: null,
    refusal_record_id: null, delivery_acknowledged: null, reference_count: 1, node_closed: true,
    cleanup_error: null, includes_forge_metadata: false };
}
const processResult = (v, code) => ({ stdout: Buffer.from(JSON.stringify(v)), stderr: Buffer.alloc(0), code });
for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) test(`${state} is a nonterminal observation, not a fabricated transaction`, () => {
  const read = readNativeOutcomeReceipt(processResult(outcome(state), 4), intent);
  assert.equal(read.outcome, 'unknown_pending'); assert.equal(read.terminal, null);
  assert.equal(read.transaction_id, state === 'undecided' ? transaction.tx_id : null);
});
test('native recovery accepts a committed key-bound seal and decision', () => {
  const v = { ...outcome(), state: 'committed', terminal: true, transaction,
    decision: { kind: 'committed', decision_sequence: 7, repository_commit_id: 'rcr:original' } };
  const read = readNativeOutcomeReceipt(processResult(v, 0), intent);
  assert.equal(read.outcome, 'committed'); assert.equal(read.terminal.decision_sequence, '7');
  assert.equal(read.transaction_id, 'tx:original');
});
test('native recovery accepts canonical refusal without pretending the key is pending', () => {
  const v = { ...outcome(), state: 'refused', terminal: true, transaction,
    decision: { kind: 'refused', decision_sequence: 8, code: 'TargetRefMoved', code_point: 1, refusal_record_id: 'refusal:original' } };
  assert.equal(readNativeOutcomeReceipt(processResult(v, 3), intent).outcome, 'refused');
  assert.throws(() => readNativeOutcomeReceipt(processResult(v, 0), intent));
});
for (const patch of [{ read_only: false }, { request_reexecuted: true }, { absence_proves_non_commit: true },
  { key_digest: { algorithm: 1, hex: 'f'.repeat(64) } }, { principal_id: '9'.repeat(32) },
  { selector: 'receive_command', command_index: 0 }, { state: 'committed' }, { transaction },
  { node_closed: false }, { extra: 'field' }]) test(`recovery rejects contradictory binding ${JSON.stringify(patch)}`, () => {
  assert.throws(() => readNativeOutcomeReceipt(processResult({ ...outcome(), ...patch }, 4), intent));
});
test('import requires the actual flat git_bundle_import receipt and exit code', () => {
  assert.equal(readNativeImportReceipt(processResult(imported(), 0), intent).outcome, 'committed');
  for (const patch of [{ type: 'bundle_import_outcome' }, { atomic: false }, { command_committed: false },
    { includes_forge_metadata: true }, { reference_count: 2 }, { delivery_acknowledged: true }]) {
    assert.throws(() => readNativeImportReceipt(processResult({ ...imported(), ...patch }, 0), intent));
  }
});
test('JSON decoder preserves u64 tokens and rejects duplicates, precision loss and excessive nesting', () => {
  assert.equal(importJson(Buffer.from('{"sequence":18446744073709551615}')).sequence, 18446744073709551615n);
  for (const raw of ['{"x":1,"x":2}', '{"x":18446744073709551616}', '{"x":1e0}', '{"x":1}{}',
    '{"x":' + '['.repeat(40) + '0' + ']'.repeat(40) + '}']) assert.throws(() => importJson(Buffer.from(raw)));
});
