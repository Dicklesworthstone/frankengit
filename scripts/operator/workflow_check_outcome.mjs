// A transaction outcome settles the original saved request, not check authority,
// execution containment, node shutdown or currentness of the source branch.
import { validateOutcomeReply } from './transaction_outcome.mjs';
import { encode, sha256, keys } from './workflow_check_protocol.mjs';
import { fail } from './workflow_watch_io.mjs';

export function recoveryScope(config) {
  const watch = config.watch;
  return { tenant_id: watch.tenant_id, repository_id: watch.repository_id,
    repository_incarnation: watch.repository_incarnation, principal_id: config.principal_id };
}
export function recoveryRecord(reply, config, job, known = null) {
  const checked = validateOutcomeReply(reply, recoveryScope(config), known?.reply ?? null);
  return { schema: 'frankengit-workflow-check-outcome-v1', request_sha256: sha256(encode(job)), reply: checked };
}
export function validateRecoveryRecord(value, config, job, known = null) {
  keys(value, ['schema', 'request_sha256', 'reply']);
  if (value.schema !== 'frankengit-workflow-check-outcome-v1' || value.request_sha256 !== sha256(encode(job))) fail('Saved outcome changed its original check request.');
  return recoveryRecord(value.reply, config, job, known);
}
export function recoveredTerminal(record) {
  const reply = record.reply;
  if (!reply.terminal) return null;
  const decision = reply.decision;
  // Do not fabricate the check ID or a native publication-specific receipt.
  return { schema: 'frankengit-workflow-check-recovered-terminal-v1', request_sha256: record.request_sha256,
    tx_id: reply.transaction.tx_id, decision_sequence: decision.decision_sequence, outcome: reply.state,
    repository_commit_id: decision.repository_commit_id ?? null, refusal_record_id: decision.refusal_record_id ?? null,
    refusal_code: decision.code ?? null, check_id: null, observation_source: 'original_key_outcome' };
}
export function matchPublication(terminal, observation) {
  if (!terminal || !observation) return;
  const reply = observation.reply;
  if (reply.transaction?.tx_id !== terminal.tx_id) fail('Workflow outcome contradicts the retained publication transaction.');
  if (!reply.terminal) return;
  const recovered = recoveredTerminal(observation);
  for (const name of ['request_sha256', 'tx_id', 'decision_sequence', 'outcome', 'repository_commit_id', 'refusal_record_id', 'refusal_code']) {
    if (terminal[name] !== recovered[name]) fail('Workflow outcome contradicts the retained terminal decision.');
  }
}
