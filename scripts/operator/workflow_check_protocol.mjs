// Native workflow recovery/publication JSON contracts, not a second check authority.
// Rust source: workflow_command/{publish,recovery}.rs and durable/recovery/inspect.rs.
import { createHash } from 'node:crypto';
import { fail } from './workflow_watch_io.mjs';
export const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const hex = bytes => Buffer.from(bytes).toString('hex');
export function record(value) { if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Expected a workflow check record.'); return value; }
export function keys(value, fields) {
  record(value);
  if (Object.keys(value).some(key => !fields.includes(key)) || fields.some(key => !Object.hasOwn(value, key))) fail('Missing or unsupported workflow check fields.');
}
export function integer(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('Invalid workflow check counter.');
  return value;
}
export function text(value, maximum = 1024) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > maximum || /[\0-\x1f\x7f\uD800-\uDFFF]/u.test(value)) fail('Invalid workflow check text.');
  return value;
}
export function digest(value) { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('Invalid SHA-256 check commitment.'); return value; }
export function principal(value) { if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('Invalid workflow publisher principal.'); return value; }
export function oid(value, format) {
  if (!['sha1', 'sha256'].includes(format)) fail('Unsupported workflow object format.');
  const raw = typeof value === 'string' && value.startsWith(`${format}:`) ? value.slice(format.length + 1) : value;
  if (typeof raw !== 'string' || !new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) fail('Workflow check source identity changed.');
  return raw;
}
export function pin(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{1,9}:[0-9a-f]{64}$/.test(value)) fail('Invalid native journal pin.');
  integer(Number(value.split(':')[0]), 72, 4294967296); return value;
}
const conclusions = Object.freeze({ succeeded: 'success', skipped: 'action_required', failed: 'failure',
  refused: 'failure', output_limit: 'failure', cancelled: 'cancelled', timed_out: 'timed_out' });
// Journal custody still reports ActionRequired for local success. Publication
// derives this distinct conclusion only through the native evidence verifier.
export function conclusion(outcome) {
  if (typeof outcome !== 'string' || !Object.hasOwn(conclusions, outcome)) fail('Unsupported native job outcome.');
  return conclusions[outcome];
}
// Custody history is deliberately not the canonical publication conclusion.
export function journalConclusion(outcome) {
  const value = conclusion(outcome);
  return value === 'success' ? 'action_required' : value;
}
export function historyPage(reply, scope, previous = null) {
  record(reply); keys(reply.scope, ['tenant', 'repository', 'journal_id']);
  if (reply.type !== 'workflow_custody_history' || reply.schema_version !== 1 ||
      reply.authoritative_check !== false || reply.execution_retried !== false || reply.execution_completion !== 'not_asserted' ||
      reply.evidence_payloads_included !== false || Object.keys(scope).some(key => reply.scope[key] !== scope[key]) ||
      !Array.isArray(reply.entries) || reply.entries.length > 128) fail('Invalid native workflow custody page.');
  pin(reply.snapshot); integer(reply.retained_batches, 0, 1024); integer(reply.pending_batches, 0, reply.retained_batches);
  if (previous && (reply.snapshot !== previous.snapshot || reply.retained_batches !== previous.retained_batches || reply.pending_batches !== previous.pending_batches)) fail('Native journal snapshot moved during discovery.');
  if (reply.next_after !== null && (!reply.entries.length || digest(reply.next_after) !== reply.entries.at(-1).batch_sha256)) fail('Invalid workflow custody continuation.');
  return reply;
}
export const JOB_FIELDS = ['directory', 'journal_id', 'minimum_pin', 'batch_sha256', 'fact_index', 'job', 'source_commit',
  'run_id', 'attempt_id', 'graph_root', 'evidence_sha256', 'conclusion', 'key'];
export function jobKey(binding, watcherId, job) {
  const { key: _, ...request } = job;
  return `fgwc1-${sha256(encode([binding, watcherId, request]))}`;
}
export function validateJob(job, config, watcherId) {
  keys(job, JOB_FIELDS);
  for (const field of ['journal_id', 'batch_sha256', 'run_id', 'attempt_id', 'graph_root', 'evidence_sha256']) digest(job[field]);
  integer(job.fact_index, 0, 127); text(job.job); pin(job.minimum_pin);
  if (oid(job.source_commit, config.watch.object_format) !== job.source_commit ||
      !Object.values(conclusions).includes(job.conclusion) || job.key !== jobKey(sha256(encode(config)), watcherId, job)) fail('Saved check request changed.');
}
// A returned decision is historical; cleanup and delivery are separate from commit.
export function publication(reply, config, job, exitCode) {
  record(reply);
  const watch = config.watch;
  if (reply.type !== 'workflow_check_publication' || reply.schema_version !== 1 || reply.trusted_local !== true ||
      ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format'].some(key => reply[key] !== watch[key]) ||
      reply.principal_id !== config.principal_id || reply.source_ref_hex !== watch.ref_hex ||
      oid(reply.source_commit, watch.object_format) !== job.source_commit ||
      ['job', 'journal_id', 'batch_sha256', 'fact_index', 'run_id', 'attempt_id', 'graph_root', 'conclusion', 'evidence_sha256'].some(key => reply[key] !== job[key]) ||
      reply.scope !== 'trusted_workflow_observations' || reply.merge_permission !== null || reply.delivery_acknowledged !== null ||
      ['evidence_payload_included', 'authoritative_check', 'execution_retried', 'journal_acknowledged', 'refs_changed', 'current_refs_asserted'].some(key => reply[key] !== false) ||
      reply.historical_outcome !== true) fail('Native check publication changed scope, request or authority semantics.');
  if (typeof reply.check_id !== 'string' || !/^check\/[0-9a-v]{51}[0g]$/.test(reply.check_id)) fail('Invalid native check identity.');
  integer(reply.evidence_bytes, 1, 1024 * 1024);
  if (typeof reply.decision_sequence !== 'string' || !/^[1-9][0-9]{0,19}$/.test(reply.decision_sequence) || BigInt(reply.decision_sequence) > 18446744073709551615n) fail('Invalid exact decision sequence.');
  text(reply.tx_id, 256);
  if (!['committed', 'refused'].includes(reply.outcome) || reply.command_committed !== (reply.outcome === 'committed')) fail('Invalid native check outcome.');
  if (reply.outcome === 'committed') {
    text(reply.repository_commit_id, 256);
    if (reply.refusal_record_id !== null || reply.refusal_code !== null) fail('Conflicting native check decisions.');
  } else {
    text(reply.refusal_record_id, 256); text(reply.refusal_code, 256);
    if (reply.repository_commit_id !== null) fail('Conflicting native check decisions.');
  }
  if (reply.node_closed === true) {
    if (reply.cleanup_error !== null || exitCode !== (reply.outcome === 'committed' ? 0 : 3)) fail('Native check exit and decision disagree.');
  } else if (reply.node_closed !== false || typeof reply.cleanup_error !== 'string' || !reply.cleanup_error ||
      Buffer.byteLength(reply.cleanup_error) > 16384 || exitCode !== 2) fail('Invalid native check cleanup result.');
  return { schema: 'frankengit-workflow-check-terminal-v1', request_sha256: sha256(encode(job)),
    check_id: reply.check_id, tx_id: reply.tx_id, decision_sequence: reply.decision_sequence, outcome: reply.outcome,
    repository_commit_id: reply.repository_commit_id, refusal_record_id: reply.refusal_record_id, refusal_code: reply.refusal_code };
}
export function validateTerminal(value, job) {
  keys(value, ['schema', 'request_sha256', 'check_id', 'tx_id', 'decision_sequence', 'outcome', 'repository_commit_id', 'refusal_record_id', 'refusal_code']);
  if (value.schema !== 'frankengit-workflow-check-terminal-v1' || value.request_sha256 !== sha256(encode(job)) ||
      typeof value.check_id !== 'string' || !/^check\/[0-9a-v]{51}[0g]$/.test(value.check_id) ||
      typeof value.decision_sequence !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value.decision_sequence) || BigInt(value.decision_sequence) > 18446744073709551615n) fail('Saved workflow terminal changed.');
  text(value.tx_id, 256);
  if (value.outcome === 'committed') {
    text(value.repository_commit_id, 256);
    if (value.refusal_record_id !== null || value.refusal_code !== null) fail('Conflicting saved terminal.');
  } else if (value.outcome === 'refused') {
    text(value.refusal_record_id, 256); text(value.refusal_code, 256);
    if (value.repository_commit_id !== null) fail('Conflicting saved terminal.');
  } else fail('Unsupported saved terminal.');
  return value;
}
