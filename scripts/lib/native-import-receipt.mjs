// Native CLI contracts read at upstream 6f20ee29:
// crates/fgit-cli/src/bundle.rs::finish_import and transaction_outcome.rs::render.
// Receipt interpretation is not a second authority or a synthetic transaction ID.
import { importError, importJson } from './native-import-process.mjs';
const label = v => typeof v === 'string' && v.length > 0 && v.length <= 256 && /^[\x21-\x7e]+$/.test(v);
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
export function nativeKeyDigest(v) {
  return exact(v, ['algorithm', 'hex']) && Number.isInteger(v.algorithm) && v.algorithm > 0 && v.algorithm <= 65535
    && typeof v.hex === 'string' && v.hex.length > 0 && v.hex.length <= 128 && v.hex.length % 2 === 0 && /^[0-9a-f]+$/.test(v.hex);
}
const sequence = v => (typeof v === 'bigint' && v > 0n && v <= 18446744073709551615n)
  || (Number.isSafeInteger(v) && v > 0);
function scope(v, intent) {
  if (v.schema_version !== 1 || v.tenant_id !== intent.tenant_id || v.repository_id !== intent.repository_id
    || v.principal_id !== intent.principal_id || v.object_format !== intent.object_format) throw importError('native_import_receipt_binding');
}
function cleanup(v, exit, expected) {
  if (v.node_closed === true && v.cleanup_error === null) {
    if (exit !== expected) throw importError('native_import_receipt_exit');
  } else if (v.node_closed === false && typeof v.cleanup_error === 'string' && v.cleanup_error.length > 0
    && v.cleanup_error.length <= 8192 && exit === 2) {
    // Native code prints the known decision, then exits with a cleanup error.
    // Retain that knowledge without claiming that cleanup completed.
  } else throw importError('native_import_receipt_cleanup');
}
export function readNativeOutcomeReceipt(result, intent) {
  const v = importJson(result.stdout);
  if (!exact(v, ['type', 'schema_version', 'tenant_id', 'repository_id', 'principal_id', 'object_format',
    'key_digest', 'selector', 'command_index', 'state', 'terminal', 'transaction', 'decision', 'read_only',
    'request_reexecuted', 'absence_proves_non_commit', 'session_completeness_established', 'node_closed', 'cleanup_error'])
    || v.type !== 'transaction_outcome' || v.selector !== 'transaction' || v.command_index !== null
    || v.read_only !== true || v.request_reexecuted !== false || v.absence_proves_non_commit !== false
    || v.session_completeness_established !== false || !nativeKeyDigest(v.key_digest)) throw importError('native_import_receipt_binding');
  scope(v, intent);
  if (intent.key_digest !== null && (v.key_digest.algorithm !== intent.key_digest.algorithm || v.key_digest.hex !== intent.key_digest.hex)) {
    throw importError('native_import_receipt_key');
  }
  const missing = ['key_not_observed', 'seal_not_observed'].includes(v.state);
  if (missing ? v.transaction !== null : !exact(v.transaction, ['tx_id', 'seal_id', 'canonical_request_digest', 'request_schema'])
    || !label(v.transaction.tx_id) || !label(v.transaction.seal_id) || !label(v.transaction.request_schema)
    || !nativeKeyDigest(v.transaction.canonical_request_digest)) throw importError('native_import_receipt_transaction');
  let outcome = 'unknown_pending', terminal = null, exit = 4;
  if (['committed', 'refused'].includes(v.state)) {
    if (v.terminal !== true || !sequence(v.decision?.decision_sequence)) throw importError('native_import_receipt_outcome');
    outcome = v.state; exit = outcome === 'committed' ? 0 : 3;
    if (outcome === 'committed') {
      if (!exact(v.decision, ['kind', 'decision_sequence', 'repository_commit_id']) || v.decision.kind !== outcome
        || !label(v.decision.repository_commit_id)) throw importError('native_import_receipt_outcome');
      terminal = { kind: outcome, rcr_id: v.decision.repository_commit_id, decision_sequence: String(v.decision.decision_sequence) };
    } else {
      if (!exact(v.decision, ['kind', 'decision_sequence', 'code', 'code_point', 'refusal_record_id']) || v.decision.kind !== outcome
        || !label(v.decision.code) || !Number.isInteger(v.decision.code_point) || v.decision.code_point < 0 || v.decision.code_point > 65535
        || !label(v.decision.refusal_record_id)) throw importError('native_import_receipt_outcome');
      terminal = { kind: outcome, code: v.decision.code, refusal_record_id: v.decision.refusal_record_id,
        decision_sequence: String(v.decision.decision_sequence) };
    }
  } else if ((!missing && v.state !== 'undecided') || v.terminal !== false || v.decision !== null) throw importError('native_import_receipt_outcome');
  cleanup(v, result.code, exit);
  return { outcome, terminal, transaction_id: v.transaction?.tx_id ?? null, key_digest: v.key_digest,
    node_closed: v.node_closed, cleanup_error: v.cleanup_error };
}
export function readNativeImportReceipt(result, intent) {
  const v = importJson(result.stdout);
  if (!exact(v, ['type', 'schema_version', 'outcome', 'command_committed', 'atomic', 'tx_id', 'decision_sequence',
    'repository_commit_id', 'refusal_code', 'refusal_record_id', 'principal_id', 'delivery_acknowledged', 'tenant_id',
    'repository_id', 'object_format', 'reference_count', 'node_closed', 'cleanup_error', 'includes_forge_metadata'])
    || v.type !== 'git_bundle_import' || v.atomic !== true || v.delivery_acknowledged !== null || v.includes_forge_metadata !== false
    || !label(v.tx_id) || !sequence(v.decision_sequence) || v.reference_count !== intent.content.declared_refs) throw importError('native_import_receipt_binding');
  scope(v, intent);
  let terminal, exit;
  if (v.outcome === 'committed' && v.command_committed === true && label(v.repository_commit_id)
    && v.refusal_code === null && v.refusal_record_id === null) {
    exit = 0; terminal = { kind: 'committed', rcr_id: v.repository_commit_id, decision_sequence: String(v.decision_sequence) };
  } else if (v.outcome === 'refused' && v.command_committed === false && v.repository_commit_id === null
    && label(v.refusal_code) && label(v.refusal_record_id)) {
    exit = 3; terminal = { kind: 'refused', code: v.refusal_code, refusal_record_id: v.refusal_record_id,
      decision_sequence: String(v.decision_sequence) };
  } else throw importError('native_import_receipt_outcome');
  cleanup(v, result.code, exit);
  return { outcome: v.outcome, terminal, transaction_id: v.tx_id, key_digest: intent.key_digest,
    node_closed: v.node_closed, cleanup_error: v.cleanup_error };
}
