// Exact fg backup export receipt and equality-only pins for later verification.
// These narrow a trusted local operation; they do not authenticate an archive.
import { importJson } from './native-import-process.mjs';
import { BACKUP_LIMITS, backupError, exact } from './repository-backup-io.mjs';

const IDENTITY = ['tenant_id', 'repository_id', 'incarnation_id', 'object_format'];
const COUNTS = { objects: 100000n, references: 100000n, payload_bytes: BigInt(BACKUP_LIMITS.maximumArchiveBytes),
  local_edges: 1000000n, external_gitlinks: 1000000n };
const TRUE = ['complete', 'object_graph_verified', 'original_payload_commitments_verified', 'source_head_revalidated', 'node_closed'];
const FALSE = ['signature_verified', 'external_artifacts_included', 'physical_orphans_included'];
const FIELDS = ['type', 'schema_version', 'sha256', 'bytes', ...IDENTITY, 'head_generation', ...Object.keys(COUNTS), ...TRUE, 'scope', ...FALSE];
const integer = (v, minimum, maximum) => (typeof v === 'bigint' || Number.isSafeInteger(v)) && BigInt(v) >= minimum && BigInt(v) <= maximum;
function fail(code) { throw backupError(code); }

export function repositoryBackupExportReceipt(result, declarations, maximumBytes) {
  if (result.code !== 0) {
    const error = backupError('backup_native_export_refused'); error.native_exit_code = result.code;
    throw error;
  }
  const v = importJson(result.stdout);
  if (!exact(v, FIELDS) || v.type !== 'repository_source_backup_export' || v.schema_version !== 1
    || typeof v.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(v.sha256)
    || IDENTITY.some(k => v[k] !== declarations[k])
    || !integer(v.head_generation, 1n, 18446744073709551615n) || String(v.head_generation) !== declarations.head_generation
    || !integer(v.bytes, 1n, BigInt(maximumBytes))
    || Object.entries(COUNTS).some(([k, limit]) => !integer(v[k], 0n, limit))
    || BigInt(v.payload_bytes) > BigInt(v.bytes)
    || TRUE.some(k => v[k] !== true) || FALSE.some(k => v[k] !== false)
    || v.scope !== 'authority_and_selected_git_objects') fail('backup_native_export_receipt_mismatch');
  return Object.freeze(Object.fromEntries(Object.entries(v).map(([k, value]) => [k, typeof value === 'bigint' ? String(value) : value])));
}

// Every value is snapshotted before the first await. A caller pin may only
// refuse different bytes/counts, never bypass native or signature verification.
export function backupExportCheckpoint(value) {
  if (!exact(value, ['sha256', 'bytes', ...Object.keys(COUNTS)])
    || typeof value.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.sha256)) fail('backup_invalid_export_checkpoint');
  const result = { sha256: value.sha256 };
  for (const [k, maximum] of Object.entries({ bytes: BigInt(BACKUP_LIMITS.maximumArchiveBytes), ...COUNTS })) {
    const v = value[k];
    if (typeof v !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(v) || BigInt(v) > maximum || (k === 'bytes' && v === '0')) fail('backup_invalid_export_checkpoint');
    result[k] = v;
  }
  if (BigInt(result.payload_bytes) > BigInt(result.bytes)) fail('backup_invalid_export_checkpoint');
  return Object.freeze(result);
}
export function checkpointFromExport(receipt) {
  return backupExportCheckpoint(Object.fromEntries(['sha256', 'bytes', ...Object.keys(COUNTS)].map(k => [k, String(receipt[k])])));
}
export function checkExportVerification(checkpoint, artifact, native) {
  if (checkpoint === undefined) return;
  if (checkpoint.sha256 !== artifact.sha256 || checkpoint.bytes !== artifact.bytes) fail('backup_export_artifact_mismatch');
  if (native && Object.keys(COUNTS).some(k => checkpoint[k] !== String(native[k]))) fail('backup_export_verification_mismatch');
}
