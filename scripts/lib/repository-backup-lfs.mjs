// Equality-only companion pins. The existing DSSE statement signs the source
// archive; native fg derives and verifies the exact LFS set from its Git blobs.
// This adapter never decodes FGLF bytes or treats a checksum as authorization.
import { BACKUP_LIMITS, backupError, exact } from './repository-backup-io.mjs';

const FIELDS = ['sha256', 'bytes', 'objects', 'payload_bytes', 'exact_snapshot'];
const COUNTS = { bytes: BigInt(BACKUP_LIMITS.maximumArchiveBytes), objects: 100000n,
  payload_bytes: BigInt(BACKUP_LIMITS.maximumArchiveBytes) };
function fail(code) { throw backupError(code); }
export function backupLfsSha256(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('backup_invalid_lfs_sha256');
  return value;
}
export function validateBackupLfsReceipt(value, maximumBytes, expected = {}) {
  if (!exact(value, FIELDS) || typeof value.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(value.sha256)
    || value.exact_snapshot !== true || Object.entries(COUNTS).some(([key, maximum]) =>
      !(typeof value[key] === 'bigint' || Number.isSafeInteger(value[key]))
      || BigInt(value[key]) < (key === 'bytes' ? 1n : 0n) || BigInt(value[key]) > maximum)
    || BigInt(value.bytes) > BigInt(maximumBytes) || BigInt(value.payload_bytes) > BigInt(value.bytes)
    || (BigInt(value.objects) === 0n && BigInt(value.payload_bytes) !== 0n)) fail('backup_native_lfs_receipt_mismatch');
  const result = { sha256: value.sha256, bytes: String(value.bytes), objects: String(value.objects),
    payload_bytes: String(value.payload_bytes), exact_snapshot: true };
  if (['sha256', ...Object.keys(COUNTS)].some(key => expected[key] !== undefined && result[key] !== expected[key])) {
    fail('backup_native_lfs_receipt_mismatch');
  }
  return Object.freeze(result);
}
// Snapshot operator checkpoints before the first await. Native JSON still has
// integer counters; only the lossless operator/checkpoint representation uses
// strings. Neither form may silently accept missing or additional fields.
export function backupLfsCheckpoint(value) {
  if (!exact(value, FIELDS) || Object.keys(COUNTS).some(key => typeof value[key] !== 'string'
    || !/^(0|[1-9][0-9]{0,19})$/.test(value[key]))) fail('backup_invalid_lfs_checkpoint');
  try {
    return validateBackupLfsReceipt({ ...value, ...Object.fromEntries(Object.keys(COUNTS).map(key => [key, BigInt(value[key])])) },
      BACKUP_LIMITS.maximumArchiveBytes);
  } catch { fail('backup_invalid_lfs_checkpoint'); }
}
export function checkBackupLfsArtifact(expected, actual) {
  if (actual.sha256 !== expected.sha256 || (expected.bytes !== undefined && actual.bytes !== expected.bytes)) {
    fail('backup_lfs_artifact_mismatch');
  }
}
