// Compose detached operator trust with the existing native fg backup protocol.
// Never decode archives, import SQL, publish authority, or replay external effects.
import { createHash } from 'node:crypto';
import { mkdtemp, lstat, realpath, rmdir, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, resolve, dirname, basename, join, sep } from 'node:path';
import { runImportProcess, importJson } from './native-import-process.mjs';
import { BACKUP_LIMITS, backupError, backupPath, backupLifetime, exact, readBackupControl, publishBackupControl } from './repository-backup-io.mjs';
import { backupDecimal, backupPolicy, authenticateRepositoryBackupFile } from './repository-backup-approval.mjs';

const IDENTITY = ['tenant_id', 'repository_id', 'incarnation_id', 'object_format'];
const COMMON = ['type', 'schema_version', 'sha256', ...IDENTITY, 'head_generation', 'objects', 'references', 'payload_bytes',
  'complete', 'scope', 'object_graph_verified', 'original_payload_commitments_verified', 'node_closed', 'signature_verified', 'routing_published', 'archive_bytes'];
const VERIFY = ['local_edges', 'external_gitlinks', 'verification_instance', 'authority_import_verified', 'git_payloads_written',
  'destination_authority_published', 'scratch_removed', 'destination_readback_verified', 'newest_checkpoint_verified', 'external_artifacts_verified'];
const RESTORE = ['destination_instance', 'source_tokens_preserved', 'reopened_and_verified', 'external_artifacts_restored',
  'streaming', 'resume_requested', 'already_published'];
function fail(code) { throw backupError(code); }
const nativeInteger = (v, minimum, maximum) => (typeof v === 'bigint' || Number.isSafeInteger(v)) && BigInt(v) >= minimum && BigInt(v) <= maximum;
export function repositoryBackupReceipt(process, operation, statement, instance, resume = false) {
  if (process.code !== 0) { const e = backupError('backup_native_refused'); e.native_exit_code = process.code; e.native_diagnostic = process.stderr?.subarray(0, 4096).toString('utf8') ?? ''; throw e; }
  const v = importJson(process.stdout);
  if (!exact(v, [...COMMON, ...(operation === 'verify' ? VERIFY : RESTORE)])
    || v.type !== `repository_source_backup_${operation}` || v.schema_version !== 1
    || IDENTITY.some(k => v[k] !== statement[k]) || v.sha256 !== statement.artifact.sha256
    || !nativeInteger(v.head_generation, 1n, 18446744073709551615n) || String(v.head_generation) !== statement.head_generation
    || !nativeInteger(v.archive_bytes, 1n, BigInt(BACKUP_LIMITS.maximumArchiveBytes)) || String(v.archive_bytes) !== statement.artifact.bytes
    || !nativeInteger(v.objects, 0n, 100000n) || !nativeInteger(v.references, 0n, 100000n)
    || !nativeInteger(v.payload_bytes, 0n, BigInt(statement.artifact.bytes))
    || ['complete', 'object_graph_verified', 'original_payload_commitments_verified', 'node_closed'].some(k => v[k] !== true)
    || v.signature_verified !== false || v.routing_published !== false || v.scope !== 'authority_and_selected_git_objects') fail('backup_native_receipt_mismatch');
  const field = operation === 'verify' ? 'verification_instance' : 'destination_instance';
  if (!nativeInteger(v[field], 1n, 9223372036854775807n) || String(v[field]) !== instance) fail('backup_native_instance_mismatch');
  if (operation === 'verify') {
    if (!nativeInteger(v.local_edges, 0n, 1000000n) || !nativeInteger(v.external_gitlinks, 0n, 1000000n)
      || v.authority_import_verified !== true || v.scratch_removed !== true
      || ['git_payloads_written', 'destination_authority_published', 'destination_readback_verified', 'newest_checkpoint_verified', 'external_artifacts_verified'].some(k => v[k] !== false)) fail('backup_native_receipt_mismatch');
  } else if (v.source_tokens_preserved !== false || v.external_artifacts_restored !== false || v.reopened_and_verified !== true
    || v.streaming !== true || v.resume_requested !== resume || typeof v.already_published !== 'boolean'
    || (!resume && v.already_published)) fail('backup_native_receipt_mismatch');
  // Stable lossless operator JSON without pretending these counters are JS-safe.
  return Object.freeze(Object.fromEntries(Object.entries(v).map(([k, value]) => [k, typeof value === 'bigint' ? String(value) : value])));
}
export function repositoryBackupOptions(value) {
  const keys = ['operation', 'fg', 'input', 'approval', 'trustKey', 'policy', 'verificationInstance', 'destination',
    'destinationInstance', 'approvalRecord', 'resume', 'trustedLocal', 'maximumBytes', 'timeoutMs', 'signal', 'onProgress'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !keys.includes(k))
    || !['verify', 'restore'].includes(value.operation) || value.trustedLocal !== true) fail('backup_explicit_local_operation_required');
  const result = { ...value, policy: backupPolicy(value.policy), resume: value.resume ?? false, onProgress: value.onProgress ?? (() => {}) };
  if (typeof result.resume !== 'boolean' || typeof result.onProgress !== 'function') fail('backup_invalid_options');
  for (const k of ['fg', 'input', 'approval', 'trustKey']) result[k] = backupPath(result[k]);
  if (!isAbsolute(result.fg)) fail('backup_absolute_fg_required');
  result.input = resolve(result.input); result.approval = resolve(result.approval); result.trustKey = resolve(result.trustKey);
  result.verificationInstance = backupDecimal(result.verificationInstance, 9223372036854775807n);
  if (result.operation === 'restore') {
    result.destination = resolve(backupPath(result.destination)); result.approvalRecord = resolve(backupPath(result.approvalRecord));
    result.destinationInstance = backupDecimal(result.destinationInstance, 9223372036854775807n);
    if (dirname(result.destination) === result.destination || result.approvalRecord === result.destination
      || result.approvalRecord.startsWith(result.destination + sep)
      || [result.fg, result.input, result.approval, result.trustKey].includes(result.approvalRecord)) fail('backup_record_must_be_separate');
  } else if (result.resume || ['destination', 'destinationInstance', 'approvalRecord'].some(k => value[k] !== undefined)) fail('backup_inapplicable_restore_option');
  // Validate every lifetime field before any file, process or temporary directory.
  backupLifetime({ maximumBytes: result.maximumBytes, timeoutMs: result.timeoutMs, signal: result.signal });
  return result;
}
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
async function absent(path) {
  try { await lstat(path); fail('backup_existing_path'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
}
async function privateCanonicalPath(path) {
  const parent = await realpath(dirname(path)), stat = await lstat(parent, { bigint: true });
  if (!stat.isDirectory() || typeof process.getuid !== 'function' || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_private_parent_required');
  return join(parent, basename(path));
}
function nativeArgs(operation, input, output, statement, instance, live, resume = false) {
  const args = ['backup', operation, input, output, '--trusted-local', '--expected-sha256', statement.artifact.sha256,
    operation === 'verify' ? '--verification-instance' : '--destination-instance', instance,
    '--max-archive-bytes', String(live.maximumBytes), '--timeout-secs', String(Math.ceil(live.remaining() / 1000))];
  if (resume) args.push('--resume');
  return args;
}
async function checkRecord(path, bytes, live) {
  const actual = await readBackupControl(path, BACKUP_LIMITS.envelopeBytes, live, true);
  if (!actual.equals(bytes)) fail('backup_restore_approval_record_mismatch');
}
export async function runApprovedRepositoryBackup(raw) {
  const options = repositoryBackupOptions(raw), live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal: options.signal });
  let state = options.resume ? 'existing_unknown' : 'not_started', scratch = null, record = null, nativeReceipt = null;
  const progress = async phase => { await options.onProgress(Object.freeze({ phase })); live.check(); };
  try {
    const encoded = await readBackupControl(options.approval, BACKUP_LIMITS.envelopeBytes, live);
    const key = await readBackupControl(options.trustKey, BACKUP_LIMITS.keyBytes, live);
    const verified = await authenticateRepositoryBackupFile(options.input, encoded, key, options.policy,
      { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal });
    const authentication = verified.authentication, statement = authentication.statement;
    await progress('authenticated'); verified.checkCurrent();
    // Resolve the actual trusted parent names before binding a destination.
    if (options.operation === 'restore') {
      options.destination = await privateCanonicalPath(options.destination);
      options.approvalRecord = await privateCanonicalPath(options.approvalRecord);
      if (options.approvalRecord === options.destination || options.approvalRecord.startsWith(options.destination + sep)) fail('backup_record_must_be_separate');
      record = Buffer.from(JSON.stringify({ type: 'repository_backup_restore_approval_v1', destination: options.destination,
        destination_instance: options.destinationInstance, trusted_key_id: authentication.trusted_key_id,
        policy: authentication.policy, statement }) + '\n');
      if (options.resume) await checkRecord(options.approvalRecord, record, live);
      else { await absent(options.destination); await absent(options.approvalRecord); }
    }
    // The native verifier needs a fresh scratch root. The adapter owns only its
    // private parent; unknown native children are NEVER recursively removed.
    scratch = await mkdtemp(join(tmpdir(), 'fg-approved-backup-'));
    const directory = await open(scratch, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    let identity;
    try {
      identity = await directory.stat({ bigint: true });
      if (!identity.isDirectory() || (identity.mode & 0o077n)) fail('backup_private_parent_required');
      const path = join(scratch, 'native'); live.check(); verified.checkCurrent();
      const result = await runImportProcess(options.fg, nativeArgs('verify', options.input, path, statement, options.verificationInstance, live), live);
      nativeReceipt = repositoryBackupReceipt(result, 'verify', statement, options.verificationInstance);
      await absent(path);
      const current = await lstat(scratch, { bigint: true });
      if (!current.isDirectory() || !same(current, identity)) fail('backup_scratch_changed');
      await rmdir(scratch); scratch = null;
    } finally { await directory.close(); }
    await progress('preflight_verified'); verified.checkCurrent();
    if (options.operation === 'verify') return { type: 'approved_repository_backup_verify', state: 'complete', authentication,
      native: nativeReceipt, signed_identity_matched_native: true, archive_bytes_authenticated: true, destination_changed: false };
    if (options.resume) await checkRecord(options.approvalRecord, record, live);
    else await publishBackupControl(options.approvalRecord, record, live);
    await progress('approval_recorded'); verified.checkCurrent();
    await checkRecord(options.approvalRecord, record, live);
    const preflight = nativeReceipt;
    await progress('restore_starting'); await checkRecord(options.approvalRecord, record, live); verified.checkCurrent();
    state = 'restore_attempted_unknown';
    // Native restore independently rechecks the signed digest before directory
    // creation and on every pass of its pinned handle. A prior pathname read
    // never authorizes changed bytes. No private key or approval path is passed.
    const result = await runImportProcess(options.fg, nativeArgs('restore', options.input, options.destination, statement,
      options.destinationInstance, live, options.resume), live);
    nativeReceipt = repositoryBackupReceipt(result, 'restore', statement, options.destinationInstance, options.resume);
    if (['objects', 'references', 'payload_bytes'].some(k => String(nativeReceipt[k]) !== String(preflight[k]))) fail('backup_restore_preflight_mismatch');
    state = 'complete';
    // Confirmed native publication wins over cancellation/expiry at completion.
    // Approval gates submission, not an in-native effect-time revocation lease.
    return { type: 'approved_repository_backup_restore', state, destination: options.destination,
      approval_record: options.approvalRecord, approval_record_sha256: createHash('sha256').update(record).digest('hex'),
      authentication, native: nativeReceipt, signed_identity_matched_native: true, approval_checked_before_restore: true,
      approval_effect_time_enforced: false, cancellation_requested: Boolean(live.signal?.aborted),
      complete_capsule_restored: false, external_effects_replayed: false };
  } catch (error) {
    error.state = state; error.verification_scratch = scratch; error.approval_record = options.approvalRecord ?? null;
    if (state === 'complete') error.native_receipt = nativeReceipt;
    throw error;
  }
}
