#!/usr/bin/env node
// Explicit remote-to-native recovery; no silent restore, checkpoint switch or retry.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BACKUP_LIMITS, backupError } from './lib/repository-backup-io.mjs';
import { MAX_REPAIR_REPLICAS } from './lib/repository-backup-chunks.mjs';
import { MAX_BACKUP_APPROVALS } from './lib/repository-backup-checkpoints.mjs';
import { backupDecimal } from './lib/repository-backup-approval.mjs';
import { MAX_RECOVERY_ACQUISITION_BYTES, repositoryBackupRecoveryOptions, recoverRepositoryBackup } from './lib/repository-backup-recovery.mjs';

export const RECOVERY_USAGE = `Usage: node scripts/recover_repository_backup.mjs verify|restore [OPTIONS]
  --cache-directory DIRECTORY      Existing owner-private acquired-byte cache
  --approval FILE                 One original local approval (singleton mode)
  --candidate APPROVAL_FILE        Repeat for 1..64 explicit checkpoint candidates
  --trust-key FILE                 Independent Ed25519 public key for all approvals
  --witness DIRECTORY              Existing independently retained checkpoint witness
  --fg ABSOLUTE_PATH --trusted-local --verification-instance N
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N      Independently retained minimum generation
  --sources PRIVATE_JSON           1..16 explicit HTTPS URLs; needed only on a cache miss
  --ca-file FILE                   Independent TLS CA; needed only for remote acquisition
  --repair-catalog FILE            Derived chunk hints for explicit local reconstruction
  --repair-replica FILE            Repeat for 1..64 damaged/truncated local copies
  --max-archive-bytes N            Individual archive bound (default 1 GiB, max 1 TiB)
  --max-acquisition-bytes N        Cache/download/publication payload work (default 4 x archive bound)
  --timeout-secs N                 One cooperative operation lifetime, 1..3600
  --progress-json                  Bounded redacted checkpoints on stderr
Restore additionally requires:
  --destination NEW_ROOT --destination-instance N --approval-record NEW_FILE
  --resume                        Resume the exact original native restore intent
  --checkpoint APPROVAL_SHA256 TRUSTED_KEY_ID
                                  Required with --resume; optional fresh equality pin

Use --approval for one checkpoint, or --candidate to begin each candidate group.
In grouped mode, following --sources, --ca-file, --repair-catalog and repeated
--repair-replica options belong to that candidate until the next --candidate.
All other options are global; singleton acquisition options cannot be mixed in.
A candidate without acquisition flags is cache-only. Every approval authenticates
before the highest unique signed checkpoint is selected; only that candidate's
payload or URL file is read. Lower or alternate candidate plans are never tried
on failure. Equal highest statements use caller order unless the exact original
checkpoint pin selects its matching serialization. Pins never override a higher
checkpoint. This selects the supplied/retained set, not an unknown global latest.

Run native signed preflight after revalidating cached or downloaded bytes. Restore
is explicit and never automatically retried. --resume requires the original
checkpoint, native destination and approval record; it is not a different restore.
A verified cache works without reading expired/missing source URLs or connecting.
A corrupt cache refuses rather than being overwritten or silently replaced.
Repair options select local reconstruction instead of HTTPS on a cache miss.
Both catalog and replicas are required; --sources/--ca-file cannot be combined.
Surviving chunks must reconstruct the ORIGINAL signed archive, then pass native
preflight. Damaged inputs and conflicting cache files are never overwritten.
A verified cache skips both HTTPS and repair; repair inputs may be omitted on resume.
The witness lease spans acquisition, native work and all owned cleanup. Crashed
witness leases are not stolen/reset. No routing or external effects are replayed.
Exit 0: native operation completed and report delivered. Exit 1: refused/unknown.
Exit 4: native completion observed, but local cleanup/report delivery failed.
Acquisition accounting excludes native engine reads, which retain native limits.
`;
const FIELDS = { '--cache-directory': 'cacheDirectory', '--sources': 'sourceFile', '--approval': 'approval',
  '--trust-key': 'trustKey', '--witness': 'witness', '--fg': 'fg', '--verification-instance': 'verificationInstance',
  '--destination': 'destination', '--destination-instance': 'destinationInstance', '--approval-record': 'approvalRecord', '--ca-file': 'caFile', '--repair-catalog': 'repairCatalog' };
const POLICY = { '--tenant-id': 'tenant_id', '--repository-id': 'repository_id', '--incarnation-id': 'incarnation_id',
  '--object-format': 'object_format', '--minimum-head-generation': 'minimum_head_generation' };
const fail = code => { throw backupError(code); };
export function recoveryArguments(args) {
  if (!Array.isArray(args) || !args.length || args.length > 1024
    || args.some(v => typeof v !== 'string' || v.length > 8192 || v.includes('\0'))
    || args.reduce((size, v) => size + Buffer.byteLength(v), 0) > 384 * 1024) fail('backup_recovery_argument_limit');
  const result = { operation: args[0], policy: {} }, seen = new Set();
  let progress = false, candidate = null, candidateSeen = new Set();
  const next = index => { if (!args[index] || args[index].startsWith('--')) fail('backup_missing_option_value'); return args[index]; };
  for (let at = 1; at < args.length; at++) {
    const flag = args[at];
    if (flag === '--candidate') {
      result.candidates ??= [];
      if (result.candidates.length === MAX_BACKUP_APPROVALS) fail('backup_candidate_limit');
      candidate = { approval: next(++at) }; result.candidates.push(candidate); candidateSeen = new Set();
      continue;
    }
    const grouped = ['--sources', '--ca-file', '--repair-catalog', '--repair-replica'].includes(flag);
    const target = grouped && candidate ? candidate : result;
    if (flag === '--repair-replica') {
      target.repairReplicas ??= [];
      if (target.repairReplicas.length === MAX_REPAIR_REPLICAS) fail('backup_chunk_replica_limit');
      target.repairReplicas.push(next(++at)); continue;
    }
    if (grouped && candidate) {
      if (candidateSeen.has(flag)) fail('backup_duplicate_option'); candidateSeen.add(flag);
      candidate[FIELDS[flag]] = next(++at); continue;
    }
    if (seen.has(flag)) fail('backup_duplicate_option'); seen.add(flag);
    if (flag === '--trusted-local') { result.trustedLocal = true; continue; }
    if (flag === '--resume') { result.resume = true; continue; }
    if (flag === '--progress-json') { progress = true; continue; }
    if (flag === '--checkpoint') { result.checkpoint = { approval_sha256: next(++at), trusted_key_id: next(++at) }; continue; }
    if (!Object.hasOwn(FIELDS, flag) && !Object.hasOwn(POLICY, flag)
      && !['--timeout-secs', '--max-archive-bytes', '--max-acquisition-bytes'].includes(flag)) fail('backup_unknown_option');
    const value = next(++at);
    if (Object.hasOwn(FIELDS, flag)) result[FIELDS[flag]] = value;
    else if (Object.hasOwn(POLICY, flag)) result.policy[POLICY[flag]] = value;
    else if (flag === '--timeout-secs') result.timeoutMs = Number(backupDecimal(value, 3600n)) * 1000;
    else if (flag === '--max-archive-bytes') result.maximumBytes = Number(backupDecimal(value, BigInt(BACKUP_LIMITS.maximumArchiveBytes)));
    else result.maximumAcquisitionBytes = Number(backupDecimal(value, BigInt(MAX_RECOVERY_ACQUISITION_BYTES)));
  }
  return { options: repositoryBackupRecoveryOptions(result), progress };
}
const write = (stream, text) => new Promise((resolve, reject) => stream.write(text, error => error ? reject(error) : resolve()));
export async function runRecoveryCommand(args, output = process.stdout, diagnostic = process.stderr, signal) {
  if (args.length === 1 && args[0] === '--help') { await write(output, RECOVERY_USAGE); return null; }
  const { options, progress } = recoveryArguments(args);
  const result = await recoverRepositoryBackup({ ...options, signal, onProgress: async event => {
    // At most seven phase markers; never emit URLs, unbounded byte progress,
    // arbitrary native diagnostics or private capability-file contents.
    if (progress && ['recovery', 'native'].includes(event.stage)) await write(diagnostic,
      JSON.stringify({ type: 'repository_backup_recovery_progress', schema_version: 1, stage: event.stage, phase: event.phase,
        checkpoint: event.checkpoint, ...(event.candidate ? { candidate: event.candidate } : {}) }) + '\n');
  } });
  try { await write(output, JSON.stringify(result) + '\n'); }
  catch (error) { error.state = 'complete'; error.completed_result = result; throw error; }
  return result;
}
export function recoveryErrorReport(error) {
  const nativeCompleted = error.recovery?.native?.state === 'complete'
    || error.completed_result?.native?.state === 'complete'
    || (error.state === 'complete' && error.native_receipt?.type?.startsWith('repository_source_backup_'));
  return { type: 'repository_backup_recovery_error', schema_version: 1, code: error.code ?? 'backup_recovery_failed',
    state: error.state ?? 'not_started', exit_code: nativeCompleted ? 4 : 1,
    recovery: error.recovery ?? null, native_receipt: error.native_receipt ?? null,
    native_exit_code: error.native_exit_code ?? null, completed_result: error.completed_result ?? null,
    witness: error.witness ?? null, witness_lock_retained: error.witness_lock_retained ?? false,
    witness_cleanup_error: error.witness_cleanup_error ?? null,
    witness_publication_state: error.witness_publication_state ?? null,
    verification_scratch: error.verification_scratch ?? null, approval_scratch: error.approval_scratch ?? null,
    approval_record: error.approval_record ?? null, cleanup_error: error.cleanup_error ?? null,
    recovery_cleanup_error: error.recovery_cleanup_error ?? null, download_state: error.download_state ?? null,
    retained_download: error.retained_download ?? null, download_cleanup_error: error.download_cleanup_error ?? null,
    publication_state: error.publication_state ?? null, replica: error.replica ?? null,
    reconstruction_chunk_index: error.chunk_index ?? null, reconstruction_replicas: error.replicas ?? null,
    reconstruction_staging_path: error.staging_path ?? null };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  const pipe = () => { controller.abort(); process.exitCode = 1; };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { await runRecoveryCommand(process.argv.slice(2), process.stdout, process.stderr, controller.signal); }
  catch (error) {
    const report = recoveryErrorReport(error); process.exitCode = report.exit_code;
    try { await write(process.stderr, JSON.stringify(report) + '\n'); } catch { process.exitCode = report.exit_code; }
  } finally { process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop); }
}
