#!/usr/bin/env node
// GET/PUT capabilities stay in an owner-private file, never command arguments.
import { resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, readBackupControl } from './lib/repository-backup-io.mjs';
import { backupDecimal, backupPolicy } from './lib/repository-backup-approval.mjs';
import { repositoryBackupReplicationCheckpoint } from './lib/repository-backup-replication.mjs';
import { uploadRepositoryBackup } from './lib/repository-backup-upload.mjs';
import { backupLfsSha256 } from './lib/repository-backup-lfs.mjs';

export const UPLOAD_USAGE = `Usage: node scripts/upload_repository_backup.mjs [OPTIONS]
  --input ARCHIVE --approval ENVELOPE --trust-key ED25519_PUBLIC_PEM
  --target PRIVATE_JSON         {archive:{get,put},approval:{get,put}} HTTPS URLs
  --lfs-archive ARCHIVE --expected-lfs-sha256 HEX   Optional exact LFS companion
  --fg ABSOLUTE_BINARY --verification-instance N --trusted-local
                               Required with LFS; native combined preflight
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N   Independent checkpoint floor, full u64 decimal
  --ca-file CERTIFICATE_PEM     Optional independently chosen TLS CA
  --checkpoint APPROVAL_SHA256 TRUSTED_KEY_ID   Exact original approval constraint
  --max-archive-bytes N         Per-archive ceiling (default 1 GiB; maximum 1 TiB)
  --max-total-bytes N           Initial read + upload read + remote readback budget
  --timeout-secs N              One deadline, 1..3600 (default 300)
  --progress-json               At most four source-only or seven paired phases

The target service must implement conditional PUT (If-None-Match:*) and
100-continue. Each GET/PUT pair must name the same origin and path; signed query
strings may differ. Capabilities are read from a private, singly linked 16 KiB
file. Paired targets also require lfs:{get,put}; all objects must be distinct. No redirect,
insecure TLS, automatic signing, overwrite, deletion or uncertain PUT retry.
The original local signature, namespace, floor, expiry and bytes are checked
before connecting. Approval publication follows exact remote archive readback.
An explicit rerun rechecks existing objects; --checkpoint retains original intent.
Paired publication requires native verification of the exact signed source and
independently pinned companion before remote access, then both remote readbacks
before approval PUT. DSSE v1 still signs only the source archive. The total-byte
budget covers JS hashing and transfer; native preflight is separately bounded
by each archive ceiling and the same deadline, not a claimed native read total.
HTTP readback is not remote physical durability, native restore or global freshness.
Sealed v1 upload jobs remain source-only.
`;
const FIELDS = { '--input': 'input', '--approval': 'approval', '--trust-key': 'trustKey', '--target': 'targetFile',
  '--ca-file': 'caFile', '--lfs-archive': 'lfsArchive', '--fg': 'fg' };
const POLICY = { '--tenant-id': 'tenant_id', '--repository-id': 'repository_id', '--incarnation-id': 'incarnation_id',
  '--object-format': 'object_format', '--minimum-head-generation': 'minimum_head_generation' };
const fail = code => { throw backupError(code); };
export function uploadArguments(args) {
  if (!Array.isArray(args) || !args.length || args.length > 80 || args.some(v => typeof v !== 'string' || v.length > 8192 || v.includes('\0'))
    || args.reduce((n, s) => n + Buffer.byteLength(s), 0) > 65536) fail('backup_upload_argument_limit');
  const result = { policy: {} }, seen = new Set(); let totalBytes;
  const next = at => { if (!args[at] || args[at].startsWith('--')) fail('backup_upload_missing_value'); return args[at]; };
  for (let at = 0; at < args.length; at++) {
    const flag = args[at]; if (seen.has(flag)) fail('backup_upload_duplicate_option'); seen.add(flag);
    if (flag === '--progress-json') { result.progressJson = true; continue; }
    if (flag === '--trusted-local') { result.trustedLocal = true; continue; }
    if (flag === '--checkpoint') {
      result.checkpoint = repositoryBackupReplicationCheckpoint({ approval_sha256: next(++at), trusted_key_id: next(++at) }); continue;
    }
    if (!Object.hasOwn(FIELDS, flag) && !Object.hasOwn(POLICY, flag)
      && !['--max-archive-bytes', '--max-total-bytes', '--timeout-secs', '--expected-lfs-sha256', '--verification-instance'].includes(flag)) fail('backup_upload_unknown_option');
    const value = next(++at);
    if (Object.hasOwn(FIELDS, flag)) result[FIELDS[flag]] = flag === '--fg' ? backupPath(value) : resolve(backupPath(value));
    else if (Object.hasOwn(POLICY, flag)) result.policy[POLICY[flag]] = value;
    else if (flag === '--expected-lfs-sha256') result.expectedLfsSha256 = backupLfsSha256(value);
    else if (flag === '--verification-instance') result.verificationInstance = backupDecimal(value, 9223372036854775807n);
    else if (flag === '--timeout-secs') result.timeoutMs = Number(backupDecimal(value, 3600n)) * 1000;
    else if (flag === '--max-total-bytes') totalBytes = value;
    else result.maximumBytes = Number(backupDecimal(value, BigInt(BACKUP_LIMITS.maximumArchiveBytes)));
  }
  for (const k of ['input', 'approval', 'trustKey', 'targetFile']) backupPath(result[k]);
  if ((result.lfsArchive !== undefined) !== (result.expectedLfsSha256 !== undefined)) fail('backup_lfs_pair_required');
  if (result.lfsArchive !== undefined) {
    if (result.trustedLocal !== true) fail('backup_explicit_local_operation_required');
    if (!isAbsolute(backupPath(result.fg))) fail('backup_absolute_fg_required');
    result.verificationInstance = backupDecimal(result.verificationInstance, 9223372036854775807n);
  } else if (['fg', 'verificationInstance', 'trustedLocal'].some(k => result[k] !== undefined)) fail('backup_lfs_pair_required');
  if (totalBytes !== undefined) result.maximumTotalBytes = Number(backupDecimal(totalBytes,
    BigInt(BACKUP_LIMITS.maximumArchiveBytes * (result.lfsArchive ? 6 : 3))));
  result.policy = backupPolicy(result.policy);
  backupLifetime({ maximumBytes: result.maximumBytes, timeoutMs: result.timeoutMs });
  return Object.freeze(result);
}
const write = (output, text) => new Promise((resolve, reject) => output.write(text, error => error ? reject(error) : resolve()));
export async function runUploadCommand(args, output = process.stdout, diagnostics = process.stderr, signal = undefined) {
  if (args.length === 1 && args[0] === '--help') { await write(output, UPLOAD_USAGE); return null; }
  const { targetFile, progressJson, ...options } = uploadArguments(args);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal });
  const bytes = await readBackupControl(targetFile, BACKUP_LIMITS.envelopeBytes, live, true);
  let target;
  try { target = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('backup_upload_target_file'); }
  finally { bytes.fill(0); }
  live.check();
  const result = await uploadRepositoryBackup({ ...options, target, timeoutMs: live.remaining(), signal,
    onProgress: async event => {
      if (progressJson) await write(diagnostics, JSON.stringify({ type: 'repository_backup_upload_progress', ...event }) + '\n');
      live.check();
    } });
  try { await write(output, JSON.stringify(result) + '\n'); }
  catch (error) { error.publication_state = 'complete'; error.completed_result = result; throw error; }
  return result;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  const pipe = () => { controller.abort(); process.exitCode = 1; };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { await runUploadCommand(process.argv.slice(2), process.stdout, process.stderr, controller.signal); }
  catch (error) {
    process.exitCode = 1;
    process.stderr.write(JSON.stringify({ type: 'repository_backup_upload_error', code: error.code ?? 'backup_upload_failed',
      publication_state: error.publication_state ?? 'not_started', checkpoint: error.checkpoint ?? null,
      target: error.target ?? null, http_status: error.http_status ?? null, streaming: error.streaming ?? null,
      cleanup_error: error.cleanup_error ?? null, completed_result: error.completed_result ?? null,
      ...(error.lfs_artifact ? { lfs_artifact: error.lfs_artifact } : {}),
      ...(error.verification_scratch ? { verification_scratch: error.verification_scratch } : {}),
      ...(error.approval_scratch ? { approval_scratch: error.approval_scratch } : {}) }) + '\n');
  } finally { process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop); }
}
