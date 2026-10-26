#!/usr/bin/env node
// Durable private custody, explicit resume, and independently supplied trust.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, readBackupControl } from './lib/repository-backup-io.mjs';
import { backupDecimal, backupPolicy } from './lib/repository-backup-approval.mjs';
import { MAX_BACKUP_UPLOAD_TARGETS, MAX_BACKUP_UPLOAD_TOTAL_BYTES, repositoryBackupUploadJobOptions,
  sealRepositoryBackupUploadJob, runRepositoryBackupUploadJob } from './lib/repository-backup-upload-job.mjs';

export const UPLOAD_JOB_USAGE = `Usage: node scripts/repository_backup_upload_job.mjs seal|run [OPTIONS]
Both operations require:
  --trusted-local                Use an explicitly selected private local job
  --trust-key PUBLIC_PEM          Independent Ed25519 trust key, never from job
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N     Independent floor, never weaker than sealed policy
  --target PRIVATE_JSON          Repeat for 1..16 HTTPS archive/approval destinations
Seal additionally requires:
  --job-directory DIRECTORY       Existing private directory for durable custody
  --input ARCHIVE --approval DSSE  Original signed archive and detached approval
Run additionally requires:
  --intent JOB_JSON               Exact upload-job-sha256-<digest>.json from seal
Optional:
  --ca-file CERTIFICATE_PEM        Independent TLS CA for all selected destinations
  --max-archive-bytes N            Archive ceiling, default 1 GiB, maximum 1 TiB
  --max-total-bytes N              Per-attempt aggregate archive payload allowance
  --timeout-secs N                 One deadline including controls, 1..3600
  --progress-json                  Redacted milestones on stderr; result on stdout

Each target file is private, single-link JSON with this shape:
  {"archive":{"get":"https://...","put":"https://..."},
   "approval":{"get":"https://...","put":"https://..."}}
GET and PUT must name the same logical object; signed query capabilities may
differ. Seal preserves the exact authenticated archive and approval locally,
then synchronizes an immutable intent before any remote publication is possible.
Run requires the same logical destination set. Fresh query capabilities and a
new path to the same independently trusted key are allowed; substituting an
object, checkpoint, namespace or weaker policy is refused.

Every explicit run reauthenticates retained bytes and verifies remote objects.
Targets run sequentially under one aggregate budget and deadline. The service
must implement If-None-Match:* and 100-continue. There is no automatic retry of
an uncertain PUT, overwrite or delete. Keep the job after interruption or lost
stdout; completed targets and ambiguous publication are reported separately.
Original source and approval paths are not needed after a successful seal.
This is signed offsite publication, not native archive verification, a freshness
witness, physical-durability proof or proof of independent failure domains.
`;
const fail = code => { throw backupError(code); };
const PATHS = { '--input': 'input', '--approval': 'approval', '--trust-key': 'trustKey',
  '--job-directory': 'jobDirectory', '--intent': 'intent', '--ca-file': 'caFile' };
const POLICY = { '--tenant-id': 'tenant_id', '--repository-id': 'repository_id', '--incarnation-id': 'incarnation_id',
  '--object-format': 'object_format', '--minimum-head-generation': 'minimum_head_generation' };

/** Validate all command grammar and scalar limits before opening any file. */
export function uploadJobArguments(args) {
  if (!Array.isArray(args) || !args.length || args.length > 100
    || args.some(value => typeof value !== 'string' || value.length > 8192 || value.includes('\0'))
    || args.reduce((n, value) => n + Buffer.byteLength(value), 0) > 128 * 1024) fail('backup_upload_job_argument_limit');
  const operation = args[0];
  if (!['seal', 'run'].includes(operation)) fail('backup_upload_job_operation');
  const parameters = { policy: {} }, targetFiles = [], seen = new Set(); let progressJson = false;
  const next = at => { if (!args[at] || args[at].startsWith('--')) fail('backup_upload_job_missing_value'); return args[at]; };
  for (let at = 1; at < args.length; at++) {
    const flag = args[at];
    if (flag === '--target') {
      if (targetFiles.length >= MAX_BACKUP_UPLOAD_TARGETS) fail('backup_upload_job_target_limit');
      targetFiles.push(resolve(backupPath(next(++at)))); continue;
    }
    if (seen.has(flag)) fail('backup_upload_job_duplicate_option'); seen.add(flag);
    if (flag === '--trusted-local') { parameters.trustedLocal = true; continue; }
    if (flag === '--progress-json') { progressJson = true; continue; }
    if (Object.hasOwn(PATHS, flag)) parameters[PATHS[flag]] = resolve(backupPath(next(++at)));
    else if (Object.hasOwn(POLICY, flag)) parameters.policy[POLICY[flag]] = next(++at);
    else if (flag === '--max-archive-bytes') parameters.maximumBytes = Number(backupDecimal(next(++at), BigInt(BACKUP_LIMITS.maximumArchiveBytes)));
    else if (flag === '--max-total-bytes') parameters.maximumTotalBytes = Number(backupDecimal(next(++at), BigInt(MAX_BACKUP_UPLOAD_TOTAL_BYTES)));
    else if (flag === '--timeout-secs') parameters.timeoutMs = Number(backupDecimal(next(++at), 3600n)) * 1000;
    else fail('backup_upload_job_unknown_option');
  }
  if (parameters.trustedLocal !== true) fail('backup_upload_job_trusted_local_required');
  if (!targetFiles.length || new Set(targetFiles).size !== targetFiles.length) fail('backup_upload_job_target_limit');
  parameters.policy = backupPolicy(parameters.policy); backupPath(parameters.trustKey);
  if (operation === 'seal') {
    if (parameters.intent !== undefined) fail('backup_upload_job_inapplicable_option');
    for (const field of ['jobDirectory', 'input', 'approval']) backupPath(parameters[field]);
  } else {
    if (['jobDirectory', 'input', 'approval'].some(field => parameters[field] !== undefined)) fail('backup_upload_job_inapplicable_option');
    backupPath(parameters.intent);
  }
  backupLifetime({ maximumBytes: parameters.maximumBytes, timeoutMs: parameters.timeoutMs });
  const { caFile, ...options } = parameters;
  return Object.freeze({ operation, parameters: Object.freeze(options), targetFiles: Object.freeze(targetFiles), caFile, progressJson });
}

const write = (output, value) => new Promise((resolve, reject) => output.write(value, error => error ? reject(error) : resolve()));
export async function runUploadJobCommand(args, output = process.stdout, diagnostic = process.stderr, signal = undefined) {
  if (Array.isArray(args) && args.length === 1 && args[0] === '--help') { await write(output, UPLOAD_JOB_USAGE); return null; }
  const command = uploadJobArguments(args), parameters = command.parameters;
  const live = backupLifetime({ maximumBytes: parameters.maximumBytes, timeoutMs: parameters.timeoutMs, signal });
  const targets = [];
  for (const path of command.targetFiles) {
    const bytes = await readBackupControl(path, BACKUP_LIMITS.envelopeBytes, live, true);
    let target;
    try { target = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { fail('backup_upload_job_target_file'); }
    finally { bytes.fill(0); }
    targets.push({ target, ...(command.caFile === undefined ? {} : { caFile: command.caFile }) });
  }
  live.check();
  const options = { ...parameters, targets, signal: live.signal,
    timeoutMs: live.remaining(),
    async onProgress(event) {
      if (command.progressJson) await write(diagnostic, JSON.stringify({ type: 'repository_backup_upload_job_progress', ...event }) + '\n');
      // The publication owner decides when liveness checks stop. A late abort
      // must not reinterpret a completed target or a sealed job as unpublished.
    },
  };
  repositoryBackupUploadJobOptions(options, command.operation);
  const result = await (command.operation === 'seal' ? sealRepositoryBackupUploadJob : runRepositoryBackupUploadJob)(options);
  try { await write(output, JSON.stringify(result) + '\n'); }
  catch (caught) {
    const error = caught instanceof Error ? caught : backupError('backup_upload_job_output_failed');
    error.completed_result = result; error.job = result.job; error.job_state = result.state;
    throw error;
  }
  return result;
}
export function uploadJobError(error) {
  return { type: 'repository_backup_upload_job_error', code: error.code ?? 'backup_upload_job_failed',
    state: error.upload_job?.state ?? error.job_state ?? error.publication_state ?? 'not_started',
    job: error.job ?? null, upload_job: error.upload_job ?? null,
    publication_state: error.publication_state ?? null, http_status: error.http_status ?? null,
    completed_result: error.completed_result ?? null, retained_temporary: error.retained_temporary ?? null,
    cleanup_error: error.cleanup_error ?? null, job_cleanup_error: error.job_cleanup_error ?? null };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  const pipe = () => { controller.abort(); process.exitCode = 1; };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { await runUploadJobCommand(process.argv.slice(2), process.stdout, process.stderr, controller.signal); }
  catch (error) { process.exitCode = 1; process.stderr.write(JSON.stringify(uploadJobError(error)) + '\n'); }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
