#!/usr/bin/env node
// Explicit immutable job selection. Never discover a latest job or reset intent.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath } from './lib/repository-backup-io.mjs';
import { backupDecimal, backupPolicy } from './lib/repository-backup-approval.mjs';
import { repositoryBackupReplenishmentOptions, MAX_REPLENISHMENT_READ_BYTES } from './lib/repository-backup-replenishment.mjs';
import { sealRepositoryBackupJob, runRepositoryBackupJob } from './lib/repository-backup-job.mjs';
import { withRepositoryBackupWitness } from './lib/repository-backup-witness.mjs';

export const JOB_USAGE = `Usage: node scripts/repository_backup_job.mjs seal|run [OPTIONS]
Both operations require:
  --trusted-local                Execute only an explicitly trusted local intent
  --trust-key PUBLIC_PEM          Independent Ed25519 trust key, never read from job
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N     Independent floor, not weaker than sealed policy
Seal additionally requires:
  --job-directory DIRECTORY       Existing private directory, separate from replicas
  --candidate ARCHIVE APPROVAL    Repeat for explicit signed source candidates
  --replica-directory DIRECTORY   Repeat for 1..16 existing private destinations
Run additionally requires:
  --intent JOB_JSON               Exact job-sha256-<digest>.json returned by seal
Optional:
  --witness DIRECTORY             Existing independent witness; mandatory if sealed
  --max-archive-bytes N           Per-archive ceiling, default 1 GiB, maximum 1 TiB
  --max-total-read-bytes N         Per-attempt aggregate payload work, at most 128 TiB
  --timeout-secs N                One operation/witness deadline, 1..3600
  --progress-json                 Bounded milestones on stderr; result on stdout

Seal preserves the original approval and immutable intent before any copying.
Run reauthenticates current bytes from only the sealed source/target paths and
hands off to verified completed replicas. It may survive loss of the original
source and stdout; it never trusts a saved completion flag or changes checkpoints.
Run cannot override destinations, source paths, approval bytes or a required
witness. Missing/corrupt intent, changed target identities and conflicts refuse.
A job is trusted-local operator intent, NOT native archive verification, global
freshness, canonical repair or a new authorization source. No signing key is used.
Witness leases remain blocking after a killed owner; no automatic lock breaking.
`;
const fail = code => { throw backupError(code); };
const POLICY = { '--tenant-id': 'tenant_id', '--repository-id': 'repository_id', '--incarnation-id': 'incarnation_id',
  '--object-format': 'object_format', '--minimum-head-generation': 'minimum_head_generation' };
const PATHS = { '--job-directory': 'jobDirectory', '--intent': 'intent', '--trust-key': 'trustKey', '--witness': 'witness' };
export function jobArguments(args) {
  if (!Array.isArray(args) || !args.length || args.length > 350
    || args.some(v => typeof v !== 'string' || v.length > 8192 || v.includes('\0'))
    || args.reduce((size, v) => size + Buffer.byteLength(v), 0) > 320 * 1024) fail('backup_job_argument_limit');
  const operation = args[0]; if (!['seal', 'run'].includes(operation)) fail('backup_job_operation');
  const value = { policy: {} }, seen = new Set(); let trustedLocal = false, progressJson = false;
  const next = index => { const v = args[index]; if (!v || v.startsWith('--')) fail('backup_missing_option_value'); return v; };
  for (let at = 1; at < args.length; at++) {
    const flag = args[at];
    if (flag === '--candidate' || flag === '--replica-directory') {
      if (operation !== 'seal') fail('backup_job_inapplicable_option');
      if (flag === '--candidate') {
        value.candidates ??= [];
        if (value.candidates.length === 64) fail('backup_candidate_limit');
        const input = next(++at), approval = next(++at); value.candidates.push({ input, approval });
      } else {
        value.destinations ??= [];
        if (value.destinations.length === 16) fail('backup_replenishment_destination_limit');
        value.destinations.push(next(++at));
      }
      continue;
    }
    if (seen.has(flag)) fail('backup_duplicate_option'); seen.add(flag);
    if (flag === '--trusted-local') { trustedLocal = true; continue; }
    if (flag === '--progress-json') { progressJson = true; continue; }
    if (Object.hasOwn(POLICY, flag)) value.policy[POLICY[flag]] = next(++at);
    else if (Object.hasOwn(PATHS, flag)) value[PATHS[flag]] = resolve(backupPath(next(++at)));
    else if (flag === '--max-archive-bytes') value.maximumBytes = Number(backupDecimal(next(++at), BigInt(BACKUP_LIMITS.maximumArchiveBytes)));
    else if (flag === '--max-total-read-bytes') value.maximumTotalBytes = Number(backupDecimal(next(++at), BigInt(MAX_REPLENISHMENT_READ_BYTES)));
    else if (flag === '--timeout-secs') value.timeoutMs = Number(backupDecimal(next(++at), 3600n)) * 1000;
    else fail('backup_unknown_option');
  }
  if (!trustedLocal) fail('backup_job_trusted_local_required');
  value.policy = backupPolicy(value.policy); backupPath(value.trustKey);
  const { witness, ...parameters } = value;
  if (operation === 'seal') {
    if (Object.hasOwn(parameters, 'intent')) fail('backup_job_inapplicable_option');
    backupPath(parameters.jobDirectory);
    const { jobDirectory, ...copyOptions } = parameters; repositoryBackupReplenishmentOptions(copyOptions);
  } else {
    if (Object.hasOwn(parameters, 'jobDirectory')) fail('backup_job_inapplicable_option');
    backupPath(parameters.intent);
    backupLifetime({ maximumBytes: parameters.maximumBytes, timeoutMs: parameters.timeoutMs });
  }
  return Object.freeze({ operation, parameters: Object.freeze(parameters), witness, progressJson });
}
async function write(output, text) {
  await new Promise((resolve, reject) => output.write(text, error => error ? reject(error) : resolve()));
}
export async function runJobCommand(args, output = process.stdout, diagnostic = process.stderr, signal = undefined) {
  let result = null;
  if (Array.isArray(args) && args.length === 1 && args[0] === '--help') { await write(output, JOB_USAGE); return null; }
  const command = jobArguments(args), p = command.parameters;
  const live = backupLifetime({ maximumBytes: p.maximumBytes, timeoutMs: p.timeoutMs, signal });
  const perform = witness => (command.operation === 'seal' ? sealRepositoryBackupJob : runRepositoryBackupJob)({ ...p,
    timeoutMs: live.remaining(), signal: live.signal,
    async onProgress(event) {
      if (command.progressJson && ['job_sealed', 'checkpoint_pinned', 'replica_complete'].includes(event.phase)) {
        await write(diagnostic, JSON.stringify({ type: 'repository_backup_job_progress', ...event }) + '\n');
      }
    },
  }, witness);
  result = command.witness
    ? await withRepositoryBackupWitness(command.witness, p.trustKey, p.policy,
      { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal }, perform)
    : await perform(null);
  try { await write(output, JSON.stringify(result) + '\n'); }
  catch (caught) {
    const error = caught instanceof Error ? caught : backupError('backup_job_output_failed');
    error.completed_result = result; error.job = result.job ?? result; error.job_state = result.state; throw error;
  }
  return result;
}
export function jobError(error) {
  return { type: 'repository_backup_job_error', code: error.code ?? 'backup_job_failed',
    state: error.job_state ?? error.replenishment?.state ?? error.state ?? 'not_started', job: error.job ?? null,
    replenishment: error.replenishment ?? null, publication_state: error.publication_state ?? null, replica: error.replica ?? null,
    completed_result: error.completed_result ?? null, retained_temporary: error.retained_temporary ?? null,
    cleanup_error: error.cleanup_error ?? null, job_cleanup_error: error.job_cleanup_error ?? null,
    replenishment_cleanup_error: error.replenishment_cleanup_error ?? null,
    witness: error.witness ?? null, witness_lock_retained: error.witness_lock_retained ?? false,
    witness_cleanup_error: error.witness_cleanup_error ?? null, witness_publication_state: error.witness_publication_state ?? null };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  const pipe = () => { controller.abort(); process.exitCode = 1; };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { await runJobCommand(process.argv.slice(2), process.stdout, process.stderr, controller.signal); }
  catch (error) { process.exitCode = 1; process.stderr.write(JSON.stringify(jobError(error)) + '\n'); }
  finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
