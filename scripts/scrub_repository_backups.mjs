#!/usr/bin/env node
// Current-checkpoint byte health, never native restore, repair or deletion.
import { resolve, dirname, basename, join, sep } from 'node:path';
import { realpath } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { BACKUP_LIMITS, backupError, backupPath, backupLifetime } from './lib/repository-backup-io.mjs';
import { backupDecimal, backupPolicy } from './lib/repository-backup-approval.mjs';
import { MAX_BACKUP_CANDIDATES, repositoryBackupCandidates, scrubRepositoryBackups } from './lib/repository-backup-selection.mjs';
import { withRepositoryBackupWitness } from './lib/repository-backup-witness.mjs';

export const SCRUB_USAGE = `Usage: node scripts/scrub_repository_backups.mjs [OPTIONS]
  --candidate ARCHIVE APPROVAL    Repeat for 1..64 explicit signed candidate pairs
  --trust-key PUBLIC_PEM          Independently trusted Ed25519 public key
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N     Independently retained checkpoint floor
  --minimum-distinct-files N      Required verified device/inode pairs (default 1)
  --max-archive-bytes N           Independent per-archive ceiling (default 1 GiB)
  --max-replica-bytes N           Aggregate payload reads (default archive ceiling)
  --timeout-secs N                Whole operation, 1..3600
  --witness DIRECTORY            EXISTING independently retained recovery witness

Verify ALL copies of the highest uniquely signed supplied checkpoint, not just
its first healthy copy. Signed older checkpoints are not scrubbed or substituted.
A complete report lists authenticated/unavailable copies and deduplicates inode
aliases. Distinct files do NOT prove independent failure domains or simultaneous
availability. Every read remains bounded; larger read budgets never widen files.

Exit 0: all copies authenticated and minimum distinct-file count met.
Exit 2: complete scrub, but degraded copies or insufficient distinct files.
Exit 1: incomplete/refused operation, including invalid trust, budget or timeout.
Both 0 and 2 produce the complete JSON report on stdout. Errors go to stderr.
A broken result pipe retains completed_result; it does not erase witness evidence.

No archive modification, repair, signer, native process or routing publication.
Without --witness, this is read-only and cannot remember omitted newer evidence.
With --witness, hold the existing exclusive lease and retain signed observations
before byte checks; missing/corrupt state and crash-held leases refuse, not reset.
Initialize separately with scripts/repository_backup_witness.mjs init.
A scrub is NOT native archive validation, full recovery, or newest-head proof.
`;
const fail = code => { throw backupError(code); };
const overlap = (a, b) => a === b || a.startsWith(b + sep) || b.startsWith(a + sep);
const fields = { '--trust-key': 'trustKey', '--witness': 'witness' };
const policyFields = { '--tenant-id': 'tenant_id', '--repository-id': 'repository_id', '--incarnation-id': 'incarnation_id',
  '--object-format': 'object_format', '--minimum-head-generation': 'minimum_head_generation' };
const numbers = { '--minimum-distinct-files': ['minimumDistinctFiles', 64n, 1],
  '--max-archive-bytes': ['maximumBytes', BigInt(BACKUP_LIMITS.maximumArchiveBytes), 1],
  '--max-replica-bytes': ['maximumReplicaBytes', BigInt(BACKUP_LIMITS.maximumArchiveBytes * MAX_BACKUP_CANDIDATES), 1],
  '--timeout-secs': ['timeoutMs', 3600n, 1000] };

export function scrubOptions(value) {
  const allowed = ['candidates', 'trustKey', 'policy', 'witness', 'minimumDistinctFiles', 'maximumBytes', 'maximumReplicaBytes', 'timeoutMs', 'signal', 'now', 'onProgress'];
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !allowed.includes(k))) fail('backup_invalid_scrub_options');
  const options = { ...value, candidates: repositoryBackupCandidates(value.candidates), policy: backupPolicy(value.policy),
    trustKey: resolve(backupPath(value.trustKey)), minimumDistinctFiles: value.minimumDistinctFiles ?? 1 };
  backupPath(options.trustKey);
  if (!Number.isSafeInteger(options.minimumDistinctFiles) || options.minimumDistinctFiles < 1 || options.minimumDistinctFiles > 64) fail('backup_invalid_scrub_options');
  const live = backupLifetime({ maximumBytes: value.maximumBytes, timeoutMs: value.timeoutMs, signal: value.signal, now: value.now, onProgress: value.onProgress });
  const budget = options.maximumReplicaBytes ?? live.maximumBytes;
  if (!Number.isSafeInteger(budget) || budget < 1 || budget > BACKUP_LIMITS.maximumArchiveBytes * MAX_BACKUP_CANDIDATES) fail('backup_invalid_scrub_options');
  if (value.witness !== undefined) {
    options.witness = resolve(backupPath(value.witness)); backupPath(options.witness);
    if ([options.trustKey, ...options.candidates.flatMap(r => [r.input, r.approval])].some(p => overlap(p, options.witness))) fail('backup_witness_separate_path_required');
  }
  return Object.freeze(options);
}
export function scrubArguments(args) {
  if (!Array.isArray(args) || args.length > 300 || args.some(a => typeof a !== 'string' || a.length > 8192 || a.includes('\0'))
    || args.reduce((n, a) => n + Buffer.byteLength(a), 0) > 320 * 1024) fail('backup_scrub_argument_limit');
  const options = { candidates: [], policy: {} }, seen = new Set();
  const next = index => { const v = args[index]; if (!v || v.startsWith('--')) fail('backup_missing_option_value'); return v; };
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--candidate') {
      if (options.candidates.length === MAX_BACKUP_CANDIDATES) fail('backup_candidate_limit');
      const input = next(++i), approval = next(++i); options.candidates.push({ input, approval }); continue;
    }
    if (seen.has(flag)) fail('backup_duplicate_option'); seen.add(flag);
    if (!Object.hasOwn(fields, flag) && !Object.hasOwn(policyFields, flag) && !Object.hasOwn(numbers, flag)) fail('backup_unknown_option');
    const value = next(++i);
    if (Object.hasOwn(fields, flag)) options[fields[flag]] = value;
    else if (Object.hasOwn(policyFields, flag)) options.policy[policyFields[flag]] = value;
    else { const [key, max, scale] = numbers[flag]; options[key] = Number(backupDecimal(value, max)) * scale; }
  }
  return scrubOptions(options);
}

// Resolve metadata aliases without opening archive payloads. Missing ancestors
// are allowed: an absent lower archive must not prevent checking the newer root.
async function physicalPath(path, live) {
  const suffix = []; let at = path;
  for (;;) {
    live.check();
    try { return join(await realpath(at), ...suffix); }
    catch (e) {
      if (!['ENOENT', 'ENOTDIR'].includes(e.code) || dirname(at) === at) throw e;
      suffix.unshift(basename(at)); at = dirname(at);
    }
  }
}
export async function runRepositoryBackupScrub(raw) {
  const options = scrubOptions(raw);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs,
    signal: options.signal, now: options.now, onProgress: options.onProgress });
  const perform = async witness => {
    const separated = async () => {
      if (!witness) return;
      const directory = witness.snapshot().directory;
      for (const path of [options.trustKey, ...options.candidates.flatMap(r => [r.input, r.approval])]) {
        if (overlap(await physicalPath(path, live), directory)) fail('backup_witness_separate_path_required');
      }
      live.check();
    };
    await separated();
    const result = await scrubRepositoryBackups(options.candidates, options.trustKey, options.policy, {
      maximumBytes: live.maximumBytes, maximumReplicaBytes: options.maximumReplicaBytes,
      timeoutMs: live.remaining(), signal: live.signal, ...(options.now === undefined ? {} : { now: options.now }),
      async onProgress(event) { await live.onProgress(event); live.check(); if (event.phase) await separated(); },
    }, witness);
    await separated(); result.checkCurrent();
    return Object.freeze({ ...result.report, minimum_distinct_files: options.minimumDistinctFiles,
      healthy: result.report.all_replicas_authenticated && result.report.distinct_authenticated_files >= options.minimumDistinctFiles });
  };
  if (!options.witness) return perform(null);
  return withRepositoryBackupWitness(options.witness, options.trustKey, options.policy,
    { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal, now: options.now }, perform);
}
export async function runScrubCommand(args, output = process.stdout, signal = undefined) {
  let report = null;
  const text = args.length === 1 && args[0] === '--help' ? SCRUB_USAGE
    : JSON.stringify(report = await runRepositoryBackupScrub({ ...scrubArguments(args), signal })) + '\n';
  try { await new Promise((resolve, reject) => output.write(text, error => error ? reject(error) : resolve())); }
  catch (caught) {
    const error = caught instanceof Error ? caught : backupError('backup_scrub_output_failed');
    error.completed_result = report; throw error;
  }
  return report;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  const pipe = () => { controller.abort(); process.exitCode = 1; };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { const result = await runScrubCommand(process.argv.slice(2), process.stdout, controller.signal);
    if (result && !result.healthy && !process.exitCode) process.exitCode = 2;
  } catch (error) {
    process.exitCode = 1;
    process.stderr.write(JSON.stringify({ type: 'repository_backup_scrub_error', code: error.code ?? 'backup_scrub_failed',
      scrub_complete: false, selected_head_generation: error.selected_head_generation ?? null,
      replica_attempts: error.replica_attempts ?? [], replica_bytes_read: error.replica_bytes_read ?? null,
      active_replica: error.active_replica ?? null, witness: error.witness ?? null,
      witness_lock_retained: error.witness_lock_retained ?? false, witness_cleanup_error: error.witness_cleanup_error ?? null,
      witness_publication_state: error.witness_publication_state ?? null, completed_result: error.completed_result ?? null }) + '\n');
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
