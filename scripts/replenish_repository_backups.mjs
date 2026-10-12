#!/usr/bin/env node
// Explicit locations only. No discovery, overwrite, re-signing or native repair.
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BACKUP_LIMITS, backupError, backupPath, backupLifetime } from './lib/repository-backup-io.mjs';
import { backupDecimal } from './lib/repository-backup-approval.mjs';
import { repositoryBackupReplenishmentOptions, replenishRepositoryBackups,
  MAX_REPLENISHMENT_READ_BYTES } from './lib/repository-backup-replenishment.mjs';
import { withRepositoryBackupWitness } from './lib/repository-backup-witness.mjs';

export const REPLENISHMENT_USAGE = `Usage: node scripts/replenish_repository_backups.mjs [OPTIONS]
  --candidate ARCHIVE APPROVAL    Repeat for 1..64 explicit signed source pairs
  --replica-directory DIRECTORY   Repeat for 1..16 EXISTING private directories
  --trust-key PUBLIC_PEM          Independent Ed25519 public key, never a signer
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N     Independent minimum acceptable generation
  --checkpoint APPROVAL_SHA KEY_ID  Pin an earlier result for exact restart
  --witness DIRECTORY             Existing independently retained checkpoint witness
  --max-archive-bytes N           Per-file ceiling, default 1 GiB, maximum 1 TiB
  --max-total-read-bytes N        ALL selection/copy/readback/scrub payload reads
                                 Default (1 + 4 x destinations) x archive ceiling
                                 Maximum 128 TiB; never enlarges a single archive
  --timeout-secs N                One whole-operation deadline, 1..3600
  --progress-json                At most 17 milestone JSON lines on stderr

Select one highest uniquely signed checkpoint, pin its exact approval/key bytes,
replenish all explicit locations create-only, then scrub the entire output set.
Healthy files are reused and synchronized. Conflicts refuse without overwriting
or deleting them. Choose fresh private locations to replace known corrupt copies.
The original selected source must remain available until copying has finished.
Success exits 0. Failure exits 1 and may retain valid published copies: inspect
replenishment.completed_replicas, active publication state and checkpoint pins.
Repeat with --checkpoint from the original result/partial receipt; this is not
an atomic job, and absence of a response never proves absence of publication.
With --witness, hold its exclusive lease through all copies, scrub and cleanup.
Missing/corrupt state and killed-owner leases refuse; no automatic reset or steal.
Initialize witnesses separately with scripts/repository_backup_witness.mjs init.
Distinct files are NOT independent failure domains. Native verification remains
mandatory before restore. This command never restores or publishes a repository.
`;
const fail = code => { throw backupError(code); };
const overlaps = (a, b) => a === b || a.startsWith(b + sep) || b.startsWith(a + sep);
const POLICY = { '--tenant-id': 'tenant_id', '--repository-id': 'repository_id',
  '--incarnation-id': 'incarnation_id', '--object-format': 'object_format',
  '--minimum-head-generation': 'minimum_head_generation' };

export function replenishmentArguments(args) {
  if (!Array.isArray(args) || args.length > 350 || args.some(a => typeof a !== 'string' || a.length > 8192 || a.includes('\0'))
    || args.reduce((n, a) => n + Buffer.byteLength(a), 0) > 320 * 1024) fail('backup_replenishment_argument_limit');
  const raw = { candidates: [], destinations: [], policy: {} }, seen = new Set();
  let witness, progressJson = false;
  const next = index => { const v = args[index]; if (!v || v.startsWith('--')) fail('backup_missing_option_value'); return v; };
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (flag === '--candidate') {
      if (raw.candidates.length === 64) fail('backup_candidate_limit');
      raw.candidates.push({ input: next(++i), approval: next(++i) }); continue;
    }
    if (flag === '--replica-directory') {
      if (raw.destinations.length === 16) fail('backup_replenishment_destination_limit');
      raw.destinations.push(next(++i)); continue;
    }
    if (seen.has(flag)) fail('backup_duplicate_option'); seen.add(flag);
    if (flag === '--progress-json') { progressJson = true; continue; }
    if (flag === '--checkpoint') { raw.checkpoint = { approval_sha256: next(++i), trusted_key_id: next(++i) }; continue; }
    if (Object.hasOwn(POLICY, flag)) raw.policy[POLICY[flag]] = next(++i);
    else if (flag === '--trust-key') raw.trustKey = next(++i);
    else if (flag === '--witness') { witness = resolve(backupPath(next(++i))); backupPath(witness); }
    else if (flag === '--max-archive-bytes') raw.maximumBytes = Number(backupDecimal(next(++i), BigInt(BACKUP_LIMITS.maximumArchiveBytes)));
    else if (flag === '--max-total-read-bytes') raw.maximumTotalBytes = Number(backupDecimal(next(++i), BigInt(MAX_REPLENISHMENT_READ_BYTES)));
    else if (flag === '--timeout-secs') raw.timeoutMs = Number(backupDecimal(next(++i), 3600n)) * 1000;
    else fail('backup_unknown_option');
  }
  const options = repositoryBackupReplenishmentOptions(raw);
  if (witness && [options.trustKey, ...options.destinations, ...options.candidates.flatMap(r => [r.input, r.approval])]
    .some(path => overlaps(path, witness))) fail('backup_witness_separate_path_required');
  return Object.freeze({ options, witness, progressJson });
}
const write = (output, text) => new Promise((resolve, reject) => output.write(text, error => error ? reject(error) : resolve()));

export async function runReplenishmentCommand(args, output = process.stdout, signal = undefined, progressOutput = process.stderr) {
  let result;
  if (Array.isArray(args) && args.length === 1 && args[0] === '--help') {
    await write(output, REPLENISHMENT_USAGE); return null;
  }
  const { options, witness, progressJson } = replenishmentArguments(args);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal });
  const perform = lease => replenishRepositoryBackups({ ...options, signal, timeoutMs: live.remaining(),
    async onProgress(event) {
      if (progressJson && ['checkpoint_pinned', 'replica_complete'].includes(event.phase)) {
        await write(progressOutput, JSON.stringify({ type: 'repository_backup_replenishment_progress',
          phase: event.phase, checkpoint: event.checkpoint ?? null, candidate: event.candidate ?? null,
          completed_destinations: event.completed_destinations, active_destination: event.active_destination }) + '\n');
      }
      live.check();
    } }, lease);
  if (witness) result = await withRepositoryBackupWitness(witness, options.trustKey, options.policy,
    { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal }, perform);
  else result = await perform(null);
  // The result and any witness lease cleanup have completed. A failed output
  // stream must retain that result, not reinterpret it as no publication.
  try { await write(output, JSON.stringify(result) + '\n'); }
  catch (caught) {
    const error = caught instanceof Error ? caught : backupError('backup_replenishment_output_failed');
    error.replenishment = result; error.completed_result = result; throw error;
  }
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  const pipe = () => { controller.abort(); process.exitCode = 1; };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { await runReplenishmentCommand(process.argv.slice(2), process.stdout, controller.signal); }
  catch (error) {
    process.exitCode = 1;
    process.stderr.write(JSON.stringify({ type: 'repository_backup_replenishment_error', code: error.code ?? 'backup_replenishment_failed',
      replenishment: error.replenishment ?? null, publication_state: error.publication_state ?? null,
      replica: error.replica ?? null, completed_result: error.completed_result ?? null,
      cleanup_error: error.cleanup_error ?? error.replenishment_cleanup_error ?? null,
      retained_temporary: error.retained_temporary ?? null,
      witness: error.witness ?? null, witness_lock_retained: error.witness_lock_retained ?? false,
      witness_cleanup_error: error.witness_cleanup_error ?? null,
      witness_publication_state: error.witness_publication_state ?? null }) + '\n');
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
