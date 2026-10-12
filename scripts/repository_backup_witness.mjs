#!/usr/bin/env node
// Explicit bootstrap/inspection and witnessed source-backup selection.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { backupError, backupLifetime, backupPath } from './lib/repository-backup-io.mjs';
import { backupPolicy, backupDecimal } from './lib/repository-backup-approval.mjs';
import { initializeRepositoryBackupWitness, withRepositoryBackupWitness } from './lib/repository-backup-witness.mjs';
import { selectRepositoryBackup, repositoryBackupCandidates } from './lib/repository-backup-selection.mjs';

export const WITNESS_USAGE = `Usage: node scripts/repository_backup_witness.mjs init|inspect|select DIRECTORY
  --trust-key PUBLIC_PEM --tenant-id HEX --repository-id HEX --incarnation-id HEX
  --object-format sha1|sha256 --minimum-head-generation POSITIVE_U64
  --candidate ARCHIVE APPROVAL       Repeat for select only, 1..64 pairs
  --timeout-secs N                   Whole operation, 1..3600 (default 300)

init creates a NEW owner-private directory under an existing private parent.
Keep this directory independently of the repository and backup artifacts.
inspect reauthenticates retained signatures; select remembers every authenticated
higher checkpoint before checking expiry or artifact availability. Conflicting
maximum-generation statements remain blocking across restarts. Neither command
restores repository state or proves global newest-checkpoint completeness.
A stronger supplied generation floor is retained; a weaker one is refused.
All operations refuse existing leases immediately. Process death leaves the
lease: never remove it until every associated native process is independently
confirmed stopped. No automatic reset, key rotation, rollback or lock breaking.
`;
const POLICY_FIELDS = { '--tenant-id': 'tenant_id', '--repository-id': 'repository_id', '--incarnation-id': 'incarnation_id',
  '--object-format': 'object_format', '--minimum-head-generation': 'minimum_head_generation' };
const fail = code => { throw backupError(code); };
export function witnessArguments(args) {
  if (!Array.isArray(args) || args.length < 2 || args.length > 300
    || args.some(a => typeof a !== 'string' || Buffer.byteLength(a) > 8192 || a.includes('\0'))
    || args.reduce((n, a) => n + Buffer.byteLength(a), 0) > 320 * 1024) fail('backup_witness_argument_limit');
  const operation = args[0], directory = resolve(backupPath(args[1]));
  if (!['init', 'inspect', 'select'].includes(operation)) fail('backup_witness_invalid_operation');
  let trustKey, timeoutMs = 300000; const policy = {}, candidates = [], seen = new Set();
  const value = at => { if (!args[at] || args[at].startsWith('--')) fail('backup_missing_option_value'); return args[at]; };
  for (let at = 2; at < args.length; at++) {
    const flag = args[at];
    if (flag === '--candidate') {
      if (operation !== 'select' || candidates.length === 64) fail('backup_witness_inapplicable_candidate');
      candidates.push({ input: value(++at), approval: value(++at) }); continue;
    }
    if (seen.has(flag)) fail('backup_duplicate_option'); seen.add(flag);
    if (flag === '--trust-key') trustKey = resolve(backupPath(value(++at)));
    else if (flag === '--timeout-secs') timeoutMs = Number(backupDecimal(value(++at), 3600n)) * 1000;
    else if (Object.hasOwn(POLICY_FIELDS, flag)) policy[POLICY_FIELDS[flag]] = value(++at);
    else fail('backup_unknown_option');
  }
  backupPath(trustKey);
  return { operation, directory, trustKey, policy: backupPolicy(policy), timeoutMs,
    candidates: operation === 'select' ? repositoryBackupCandidates(candidates) : [] };
}
export async function runWitnessCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return WITNESS_USAGE;
  const options = witnessArguments(args), live = backupLifetime({ timeoutMs: options.timeoutMs, signal });
  const lifetime = () => ({ timeoutMs: live.remaining(), signal });
  if (options.operation === 'init') return initializeRepositoryBackupWitness(options.directory, options.trustKey, options.policy, lifetime());
  return withRepositoryBackupWitness(options.directory, options.trustKey, options.policy, lifetime(), async witness => {
    if (options.operation === 'inspect') return { type: 'repository_backup_witness_inspection', witness: witness.snapshot(), repository_changed: false };
    return (await selectRepositoryBackup(options.candidates, options.trustKey, options.policy, lifetime(), witness)).report;
  });
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  const pipe = () => { stop(); process.exitCode = 1; };
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  let result;
  try {
    result = await runWitnessCommand(process.argv.slice(2), controller.signal);
    const text = typeof result === 'string' ? result : JSON.stringify(result) + '\n';
    await new Promise((yes, no) => process.stdout.write(text, e => e ? no(e) : yes()));
  } catch (error) {
    process.exitCode = 1;
    process.stderr.write(JSON.stringify({ type: 'repository_backup_witness_error', code: error.code ?? 'backup_witness_failed',
      witness: error.witness ?? null, witness_directory: error.witness_directory ?? null,
      witness_cleanup_error: error.witness_cleanup_error ?? null, witness_lock_retained: error.witness_lock_retained ?? false,
      completed_result: result ?? error.completed_result ?? null, repository_changed: false }) + '\n');
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
