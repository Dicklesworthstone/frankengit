#!/usr/bin/env node
// Explicit candidates, independently supplied trust, no directory scan or retry.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { backupError, BACKUP_LIMITS } from './lib/repository-backup-io.mjs';
import { backupDecimal } from './lib/repository-backup-approval.mjs';
import { selectedRepositoryBackupOptions, runSelectedRepositoryBackup } from './lib/repository-backup-selected.mjs';

export const SELECTION_USAGE = `Usage: node scripts/select_repository_backup_native.mjs select|verify|restore [OPTIONS]
  --candidate ARCHIVE APPROVAL    Repeat for 1..64 explicitly selected pairs
  --trust-key PUBLIC_PEM          Independently trusted Ed25519 key
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N     Independently retained minimum checkpoint
  --max-archive-bytes N           Selected artifact ceiling (default 1 GiB)
  --timeout-secs N                Whole selection/native operation, 1..3600
Native verify/restore additionally require:
  --fg ABSOLUTE_PATH --trusted-local --verification-instance N
Restore additionally requires:
  --destination NEW_ROOT --destination-instance N --approval-record NEW_FILE
  --resume                       Match the exact existing native intent/approval

Rank signed generations before checking winner availability or expiry. A newer
unusable or ambiguous checkpoint refuses, never falls back to an older archive.
Selection is only within the supplied set, NOT proof of the newest global head.
Native checks remain required; select itself neither opens a node nor restores.
Resume never switches checkpoints or weakens the original approval policy.
`;
const FIELDS = { '--trust-key': 'trustKey', '--fg': 'fg', '--verification-instance': 'verificationInstance',
  '--destination': 'destination', '--destination-instance': 'destinationInstance', '--approval-record': 'approvalRecord' };
const POLICY = { '--tenant-id': 'tenant_id', '--repository-id': 'repository_id', '--incarnation-id': 'incarnation_id',
  '--object-format': 'object_format', '--minimum-head-generation': 'minimum_head_generation' };
const fail = code => { throw backupError(code); };
export function selectionArguments(args) {
  if (!Array.isArray(args) || !args.length || args.length > 300 || args.some(a => typeof a !== 'string' || a.length > 8192 || a.includes('\0'))
    || args.reduce((n, a) => n + Buffer.byteLength(a), 0) > 320 * 1024) fail('backup_selection_argument_limit');
  const result = { operation: args[0], candidates: [], policy: {} }, seen = new Set();
  const next = index => { const v = args[index]; if (!v || v.startsWith('--')) fail('backup_missing_option_value'); return v; };
  for (let at = 1; at < args.length; at++) {
    const flag = args[at];
    if (flag === '--candidate') {
      if (result.candidates.length === 64) fail('backup_candidate_limit');
      const input = next(++at), approval = next(++at); result.candidates.push({ input, approval }); continue;
    }
    if (seen.has(flag)) fail('backup_duplicate_option'); seen.add(flag);
    if (flag === '--trusted-local') { result.trustedLocal = true; continue; }
    if (flag === '--resume') { result.resume = true; continue; }
    if (!Object.hasOwn(FIELDS, flag) && !Object.hasOwn(POLICY, flag) && !['--max-archive-bytes', '--timeout-secs'].includes(flag)) fail('backup_unknown_option');
    const value = next(++at);
    if (Object.hasOwn(FIELDS, flag)) result[FIELDS[flag]] = value;
    else if (Object.hasOwn(POLICY, flag)) result.policy[POLICY[flag]] = value;
    else if (flag === '--timeout-secs') result.timeoutMs = Number(backupDecimal(value, 3600n)) * 1000;
    else result.maximumBytes = Number(backupDecimal(value, BigInt(BACKUP_LIMITS.maximumArchiveBytes)));
  }
  selectedRepositoryBackupOptions(result); // Complete validation before any I/O.
  return result;
}
export async function runSelectionCommand(args, output = process.stdout, signal = undefined) {
  let result = null;
  const text = args.length === 1 && args[0] === '--help' ? SELECTION_USAGE
    : JSON.stringify(result = await runSelectedRepositoryBackup({ ...selectionArguments(args), signal })) + '\n';
  try { await new Promise((resolve, reject) => output.write(text, error => error ? reject(error) : resolve())); }
  catch (error) { error.state = result?.state ?? (result ? 'selection_complete' : 'not_started'); error.completed_result = result; throw error; }
  return result;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  const pipe = () => { controller.abort(); process.exitCode = 1; };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { await runSelectionCommand(process.argv.slice(2), process.stdout, controller.signal); }
  catch (error) {
    process.exitCode = 1;
    process.stderr.write(JSON.stringify({ type: 'repository_backup_selection_error', code: error.code ?? 'backup_selection_failed',
      state: error.state ?? 'not_started', selected: error.selection?.selected ?? null,
      approval_record: error.approval_record ?? null, verification_scratch: error.verification_scratch ?? null,
      completed_result: error.completed_result ?? null }) + '\n');
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
