#!/usr/bin/env node
// Publish another signed byte replica. Native verification is still mandatory
// when consuming it; this operator command never launches a restore or signer.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { backupError, BACKUP_LIMITS } from './lib/repository-backup-io.mjs';
import { backupDecimal } from './lib/repository-backup-approval.mjs';
import { repositoryBackupReplicationOptions, replicateRepositoryBackup } from './lib/repository-backup-replication.mjs';
import { selectionArguments } from './select_repository_backup_native.mjs';

export const REPLICATION_USAGE = `Usage: node scripts/replicate_repository_backup_native.mjs [OPTIONS]
  --candidate ARCHIVE APPROVAL    Repeat for 1..64 explicit signed candidate pairs
  --trust-key PUBLIC_PEM          Independently retained Ed25519 public key
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N     Independently retained minimum checkpoint
  --replica-directory DIRECTORY   EXISTING owner-private local directory (0700)
  --max-archive-bytes N           Per-archive size ceiling (default 1 GiB)
  --max-total-read-bytes N        Selection + copy + readback budget
                                 (default 4 x archive ceiling; maximum 4 TiB)
  --timeout-secs N                Whole operation, 1..3600

Stream the highest uniquely signed supplied checkpoint; never select an older
checkpoint after a failure. Publish its exact approval only after the archive's
signed digest/length, readback, file sync and directory sync. Names bind exact
content; publication is create-only. Exact retries reuse and synchronize files.
No signing key, unsigned bypass, mutable latest pointer, or automatic deletion.
A failed publication may leave a valid unadvertised body; retry the same command.
The JSON candidate can be passed to select_repository_backup_native.mjs using
--candidate <candidate.input> <candidate.approval>, then native verify/restore.
This is trusted-local POSIX copying, NOT native validation, a restored repository,
a complete capsule, or proof of the newest global checkpoint.
`;
const fail = code => { throw backupError(code); };

export function replicationArguments(args) {
  if (!Array.isArray(args) || args.length > 300
    || args.some(a => typeof a !== 'string' || a.length > 8192 || a.includes('\0'))
    || args.reduce((n, a) => n + Buffer.byteLength(a), 0) > 320 * 1024) fail('backup_replication_argument_limit');
  const rest = [], seen = new Set(); let destination, maximumTotalBytes;
  // Reuse the already strict select-only policy/candidate grammar. Native
  // destination, signer, resume and process options are deliberately inapplicable.
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (!['--replica-directory', '--max-total-read-bytes'].includes(flag)) { rest.push(flag); continue; }
    if (seen.has(flag)) fail('backup_duplicate_option'); seen.add(flag);
    const value = args[++index];
    if (!value || value.startsWith('--')) fail('backup_missing_option_value');
    if (flag === '--replica-directory') destination = value;
    else maximumTotalBytes = Number(backupDecimal(value, BigInt(BACKUP_LIMITS.maximumArchiveBytes * 4)));
  }
  const { operation, ...selected } = selectionArguments(['select', ...rest]);
  return repositoryBackupReplicationOptions({ ...selected, destination, maximumTotalBytes });
}

export async function runReplicationCommand(args, output = process.stdout, signal = undefined) {
  let result;
  const text = args.length === 1 && args[0] === '--help' ? REPLICATION_USAGE
    : JSON.stringify(result = await replicateRepositoryBackup({ ...replicationArguments(args), signal })) + '\n';
  try {
    await new Promise((resolve, reject) => output.write(text, error => error ? reject(error) : resolve()));
  } catch (caught) {
    const error = caught instanceof Error ? caught : backupError('backup_replication_output_failed');
    error.publication_state = result?.state ?? 'not_started';
    error.replica = result?.candidate ?? null; error.completed_result = result ?? null;
    throw error;
  }
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController(), stop = () => controller.abort();
  const pipe = () => { controller.abort(); process.exitCode = 1; };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  process.stdout.on('error', pipe); process.stderr.on('error', pipe);
  try { await runReplicationCommand(process.argv.slice(2), process.stdout, controller.signal); }
  catch (error) {
    process.exitCode = 1;
    process.stderr.write(JSON.stringify({ type: 'repository_backup_replication_error',
      code: error.code ?? 'backup_replication_failed', publication_state: error.publication_state ?? 'not_started',
      replica: error.replica ?? null, cleanup_error: error.cleanup_error ?? null,
      retained_temporary: error.retained_temporary ?? null, completed_result: error.completed_result ?? null }) + '\n');
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
