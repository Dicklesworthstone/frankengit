#!/usr/bin/env node
// Publish another signed byte replica. Optional paired LFS publication first
// runs native signed verification; this command never restores or signs.
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
Optional exact LFS pair (all required together):
  --lfs-archive FILE --expected-lfs-sha256 HEX
  --fg ABSOLUTE_PATH --trusted-local --verification-instance N
Paired mode runs signed native source+companion verification before publication.
Both files have the independent archive-size ceiling; the JS selection/copy/
readback allowance defaults to 8 x that ceiling (maximum 8 TiB). Native
preflight has its own finite archive/object limits and shares the deadline;
its internal reads are NOT measured by --max-total-read-bytes.

Stream the highest uniquely signed supplied checkpoint; never select an older
checkpoint after a failure. Publish its exact approval only after the archive's
signed digest/length, readback, file sync and directory sync. Names bind exact
content; publication is create-only. Exact retries reuse and synchronize files.
No signing key, unsigned bypass, mutable latest pointer, or automatic deletion.
A failed publication may leave a valid unadvertised body; retry the same command.
The JSON candidate can be passed to select_repository_backup_native.mjs using
--candidate <candidate.input> <candidate.approval>, then native verify/restore.
For paired recovery, pass candidate.input/candidate.approval plus lfs_archive
and lfs_companion.sha256 to restore_repository_backup_native.mjs. The ordinary
approval remains source-only; native pointer commitments authenticate LFS.
Companion loss/mismatch never selects an older checkpoint or omits the pair.
Jobs, replenishment and HTTPS adapters remain source-only.
Source-only mode is trusted-local POSIX copying, NOT native validation.
Paired mode adds native validation of its exact source and companion. Neither
mode restores a repository or proves a complete capsule or newest global head.
`;
const fail = code => { throw backupError(code); };

export function replicationArguments(args) {
  if (!Array.isArray(args) || args.length > 300
    || args.some(a => typeof a !== 'string' || a.length > 8192 || a.includes('\0'))
    || args.reduce((n, a) => n + Buffer.byteLength(a), 0) > 320 * 1024) fail('backup_replication_argument_limit');
  const rest = [], seen = new Set(), companion = {}; let destination, maximumTotalBytes;
  const paired = { '--lfs-archive': 'lfsArchive', '--expected-lfs-sha256': 'expectedLfsSha256',
    '--fg': 'fg', '--verification-instance': 'verificationInstance' };
  // Reuse the already strict select-only policy/candidate grammar. Native
  // destination, signer, resume and process options are deliberately inapplicable.
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (!['--replica-directory', '--max-total-read-bytes', '--trusted-local', ...Object.keys(paired)].includes(flag)) { rest.push(flag); continue; }
    if (seen.has(flag)) fail('backup_duplicate_option'); seen.add(flag);
    if (flag === '--trusted-local') { companion.trustedLocal = true; continue; }
    const value = args[++index];
    if (!value || value.startsWith('--')) fail('backup_missing_option_value');
    if (flag === '--replica-directory') destination = value;
    else if (Object.hasOwn(paired, flag)) companion[paired[flag]] = value;
    else maximumTotalBytes = Number(backupDecimal(value, BigInt(BACKUP_LIMITS.maximumArchiveBytes * 8)));
  }
  const { operation, ...selected } = selectionArguments(['select', ...rest]);
  return repositoryBackupReplicationOptions({ ...selected, destination, maximumTotalBytes, ...companion });
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
    if (result?.lfs_archive) { error.lfs_archive = result.lfs_archive; error.lfs_publication_state = 'lfs_durable'; }
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
      retained_temporary: error.retained_temporary ?? null, completed_result: error.completed_result ?? null,
      ...(error.lfs_publication_state === undefined ? {} : { lfs_archive: error.lfs_archive ?? null,
        lfs_publication_state: error.lfs_publication_state, verification_scratch: error.verification_scratch ?? null,
        approval_scratch: error.approval_scratch ?? null, native_receipt: error.native_receipt ?? null }) }) + '\n');
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
