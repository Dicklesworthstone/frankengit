#!/usr/bin/env node
// Explicit signed repository-source recovery through the existing native fg.
import { pathToFileURL } from 'node:url';
import { backupError, BACKUP_LIMITS } from './lib/repository-backup-io.mjs';
import { backupDecimal } from './lib/repository-backup-approval.mjs';
import { repositoryBackupOptions, runApprovedRepositoryBackup } from './lib/repository-backup-native.mjs';

export const HELP = `Usage: node scripts/restore_repository_backup_native.mjs verify|restore ARCHIVE
  --fg ABSOLUTE_FG --approval APPROVAL.json --trust-key PUBLIC.pem --trusted-local
  --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
  --minimum-head-generation N --verification-instance N
Restore also requires:
  --destination NEW_ROOT --destination-instance N --approval-record NEW_PRIVATE_FILE
Resume requires those same identity/approval parameters and adds --resume.
Optional: --max-archive-bytes N (default 1 GiB, at most 1 TiB),
          --timeout-secs N (default 300, at most 3600), -- before a literal path.

Authenticate the independent Ed25519 approval and actual archive bytes, then run
native fg backup verify. Check every signed identity against the native receipt
BEFORE starting fg backup restore. All phases share one bounded deadline.
Restore retains a synchronized approval record outside the destination. Resume
must reauthenticate and match that record, including its exact generation floor.
The destination and record parents must already be owner-private directories.
Native restore alone owns quarantine, original commitments, graph checks,
authority-last publication and exact --resume behavior. Never serve a partial
root or replay external effects automatically. No shell, PATH lookup, Git helper,
archive decoder or unsigned fallback. A failed/interrupted restore stays unknown,
not rolled back. Failed native preflight scratch is retained for diagnosis.
Approval expiry gates native submission; it is NOT an in-native revocation lease.
This restores the native authority-and-selected-Git profile, not external artifacts,
routing, or a complete Repository Capsule. The explicitly chosen fg must be trusted.
`;
export function nativeBackupArguments(args) {
  if (!Array.isArray(args) || args.length > 64 || args.some(a => typeof a !== 'string' || a.length > 8192 || a.includes('\0'))
    || args.reduce((n, a) => n + Buffer.byteLength(a), 0) > 32768) throw backupError('backup_argument_limit');
  const operation = args[0], map = new Map(), paths = []; let literal = false;
  const allowed = ['--fg', '--approval', '--trust-key', '--tenant-id', '--repository-id', '--incarnation-id', '--object-format',
    '--minimum-head-generation', '--verification-instance', '--destination', '--destination-instance', '--approval-record',
    '--max-archive-bytes', '--timeout-secs', '--trusted-local', '--resume'];
  for (let at = 1; at < args.length; at++) {
    const arg = args[at];
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      if (!allowed.includes(arg) || map.has(arg)) throw backupError('backup_unknown_or_duplicate_option');
      if (arg === '--trusted-local' || arg === '--resume') { map.set(arg, true); continue; }
      const value = args[++at]; if (!value || value.startsWith('--')) throw backupError('backup_missing_value');
      map.set(arg, value);
    } else paths.push(arg);
  }
  if (paths.length !== 1) throw backupError('backup_one_archive_required');
  const get = key => map.get(key), policy = Object.fromEntries(['tenant_id', 'repository_id', 'incarnation_id', 'object_format', 'minimum_head_generation']
    .map(k => [k, get('--' + k.replaceAll('_', '-'))]));
  return repositoryBackupOptions({ operation, input: paths[0], fg: get('--fg'), approval: get('--approval'), trustKey: get('--trust-key'), policy,
    trustedLocal: get('--trusted-local'), verificationInstance: get('--verification-instance'), resume: get('--resume') ?? false,
    destination: get('--destination'), destinationInstance: get('--destination-instance'), approvalRecord: get('--approval-record'),
    maximumBytes: Number(backupDecimal(get('--max-archive-bytes') ?? String(BACKUP_LIMITS.maximumBytes), BigInt(BACKUP_LIMITS.maximumArchiveBytes))),
    timeoutMs: 1000 * Number(backupDecimal(get('--timeout-secs') ?? '300', 3600n)) });
}
export async function runNativeBackupCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return HELP;
  return runApprovedRepositoryBackup({ ...nativeBackupArguments(args), signal });
}
async function main() {
  const controller = new AbortController(), stop = () => controller.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  const outputError = () => { stop(); process.exitCode = 1; };
  process.stdout.on('error', outputError); process.stderr.on('error', outputError);
  let result = null;
  try {
    result = await runNativeBackupCommand(process.argv.slice(2), controller.signal);
    const text = typeof result === 'string' ? result : JSON.stringify(result) + '\n';
    await new Promise((resolve, reject) => process.stdout.write(text, e => e ? reject(e) : resolve()));
  } catch (error) {
    process.stderr.write(JSON.stringify({ type: 'approved_repository_backup_error', code: error.code ?? 'backup_failed',
      state: result?.state ?? error.state ?? 'not_started', native_exit_code: error.native_exit_code ?? null,
      native_diagnostic: error.native_diagnostic ?? null,
      verification_scratch: error.verification_scratch ?? null, approval_record: result?.approval_record ?? error.approval_record ?? null,
      absence_proves_non_publication: false }) + '\n'); process.exitCode = 1;
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
