#!/usr/bin/env node
// Detached operator approval; native verification is explicit and opt-in.
import { exportApprovedRepositoryBackup } from './lib/repository-backup-export.mjs';
import { pathToFileURL } from 'node:url';
import { approveVerifiedRepositoryBackup } from './lib/repository-backup-verified-sign.mjs';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath, readBackupControl, publishBackupControl } from './lib/repository-backup-io.mjs';
import { backupDecimal, backupPolicy, repositoryBackupDeclarations, signRepositoryBackupFile, authenticateRepositoryBackupFile } from './lib/repository-backup-approval.mjs';

export const BACKUP_APPROVAL_HELP = `Usage:
  node scripts/attest_repository_backup.mjs sign ARCHIVE NEW_APPROVAL --private-key PEM
    --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
    --head-generation N [--expires-at YYYY-MM-DDTHH:MM:SSZ]
  node scripts/attest_repository_backup.mjs verify-sign ARCHIVE NEW_APPROVAL --private-key PEM
    --fg /absolute/path/to/fg --verification-instance N --trusted-local
    --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
    --head-generation N [--expires-at YYYY-MM-DDTHH:MM:SSZ]
  node scripts/attest_repository_backup.mjs export-sign SOURCE NEW_ARCHIVE NEW_APPROVAL --private-key PEM
    --fg /absolute/path/to/fg --verification-instance N --trusted-local
    --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
    --head-generation N [--expires-at YYYY-MM-DDTHH:MM:SSZ]
  node scripts/attest_repository_backup.mjs check ARCHIVE APPROVAL --trust-key PEM
    --tenant-id HEX --repository-id HEX --incarnation-id HEX --object-format sha1|sha256
    --minimum-head-generation N

All operations accept --max-archive-bytes N (default 1 GiB, at most 1 TiB)
and --timeout-secs N (default 300, at most 3600). Use -- before literal paths.
Offline sign binds actual streamed bytes to OPERATOR-SUPPLIED identity declarations;
it does not parse or verify the native archive. Check authenticates the supplied
Ed25519 key, exact namespace/incarnation/format and external generation floor,
then streams and hashes the artifact. It does not restore a repository, prove
this is the latest checkpoint, validate native authority, or verify a capsule.
Verify-sign runs trusted local fg backup verify before reading the private key.
The verified digest, namespace, incarnation, format and generation must match the
final signing pass before any approval is published. The native verification
receipt is not embedded in the signature: restore still verifies independently.
Export-sign first runs native fg backup export, then verifies and signs the exact
exported digest and object/graph counts. Both outputs must be outside SOURCE.
Archive and approval publish separately; an interruption can leave an unsigned
archive. It is retained, never deleted, overwritten, or automatically retried.
Use verify-sign explicitly to verify and approve retained bytes after inspection.
Unknown verification scratch is retained and reported, never recursively deleted.
The detached approval has its own DSSE type; Git-bundle approvals are refused.
The private key must be owner-private and single-link. NEW_APPROVAL's parent
must be an existing owner-private directory. Existing outputs are never replaced.
`;
export function approvalArguments(args) {
  if (args.length > 64 || args.reduce((n, a) => n + Buffer.byteLength(a), 0) > 32768
    || args.some(a => a.length > 8192 || a.includes('\0'))) throw backupError('backup_argument_limit');
  const op = args[0], paths = [], flags = new Map(); let literal = false;
  if (!['sign', 'verify-sign', 'export-sign', 'check'].includes(op)) throw backupError('backup_operation_required');
  const isNative = ['verify-sign', 'export-sign'].includes(op);
  const allowed = new Set(['--tenant-id', '--repository-id', '--incarnation-id', '--object-format',
    '--max-archive-bytes', '--timeout-secs', ...(op !== 'check' ? ['--private-key', '--head-generation', '--expires-at'] : ['--trust-key', '--minimum-head-generation']),
    ...(isNative ? ['--fg', '--verification-instance', '--trusted-local'] : [])]);
  for (let at = 1; at < args.length; at++) {
    const arg = args[at];
    if (!literal && arg === '--') { literal = true; continue; }
    if (!literal && arg.startsWith('-')) {
      if (!allowed.has(arg) || flags.has(arg)) throw backupError('backup_unknown_or_duplicate_option');
      if (arg === '--trusted-local') { flags.set(arg, true); continue; }
      const value = args[++at]; if (!value || value.startsWith('--')) throw backupError('backup_missing_value');
      flags.set(arg, value);
    } else paths.push(backupPath(arg));
  }
  if (paths.length !== (op === 'export-sign' ? 3 : 2)) throw backupError(op === 'export-sign' ? 'backup_three_paths_required' : 'backup_two_paths_required');
  const required = key => { const value = flags.get(key); if (value === undefined) throw backupError('backup_missing_option'); return value; };
  const shared = Object.fromEntries(['tenant_id', 'repository_id', 'incarnation_id', 'object_format'].map(k => [k, required('--' + k.replaceAll('_', '-'))]));
  const generation = backupDecimal(required(op !== 'check' ? '--head-generation' : '--minimum-head-generation'));
  const policy = backupPolicy({ ...shared, minimum_head_generation: generation });
  const maximumBytes = Number(backupDecimal(flags.get('--max-archive-bytes') ?? String(BACKUP_LIMITS.maximumBytes), BigInt(BACKUP_LIMITS.maximumArchiveBytes)));
  const timeoutMs = Number(backupDecimal(flags.get('--timeout-secs') ?? '300', 3600n)) * 1000;
  const keyPath = backupPath(required(op !== 'check' ? '--private-key' : '--trust-key'));
  const declarations = op !== 'check' ? repositoryBackupDeclarations({ ...shared, head_generation: generation,
    ...(flags.has('--expires-at') ? { expires_at: flags.get('--expires-at') } : {}) }) : null;
  const native = isNative ? { fg: backupPath(required('--fg')),
    verificationInstance: backupDecimal(required('--verification-instance'), 9223372036854775807n),
    trustedLocal: required('--trusted-local') === true } : {};
  return { op, paths, keyPath, policy, declarations, maximumBytes, timeoutMs, ...native };
}
export async function runApprovalCommand(args, signal) {
  if (args.length === 1 && args[0] === '--help') return BACKUP_APPROVAL_HELP;
  const options = approvalArguments(args), live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal });
  if (options.op === 'export-sign') return JSON.stringify(await exportApprovedRepositoryBackup({
    fg: options.fg, source: options.paths[0], archive: options.paths[1], output: options.paths[2], privateKey: options.keyPath,
    declarations: options.declarations, verificationInstance: options.verificationInstance, trustedLocal: options.trustedLocal,
    maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal,
  })) + '\n';
  if (options.op === 'verify-sign') return JSON.stringify(await approveVerifiedRepositoryBackup({
    fg: options.fg, input: options.paths[0], output: options.paths[1], privateKey: options.keyPath,
    declarations: options.declarations, verificationInstance: options.verificationInstance, trustedLocal: options.trustedLocal,
    maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal,
  })) + '\n';
  const key = await readBackupControl(options.keyPath, BACKUP_LIMITS.keyBytes, live, options.op === 'sign');
  try {
    if (options.op === 'sign') {
      const signed = await signRepositoryBackupFile(options.paths[0], key, options.declarations,
        { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal });
      live.check();
      const output = await publishBackupControl(options.paths[1], signed.envelope, { ...live, check() {
        live.check();
        if (signed.statement.expires_at !== null && Date.parse(signed.statement.expires_at) <= live.now()) throw backupError('backup_approval_expired');
      } });
      return JSON.stringify({ type: 'repository_backup_approval_created', ...output, statement: signed.statement,
        trusted_key_id: signed.trusted_key_id, native_content_verified: false, streaming: signed.streaming }) + '\n';
    }
    const encoded = await readBackupControl(options.paths[1], BACKUP_LIMITS.envelopeBytes, live);
    const verified = await authenticateRepositoryBackupFile(options.paths[0], encoded, key, options.policy,
      { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal });
    verified.checkCurrent(); live.check();
    return JSON.stringify({ type: 'repository_backup_approval_check', ...verified.authentication,
      archive_bytes_authenticated: true, streaming: verified.streaming }) + '\n';
  } finally { key.fill(0); }
}
async function main() {
  const controller = new AbortController(), stop = () => controller.abort();
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
  const failedOutput = () => { stop(); process.exitCode = 1; };
  process.stdout.on('error', failedOutput); process.stderr.on('error', failedOutput);
  let completed = false;
  try {
    const text = await runApprovalCommand(process.argv.slice(2), controller.signal); completed = true;
    await new Promise((resolve, reject) => process.stdout.write(text, error => error ? reject(error) : resolve()));
  } catch (error) {
    process.stderr.write(JSON.stringify({ type: 'repository_backup_approval_error', code: error.code ?? 'backup_failed',
      operation_completed: completed, publication_state: error.publication_state ?? null, cleanup_error: error.cleanup_error ?? null,
      ...(error.verification_scratch !== undefined ? { verification_scratch: error.verification_scratch } : {}),
      ...(error.archive_state !== undefined ? { archive_state: error.archive_state, archive_path: error.archive_path, approval_path: error.approval_path } : {}) }) + '\n');
    process.exitCode = 1;
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
