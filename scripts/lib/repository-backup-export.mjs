// One bounded native export -> verify -> detached approval operation. Native fg
// owns archive encoding/publication; only an independently verified artifact is
// approved. This never copies a live storage directory or runs a foreign Git.
import { lstat, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { runImportProcess } from './native-import-process.mjs';
import { backupError, backupLifetime, backupPath } from './repository-backup-io.mjs';
import { backupDecimal, repositoryBackupDeclarations } from './repository-backup-approval.mjs';
import { repositoryBackupExportReceipt, checkpointFromExport } from './repository-backup-export-receipt.mjs';
import { approveVerifiedRepositoryBackup } from './repository-backup-verified-sign.mjs';

function fail(code) { throw backupError(code); }
async function absent(path) {
  try { await lstat(path); fail('backup_existing_path'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
async function privateDestination(path) {
  const parent = await realpath(dirname(path)), stat = await lstat(parent, { bigint: true });
  if (!stat.isDirectory() || typeof process.getuid !== 'function'
    || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n)) fail('backup_private_parent_required');
  return join(parent, basename(path));
}

/** Produce an archive, independently verify it, then publish its signed approval.
 * The files are NOT one atomic filesystem transaction: either archive may exist
 * without an approval after any interruption. Never overwrite, delete or retry
 * that archive automatically. `verify-sign` can independently validate and sign
 * retained bytes in a subsequent explicitly requested operation.
 *
 * Identity/generation are exact operator pins, not inferred authorization. The
 * optional LFS set is natively bound to the exact source snapshot. Other
 * external artifacts and full Capsule/service backup remain outside this scope.
 * No destination repository or routing is changed.
 */
export async function exportApprovedRepositoryBackup(raw) {
  const keys = ['fg', 'source', 'archive', 'output', 'privateKey', 'declarations', 'verificationInstance',
    'trustedLocal', 'maximumBytes', 'timeoutMs', 'signal', 'lfsRoot', 'lfsOutput'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !keys.includes(k))
    || raw.trustedLocal !== true) fail('backup_explicit_local_operation_required');
  const options = { ...raw };
  const includeLfs = options.lfsRoot !== undefined || options.lfsOutput !== undefined;
  if (includeLfs && (options.lfsRoot === undefined || options.lfsOutput === undefined)) fail('backup_lfs_pair_required');
  for (const field of ['fg', 'source', 'archive', 'output', 'privateKey']) options[field] = backupPath(options[field]);
  if (!isAbsolute(options.fg)) fail('backup_absolute_fg_required');
  for (const field of ['source', 'archive', 'output', 'privateKey']) options[field] = resolve(options[field]);
  if (includeLfs) for (const field of ['lfsRoot', 'lfsOutput']) options[field] = resolve(backupPath(options[field]));
  const instance = backupDecimal(options.verificationInstance, 9223372036854775807n);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal: options.signal });
  const declarations = Object.freeze(repositoryBackupDeclarations(options.declarations, live.now()));
  const current = () => {
    live.check();
    if (Date.parse(declarations.issued_at) > live.now() + 300000) fail('backup_approval_in_future');
    if (declarations.expires_at !== null && Date.parse(declarations.expires_at) <= live.now()) fail('backup_approval_expired');
  };
  current();
  let state = 'not_started', native = null;
  try {
    if (!(await lstat(options.source)).isDirectory()) fail('backup_source_directory_required');
    options.source = await realpath(options.source);
    options.archive = await privateDestination(options.archive);
    options.output = await privateDestination(options.output);
    if (includeLfs) {
      if (!(await lstat(options.lfsRoot)).isDirectory()) fail('backup_lfs_source_directory_required');
      options.lfsRoot = await realpath(options.lfsRoot);
      options.lfsOutput = await privateDestination(options.lfsOutput);
    }
    const sources = [options.source, ...(includeLfs ? [options.lfsRoot] : [])];
    const outputs = [options.archive, options.output, ...(includeLfs ? [options.lfsOutput] : [])];
    if (new Set(outputs).size !== outputs.length || outputs.some(path => sources.some(source =>
      path === source || path.startsWith(source.endsWith(sep) ? source : source + sep)))) fail('backup_outputs_must_be_separate');
    for (const path of outputs) await absent(path);
    current();
    const args = ['backup', 'export', options.source, options.archive, declarations.tenant_id, declarations.repository_id,
      '--trusted-local', '--object-format', declarations.object_format, '--max-archive-bytes', String(live.maximumBytes),
      '--timeout-secs', String(Math.ceil(live.remaining() / 1000))];
    if (includeLfs) args.push('--lfs-root', options.lfsRoot, '--lfs-output', options.lfsOutput);
    state = 'export_attempted_unknown';
    native = repositoryBackupExportReceipt(await runImportProcess(options.fg, args, live), declarations, live.maximumBytes, includeLfs);
    state = 'export_reported_complete'; current();
    const approval = await approveVerifiedRepositoryBackup({ fg: options.fg, input: options.archive, output: options.output,
      privateKey: options.privateKey, declarations, verificationInstance: instance, trustedLocal: true,
      maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal,
      checkpoint: checkpointFromExport(native), ...(includeLfs ? { lfsArchive: options.lfsOutput,
        expectedLfsSha256: native.lfs_companion.sha256, lfsCheckpoint: native.lfs_companion } : {}) });
    // The approval publisher has already crossed its visible/durable boundary.
    // Do not turn that confirmed result into an automatic retry on cancellation.
    return { type: 'approved_repository_backup_export', state: 'complete', archive: options.archive,
      approval: options.output, native, approval_result: approval, complete_capsule_exported: false,
      external_artifacts_included: false, ...(includeLfs ? { lfs_archive: options.lfsOutput,
        lfs_companion: native.lfs_companion, lfs_payloads_included: true, lfs_companion_signed: false } : {}) };
  } catch (error) {
    error.archive_state = state; error.archive_path = options.archive; error.approval_path = options.output;
    error.publication_state ??= 'not_created';
    if (includeLfs) { error.lfs_archive_path = options.lfsOutput; error.lfs_archive_state = state; }
    if (native) error.export_receipt = native;
    throw error;
  }
}
