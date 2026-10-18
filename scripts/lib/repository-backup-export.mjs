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
 * The two files are NOT one atomic filesystem transaction: the archive may exist
 * without an approval after any interruption. Never overwrite, delete or retry
 * that archive automatically. `verify-sign` can independently validate and sign
 * retained bytes in a subsequent explicitly requested operation.
 *
 * Identity/generation are exact operator pins, not inferred authorization. The
 * existing native source-backup scope excludes external artifacts and is not a
 * full Capsule/service backup. No destination repository or routing is changed.
 */
export async function exportApprovedRepositoryBackup(raw) {
  const keys = ['fg', 'source', 'archive', 'output', 'privateKey', 'declarations', 'verificationInstance',
    'trustedLocal', 'maximumBytes', 'timeoutMs', 'signal'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !keys.includes(k))
    || raw.trustedLocal !== true) fail('backup_explicit_local_operation_required');
  const options = { ...raw };
  for (const field of ['fg', 'source', 'archive', 'output', 'privateKey']) options[field] = backupPath(options[field]);
  if (!isAbsolute(options.fg)) fail('backup_absolute_fg_required');
  for (const field of ['source', 'archive', 'output', 'privateKey']) options[field] = resolve(options[field]);
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
    if (options.archive === options.output || [options.archive, options.output].some(path =>
      path === options.source || path.startsWith(options.source.endsWith(sep) ? options.source : options.source + sep))) fail('backup_outputs_must_be_separate');
    await absent(options.archive); await absent(options.output); current();
    const args = ['backup', 'export', options.source, options.archive, declarations.tenant_id, declarations.repository_id,
      '--trusted-local', '--object-format', declarations.object_format, '--max-archive-bytes', String(live.maximumBytes),
      '--timeout-secs', String(Math.ceil(live.remaining() / 1000))];
    state = 'export_attempted_unknown';
    native = repositoryBackupExportReceipt(await runImportProcess(options.fg, args, live), declarations, live.maximumBytes);
    state = 'export_reported_complete'; current();
    const approval = await approveVerifiedRepositoryBackup({ fg: options.fg, input: options.archive, output: options.output,
      privateKey: options.privateKey, declarations, verificationInstance: instance, trustedLocal: true,
      maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal,
      checkpoint: checkpointFromExport(native) });
    // The approval publisher has already crossed its visible/durable boundary.
    // Do not turn that confirmed result into an automatic retry on cancellation.
    return { type: 'approved_repository_backup_export', state: 'complete', archive: options.archive,
      approval: options.output, native, approval_result: approval, complete_capsule_exported: false,
      external_artifacts_included: false };
  } catch (error) {
    error.archive_state = state; error.archive_path = options.archive; error.approval_path = options.output;
    error.publication_state ??= 'not_created';
    if (native) error.export_receipt = native;
    throw error;
  }
}
