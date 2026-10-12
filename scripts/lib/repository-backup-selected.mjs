// One explicit checkpoint selection followed by the SAME approved native path.
// No automatic fallback/reselection, global-currentness claim or restore engine.
import { resolve, dirname, basename, join, sep } from 'node:path';
import { realpath } from 'node:fs/promises';
import { BACKUP_LIMITS, backupError, backupLifetime, backupPath } from './repository-backup-io.mjs';
import { backupPolicy } from './repository-backup-approval.mjs';
import { MAX_BACKUP_CANDIDATES, repositoryBackupCandidates, selectRepositoryBackup } from './repository-backup-selection.mjs';
import { repositoryBackupOptions, runApprovedRepositoryBackup } from './repository-backup-native.mjs';
import { withRepositoryBackupWitness } from './repository-backup-witness.mjs';

const fail = code => { throw backupError(code); };
export function selectedRepositoryBackupOptions(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ['input', 'approval', 'checkpoint', 'native'].some(k => Object.hasOwn(value, k))) fail('backup_invalid_selection_options');
  const { candidates, witness: requestedWitness, maximumReplicaBytes, ...rest } = value, rows = repositoryBackupCandidates(candidates);
  // This budget constrains selection reads only, never the native archive size.
  if (maximumReplicaBytes !== undefined && (!Number.isSafeInteger(maximumReplicaBytes) || maximumReplicaBytes < 1
    || maximumReplicaBytes > BACKUP_LIMITS.maximumArchiveBytes * MAX_BACKUP_CANDIDATES)) fail('backup_invalid_options');
  let native = null;
  if (rest.operation === 'select') {
    if (Object.keys(rest).some(k => !['operation', 'trustKey', 'policy', 'maximumBytes', 'timeoutMs', 'signal', 'onProgress'].includes(k))) fail('backup_inapplicable_selection_option');
    rest.policy = backupPolicy(rest.policy); rest.trustKey = resolve(backupPath(rest.trustKey));
    rest.onProgress ??= (() => {});
    backupLifetime({ maximumBytes: rest.maximumBytes, timeoutMs: rest.timeoutMs, signal: rest.signal, onProgress: rest.onProgress });
  } else {
    // Validate every possible destination/input collision and the entire native
    // grammar before ANY signature/file I/O. No invented placeholder paths.
    for (const row of rows) {
      const checked = repositoryBackupOptions({ ...rest, ...row });
      native ??= checked;
    }
    rest.policy = native.policy; rest.trustKey = native.trustKey; rest.onProgress = native.onProgress;
  }
  let witness;
  if (requestedWitness !== undefined) {
    witness = resolve(backupPath(requestedWitness)); backupPath(witness);
    const protectedPaths = [rest.trustKey, native?.fg, native?.destination, native?.approvalRecord,
      ...rows.flatMap(row => [row.input, row.approval])].filter(p => p !== undefined).map(resolvePath => resolve(resolvePath));
    if (protectedPaths.some(path => path === witness || path.startsWith(witness + sep) || witness.startsWith(path + sep))) fail('backup_witness_separate_path_required');
  }
  return Object.freeze({ ...rest, candidates: rows, native,
    ...(maximumReplicaBytes === undefined ? {} : { maximumReplicaBytes }), ...(witness ? { witness } : {}) });
}

// Lexical validation above is deliberately synchronous. Before native work,
// also resolve existing parent aliases: the independently retained witness must
// not become a child of the restored repository, or contain the restored root.
// Inspect only the selected artifact, never unavailable lower-generation files.
// Stable owner-controlled parent directories remain a required trust boundary.
async function requireSeparatedPaths(witness, paths, live) {
  const directory = witness.snapshot().directory;
  for (const path of paths.filter(value => value !== undefined)) {
    live.check();
    let physical;
    try { physical = await realpath(path); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      physical = join(await realpath(dirname(path)), basename(path));
    }
    live.check();
    if (physical === directory || physical.startsWith(directory + sep) || directory.startsWith(physical + sep)) fail('backup_witness_separate_path_required');
  }
}

export async function runSelectedRepositoryBackup(raw) {
  const options = selectedRepositoryBackupOptions(raw);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal: options.signal });
  let selection = null;
  const progress = stage => async event => {
    await options.onProgress(Object.freeze({ ...event, stage })); live.check();
  };
  const perform = async witness => {
    const nativePaths = [options.trustKey, options.native?.fg, options.native?.destination, options.native?.approvalRecord];
    if (witness) await requireSeparatedPaths(witness, nativePaths, live);
    const selected = await selectRepositoryBackup(options.candidates, options.trustKey, options.policy, {
      maximumBytes: live.maximumBytes, maximumReplicaBytes: options.maximumReplicaBytes,
      timeoutMs: live.remaining(), signal: live.signal, onProgress: progress('selection'),
    }, witness);
    selection = selected.report;
    const selectedPaths = [...nativePaths, selection.selected.input, selection.selected.approval];
    if (witness) await requireSeparatedPaths(witness, selectedPaths, live);
    await progress('selection')({ phase: 'selection_complete' }); selected.checkCurrent();
    if (options.operation === 'select') return selection;
    live.check();
    // Reopen only through full approval/key/artifact authentication, with exact
    // envelope/key pins preventing a different VALID checkpoint being swapped
    // into the same paths between phases. All native checks remain mandatory.
    const result = await runApprovedRepositoryBackup({ ...options.native,
      input: selection.selected.input, approval: selection.selected.approval,
      checkpoint: selection.checkpoint, timeoutMs: live.remaining(), signal: live.signal,
      onProgress: async event => {
        await progress('native')(event);
        if (witness) {
          witness.require(selection.authentication.statement);
          // The observer must not substitute an aliased destination between
          // preflight and the native publication submission.
          await requireSeparatedPaths(witness, selectedPaths, live);
        }
      } });
    // No cancellation/expiry gate after confirmed native completion.
    return { type: `selected_repository_backup_${options.operation}`, state: result.state, selection, result };
  };
  try {
    live.check();
    if (!options.witness) return await perform(null);
    return await withRepositoryBackupWitness(options.witness, options.trustKey, options.policy,
      { maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal }, perform);
  } catch (caught) {
    const error = caught instanceof Error ? caught : backupError('backup_selection_observer_failed');
    error.state ??= options.native?.resume ? 'existing_unknown' : 'not_started';
    error.selection = selection;
    throw error;
  }
}
