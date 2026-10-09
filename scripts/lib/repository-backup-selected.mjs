// One explicit checkpoint selection followed by the SAME approved native path.
// No automatic fallback/reselection, global-currentness claim or restore engine.
import { resolve } from 'node:path';
import { backupError, backupLifetime, backupPath } from './repository-backup-io.mjs';
import { backupPolicy } from './repository-backup-approval.mjs';
import { repositoryBackupCandidates, selectRepositoryBackup } from './repository-backup-selection.mjs';
import { repositoryBackupOptions, runApprovedRepositoryBackup } from './repository-backup-native.mjs';

const fail = code => { throw backupError(code); };
export function selectedRepositoryBackupOptions(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ['input', 'approval', 'checkpoint', 'native'].some(k => Object.hasOwn(value, k))) fail('backup_invalid_selection_options');
  const { candidates, ...rest } = value, rows = repositoryBackupCandidates(candidates);
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
  return Object.freeze({ ...rest, candidates: rows, native });
}

export async function runSelectedRepositoryBackup(raw) {
  const options = selectedRepositoryBackupOptions(raw);
  const live = backupLifetime({ maximumBytes: options.maximumBytes, timeoutMs: options.timeoutMs, signal: options.signal });
  let selection = null;
  const progress = stage => async event => {
    await options.onProgress(Object.freeze({ ...event, stage })); live.check();
  };
  try {
    const selected = await selectRepositoryBackup(options.candidates, options.trustKey, options.policy, {
      maximumBytes: live.maximumBytes, timeoutMs: live.remaining(), signal: live.signal, onProgress: progress('selection'),
    });
    selection = selected.report;
    await progress('selection')({ phase: 'selection_complete' }); selected.checkCurrent();
    if (options.operation === 'select') return selection;
    live.check();
    // Reopen only through full approval/key/artifact authentication, with exact
    // envelope/key pins preventing a different VALID checkpoint being swapped
    // into the same paths between phases. All native checks remain mandatory.
    const result = await runApprovedRepositoryBackup({ ...options.native,
      input: selection.selected.input, approval: selection.selected.approval,
      checkpoint: selection.checkpoint, timeoutMs: live.remaining(), signal: live.signal,
      onProgress: progress('native') });
    // No cancellation/expiry gate after confirmed native completion.
    return { type: `selected_repository_backup_${options.operation}`, state: result.state, selection, result };
  } catch (caught) {
    const error = caught instanceof Error ? caught : backupError('backup_selection_observer_failed');
    error.state ??= options.native?.resume ? 'existing_unknown' : 'not_started';
    error.selection = selection;
    throw error;
  }
}
