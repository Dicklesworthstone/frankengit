// Durable rebase decisions are a bounded history of observed stops. Each retry
// reconstructs the entire original suffix; no mutable sequencer or candidate
// prefix is retained. Native replay and complete bundle inspection remain the
// authority for tree contents, ancestry and publication eligibility.
import { webcrypto } from 'node:crypto';
import { subject, snapshot, integer, oid, form, utf8, principal, opaque, pinned } from
  '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { rebasePreparationCommand, rebasePreparationReply } from
  '../../crates/fgit-node/src/smart_http/server/browser/pulls-rebase.mjs';
import { rebaseResolutionUpload, rebaseRecipeUpload, verifyRebaseResolutions } from
  '../../crates/fgit-node/src/smart_http/server/browser/pulls-rebase-resolution.mjs';
import { resolutionPath, RESOLUTION_FILE_LIMIT } from
  '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution.mjs';
import { CandidateError, candidateFail, candidateKeys, candidateJson, CANDIDATE_IO_LIMITS } from './pull_candidate_io.mjs';

export const REBASE_HISTORY_SCHEMA = 'frankengit-pull-rebase-history-v1';
export const REBASE_HISTORY_MAX_ROUNDS = 129;
export const REBASE_CHOICE_BYTES = 4 * 1024 * 1024;
export const REBASE_RECEIPT_FIELDS = Object.freeze([
  'resolution_profile', 'resolution_input_commits', 'resolution_consumed_commits', 'resolutions',
]);
const MAX_CHOICES = 128;
const STOP_FIELDS = ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
  'source_head', 'snapshot_token', 'profile', 'method', 'subject', 'merge_base', 'committer', 'timestamp', 'empty_policy',
  'read_only', 'objects_staged', 'transaction_created', 'published', 'merge_authorized', 'original_authors_preserved',
  'original_messages_preserved', 'original_signatures_copied', 'author_identity_verified', 'state', 'series_complete',
  'provisional_steps', 'candidate_commit', 'root_tree', 'bundle', 'stopped_commit', 'conflicts', 'step_count', 'steps'];
const MODES = [0o040000, 0o100644, 0o100755, 0o120000, 0o160000];
const KINDS = ['content', 'binary', 'modify_delete', 'type_change', 'mode', 'opaque', 'attributes_require_driver'];
const copy = value => candidateJson(Buffer.from(JSON.stringify(value)), CANDIDATE_IO_LIMITS.capture);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function exactOid(value, algorithm) {
  if (oid(value, algorithm) !== value) candidateFail('candidate_rebase_exact_original_required');
  return value;
}
function refusal(error) {
  if (error instanceof CandidateError) throw error;
  candidateFail('invalid_candidate_rebase_history');
}

// Public CLI action. An original native ID is explicit even though the package
// already names the current stop, preventing a choice file from drifting to a
// different original commit. Earlier choices are read from the pinned package.
export function candidateRebaseAction(input, algorithm) {
  try {
    const resolving = input?.action === 'resolve';
    candidateKeys(input, resolving ? ['action', 'original', 'choices'] : ['action', 'original', 'from_empty', 'empty']);
    const original = exactOid(input.original, algorithm);
    if (!resolving) {
      if (input.action !== 'continue-empty' || input.from_empty !== 'stop' || !['drop', 'keep'].includes(input.empty)) {
        candidateFail('candidate_rebase_explicit_empty_transition_required');
      }
      return { action: 'continue-empty', original, from_empty: 'stop', empty: input.empty };
    }
    if (!Array.isArray(input.choices) || !input.choices.length || input.choices.length > MAX_CHOICES) {
      candidateFail('invalid_candidate_rebase_choices');
    }
    let bytes = 0;
    const choices = input.choices.map(value => {
      const file = value?.choice === 'file';
      candidateKeys(value, ['path_hex', 'choice', ...(file ? ['mode', 'content_hex'] : [])]);
      resolutionPath(value.path_hex);
      if (!['base', 'ours', 'theirs', 'delete', 'file'].includes(value.choice)) candidateFail('invalid_candidate_rebase_choice');
      const result = { path_hex: value.path_hex, choice: value.choice };
      bytes += value.path_hex.length / 2;
      if (file) {
        if (!['100644', '100755'].includes(value.mode) || typeof value.content_hex !== 'string' ||
            value.content_hex.length > 2 * RESOLUTION_FILE_LIMIT || value.content_hex.length % 2 ||
            !/^[0-9a-f]*$/.test(value.content_hex)) candidateFail('invalid_candidate_rebase_file');
        bytes += value.content_hex.length / 2;
        result.mode = value.mode; result.content_hex = value.content_hex;
      }
      if (bytes > REBASE_CHOICE_BYTES) candidateFail('candidate_rebase_resolution_budget');
      return result;
    }).sort((a, b) => a.path_hex < b.path_hex ? -1 : a.path_hex > b.path_hex ? 1 : 0);
    if (choices.some((row, index) => index && row.path_hex === choices[index - 1].path_hex)) {
      candidateFail('duplicate_candidate_rebase_path');
    }
    return { action: 'resolve', original, choices };
  } catch (error) { refusal(error); }
}

function context(input) {
  candidateKeys(input, ['number', 'command', 'scope', 'head', 'sourceHead']);
  candidateKeys(input.scope, ['tenant', 'repository', 'incarnation', 'format']);
  for (const key of ['tenant', 'repository', 'incarnation']) principal(input.scope[key]);
  integer(input.number, 'PR number', 1); snapshot(input.head); opaque(input.sourceHead);
  const raw = input.command, command = rebasePreparationCommand(subject(raw), {
    upstream: raw.upstream, committer: raw.committer, timestamp: raw.timestamp, empty: raw.empty,
  });
  candidateKeys(raw, Object.keys(command));
  if (raw.profile !== 'path-v1' || input.scope.format !== command.object_format) candidateFail('candidate_rebase_history_context');
  return { ...input, command };
}
function identity(value, algorithm) {
  if (value === null) return;
  candidateKeys(value, ['mode', 'oid']);
  if (!MODES.includes(value.mode)) candidateFail('candidate_rebase_conflict_mode');
  exactOid(value.oid, algorithm);
}
function conflict(row, algorithm) {
  candidateKeys(row, ['path_hex', 'kind', 'base', 'ours', 'theirs']);
  resolutionPath(row.path_hex);
  if (!KINDS.includes(row.kind)) candidateFail('candidate_rebase_conflict_kind');
  for (const side of ['base', 'ours', 'theirs']) identity(row[side], algorithm);
}
function strictReceipts(report, recipes, algorithm) {
  if (!recipes.length) return;
  integer(report.resolution_input_commits, 'resolution input commits', 1, MAX_CHOICES);
  integer(report.resolution_consumed_commits, 'resolution consumed commits', 1, MAX_CHOICES);
  if (!Array.isArray(report.resolutions) || report.resolutions.length > MAX_CHOICES) candidateFail('invalid_candidate_rebase_receipts');
  for (const row of report.resolutions) {
    candidateKeys(row, ['original', 'paths']); exactOid(row.original, algorithm);
    if (!Array.isArray(row.paths) || !row.paths.length || row.paths.length > MAX_CHOICES) candidateFail('invalid_candidate_rebase_receipt_paths');
    for (const path of row.paths) {
      candidateKeys(path, ['conflict', 'choice', 'result']); conflict(path.conflict, algorithm); identity(path.result, algorithm);
      if (!['base', 'ours', 'theirs', 'delete', 'file'].includes(path.choice)) candidateFail('invalid_candidate_rebase_choice');
    }
  }
}
function strictStop(report, recipes, algorithm) {
  candidateKeys(report, [...STOP_FIELDS, ...(recipes.length ? REBASE_RECEIPT_FIELDS : [])]);
  if (!['conflicted', 'became_empty'].includes(report.state) || report.original_authors_preserved !== true ||
      report.original_messages_preserved !== true || report.original_signatures_copied !== false ||
      report.author_identity_verified !== false) candidateFail('candidate_rebase_original_stop_required');
  for (const row of report.steps) {
    candidateKeys(row, ['original', 'rewritten', 'tree', 'kind']);
    for (const name of ['original', 'rewritten', 'tree']) exactOid(row[name], algorithm);
  }
  exactOid(report.stopped_commit, algorithm);
  for (const row of report.conflicts) conflict(row, algorithm);
  strictReceipts(report, recipes, algorithm);
}

// A later decision can affect only its original commit and following suffix.
// Even a different empty policy cannot alter an already completed prefix.
function progress(last, report) {
  if (last === null) return;
  const previous = last.preparation, count = previous.steps.length;
  if (report.steps.length < count || previous.steps.some((row, index) =>
    ['original', 'rewritten', 'tree', 'kind'].some(key => row[key] !== report.steps[index][key]))) {
    candidateFail('candidate_rebase_completed_prefix_changed');
  }
  if (last.action.action === 'resolve' && report.state === 'became_empty' &&
      report.stopped_commit === previous.stopped_commit && report.steps.length === count) return;
  const advanced = report.steps[count];
  if (!advanced || advanced.original !== previous.stopped_commit) candidateFail('candidate_rebase_original_frontier_changed');
  if (last.action.action === 'continue-empty' &&
      advanced.kind !== (last.action.empty === 'drop' ? 'dropped_empty' : 'replayed')) {
    candidateFail('candidate_rebase_empty_outcome_changed');
  }
}
function checkBinding(report, state) {
  pinned(report, state.context.scope, state.context.head);
  if (report.source_head !== state.context.sourceHead || report.empty_policy !== state.command.empty ||
      report.committer !== state.command.committer || report.timestamp !== state.command.timestamp ||
      oid(report.merge_base, state.command.object_format) !== state.command.upstream) {
    candidateFail('candidate_rebase_history_binding_changed');
  }
}

// Call after the complete preparation parser, and before inspection/publication
// handoff. This joins the final report to every retained original-commit recipe;
// it does not independently verify tree contents or an opaque bundle.
export function verifyRebaseHistoryResult(report, state) {
  try {
    checkBinding(report, state);
    strictReceipts(report, state.recipes, state.command.object_format);
    verifyRebaseResolutions(report, state.recipes, state.command.object_format);
    progress(state.last, report);
  } catch (error) { refusal(error); }
}
async function stopped(report, state, crypto, check) {
  check();
  strictStop(report, state.recipes, state.command.object_format);
  const value = utf8.encode(JSON.stringify(report));
  await rebasePreparationReply({ status: 409, type: 'application/json', value }, state.context.number,
    state.command, state.context.scope, crypto, state.context.head);
  check();
  if (report.stopped_commit === state.command.upstream || report.steps.some(row =>
    row.original === state.command.upstream || row.original === state.command.source_tip)) {
    candidateFail('candidate_rebase_original_frontier_changed');
  }
  verifyRebaseHistoryResult(report, state);
}
function budget(recipes, choices) {
  let count = choices.length, bytes = choices.reduce((n, row) => n + row.path_hex.length / 2 + (row.content_hex?.length ?? 0) / 2, 0);
  for (const recipe of recipes) for (const path of recipe.paths) {
    count++; bytes += path.conflict.path_hex.length / 2 + (path.bytes?.length ?? 0);
  }
  if (count > MAX_CHOICES || bytes > REBASE_CHOICE_BYTES) candidateFail('candidate_rebase_resolution_budget');
}
async function advance(state, report, action, crypto, check) {
  if (action.original !== report.stopped_commit) candidateFail('candidate_rebase_wrong_original');
  let upload, operation = 'resolve-rebase';
  if (action.action === 'resolve') {
    if (report.state !== 'conflicted') candidateFail('candidate_rebase_conflicts_required');
    budget(state.recipes, action.choices);
    const choices = action.choices.map(({ content_hex, ...row }) => content_hex === undefined ? row
      : { ...row, bytes: new Uint8Array(Buffer.from(content_hex, 'hex')) });
    upload = await rebaseResolutionUpload(report, state.command, state.context.head, state.recipes, choices, crypto, check);
    state.recipes = upload.recipes;
  } else {
    if (report.state !== 'became_empty' || action.from_empty !== state.command.empty || state.command.empty !== 'stop') {
      candidateFail('candidate_rebase_explicit_empty_transition_required');
    }
    state.command = { ...state.command, empty: action.empty };
    if (state.recipes.length) upload = rebaseRecipeUpload(state.command, state.context.head, state.recipes, crypto, check);
    else {
      operation = 'prepare-rebase';
      // The native prepare grammar has no expected_head field. Its returned
      // snapshot must still match the retained selection before any acceptance.
      upload = { bytes: utf8.encode(form(state.command)), contentType: 'application/x-www-form-urlencoded' };
    }
  }
  check(); state.last = { preparation: report, action };
  state.history.rounds.push(state.last);
  return { upload, operation };
}
function controls(options) {
  candidateKeys(options, ['crypto', 'check'], []);
  const crypto = options.crypto ?? webcrypto, check = options.check ?? (() => {});
  if (typeof check !== 'function') candidateFail('invalid_candidate_rebase_checkpoint');
  return { crypto, check };
}
async function replay(input, rawContext, crypto, check) {
  const selected = context(rawContext), history = input ?? { schema: REBASE_HISTORY_SCHEMA, rounds: [] };
  candidateKeys(history, ['schema', 'rounds']);
  if (history.schema !== REBASE_HISTORY_SCHEMA || !Array.isArray(history.rounds) || history.rounds.length > REBASE_HISTORY_MAX_ROUNDS) {
    candidateFail('candidate_rebase_history_limit');
  }
  const state = { history: { schema: REBASE_HISTORY_SCHEMA, rounds: [] }, context: selected,
    command: { ...selected.command }, recipes: [], last: null };
  for (const round of history.rounds) {
    check(); candidateKeys(round, ['preparation', 'action']);
    const action = candidateRebaseAction(round.action, state.command.object_format);
    if (!same(action, round.action)) candidateFail('noncanonical_candidate_rebase_action');
    await stopped(round.preparation, state, crypto, check);
    await advance(state, round.preparation, action, crypto, check);
  }
  check(); return state;
}

export async function replayRebaseHistory(history, selected, options = {}) {
  try {
    const { crypto, check } = controls(options); check();
    // Freeze all retained conflict reports and file hex before any WebCrypto await.
    const detached = copy({ history, selected });
    return await replay(detached.history, detached.selected, crypto, check);
  } catch (error) { refusal(error); }
}

export async function extendRebaseHistory(history, report, action, selected, options = {}) {
  try {
    const { crypto, check } = controls(options); check();
    const detached = copy({ history, report, action, selected });
    const chosen = candidateRebaseAction(detached.action, detached.selected.scope.format);
    const combined = { schema: REBASE_HISTORY_SCHEMA, rounds: [
      ...(detached.history?.rounds ?? []), { preparation: detached.report, action: chosen },
    ] };
    // The new complete capture must fit before hashing any new file or upload.
    copy(combined);
    if (combined.rounds.length > REBASE_HISTORY_MAX_ROUNDS) candidateFail('candidate_rebase_history_limit');
    const state = await replay(detached.history, detached.selected, crypto, check);
    await stopped(detached.report, state, crypto, check);
    const transport = await advance(state, detached.report, chosen, crypto, check);
    return { ...state, ...transport };
  } catch (error) { refusal(error); }
}
