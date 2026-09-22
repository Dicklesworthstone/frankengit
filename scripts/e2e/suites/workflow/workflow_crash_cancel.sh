#!/usr/bin/env bash
# =============================================================================
# FG-095c: Workflow Crash Recovery, Cancellation, and Quiescence Suite
# =============================================================================
# Proves:
#   1. Request -> drain -> finalize cancellation lifecycle for queued and running runs;
#   2. Concurrency group cancel-in-progress preempts superseded runs cleanly;
#   3. Coordinator crash recovery marks in-flight runs reaped and invalidates stale heads;
#   4. Process tree reaping upon cancellation with zero surviving detached tasks;
#   5. Missing isolation refuses without unconfined fallback and revokes secrets;
#   6. Spawn boundary cancellation executes nothing;
#   7. Timeout reaps child without false quiescence claims.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

fge_init fg095c-workflow-crash-cancel
fge_context bead frankengit-fg095c-workflow-evidence-6opd
fge_context suite workflow-crash-cancel
fge_context evidence_class local_exact
fge_context non_claim 'Crash, cancellation, and drain evidence verifies process tree reaping, timeout enforcement, state machine invalidation, and quiescence without surviving detached obligations in local execution profiles.'

export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/frankengit-targets/antigravity_rc}"

main() {
  local coord_exit=0 hostile_exit=0 proc_exit=0
  local coord_output="" hostile_output="" proc_output=""

  fge_phase setup
  fge_step setup 'initializing workflow crash and cancellation evidence harness'

  fge_phase action
  fge_step action-coordinator-lifecycle 'running coordinator cancellation and crash recovery lifecycle'
  fge_capture 'coordinator-cancel-worker' \
    cargo test --locked -p fgit-runner --test workflow_coordinator -- --nocapture \
    || coord_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    coord_output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi

  fge_step action-hostile-containment 'running hostile runner cancellation and tree reaping suite'
  fge_capture 'hostile-reap-worker' \
    cargo test --locked -p fgit-runner --test hostile_corpus -- --nocapture \
    || hostile_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    hostile_output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi

  fge_step action-process-cancellation 'running process execution cancellation and timeout containment'
  fge_capture 'process-cancel-worker' \
    cargo test --locked -p fgit-runner --test workflow_execution process:: -- --nocapture \
    || proc_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    proc_output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi

  fge_phase assert
  fge_assert_exit 'FG-095C-CANCEL-001' 0 "$coord_exit" \
    'coordinator cancellation and crash recovery suite completes successfully'
  fge_assert_contains 'FG-095C-CANCEL-002' "$coord_output" \
    'request_drain_finalize_cancellation_lifecycle' \
    'request-drain-finalize lifecycle closes queued and running runs'
  fge_assert_contains 'FG-095C-CANCEL-003' "$coord_output" \
    'concurrency_group_cancel_in_progress_preempts_older_run' \
    'concurrency group cancel-in-progress preempts older in-flight run'
  fge_assert_contains 'FG-095C-CANCEL-004' "$coord_output" \
    'crash_recovery_marks_inflight_runs_as_reaped_and_invalidates_stale_heads' \
    'crash recovery marks in-flight runs reaped and invalidates stale authority heads'

  fge_assert_exit 'FG-095C-CANCEL-010' 0 "$hostile_exit" \
    'hostile runner cancellation and tree containment suite completes successfully'
  fge_assert_contains 'FG-095C-CANCEL-011' "$hostile_output" \
    'cancellation_reaps_the_full_observed_tree_and_keeps_the_cancelled_outcome' \
    'cancellation reaps full observed process tree and preserves cancelled terminal outcome'
  fge_assert_contains 'FG-095C-CANCEL-012' "$hostile_output" \
    'missing_filesystem_isolation_refuses_without_unconfined_fallback_and_revokes_secrets' \
    'missing filesystem isolation refuses without unconfined fallback and revokes secrets'

  fge_assert_exit 'FG-095C-CANCEL-020' 0 "$proc_exit" \
    'process execution cancellation and timeout suite completes successfully'
  fge_assert_contains 'FG-095C-CANCEL-021' "$proc_output" \
    'cancellation_at_spawn_boundary_executes_nothing' \
    'cancellation at spawn boundary executes nothing'
  fge_assert_contains 'FG-095C-CANCEL-022' "$proc_output" \
    'timeout_reaps_direct_child_without_claiming_descendant_quiescence' \
    'timeout reaps child process without false quiescence claim'

  fge_phase teardown
  fge_note summary 'workflow crash and cancellation evidence verified: request-drain-finalize lifecycle, crash invalidation, process tree reaping, and zero detached obligations'
}

main "$@"
