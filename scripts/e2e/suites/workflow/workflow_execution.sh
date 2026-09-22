#!/usr/bin/env bash
# =============================================================================
# FG-095c: Workflow Execution, Hostile Runner, and Containment Evidence Suite
# =============================================================================
# Proves:
#   1. Live multi-job workflow DAG execution with exact BuildInputCapsules;
#   2. Fabricated success exits are refused and dependent jobs skipped;
#   3. Output capture budgets clamp misreporting workers;
#   4. Hostile runner exfiltration and ambient probes refused before admission;
#   5. Fork/PR attenuation enforces denied network and isolated cache/secrets;
#   6. Secret redaction and log containment verified without leakage;
#   7. Condition predicates (always, success, failure) evaluated correctly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

fge_init fg095c-workflow-execution
fge_context bead frankengit-fg095c-workflow-evidence-6opd
fge_context suite workflow-execution
fge_context evidence_class local_exact
fge_context non_claim 'Execution evidence verifies hermetic containment, secret redaction, fork attenuation, and step order in local container/process profiles without external cloud dependencies.'

export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/frankengit-targets/antigravity_rc}"

main() {
  local exec_exit=0 hostile_exit=0 conditions_exit=0 reuse_exit=0
  local exec_output="" hostile_output="" conditions_output="" reuse_output=""

  fge_phase setup
  fge_step setup 'initializing workflow execution evidence harness'

  fge_phase action
  fge_step action-exec 'running core workflow execution and containment suite'
  fge_capture 'workflow-exec-worker' \
    cargo test --locked -p fgit-runner --test workflow_execution -- --nocapture \
    || exec_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    exec_output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi

  fge_step action-hostile 'running hostile runner and exfiltration corpus'
  fge_capture 'hostile-corpus-worker' \
    cargo test --locked -p fgit-runner --test hostile_corpus -- --nocapture \
    || hostile_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    hostile_output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi

  fge_step action-conditions 'running condition predicate evaluation suite'
  fge_capture 'conditions-worker' \
    cargo test --locked -p fgit-runner --test workflow_conditions -- --nocapture \
    || conditions_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    conditions_output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi

  fge_step action-reuse 'running trust-domain reuse and settlement suites'
  fge_capture 'reuse-settlement-worker' \
    cargo test --locked -p fgit-runner --test reuse --test reuse_campaign --test settlement -- --nocapture \
    || reuse_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    reuse_output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi

  fge_phase assert
  fge_assert_exit 'FG-095C-EXEC-001' 0 "$exec_exit" \
    'workflow execution suite completes successfully'
  fge_assert_contains 'FG-095C-EXEC-002' "$exec_output" \
    'ordered_steps_dependency_skip_and_independent_continuation' \
    'multi-job workflow steps execute in topological order with dependency propagation'
  fge_assert_contains 'FG-095C-EXEC-003' "$exec_output" \
    'a_fabricated_success_exit_is_not_accepted_and_stops_further_jobs' \
    'a fabricated success exit is rejected and stops further dependent jobs'
  fge_assert_contains 'FG-095C-EXEC-004' "$exec_output" \
    'output_budget_is_aggregate_and_clamps_a_misreporting_worker' \
    'output budget is aggregate and clamps misreporting workers'

  fge_assert_exit 'FG-095C-EXEC-010' 0 "$hostile_exit" \
    'hostile runner corpus completes successfully'
  fge_assert_contains 'FG-095C-EXEC-011' "$hostile_output" \
    'ambient_and_metadata_exfiltration_fixtures_are_refused_before_admission' \
    'ambient credential and metadata probe fixtures are refused before admission'
  fge_assert_contains 'FG-095C-EXEC-012' "$hostile_output" \
    'forked_work_cannot_reuse_trusted_cache_or_secret_authority' \
    'forked work cannot reuse trusted cache or secret authority'
  fge_assert_contains 'FG-095C-EXEC-013' "$hostile_output" \
    'network_egress_weakening_is_refused_and_observed_egress_is_terminated' \
    'network egress weakening is refused and observed egress is terminated'

  fge_assert_exit 'FG-095C-EXEC-020' 0 "$conditions_exit" \
    'condition predicate suite completes successfully'
  fge_assert_contains 'FG-095C-EXEC-021' "$conditions_output" \
    'always_never_overrides_lost_containment' \
    'always condition never overrides lost containment'

  fge_assert_exit 'FG-095C-EXEC-030' 0 "$reuse_exit" \
    'cache reuse and settlement suite completes successfully'
  fge_assert_contains 'FG-095C-EXEC-031' "$reuse_output" \
    'trust_domains_and_nondeterministic_declarations_never_reuse_outputs' \
    'trust domains and nondeterministic declarations never reuse cached outputs'

  fge_phase teardown
  fge_note summary 'workflow execution evidence verified: step ordering, output bounding, hostile probe refusal, fork attenuation, and cache isolation'
}

main "$@"
