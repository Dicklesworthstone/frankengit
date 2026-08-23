#!/usr/bin/env bash
# e2e: exercises the FG-073 effect-broker journal/reconciliation slice through
# its real crate tests and preserves their runner output as evidence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='broker'
readonly RUN_OBLIGATION='fg073-effect-broker-test-runner'

main() {
  local test_exit=0
  local output=''

  fge_phase setup
  fge_context bead frankengit-fg073-effect-broker-ledger-7kh3
  fge_context suite effect-broker-ledger
  fge_context evidence_class local_exact
  fge_context non_claim 'this in-process evidence exercises the typed broker, resource obligation, and modeled downstream channel; it is not evidence about a live external provider or durable journal publication'

  fge_phase action
  fge_obligation_open "$RUN_OBLIGATION" RunnerSlot
  fge_capture effect-broker-ledger-tests \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-agent --test "$TEST_NAME" -- --nocapture || test_exit=$?
  fge_obligation_close "$RUN_OBLIGATION"
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" effect-broker-ledger-stdout
    output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" effect-broker-ledger-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-073-E2E-001' 0 "$test_exit" \
    'the effect broker ledger test target completes successfully'
  fge_assert_contains 'FG-073-E2E-002' "$output" \
    'duplicate_effect_id_is_refused_before_a_second_budget_grant_and_permitted_twin_proceeds' \
    'a repeated EffectId refuses before another reservation while a distinct twin proceeds'
  fge_assert_contains 'FG-073-E2E-003' "$output" \
    'crash_mid_external_effect_reconciles_to_the_downstream_outcome_and_replays_history' \
    'a crash-window delivery probes downstream state and journals the typed outcome'
  fge_assert_contains 'FG-073-E2E-004' "$output" \
    'weak_downstream_unknown_probe_is_an_explicit_escalated_record_not_maybe' \
    'an unknowable weak downstream result becomes an explicit escalation rather than a fabricated success'
}

fge_init fg073-effect-broker-ledger
main
