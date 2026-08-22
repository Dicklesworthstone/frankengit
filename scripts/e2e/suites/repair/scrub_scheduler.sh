#!/usr/bin/env bash
# FG-078: continuous scrub scheduling and durability-health evidence.
#
# The bead names scripts/e2e/scrub_scheduler.sh, while the frozen harness
# discovers only executable suites under scripts/e2e/suites/**. This file is
# therefore the registered form: suites-repair-scrub_scheduler. No runner
# behavior is changed to accommodate the bead wording.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='scrub_scheduler'
readonly EXPECTED_DRILLS=8

main() {
  local worker_exit=0 output=''

  fge_phase setup
  fge_assert_file 'FG-078-E2E-001' \
    "$REPOSITORY_ROOT/crates/fgit-repair/tests/$TEST_NAME.rs" \
    'the scrub and durability-health drills are checked in'

  fge_phase action
  fge_capture 'scrub-scheduler-worker' env \
    'RCH_CARGO_WRAPPER_BYPASS=1' \
    cargo test --locked -p fgit-repair --test "$TEST_NAME" \
    || worker_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" scrub-scheduler-worker-stdout
    output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi

  fge_phase assert
  fge_assert_exit 'FG-078-E2E-010' 0 "$worker_exit" \
    'the bounded scrub worker accepts permitted repair work'
  fge_assert_contains 'FG-078-E2E-011' "$output" "$EXPECTED_DRILLS passed" \
    'the complete scrub campaign ran; a shrinking test set is observable'
  fge_assert_contains 'FG-078-E2E-012' "$output" "running $EXPECTED_DRILLS tests" \
    'the scrub campaign is not vacuously empty'
  fge_assert_contains 'FG-078-E2E-013' "$output" \
    'missing_and_corrupt_placements_emit_suspects_and_reach_repair' \
    'an injected missing or corrupt placement becomes Suspect and enters repair'
  fge_assert_contains 'FG-078-E2E-014' "$output" \
    'foreground_floor_refuses_before_the_scrub_source_is_read' \
    'the foreground floor is enforced before background source work'
  fge_assert_contains 'FG-078-E2E-015' "$output" \
    'cancellation_between_targets_releases_worker_budget' \
    'cancellation releases the worker obligation rather than leaking it'
  fge_assert_contains 'FG-078-E2E-016' "$output" \
    'health_replay_tracks_injected_backlog_and_raises_threshold_alarm' \
    'lag and coverage threshold breaches produce typed health alarms'
  fge_assert_contains 'FG-078-E2E-017' "$output" \
    'drill_cadence_flags_an_overdue_class_and_a_fresh_drill_proceeds' \
    'a destructive drill overdue for this durable class is observable'
  fge_assert_contains 'FG-078-E2E-018' "$output" '0 ignored' \
    'no scrub drill is skipped'
}

fge_init fg078-scrub-scheduler
fge_context bead frankengit-fg078-scrub-scheduler-k57b
fge_context crate fgit-repair
fge_context durable_class DUR-016
fge_context evidence_class bounded_fault_and_cancellation_campaign
fge_context non_claim 'This test-double-driven campaign proves the worker boundary and repair delegation for microsegment_v1. It does not claim a durable provider implementation, media-loss recovery, a fleet-wide SLO, or a production destructive-drill cadence executor.'
main
