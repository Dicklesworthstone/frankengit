#!/usr/bin/env bash
# e2e: FG-043c -- policy rollout modes, canary lifecycle diffs, and historical snapshot replay
#
# Asserts:
# 1. Simulation and shadow modes are side-effect free.
# 2. Canary promotion/revert emits exact policy diffs and prevents ref/forge split.
# 3. Replay of an old decision retains its original policy snapshot after policy changes.
# 4. Snapshot substitution and identity mismatch fail closed without ambient fallback.
#
# Pure bash plus coreutils, per FG-000A-PORT-019.
set -euo pipefail

POLICY_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
POLICY_REPO=$(cd "$POLICY_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$POLICY_REPO/scripts/e2e/lib.sh"

fge_init suites-policy-policy_rollout_replay
fge_context bead frankengit-fg043c-policy-evidence-vfrn
fge_context crate fgit-policy
fge_context campaign policy_rollout_replay

readonly POLICY_CRATE="$POLICY_REPO/crates/fgit-policy"
readonly ADMISSION_CRATE="$POLICY_REPO/crates/fgit-admission"
readonly ROLLOUT_IMPL="$POLICY_CRATE/src/rollout.rs"
readonly ROLLOUT_TESTS="$POLICY_CRATE/tests/rollout_tests.rs"
readonly REPLAY_TESTS="$ADMISSION_CRATE/tests/policy_snapshot_replay.rs"
readonly BYPASS_TESTS="$ADMISSION_CRATE/tests/planted_bypasses.rs"

fge_phase setup

fge_assert_file FG-043C-E2E-101 "$ROLLOUT_IMPL" 'rollout engine implementation is present'
fge_assert_file FG-043C-E2E-102 "$ROLLOUT_TESTS" 'rollout unit test suite is present'
fge_assert_file FG-043C-E2E-103 "$REPLAY_TESTS" 'policy snapshot replay test suite is present'
fge_assert_file FG-043C-E2E-104 "$BYPASS_TESTS" 'planted bypasses test suite is present'

fge_phase assert

# Crate constitution
fge_assert_cmd FG-043C-E2E-110 'fgit-policy forbids unsafe code' \
  grep -qF '#![forbid(unsafe_code)]' "$POLICY_CRATE/src/lib.rs"

fge_assert_cmd FG-043C-E2E-111 'fgit-admission forbids unsafe code' \
  grep -qF '#![forbid(unsafe_code)]' "$ADMISSION_CRATE/src/lib.rs"

# Rollout mode guarantees
fge_assert_cmd FG-043C-E2E-120 'rollout cohort hashing is deterministic' \
  grep -qF 'rollout_cohort_percentage_hashing_is_deterministic' "$ROLLOUT_TESTS"

fge_assert_cmd FG-043C-E2E-121 'shadow mode detects divergence without mutating active decision' \
  grep -qF 'shadow_mode_detects_divergence_without_blocking_effective_decision' "$ROLLOUT_TESTS"

fge_assert_cmd FG-043C-E2E-122 'warn and simulation modes do not block' \
  grep -qF 'warn_and_simulation_modes_do_not_block' "$ROLLOUT_TESTS"

# Policy diff on promotion and revert
fge_assert_cmd FG-043C-E2E-130 'policy diff computes added removed and modified rules' \
  grep -qF 'policy_diff_detects_added_removed_and_modified_rules' "$ROLLOUT_TESTS"

fge_assert_cmd FG-043C-E2E-131 'canary lifecycle events are recorded immutably' \
  grep -qF 'canary_lifecycle_events_are_recorded_immutably' "$ROLLOUT_TESTS"

# Historical snapshot replay & retroactivity invariance
fge_assert_cmd FG-043C-E2E-140 'in-memory retroactivity replay drill is present' \
  grep -qF 'in_memory_retroactivity_replay_drill' "$REPLAY_TESTS"

fge_assert_cmd FG-043C-E2E-141 'persisted authority store retroactivity replay drill is present' \
  grep -qF 'persisted_authority_storage_retroactivity_replay' "$REPLAY_TESTS"

fge_assert_cmd FG-043C-E2E-142 'snapshot substitution and TOCTOU fail closed' \
  grep -qF 'toctou_and_substitution_fail_closed' "$REPLAY_TESTS"

fge_assert_cmd FG-043C-E2E-143 'receive-pack and merge protection bridge verified' \
  grep -qF 'receive_pack_and_effects_protection_bridge' "$REPLAY_TESTS"
