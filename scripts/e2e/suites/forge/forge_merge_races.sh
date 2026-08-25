#!/usr/bin/env bash
# FG-029b — forge merge-admission evidence campaign.
#
# This is a four-part harness.  The composed merge race uses the real
# `MergeEffectPackage -> admit_merge -> authority` path; the other three lanes
# retain independent checks for the lab's CAS scheduler and the admission
# snapshot-generation fence:
#
# * `forge_merge_races` drives a seeded three-way same-PR race, lost-response
#   retry, and both sides of the synchronous authority publication boundary;
# * `dpor_authority` proves that the deterministic lab can explore and replay
#   real authority CAS schedules; and
# * `pinned_snapshot_toctou` proves, through the real admission API, that a
#   head-generation change cannot authorize a stale snapshot; and
# * `fault_campaign` plants a seeded double-success backend and proves that the
#   independent authority linearizability checker rejects the observed history.
#
# The current admission route explicitly carries forge-position and outbox
# roots forward, so this campaign makes no redelivery or projection-rebuild
# claim.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init fg029b-forge-merge-races
seed=$(fge_seed)
fg029b_target_dir="${CARGO_TARGET_DIR:-/data/frankengit-targets/fg029b-e2e}"
fge_context bead frankengit-fg029b-forge-evidence-bkk
fge_context evidence_class E1
fge_context composed_merge_race crates/fgit-admission/tests/forge_merge_races.rs
fge_context sync_merge_publication_faults crates/fgit-admission/tests/forge_merge_races.rs
fge_context n_way_schedule_seed 0x168
fge_context checker_seed "0x$seed"
fge_context lab_schedule_harness crates/fgit-lab/tests/dpor_authority.rs
fge_context mixed_generation_corpus crates/fgit-admission/tests/pinned_snapshot_toctou.rs
fge_context planted_double_winner_checker crates/fgit-authority/tests/fault_campaign.rs
fge_context admission_cas_composition covered_by:crates/fgit-admission/tests/forge_merge_races.rs
fge_context outbox_redelivery deferred_by:frankengit-asa3
fge_context projection_rebuild 'typed_non_claim: blocked on the unpublished upstream crate required by frankengit-fg093b-projection-implementation-b9vp'
fge_context non_claim 'This lane proves sync admit_merge races, response-loss convergence, and before/after authority-CAS crash recovery. It does not claim durable merge admission, forge-position advancement, outbox redelivery, or projection rebuild.'

fge_phase setup
fge_assert_file FG-029B-E2E-001 \
  "$E2E_ROOT/../../crates/fgit-admission/tests/forge_merge_races.rs" \
  'the composed merge-race admission target is present'
fge_assert_file FG-029B-E2E-002 \
  "$E2E_ROOT/../../crates/fgit-lab/tests/dpor_authority.rs" \
  'the deterministic authority-CAS schedule harness is present'
fge_assert_file FG-029B-E2E-003 \
  "$E2E_ROOT/../../crates/fgit-admission/tests/pinned_snapshot_toctou.rs" \
  'the pinned-snapshot mixed-generation corpus is present'
fge_assert_file FG-029B-E2E-004 \
  "$E2E_ROOT/../../crates/fgit-authority/tests/fault_campaign.rs" \
  'the independent planted-double-winner checker campaign is present'

fge_phase action
fge_capture forge-composed-merge-race \
  env CARGO_TARGET_DIR="$fg029b_target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-admission --test forge_merge_races -- --nocapture || true
merge_exit=$FGE_LAST_EXIT
merge_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_capture forge-lab-cas-schedules \
  env CARGO_TARGET_DIR="$fg029b_target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-lab --test dpor_authority -- --nocapture || true
lab_exit=$FGE_LAST_EXIT
lab_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_capture forge-mixed-generation-admission \
  env CARGO_TARGET_DIR="$fg029b_target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-admission --test pinned_snapshot_toctou -- --nocapture || true
admission_exit=$FGE_LAST_EXIT
admission_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_capture forge-planted-double-winner-checker \
  env CARGO_TARGET_DIR="$fg029b_target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
  "FG_AUTHORITY_FAULT_SEED=0x$seed" \
  cargo test --locked -p fgit-authority --test fault_campaign \
    seeded_double_success_bug_is_caught_by_the_same_checker -- --nocapture || true
checker_exit=$FGE_LAST_EXIT
checker_output=$(<"$FGE_LAST_STDOUT_FILE")
checker_receipt="$FGE_ARTIFACT_DIR/seeded-double-winner.ndjson"
rg '^\{"schema":"fgit.authority.fault-campaign.v1"' "$FGE_LAST_STDOUT_FILE" >"$checker_receipt" || true

fge_phase assert
fge_assert_exit FG-029B-E2E-005 0 "$merge_exit" \
  'the real merge-admission campaign reaches terminal outcomes for every contender and retry'
fge_assert_contains FG-029B-E2E-006 "$merge_output" \
  'test scheduled_merge_race_has_one_winner_and_no_half_merged_ref_state ... ok' \
  'the scheduled merge race observes exactly one winner and no half-merged canonical ref state'
fge_assert_contains FG-029B-E2E-007 "$merge_output" \
  'test seeded_three_way_merge_race_has_exactly_one_winner_for_one_pull_request ... ok' \
  'three concurrent same-PR merge attempts yield exactly one authority winner under a recorded seed'
fge_assert_contains FG-029B-E2E-008 "$merge_output" \
  'test lost_merge_response_retries_to_the_one_committed_terminal ... ok' \
  'a response lost after the sync merge CAS converges to one exact committed terminal'
fge_assert_contains FG-029B-E2E-009 "$merge_output" \
  'test crash_before_merge_cas_leaves_the_sealed_merge_undecided_for_retry ... ok' \
  'the before-effect side of the sync authority publication point leaves the sealed merge retryable'
fge_assert_contains FG-029B-E2E-010 "$merge_output" \
  'test crash_after_merge_cas_recovers_the_same_terminal_and_complete_ref_state ... ok' \
  'the after-effect side of the sync authority publication point recovers one complete terminal decision'

fge_assert_exit FG-029B-E2E-011 0 "$lab_exit" \
  'the lab explores and replays real authority CAS schedules'
fge_assert_contains FG-029B-E2E-012 "$lab_output" \
  'test correct_clients_survive_every_interleaving ... ok' \
  'the non-defective CAS clients survive every explored schedule class'
fge_assert_contains FG-029B-E2E-013 "$lab_output" \
  'test the_counterexample_schedule_replays_the_violation ... ok' \
  'the lab exports a concrete schedule that reproduces the detected CAS defect'

fge_assert_exit FG-029B-E2E-014 0 "$admission_exit" \
  'the real admission mixed-generation corpus passes'
fge_assert_contains FG-029B-E2E-015 "$admission_output" \
  'test the_snapshot_answer_changes_with_the_head_it_is_pinned_to ... ok' \
  'the same request sees a different admission answer when its authenticated basis changes'
fge_assert_contains FG-029B-E2E-016 "$admission_output" \
  'test a_concurrent_head_change_cannot_slip_past_the_pinned_snapshot ... ok' \
  'a stale pinned snapshot cannot publish authorization after a competing head change'
fge_assert_contains FG-029B-E2E-017 "$admission_output" \
  'test a_permitted_twin_proceeds_without_the_race ... ok' \
  'the stale-snapshot refusal has an admissible no-race control'

fge_assert_exit FG-029B-E2E-018 0 "$checker_exit" \
  'the seeded planted-double-winner campaign runs to its expected rejected checker verdict'
fge_assert_contains FG-029B-E2E-019 "$checker_output" \
  'test seeded_double_success_bug_is_caught_by_the_same_checker ... ok' \
  'the independent checker catches a seeded backend that reports two old-token CAS winners'
fge_assert_ndjson FG-029B-E2E-020 "$checker_receipt" \
  'the planted-double-winner checker receipt is replayable NDJSON'
fge_assert_ndjson FG-029B-E2E-021 "$FGE_LOG" \
  'the forge evidence campaign harness record is valid NDJSON'
