#!/usr/bin/env bash
# FG-029b — forge merge-admission evidence campaign.
#
# This is a three-part harness.  The composed merge race uses the real
# `MergeEffectPackage -> admit_merge -> authority` path; the other two lanes
# retain independent checks for the lab's CAS scheduler and the admission
# snapshot-generation fence:
#
# * `forge_merge_races` schedules a competing real merge after candidate A
#   opens its authenticated snapshot and before A can CAS the authority head;
# * `dpor_authority` proves that the deterministic lab can explore and replay
#   real authority CAS schedules; and
# * `pinned_snapshot_toctou` proves, through the real admission API, that a
#   head-generation change cannot authorize a stale snapshot.
#
# The current admission route explicitly carries forge-position and outbox
# roots forward, so this campaign makes no redelivery or projection-rebuild
# claim.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init fg029b-forge-merge-races
fge_context bead frankengit-fg029b-forge-evidence-bkk
fge_context evidence_class E1
fge_context composed_merge_race crates/fgit-lab/tests/forge_merge_races.rs
fge_context merge_crash_recovery crates/fgit-lab/tests/forge_merge_races.rs
fge_context lab_schedule_harness crates/fgit-lab/tests/dpor_authority.rs
fge_context mixed_generation_corpus crates/fgit-admission/tests/pinned_snapshot_toctou.rs
fge_context admission_cas_composition covered_by:crates/fgit-lab/tests/forge_merge_races.rs
fge_context outbox_redelivery deferred_by:frankengit-asa3
fge_context projection_rebuild deferred_by:frankengit-fg093b
fge_context non_claim 'This lane proves one controlled merge-admission race, a post-effect merge-CAS crash/recovery, and final canonical ref states. It does not claim forge-position advancement, outbox redelivery, or projection rebuild.'

fge_phase setup
fge_assert_file FG-029B-E2E-001 \
  "$E2E_ROOT/../../crates/fgit-lab/tests/forge_merge_races.rs" \
  'the composed merge-race lab target is present'
fge_assert_file FG-029B-E2E-002 \
  "$E2E_ROOT/../../crates/fgit-lab/tests/dpor_authority.rs" \
  'the deterministic authority-CAS schedule harness is present'
fge_assert_file FG-029B-E2E-003 \
  "$E2E_ROOT/../../crates/fgit-admission/tests/pinned_snapshot_toctou.rs" \
  'the pinned-snapshot mixed-generation corpus is present'

fge_phase action
fge_capture forge-composed-merge-race \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-lab --test forge_merge_races -- --nocapture || true
merge_exit=$FGE_LAST_EXIT
merge_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_capture forge-lab-cas-schedules \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-lab --test dpor_authority -- --nocapture || true
lab_exit=$FGE_LAST_EXIT
lab_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_capture forge-mixed-generation-admission \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-admission --test pinned_snapshot_toctou -- --nocapture || true
admission_exit=$FGE_LAST_EXIT
admission_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_phase assert
fge_assert_exit FG-029B-E2E-004 0 "$merge_exit" \
  'the real merge-admission race reaches a terminal outcome for both candidates'
fge_assert_contains FG-029B-E2E-005 "$merge_output" \
  'test scheduled_merge_race_has_one_winner_and_no_half_merged_ref_state ... ok' \
  'the scheduled merge race observes exactly one winner and no half-merged canonical ref state'
fge_assert_contains FG-029B-E2E-006 "$merge_output" \
  'test crash_after_merge_cas_recovers_the_same_terminal_and_complete_ref_state ... ok' \
  'a post-effect merge CAS crash recovers the same terminal decision and complete canonical ref state'

fge_assert_exit FG-029B-E2E-007 0 "$lab_exit" \
  'the lab explores and replays real authority CAS schedules'
fge_assert_contains FG-029B-E2E-008 "$lab_output" \
  'test correct_clients_survive_every_interleaving ... ok' \
  'the non-defective CAS clients survive every explored schedule class'
fge_assert_contains FG-029B-E2E-009 "$lab_output" \
  'test the_counterexample_schedule_replays_the_violation ... ok' \
  'the lab exports a concrete schedule that reproduces the detected CAS defect'

fge_assert_exit FG-029B-E2E-010 0 "$admission_exit" \
  'the real admission mixed-generation corpus passes'
fge_assert_contains FG-029B-E2E-011 "$admission_output" \
  'test the_snapshot_answer_changes_with_the_head_it_is_pinned_to ... ok' \
  'the same request sees a different admission answer when its authenticated basis changes'
fge_assert_contains FG-029B-E2E-012 "$admission_output" \
  'test a_concurrent_head_change_cannot_slip_past_the_pinned_snapshot ... ok' \
  'a stale pinned snapshot cannot publish authorization after a competing head change'
fge_assert_contains FG-029B-E2E-013 "$admission_output" \
  'test a_permitted_twin_proceeds_without_the_race ... ok' \
  'the stale-snapshot refusal has an admissible no-race control'
