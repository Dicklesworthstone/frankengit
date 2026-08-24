#!/usr/bin/env bash
# FG-029b — forge merge-admission evidence campaign.
#
# This is deliberately a two-part harness while frankengit-asa3 supplies the
# production MergeEffectPackage admission/CAS seam:
#
# * `dpor_authority` proves that the deterministic lab can explore and replay
#   real authority CAS schedules; and
# * `pinned_snapshot_toctou` proves, through the real admission API, that a
#   head-generation change cannot authorize a stale snapshot.
#
# They are not presented as a composed forge-merge race.  The composed race,
# outbox redelivery, and exactly-one-winner assertions must be added only once
# asa3 exposes a real executor to drive; a test-local executor would be a
# simulation of the missing production path.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init fg029b-forge-merge-races
fge_context bead frankengit-fg029b-forge-evidence-bkk
fge_context evidence_class E1
fge_context lab_schedule_harness crates/fgit-lab/tests/dpor_authority.rs
fge_context mixed_generation_corpus crates/fgit-admission/tests/pinned_snapshot_toctou.rs
fge_context admission_cas_composition deferred_by:frankengit-asa3
fge_context outbox_redelivery deferred_by:frankengit-asa3
fge_context projection_rebuild deferred_by:frankengit-fg093b
fge_context non_claim 'The two current corpora are not a composed fgit-forge merge execution. This lane does not claim exactly-one merge winner, target-move publication, outbox redelivery, or projection rebuild.'

fge_phase setup
fge_assert_file FG-029B-E2E-001 \
  "$E2E_ROOT/../../crates/fgit-lab/tests/dpor_authority.rs" \
  'the deterministic authority-CAS schedule harness is present'
fge_assert_file FG-029B-E2E-002 \
  "$E2E_ROOT/../../crates/fgit-admission/tests/pinned_snapshot_toctou.rs" \
  'the pinned-snapshot mixed-generation corpus is present'

fge_phase action
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
fge_assert_exit FG-029B-E2E-003 0 "$lab_exit" \
  'the lab explores and replays real authority CAS schedules'
fge_assert_contains FG-029B-E2E-004 "$lab_output" \
  'test correct_clients_survive_every_interleaving ... ok' \
  'the non-defective CAS clients survive every explored schedule class'
fge_assert_contains FG-029B-E2E-005 "$lab_output" \
  'test the_counterexample_schedule_replays_the_violation ... ok' \
  'the lab exports a concrete schedule that reproduces the detected CAS defect'

fge_assert_exit FG-029B-E2E-006 0 "$admission_exit" \
  'the real admission mixed-generation corpus passes'
fge_assert_contains FG-029B-E2E-007 "$admission_output" \
  'test the_snapshot_answer_changes_with_the_head_it_is_pinned_to ... ok' \
  'the same request sees a different admission answer when its authenticated basis changes'
fge_assert_contains FG-029B-E2E-008 "$admission_output" \
  'test a_concurrent_head_change_cannot_slip_past_the_pinned_snapshot ... ok' \
  'a stale pinned snapshot cannot publish authorization after a competing head change'
fge_assert_contains FG-029B-E2E-009 "$admission_output" \
  'test a_permitted_twin_proceeds_without_the_race ... ok' \
  'the stale-snapshot refusal has an admissible no-race control'
