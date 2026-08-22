#!/usr/bin/env bash
# FG-089: the shared worker-budget calculator's determinism and memory bounds.
#
# Drives `crates/fgit-resource/tests/worker_budget_determinism.rs`.
#
# What this adds beyond `cargo test` is the evidence boundary. A determinism
# suite can be green and prove nothing in three specific ways, and each has an
# assertion below:
#
#   1. It compares a result to itself, or runs a single worker count. The Rust
#      suite sweeps 1..=16 and asserts N=1 against N=max explicitly; this suite
#      asserts the drill count so a campaign that silently loses the sweep is
#      visible from the receipt alone.
#   2. It asserts that the output is stable without ever showing that anything
#      COULD have been unstable. The suite's first drill asserts that the naive
#      per-worker concatenation genuinely does diverge across worker counts, so
#      the invariance drills cannot pass vacuously. That presence case is
#      asserted by name here, because it is the one drill whose deletion would
#      quietly hollow out every other claim in the file.
#   3. It checks the memory bound at one convenient point. The property sweep
#      asserts its own denominator (6*5*4*3*3 = 1080 parameter combinations)
#      and asserts that BOTH branches were exercised - at least one fleet
#      planned and at least one below-one-job refusal - so a sweep that stopped
#      reaching the boundary fails instead of passing quietly.
#
# NON-CLAIM, recorded rather than left inferable: this suite is evidence about
# the calculator's arithmetic, not about real memory. `per_job_rss_bytes` is an
# estimate the caller declares; nothing here observes a real process, enforces
# a limit, or proves a job stays inside its estimate. A job that outgrows its
# estimate is a job-level failure for the runtime's obligation machinery.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='worker_budget_determinism'
# The drill count the Rust suite is expected to run. Asserted, not assumed.
readonly EXPECTED_DRILLS=17

main() {
  local artifacts='' worker_exit=0 output=''

  fge_phase setup
  artifacts="$FGE_ARTIFACT_DIR/worker-budgets"
  mkdir -p "$artifacts"

  fge_phase action

  # RCH_CARGO_WRAPPER_BYPASS is not optional (AGENTS.md §16.2). Without it the
  # rch offload wrapper intercepts cargo and produces a green worker whose
  # artifacts never appear locally, so assertions fail on MISSING output rather
  # than wrong output. Set from the first line rather than retrofitted.
  #
  # The only form that tests the unset case:
  #   env -u RCH_CARGO_WRAPPER_BYPASS bash scripts/e2e/suites/resource/worker_budgets.sh
  #
  # `fge_capture`, not `fge_run_ok`: the latter calls `fge_die` and would abort
  # before a single assertion ran, discarding the output this suite reads.
  fge_capture 'worker-budget-worker' env \
    "RCH_CARGO_WRAPPER_BYPASS=1" \
    cargo test --locked -p fgit-resource --test "$TEST_NAME" \
    || worker_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" worker-budget-worker-stdout
    output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi

  fge_phase assert

  fge_assert_exit 'FG-089-E2E-001' 0 "$worker_exit" \
    'the worker-budget determinism campaign passes every drill'

  # The denominator. `test result: ok. N passed` is the only place the campaign
  # states how much it actually ran.
  fge_assert_contains 'FG-089-E2E-002' "$output" "$EXPECTED_DRILLS passed" \
    'the campaign runs its full complement of drills'

  # Anchored on the full summary prefix, not the bare substring "0 passed":
  # "10 passed" and "20 passed" both CONTAIN "0 passed", so the loose form
  # would start false-failing the moment this campaign grew past nine drills.
  fge_assert_not_contains 'FG-089-E2E-003' "$output" 'test result: ok. 0 passed' \
    'the campaign is not vacuously empty'

  # Cargo's summary always contains the word "ignored" ("0 ignored"), so
  # asserting its ABSENCE would fail permanently. The honest assertion is that
  # the count is zero.
  fge_assert_contains 'FG-089-E2E-004' "$output" '0 ignored' \
    'no drill is skipped: zero #[ignore] and zero fge_skip in this campaign'

  # THE LOAD-BEARING ONE. Every invariance claim in this suite rests on the
  # presence case proving the naive order really does diverge. If that drill is
  # deleted or renamed, the remaining drills still pass while proving nothing,
  # so it is asserted by name.
  fge_assert_contains 'FG-089-E2E-005' "$output" \
    'the_naive_concatenation_really_does_diverge_across_worker_counts' \
    'the presence case that keeps the determinism drills from being vacuous is present'

  # Each contract from the bead's acceptance, asserted by drill name so a
  # silently deleted drill is visible in the receipt rather than only to
  # someone re-reading the source.
  fge_assert_contains 'FG-089-E2E-006' "$output" \
    'merged_output_is_byte_identical_across_every_worker_count' \
    'output is byte-identical across the worker-count sweep'

  fge_assert_contains 'FG-089-E2E-007' "$output" \
    'merged_output_is_identical_for_one_worker_and_the_maximum' \
    'the N=1 vs N=max case the acceptance names explicitly is drilled'

  fge_assert_contains 'FG-089-E2E-008' "$output" \
    'the_memory_bound_holds_across_the_parameter_space' \
    'the memory bound is a swept property, not a spot check'

  fge_assert_contains 'FG-089-E2E-009' "$output" \
    'planning_is_a_pure_function_of_its_inputs' \
    'the calculator consults no clock, environment, or core count'

  fge_assert_contains 'FG-089-E2E-010' "$output" \
    'every_job_is_assigned_to_exactly_one_worker' \
    'the assignment loses and duplicates nothing at any worker count'

  # Integrity refusals: a batch that lost a job must refuse, not shorten.
  fge_assert_contains 'FG-089-E2E-011' "$output" \
    'a_lost_job_is_a_refusal_rather_than_a_short_result' \
    'a dropped job is a typed refusal rather than silent truncation'

  fge_assert_contains 'FG-089-E2E-012' "$output" \
    'a_duplicated_job_is_a_refusal' \
    'a duplicated job is a typed refusal'

  fge_assert_contains 'FG-089-E2E-013' "$output" \
    'a_result_from_outside_the_batch_is_a_refusal' \
    'a result claiming an out-of-range index is a typed refusal'

  # Batch-size cap. The bound was missing from the first cut and was found by
  # comparing against fgit-doc's independent implementation; these assert that
  # the cap narrows without becoming an escape hatch.
  fge_assert_contains 'FG-089-E2E-014' "$output" \
    'a_fleet_is_never_larger_than_the_batch_it_serves' \
    'the fleet is capped by the batch it serves'

  fge_assert_contains 'FG-089-E2E-015' "$output" \
    'capping_never_raises_the_count_or_relaxes_the_memory_bound' \
    'the batch-size cap never overrides the memory bound'

  fge_assert_contains 'FG-089-E2E-016' "$output" \
    'capping_by_batch_size_shrinks_the_reservation_too' \
    'a capped fleet reserves less memory rather than carrying the uncapped figure'

  fge_assert_contains 'FG-089-E2E-017' "$output" \
    'a_batch_capped_fleet_still_merges_deterministically' \
    'the cap opens no hole in the determinism contract'

  fge_phase report
}

fge_init fg089-worker-budgets
fge_context bead frankengit-fg089-worker-budgets-m2f1
fge_context evidence_class determinism_property
fge_context denominator 'the Rust suite asserts its own parameter-space denominator (6*5*4*3*3 = 1080 combinations) and asserts both branches fired; this suite asserts the drill count, so a shrinking campaign is visible from the receipt alone'
fge_context presence_case 'the naive per-worker concatenation is asserted to DIVERGE across worker counts before any invariance claim is made, so the determinism drills cannot pass vacuously'
fge_context non_claim 'this is evidence about the calculator arithmetic, not about real memory. per_job_rss_bytes is a caller-declared estimate; nothing here observes a real process, enforces a limit, or proves a job stays inside its estimate.'
fge_context non_claim_scope 'no consumer subsystem is wired to the calculator by this suite; the shared-mechanism claim is about availability, not adoption'
main
