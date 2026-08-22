#!/usr/bin/env bash
# FG-054 — the identity-bound statistical policy framework, end to end.
#
# The bead's test plan names this script at `scripts/e2e/statistical_framework_demo.sh`.
# It lives under `suites/statistics/` instead, deliberately: `run_all.sh` states
# in its own header that discovery walks `suites/**` recursively and that
# "ANYTHING OUTSIDE `suites/` IS NOT DISCOVERED AND RUNS NOWHERE." A script at
# the path the bead names would satisfy the sentence and never execute, which is
# strictly worse than being one directory away from it. No harness edit is
# needed at this path, so the frozen `run_all.sh` and `lib.sh` are untouched.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly TEST_NAME='statistical_framework_demo'
readonly CRATE_SRC="${REPOSITORY_ROOT}/crates/fgit-statistics/src"
readonly CRATE_TESTS="${REPOSITORY_ROOT}/crates/fgit-statistics/tests"

main() {
  local tests_exit=0
  local output=''

  fge_phase setup
  fge_context suite statistical-framework
  fge_context evidence_class integer_known_answer_and_drill
  fge_context arithmetic 'integer throughout; no floating point in the mechanism or its tests'
  fge_context non_claim \
    'the retry-backoff controller demonstrates the substrate; it is not a calibrated production policy'
  fge_context non_claim \
    'CUSUM detects departure from a DECLARED target and does not adapt to an observed level'
  fge_context non_claim \
    'the evidence body has canonical bytes but no digest identity until its domain is registered in fgit-crypto'
  fge_context non_claim \
    'only regime detection is implemented; conformal bounds, e-processes, bandit selection, OPE and Lyapunov governors are not'

  # Structural: every acceptance line has a file behind it. An acceptance line
  # with nothing behind it is the failure this suite exists to make loud.
  fge_assert_file 'FG-054-E2E-001' "${CRATE_SRC}/regime.rs" \
    'the regime detector with executable assumption checks is present'
  fge_assert_file 'FG-054-E2E-002' "${CRATE_SRC}/fallback.rs" \
    'the fail-closed selection rule is present'
  fge_assert_file 'FG-054-E2E-003' "${CRATE_SRC}/evidence.rs" \
    'the typed evidence body carrying the section 8 bindings is present'
  fge_assert_file 'FG-054-E2E-004' "${CRATE_SRC}/authority.rs" \
    'the section 33.4 forbidden-decision boundary is present'
  fge_assert_file 'FG-054-E2E-005' "${CRATE_SRC}/controller.rs" \
    'the end-to-end demo controller is present'
  fge_assert_file 'FG-054-E2E-006' "${CRATE_TESTS}/controller_drill.rs" \
    'the fallback drill is present'

  fge_phase action
  fge_capture statistics-tests \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-statistics --all-targets || tests_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "${FGE_LAST_STDOUT_FILE}" statistics-tests-stdout
    # Read the file rather than FGE_LAST_STDOUT: that variable is truncated to
    # FGE_MAX_CAPTURE, and a truncated log would make the named-test assertions
    # below fail for a reason unrelated to the tests.
    output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "${FGE_LAST_STDERR_FILE}" statistics-tests-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-054-E2E-010' 0 "${tests_exit}" \
    'the statistics crate test suite passes'

  # Named-test assertions, because exit 0 is also what a run that compiled and
  # executed ZERO tests returns. Each name below stands for one acceptance line,
  # so a silently skipped file is visible rather than absorbed into a green.
  fge_assert_contains 'FG-054-E2E-011' "${output}" \
    'an_injected_regime_shift_drives_the_controller_onto_its_pinned_fallback' \
    'the fallback drill on an injected regime shift actually ran'
  fge_assert_contains 'FG-054-E2E-012' "${output}" \
    'every_forbidden_target_is_refused_by_name' \
    'the section 33.4 forbidden-target negatives actually ran'
  fge_assert_contains 'FG-054-E2E-013' "${output}" \
    'every_binding_is_load_bearing_in_the_canonical_bytes' \
    'the evidence-binding mutation test actually ran'
  fge_assert_contains 'FG-054-E2E-014' "${output}" \
    'a_configuration_that_could_saturate_is_refused_before_it_can_lie' \
    'the detector assumption checks actually ran'
  fge_assert_contains 'FG-054-E2E-015' "${output}" \
    'the_controller_produces_a_bindable_evidence_body' \
    'the loop from observations to canonical evidence bytes actually ran'

  # The permitted twin for the assertions above: they check that named tests are
  # PRESENT, which a log containing every name and zero results would also
  # satisfy. This checks no binary reported an empty run.
  fge_assert_not_contains 'FG-054-E2E-016' "${output}" \
    '0 passed' \
    'no test binary in the crate reported zero passing tests'

  fge_phase teardown
  return 0
}

fge_init fg054-statistical-framework
fge_context bead frankengit-fg054-statistical-framework-t3l
main
