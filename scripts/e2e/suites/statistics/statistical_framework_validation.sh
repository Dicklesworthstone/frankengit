#!/usr/bin/env bash
# FG-054b — per-mechanism statistical validation campaign with an NDJSON receipt.
#
# The bead names this script at `scripts/e2e/statistical_framework_validation.sh`.
# It lives under `suites/statistics/` for the reason `run_all.sh` states in its
# own header: discovery walks `suites/**`, and "ANYTHING OUTSIDE `suites/` IS NOT
# DISCOVERED AND RUNS NOWHERE." A script at the named path satisfies the sentence
# and never executes.
#
# This suite differs from `statistical_framework_demo.sh` in what it trusts. The
# demo asserts on captured stdout, which proves named tests ran. This one asserts
# on a STRUCTURED RECEIPT the campaign emits, so coverage is machine-readable per
# mechanism rather than inferred from log text — and a campaign that quietly
# stopped covering a mechanism fails on the denominator instead of shrinking.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly TEST_NAME='statistical_framework_validation'
readonly RECEIPT_NAME='statistics-validation.ndjson'

# Every mechanism the campaign must account for. The e2e lane keeps its own copy
# deliberately: if the campaign drops a mechanism, a list derived from the
# campaign's own output would shrink with it and report green.
readonly EXPECTED_MECHANISMS=(
  'cusum-regime-detection'
  'split-conformal-bounds'
  'e-process-alarm'
  'successive-elimination'
  'off-policy-evaluation'
  'beta-bernoulli-posterior'
  'lyapunov-progress-governor'
  'deterministic-fallback-gate'
)

main() {
  local artifacts="${FGE_ARTIFACT_DIR}/statistics-validation"
  local campaign_exit=0
  local receipt=''
  local receipt_path=''
  mkdir -p "${artifacts}"

  fge_phase setup
  fge_context suite statistical-validation
  fge_context evidence_class per_mechanism_known_answer_and_seeded
  fge_context arithmetic 'integer throughout; the campaign generator is an LCG and is not a distribution claim'
  fge_context non_claim \
    'the seeded streams establish invariants under a reproducible spread of values, not distributional coverage'
  fge_context non_claim \
    'Beta-Bernoulli expected loss is not implemented; see NEG-025 for the measured failure of the fixed-point approach'

  fge_assert_file 'FG-054B-E2E-001' \
    "${REPOSITORY_ROOT}/crates/fgit-statistics/tests/validation_campaign.rs" \
    'the per-mechanism validation campaign is present'

  fge_phase action
  fge_capture statistics-validation-campaign \
    env \
      RCH_CARGO_WRAPPER_BYPASS=1 \
      "FGIT_STATISTICS_CAMPAIGN_ARTIFACT_DIR=${artifacts}" \
      cargo test --locked -p fgit-statistics --test validation_campaign || campaign_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "${FGE_LAST_STDOUT_FILE}" statistics-validation-stdout
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "${FGE_LAST_STDERR_FILE}" statistics-validation-stderr
  fi
  receipt_path="${artifacts}/${RECEIPT_NAME}"

  fge_phase assert
  fge_assert_exit 'FG-054B-E2E-010' 0 "${campaign_exit}" \
    'the per-mechanism validation campaign passes'
  fge_assert_file 'FG-054B-E2E-011' "${receipt_path}" \
    'the campaign writes its NDJSON receipt'
  fge_assert_ndjson 'FG-054B-E2E-012' "${receipt_path}" \
    'the campaign receipt is parseable NDJSON'

  if [[ -f "${receipt_path}" ]]; then
    receipt="$(<"${receipt_path}")"

    # One assertion per mechanism, from the suite's OWN list, so a campaign that
    # dropped a mechanism fails here rather than reporting a smaller success.
    local index=1
    local mechanism
    for mechanism in "${EXPECTED_MECHANISMS[@]}"; do
      fge_assert_contains "FG-054B-E2E-1$(printf '%02d' "${index}")" "${receipt}" \
        "\"mechanism\":\"${mechanism}\"" \
        "the receipt accounts for ${mechanism}"
      index=$((index + 1))
    done

    # The denominator. A receipt naming every mechanism could still be a
    # partial run if the campaign emitted extra or duplicate lines.
    local lines
    lines=$(grep -c '"mechanism"' "${receipt_path}" 2>/dev/null || echo 0)
    fge_assert_eq 'FG-054B-E2E-020' "${#EXPECTED_MECHANISMS[@]}" "${lines}" \
      'the receipt carries exactly one record per expected mechanism'

    # Outcome, and the twin: every record must be a pass, and the campaign must
    # not be able to report a pass without having exercised anything.
    fge_assert_not_contains 'FG-054B-E2E-021' "${receipt}" \
      '"outcome":"fail"' \
      'no mechanism reported a failing outcome'
    fge_assert_not_contains 'FG-054B-E2E-022' "${receipt}" \
      '"known_answer_cases":0' \
      'no mechanism was recorded with zero known-answer cases'

    fge_artifact "${receipt_path}" statistics-validation-receipt
  fi

  fge_phase teardown
  return 0
}

fge_init fg054b-statistical-validation
fge_context bead frankengit-un75
main
