#!/usr/bin/env bash
# e2e: FG-072 Verifier-independence classification and enforcement
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='ecc_independence'
readonly RUN_OBLIGATION='fg072-verifier-independence-test-runner'
readonly CARGO_TARGET_DIR_DEFAULT="/data/frankengit-targets/antigravity_rc"

main() {
  local target_dir="${CARGO_TARGET_DIR:-$CARGO_TARGET_DIR_DEFAULT}"
  local test_exit=0
  local output=''

  fge_phase setup
  fge_context bead frankengit-fg072-verifier-independence-0vuk
  fge_context suite verifier-independence
  fge_context evidence_class exact_deterministic_matrix
  fge_context non_claim 'Verifier independence classification is exact and deterministic over recorded facts; does not attest to physical hardware isolation beyond recorded dimension identities.'

  fge_phase action
  fge_obligation_open "$RUN_OBLIGATION" RunnerSlot
  fge_capture verifier-independence-tests \
    env CARGO_TARGET_DIR="$target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-agent --test "$TEST_NAME" -- --nocapture || test_exit=$?
  fge_obligation_close "$RUN_OBLIGATION"
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" verifier-independence-stdout
    output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" verifier-independence-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-072-E2E-001' 0 "$test_exit" \
    'the verifier independence test target completes successfully'
  fge_assert_contains 'FG-072-E2E-002' "$output" \
    'a_verifier_sharing_nothing_is_fully_independent' \
    'a verifier sharing nothing across all 7 dimensions is classified fully independent'
  fge_assert_contains 'FG-072-E2E-003' "$output" \
    'a_verifier_sharing_workspace_or_credentials_is_never_independent' \
    'shared workspace or credentials colluding pairs are detected as non-independent'
  fge_assert_contains 'FG-072-E2E-004' "$output" \
    'a_policy_requiring_independence_refuses_a_verifier_that_shares_that_dimension' \
    'policy requiring independence refuses a verifier that shares that dimension'
  fge_assert_contains 'FG-072-E2E-005' "$output" \
    'a_policy_requiring_independence_on_an_unreported_dimension_refuses_typed' \
    'policy requiring independence refuses when a dimension is unreported'
  fge_assert_contains 'FG-072-E2E-006' "$output" \
    'sharing_any_single_dimension_is_detected_and_does_not_smear' \
    'all seven dimensions are verified individually without smearing'
}

fge_init fg072-verifier-independence
main
