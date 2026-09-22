#!/usr/bin/env bash
# e2e: executes the FG-074 SubIntent delegation, ancestry verification,
# amplification refusal, aggregate budget conservation, and bounded fan-out suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='delegation'
readonly RUN_OBLIGATION='fg074-agent-delegation-test-runner'

main() {
  local test_exit=0
  local output=''

  fge_phase setup
  fge_context bead frankengit-fg074-agent-delegation-128n
  fge_context suite agent-delegation
  fge_context evidence_class local_exact
  fge_context non_claim 'delegation is verified via cryptographic HMAC capability chains and algebra bounds; this suite does not claim remote multi-machine network RPC execution'

  fge_phase action
  fge_obligation_open "$RUN_OBLIGATION" RunnerSlot
  fge_capture agent-delegation-tests \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-agent --test "$TEST_NAME" -- --nocapture || test_exit=$?
  fge_obligation_close "$RUN_OBLIGATION"
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" agent-delegation-stdout
    output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" agent-delegation-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-074-E2E-001' 0 "$test_exit" \
    'the agent delegation test target completes successfully'
  fge_assert_contains 'FG-074-E2E-002' "$output" \
    'selector_amplification_is_refused_while_narrowing_is_permitted' \
    'widening a selector is refused while narrowing is permitted'
  fge_assert_contains 'FG-074-E2E-003' "$output" \
    'missing_intermediate_capability_in_chain_is_refused' \
    'a delegation chain with missing intermediate capability is refused'
  fge_assert_contains 'FG-074-E2E-004' "$output" \
    'forged_intermediate_link_authenticator_is_refused' \
    'an intermediate link with a forged or invalid authenticator is refused'
  fge_assert_contains 'FG-074-E2E-005' "$output" \
    'aggregate_budget_conservation_property_test' \
    'aggregate budget conservation strictly holds across arbitrary sub-agent operations'
  fge_assert_contains 'FG-074-E2E-006' "$output" \
    'fan_out_bound_enforced_with_typed_refusal_at_limit' \
    'sub-intent fan-out bound is enforced with typed refusal at the limit'
  fge_assert_contains 'FG-074-E2E-007' "$output" \
    'recursion_depth_bound_enforced_hierarchically' \
    'recursion depth bound is enforced hierarchically across delegation tiers'
}

fge_init fg074-agent-delegation
main
