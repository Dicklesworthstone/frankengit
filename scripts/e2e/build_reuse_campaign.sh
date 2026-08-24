#!/usr/bin/env bash
# e2e: FG-040b bounded campaign for trust-scoped runner output reuse.
#
# This root-level path is explicitly included by run_all.sh because the bead
# names it as the stable campaign entry point. It is not discovery coverage:
# the runner contains the one named invocation below so removal is visible.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh}"

readonly TEST_NAME='reuse_campaign'
readonly EXPECTED_DRILLS=4

main() {
  local worker_exit=0
  local output=''
  local artifact_dir=''
  local economics=''

  fge_phase setup
  fge_context suite runner-build-reuse-campaign
  fge_context campaign_seed "$(fge_seed)"
  fge_context workload '24 distinct warm-cache runner capsules; fixed containment observations; one-half deterministic spot-check schedule'
  fge_context economics_scope 'bounded runner control-plane latency and execution-count accounting only'
  artifact_dir=$(fge_tempdir build-reuse-campaign)
  economics="$artifact_dir/reuse-economics.txt"
  : >"$economics"

  fge_phase action
  fge_capture reuse-campaign-worker env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-runner --test "$TEST_NAME" -- --nocapture \
    || worker_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" reuse-campaign-worker-stdout
    output="$(<"$FGE_LAST_STDOUT_FILE")"
    grep '^reuse-campaign-economics ' "$FGE_LAST_STDOUT_FILE" >"$economics" || true
  fi
  fge_artifact "$economics" reuse-campaign-economics

  fge_phase assert
  fge_assert_exit FG-040B-E2E-001 0 "$worker_exit" \
    'the bounded reuse campaign completes without a poisoning or bypass acceptance'
  fge_assert_contains FG-040B-E2E-002 "$output" \
    "test result: ok. $EXPECTED_DRILLS passed;" \
    'the full fixed campaign denominator executes'
  fge_assert_contains FG-040B-E2E-003 "$output" \
    'trusted_output_cannot_poison_an_untrusted_reuse_namespace' \
    'trusted output cannot be accepted through an untrusted cache namespace'
  fge_assert_contains FG-040B-E2E-004 "$output" \
    'nondeterministic_and_release_verification_reuse_attempts_are_refused' \
    'declared nondeterminism and release verification structurally refuse reuse'
  fge_assert_contains FG-040B-E2E-005 "$output" \
    'spot_check_mismatch_quarantines_and_emits_negative_evidence' \
    'the sampled mismatch drill detects, reevaluates, quarantines, and records evidence'
  fge_assert_file FG-040B-E2E-006 "$economics" \
    'the campaign writes its bounded economics artifact'
  fge_assert_cmd FG-040B-E2E-007 \
    'economics artifact binds its schema and representative workload identity' \
    grep -qF 'schema=frankengit.reuse.economics.v1' "$economics"
  fge_assert_cmd FG-040B-E2E-008 \
    'economics artifact records hit rate, latency, and spot-check execution overhead' \
    grep -qF 'hit_rate_ppm=' "$economics"
  fge_assert_cmd FG-040B-E2E-009 \
    'economics artifact records the cost model instead of claiming a universal speedup' \
    grep -qF 'spot_check_runner_executions=' "$economics"
  fge_assert_cmd FG-040B-E2E-010 \
    'economics artifact retains its bounded applicability non-claim' \
    grep -qF 'claim=bounded-control-plane-only' "$economics"
}

fge_init fg040b-build-reuse-campaign
fge_context bead frankengit-fg040b-reuse-campaign-ox7
fge_context evidence_class bounded_adversarial_and_economics_campaign
fge_context non_claim 'This campaign does not measure a hosted CI fleet, production cache backend, concrete OS isolation provider, target-native release matrix, or universal performance improvement.'
main
