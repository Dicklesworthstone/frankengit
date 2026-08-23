#!/usr/bin/env bash
# FG-034b — public-surface adversarial corpus for runner containment receipts.
#
# This file deliberately lives under `suites/`: run_all.sh discovers only this
# tree, so a root-level `scripts/e2e/ci_hostile_corpus.sh` would silently run
# nowhere. The Rust corpus drives the real public runner contract and captures
# its transcript as an artifact.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"

readonly TEST_NAME='hostile_corpus'
readonly EXPECTED_DRILLS=6

main() {
  local worker_exit=0
  local output=''

  fge_phase setup
  fge_context suite runner-hostile-corpus
  fge_context runner_corpus_seed "$(fge_seed)"

  fge_phase action
  fge_capture runner-hostile-worker env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-runner --test "$TEST_NAME" -- --nocapture \
    || worker_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" runner-hostile-worker-stdout
    output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi

  fge_phase assert
  fge_assert_exit FG-034B-E2E-001 0 "$worker_exit" \
    'the adversarial runner corpus completes without a control-plane escape'
  fge_assert_contains FG-034B-E2E-002 "$output" \
    "test result: ok. $EXPECTED_DRILLS passed;" \
    'the corpus executes its full fixed drill denominator'
  fge_assert_not_contains FG-034B-E2E-003 "$output" 'test result: ok. 0 passed' \
    'the corpus is not vacuously empty'
  fge_assert_contains FG-034B-E2E-004 "$output" '0 ignored' \
    'no hostile drill is skipped or ignored'
  fge_assert_contains FG-034B-E2E-005 "$output" \
    'ambient_and_metadata_exfiltration_fixtures_are_refused_before_admission' \
    'ambient credentials and metadata probes are refused before launch'
  fge_assert_contains FG-034B-E2E-006 "$output" \
    'network_egress_weakening_is_refused_and_observed_egress_is_terminated' \
    'egress-policy weakening and observed egress receive typed containment'
  fge_assert_contains FG-034B-E2E-007 "$output" \
    'missing_filesystem_isolation_refuses_without_unconfined_fallback_and_revokes_secrets' \
    'unavailable filesystem isolation refuses rather than falling back unconfined'
  fge_assert_contains FG-034B-E2E-008 "$output" \
    'cancellation_reaps_the_full_observed_tree_and_keeps_the_cancelled_outcome' \
    'cancellation preserves the reaped process-tree receipt'
  fge_assert_contains FG-034B-E2E-009 "$output" \
    'forked_work_cannot_reuse_trusted_cache_or_secret_authority' \
    'forked jobs cannot poison or read through a trusted cache/secret boundary'
  fge_assert_contains FG-034B-E2E-010 "$output" \
    'stored_check_receipts_disclose_neither_secret_class_nor_secret_material' \
    'stored receipt output excludes the brokered secret class and material'
}

fge_init
fge_context bead frankengit-fg034b-ci-corpus-kzi
fge_context evidence_class adversarial_public_surface_corpus
fge_context non_claim 'This corpus does not execute an operating-system sandbox or attest a concrete Linux namespace/cgroup provider; it verifies the typed runner control plane and its ContainmentSubstrate contract only.'
fge_context non_claim_scope 'No durable cache backend or raw log store exists in this slice. Cache evidence is namespace/authority separation; log evidence is the receipt boundary that carries commitments and never raw secret values.'
fge_context cancellation_matrix 'admission rejection, isolation refusal before launch, resource termination, and cancellation after a three-process observation'
main
