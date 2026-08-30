#!/usr/bin/env bash
# =============================================================================
# FG-060: Artifact, release payload fabric, and package provenance suite
# =============================================================================
# Acceptance verification:
# - Artifact upload/download with identity verification
# - Alias publish/republish/yank as events with race-refusals on expected-value mismatch
# - Provenance chain queryable end-to-end for a fixture build-and-release flow
# - Retention/GC integration: artifact roots participate exactly like Git objects
# - Namespace-race corpus (concurrent publish of one version: exactly one winner, typed loser)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly EXPECTED_ASSERTIONS=2

main() {
  local artifacts="" worker_exit=0

  fge_phase setup
  artifacts="$FGE_ARTIFACT_DIR/artifact-provenance"
  mkdir -p "$artifacts"

  fge_phase action

  # Run the unit and integration suites in fgit-object-fabric
  fge_capture 'artifact-conformance-worker' env \
    "RCH_CARGO_WRAPPER_BYPASS=1" \
    cargo test --locked -p fgit-object-fabric --test artifact_provenance_conformance \
    || worker_exit=$?

  fge_assert_eq 'conformance-worker-exit-0' "$worker_exit" '0'

  worker_exit=0
  fge_capture 'artifact-planted-negatives-worker' env \
    "RCH_CARGO_WRAPPER_BYPASS=1" \
    cargo test --locked -p fgit-object-fabric --test artifact_planted_negatives \
    || worker_exit=$?

  fge_assert_eq 'planted-negatives-worker-exit-0' "$worker_exit" '0'

  # Acceptance-class coverage lives in the two workers above, not in labels:
  # conformance — artifact_identity_and_payload_verification,
  # package_namespace_publication_and_yank_lifecycle,
  # provenance_chain_end_to_end_query_and_verification,
  # retention_root_and_gc_sweep_lifecycle; planted negatives —
  # planted_negative_namespace_race_collision_typed_refusal,
  # planted_negative_yank_precondition_and_double_yank_refused,
  # planted_negative_broken_provenance_chain_fails_closed. The former six
  # `fge_assert '...' true` labels both called a nonexistent function (exit
  # 127) and asserted nothing (RH-5); the workers are the verification.

  fge_phase teardown
}


# Mandatory harness bootstrap (lib.sh: `fge_init` — "start a run; must be
# called first"): without it FGE_ARTIFACT_DIR is empty and the run dies at
# `mkdir -p /artifact-provenance` before any assertion, both directly and
# under run_all.sh (missing_terminal).
fge_init artifact-provenance

main "$@"
