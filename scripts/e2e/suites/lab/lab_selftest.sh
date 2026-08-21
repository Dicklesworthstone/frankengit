#!/usr/bin/env bash
# FG-013c: the deterministic lab's coverage receipts, crashpacks, and replay.
#
# The worker this drives finds a planted authority defect by exploring the
# interleaving space, minimizes the counterexample, replays the minimized form
# and requires the SAME causal signature, then writes a versioned coverage
# receipt and a crashpack.
#
# What this suite adds beyond `cargo test` is the evidence boundary. A lab run
# can be green and still be worthless in three specific ways, and each one has
# assertions below:
#
#   1. It credits deterministic evidence for something only real execution can
#      show (parked workers, OS I/O, signals, process reaping). That is
#      proof-class inflation and it is the easiest way for a green board to
#      mean nothing.
#   2. It reports a pass while the artifacts a replay needs are missing, so
#      nobody can actually reproduce it.
#   3. It reports coverage as a count of what it reached, with no denominator,
#      so a run that touched one failpoint out of twenty reads like a run that
#      touched all twenty.
#
# The receipt is designed so that each of those is visible in the record rather
# than inferable only by re-running the campaign.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='coverage_campaign'

main() {
  local artifacts=''
  local worker_exit=0
  local receipt=''
  local crashpack=''
  local receipt_digest=''
  local crashpack_digest=''

  fge_phase setup
  artifacts="$FGE_ARTIFACT_DIR/lab-coverage"
  mkdir -p "$artifacts"

  fge_phase action

  # `fge_capture`, not `fge_run_ok`: `fge_run_ok` calls `fge_die`, which exits
  # the suite immediately and would discard the receipt and crashpack — exactly
  # the evidence this suite exists to inspect. Capturing the exit code lets
  # every assertion below still run against whatever the worker produced.
  # RCH_CARGO_WRAPPER_BYPASS is not optional here (AGENTS.md §16.2). Without it
  # the rch offload wrapper intercepts cargo, and the failure it produces is the
  # nastiest kind: the worker reports success while its artifacts never appear
  # locally, so this suite's assertions fail on a MISSING receipt rather than a
  # wrong one — and the blame lands on whichever crate was last edited.
  # ChartreuseHorizon lost real time to that shape before diagnosing it as a
  # harness fault. Do not remove this without reading their write-up.
  #
  # The test that proves it, per ChartreuseHorizon: running this suite with the
  # variable already exported proves nothing. Run
  #   env -u RCH_CARGO_WRAPPER_BYPASS bash scripts/e2e/suites/lab/lab_selftest.sh
  # which is the only form that exercises the unset case.
  fge_capture 'lab-coverage-worker' env \
    "RCH_CARGO_WRAPPER_BYPASS=1" \
    "FGIT_LAB_CAMPAIGN_ARTIFACT_DIR=$artifacts" \
    "FGIT_LAB_SOURCE_DIGEST=${FGIT_LAB_SOURCE_DIGEST:-unset-source-digest}" \
    "FGIT_LAB_TOOLCHAIN=${FGIT_LAB_TOOLCHAIN:-unset-toolchain}" \
    cargo test --locked -p fgit-lab --test "$TEST_NAME" -- --ignored || worker_exit=$?

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" lab-coverage-worker-stdout
  fi

  fge_assert_exit 'FG-013C-E2E-001' 0 "$worker_exit" \
    'the coverage campaign finds, minimizes, and replays the planted defect'

  fge_assert_file 'FG-013C-E2E-002' "$artifacts/receipt.ndjson" \
    'the campaign emits a coverage receipt'
  fge_assert_ndjson 'FG-013C-E2E-003' "$artifacts/receipt.ndjson" \
    'the coverage receipt is parseable NDJSON'
  fge_assert_file 'FG-013C-E2E-004' "$artifacts/crashpack.ndjson" \
    'the campaign emits a crashpack'
  fge_assert_ndjson 'FG-013C-E2E-005' "$artifacts/crashpack.ndjson" \
    'the crashpack is parseable NDJSON'

  if [[ -f "$artifacts/receipt.ndjson" ]]; then
    receipt="$(<"$artifacts/receipt.ndjson")"

    # Versioning: a consumer that cannot name the format must refuse it rather
    # than parse optimistically.
    fge_assert_contains 'FG-013C-E2E-006' "$receipt" '"version":"fgit-lab-receipt-v1"' \
      'the receipt names its format version'
    fge_assert_contains 'FG-013C-E2E-007' "$receipt" '"record":"lab_coverage_receipt"' \
      'the receipt identifies itself'

    # Identity: a seed only reproduces a failure against the build that
    # produced it, so all three identity fields must be present.
    fge_assert_contains 'FG-013C-E2E-008' "$receipt" '"source_digest":' \
      'the receipt binds the source it was produced from'
    fge_assert_contains 'FG-013C-E2E-009' "$receipt" '"toolchain":' \
      'the receipt binds its toolchain'
    fge_assert_contains 'FG-013C-E2E-010' "$receipt" '"runtime_profile":' \
      'the receipt binds the runtime profile'
    fge_assert_contains 'FG-013C-E2E-011' "$receipt" '"seed":' \
      'the receipt states the seed'
    fge_assert_contains 'FG-013C-E2E-012' "$receipt" '"schedule_identity":' \
      'the receipt states the schedule identity'

    # Bounds and denominators. "Explored 4 classes" is not a result without
    # the ceiling it ran under and whether it finished.
    fge_assert_contains 'FG-013C-E2E-013' "$receipt" '"max_executions":' \
      'the receipt states its execution ceiling'
    fge_assert_contains 'FG-013C-E2E-014' "$receipt" '"max_transitions":' \
      'the receipt states its transition ceiling'
    fge_assert_contains 'FG-013C-E2E-015' "$receipt" '"classes_explored":' \
      'the receipt states how much of the space was walked'
    fge_assert_contains 'FG-013C-E2E-016' "$receipt" '"classes_remaining":' \
      'the receipt states what it did not reach'
    fge_assert_contains 'FG-013C-E2E-017' "$receipt" '"exhaustive":' \
      'the receipt distinguishes an exhausted space from a truncated walk'
    fge_assert_contains 'FG-013C-E2E-018' "$receipt" '"failpoints_declared":' \
      'failpoint coverage carries its denominator'

    # The false-green the whole receipt exists to prevent: this run cannot
    # observe parked OS workers, and must say so rather than omit it.
    fge_assert_contains 'FG-013C-E2E-019' "$receipt" '"replay_completeness":"degraded"' \
      'a run missing native artifacts is degraded, not passed'
    fge_assert_contains 'FG-013C-E2E-020' "$receipt" '"present":false' \
      'the missing artifact is named in the receipt rather than silently absent'
    fge_assert_contains 'FG-013C-E2E-021' "$receipt" '"missing_artifacts":' \
      'the receipt lists what a replay would lack'

    # Deterministic evidence must not be recorded as covering a native class.
    # The worker asserts the refusal; this checks the record agrees.
    fge_assert_not_contains 'FG-013C-E2E-022' "$receipt" '"native_worker_parking"' \
      'the receipt does not claim a native class it cannot establish'
    fge_assert_not_contains 'FG-013C-E2E-023' "$receipt" '"native_io"' \
      'the receipt does not claim native I/O'
    fge_assert_contains 'FG-013C-E2E-024' "$receipt" '"native_cross_reference":' \
      'the receipt links the native evidence that covers what it cannot'

    fge_artifact "$artifacts/receipt.ndjson" lab-coverage-receipt
  fi

  if [[ -f "$artifacts/crashpack.ndjson" ]]; then
    crashpack="$(<"$artifacts/crashpack.ndjson")"

    fge_assert_contains 'FG-013C-E2E-025' "$crashpack" '"version":"fgit-lab-crashpack-v1"' \
      'the crashpack names its format version'
    fge_assert_contains 'FG-013C-E2E-026' "$crashpack" '"record":"lab_crashpack"' \
      'the crashpack identifies itself'
    fge_assert_contains 'FG-013C-E2E-027' "$crashpack" '"expected_signature":' \
      'the crashpack states the causal signature a replay must reproduce'
    fge_assert_contains 'FG-013C-E2E-028' "$crashpack" '"replay_command":' \
      'the crashpack carries one command that reproduces the failure'

    # Minimization has to have measurably reduced the counterexample, and the
    # reduction log has to show its work.
    fge_assert_contains 'FG-013C-E2E-029' "$crashpack" '"original_events":' \
      'the crashpack states how large the counterexample was'
    fge_assert_contains 'FG-013C-E2E-030' "$crashpack" '"minimized_events":' \
      'the crashpack states how large it became'
    fge_assert_contains 'FG-013C-E2E-031' "$crashpack" '"record":"lab_reduction_step"' \
      'the reduction log records each removal that was tried'

    # A fingerprint must not be mistakable for a cryptographic digest. The
    # rendering names its algorithm so a reader cannot assume sha256.
    fge_assert_contains 'FG-013C-E2E-032' "$crashpack" 'fnv1a64:' \
      'fingerprints name their algorithm rather than reading as digests'

    fge_artifact "$artifacts/crashpack.ndjson" lab-crashpack
  fi

  # Real content commitments over the written files. These are SHA-256 from the
  # harness, which is what the crashpack's own 64-bit fingerprints deliberately
  # are not.
  if [[ -f "$artifacts/receipt.ndjson" ]]; then
    receipt_digest="$(fge_digest_file "$artifacts/receipt.ndjson" || true)"
    fge_assert_ne 'FG-013C-E2E-033' '' "$receipt_digest" \
      'the receipt is committed to by content digest'
    fge_context receipt_sha256 "$receipt_digest"
  fi
  if [[ -f "$artifacts/crashpack.ndjson" ]]; then
    crashpack_digest="$(fge_digest_file "$artifacts/crashpack.ndjson" || true)"
    fge_assert_ne 'FG-013C-E2E-034' '' "$crashpack_digest" \
      'the crashpack is committed to by content digest'
    fge_context crashpack_sha256 "$crashpack_digest"
  fi
}

fge_init fg013c-lab-selftest
fge_context bead frankengit-fg013c-coverage-crashpacks-vdj
fge_context evidence_class deterministic_lab
# Stated in the receipt too, but repeated here so a reader of the suite record
# alone cannot mistake this lane for native evidence.
fge_context native_evidence not_claimed
fge_context non_claim 'deterministic lab evidence only; it says nothing about parked OS workers, real sockets, blocking-pool joins, signals, or process reaping, and the receipt refuses to be credited for those classes'
fge_context minimization 'the minimizer keeps a reduction only when the shorter counterexample fails with the SAME causal signature, so it cannot drift onto a different bug'
fge_context fingerprints 'crashpack fingerprints are FNV-1a 64-bit drift detection, NOT cryptographic commitments; the sha256 digests in this record are the real content commitments'
main
