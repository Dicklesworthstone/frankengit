#!/usr/bin/env bash
# e2e: runs the FG-012b deterministic obligation/quiescence campaign and retains its typed receipt.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='quiescence_oracle_campaign'
readonly RECEIPT_NAME='obligation-quiescence.ndjson'
readonly CAMPAIGN_RUN_OBLIGATION='fg012b-campaign-runner'

main() {
  local artifacts=''
  local campaign_exit=0
  local receipt=''
  local receipt_digest=''
  local seed=''

  fge_phase setup
  artifacts="$FGE_ARTIFACT_DIR/obligation-quiescence"
  mkdir -p "$artifacts"
  seed="$(fge_seed)"
  fge_context suite obligation-quiescence
  fge_context campaign_seed "$seed"
  fge_context evidence_class deterministic_lab
  fge_context native_evidence not_claimed
  fge_context non_claim 'this deterministic campaign proves typed obligation settlement and logical region closure only; it does not prove OS worker, socket, process, or signal teardown'

  fge_phase action
  # The test writes its single typed campaign receipt to the supplied directory.
  # Capture rather than fail-fast so every assertion below can explain a bad or
  # missing receipt without throwing away the worker's complete transcript.
  fge_obligation_open "$CAMPAIGN_RUN_OBLIGATION" RunnerSlot
  fge_capture obligation-quiescence-campaign \
    env \
      "RCH_CARGO_WRAPPER_BYPASS=1" \
      "FGIT_OBLIGATION_CAMPAIGN_ARTIFACT_DIR=$artifacts" \
      "FGIT_OBLIGATION_CAMPAIGN_SEED=0x$seed" \
      cargo test --locked -p fgit-lab --test "$TEST_NAME" -- --nocapture || campaign_exit=$?
  fge_obligation_close "$CAMPAIGN_RUN_OBLIGATION"

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" obligation-quiescence-worker-stdout
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" obligation-quiescence-worker-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-012B-E2E-001' 0 "$campaign_exit" \
    'the all-obligation cancellation campaign completes successfully'
  fge_assert_file 'FG-012B-E2E-002' "$artifacts/$RECEIPT_NAME" \
    'the campaign writes a typed receipt rather than leaving evidence only in test diagnostics'
  fge_assert_ndjson 'FG-012B-E2E-003' "$artifacts/$RECEIPT_NAME" \
    'the typed campaign receipt is parseable NDJSON'

  if [[ -f "$artifacts/$RECEIPT_NAME" ]]; then
    receipt="$(<"$artifacts/$RECEIPT_NAME")"
    fge_assert_contains 'FG-012B-E2E-004' "$receipt" \
      '"schema":"fgit.obligation-quiescence.v1"' \
      'the receipt names its independently readable schema'
    fge_assert_contains 'FG-012B-E2E-005' "$receipt" \
      '"verdict":"quiescent"' \
      'all non-planted cancellation paths finish with no silent obligation drop'
    fge_assert_contains 'FG-012B-E2E-006' "$receipt" \
      '"obligation_classes":11' \
      'the campaign accounts for every concrete obligation class'
    fge_assert_contains 'FG-012B-E2E-007' "$receipt" \
      '"boundaries":4' \
      'the campaign covers reserve commit acknowledge and abort boundaries'
    fge_assert_contains 'FG-012B-E2E-008' "$receipt" \
      '"seeded_leaks_caught":true' \
      'the deliberately leaky variants are rejected by the same oracle'
    fge_assert_contains 'FG-012B-E2E-009' "$receipt" \
      '"replay_complete":true' \
      'the ledger trace reconstructs the campaign history exactly'
    fge_assert_contains 'FG-012B-E2E-010' "$receipt" \
      '"post_commit_retry_idempotent":true' \
      'the committed-but-unacknowledged retry preserves its idempotency key'
    fge_assert_contains 'FG-012B-E2E-011' "$receipt" \
      '"unacknowledged_record_observed":true' \
      'region close records the outstanding post-commit effect rather than silencing it'
    fge_artifact "$artifacts/$RECEIPT_NAME" obligation-quiescence-receipt
    receipt_digest="$(fge_digest_file "$artifacts/$RECEIPT_NAME" || true)"
    fge_assert_ne 'FG-012B-E2E-012' '' "$receipt_digest" \
      'the receipt has a concrete SHA-256 content commitment'
    fge_context receipt_sha256 "$receipt_digest"
  fi
}

fge_init fg012b-obligation-quiescence
fge_context bead frankengit-fg012b-quiescence-oracle-jp5
main
