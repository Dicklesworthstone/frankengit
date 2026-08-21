#!/usr/bin/env bash
# FG-025b — bounded refinement safety and retry-liveness evidence campaign.
#
# `run_all.sh` discovers executable scripts beneath `suites/` recursively, so
# this is the registered suite entry without changing the frozen harness.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly TEST_NAME='refinement_campaign'
readonly RECEIPT_NAME='witness-refinement.ndjson'
readonly CAMPAIGN_SEED="${FGIT_WITNESS_CAMPAIGN_SEED:-0x00000000025bcafe}"

main() {
  local artifacts="${FGE_ARTIFACT_DIR}/witness-refinement"
  local campaign_exit=0
  local doctest_exit=0
  local receipt=''
  mkdir -p "${artifacts}"

  fge_phase setup
  fge_context suite witness-refinement
  fge_context campaign_seed "${CAMPAIGN_SEED}"
  fge_context evidence_class bounded_schedule_campaign
  fge_context corpus crates/fgit-witness/tests/corpus/refinement-schedules.tsv
  fge_context non_claim 'finite named schedules establish neither unbounded fairness nor VOI calibration'
  fge_assert_file 'FG-025B-E2E-001' \
    "${REPOSITORY_ROOT}/crates/fgit-witness/tests/refinement_campaign.rs" \
    'the independent refinement and liveness campaign test is present'
  fge_assert_file 'FG-025B-E2E-002' \
    "${REPOSITORY_ROOT}/crates/fgit-witness/tests/corpus/refinement-schedules.tsv" \
    'the schedule-bound refinement corpus is present'

  fge_phase action
  fge_capture witness-refinement-campaign \
    env \
      RCH_CARGO_WRAPPER_BYPASS=1 \
      "FGIT_WITNESS_CAMPAIGN_ARTIFACT_DIR=${artifacts}" \
      "FGIT_WITNESS_CAMPAIGN_SEED=${CAMPAIGN_SEED}" \
      cargo test --locked -p fgit-witness --test "${TEST_NAME}" -- --nocapture || campaign_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "${FGE_LAST_STDOUT_FILE}" witness-refinement-worker-stdout
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "${FGE_LAST_STDERR_FILE}" witness-refinement-worker-stderr
  fi
  fge_capture witness-sketch-type-control \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-witness --doc || doctest_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "${FGE_LAST_STDOUT_FILE}" witness-sketch-type-control-stdout
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "${FGE_LAST_STDERR_FILE}" witness-sketch-type-control-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-025B-E2E-003' 0 "${campaign_exit}" \
    'all bounded refinement-safety and retry-liveness assertions hold'
  fge_assert_exit 'FG-025B-E2E-004' 0 "${doctest_exit}" \
    'the sealed sketch type-control compile-fail doctest rejects a sketch as disjointness proof'
  fge_assert_file 'FG-025B-E2E-005' "${artifacts}/${RECEIPT_NAME}" \
    'the campaign writes its independent NDJSON receipt'
  fge_assert_ndjson 'FG-025B-E2E-006' "${artifacts}/${RECEIPT_NAME}" \
    'the campaign receipt is parseable NDJSON'
  if [[ -f "${artifacts}/${RECEIPT_NAME}" ]]; then
    receipt="$(<"${artifacts}/${RECEIPT_NAME}")"
    fge_assert_contains 'FG-025B-E2E-007' "${receipt}" \
      '"schema":"frankengit.witness-evidence.v1"' \
      'the receipt names its independently readable evidence schema'
    fge_assert_contains 'FG-025B-E2E-008' "${receipt}" \
      '"true_conflict_removals":0' \
      'exact refinement removes no true conflict in the named corpus'
    fge_assert_contains 'FG-025B-E2E-009' "${receipt}" \
      '"seeded_unsafe_refiner_caught":true' \
      'the campaign control proves the reference comparator catches an unsafe removal'
    fge_assert_contains 'FG-025B-E2E-010' "${receipt}" \
      '"starvation_schedule":"contender-before-old-v1"' \
      'the liveness claim binds its concrete adversarial schedule'
    fge_assert_contains 'FG-025B-E2E-011' "${receipt}" \
      '"all_named_participants_committed":true' \
      'every named participant commits within the schedule-bound drill'
    fge_assert_contains 'FG-025B-E2E-012' "${receipt}" \
      '"regime_reset":true' \
      'the retry controller records its stale-history reset drill'
    fge_artifact "${artifacts}/${RECEIPT_NAME}" witness-refinement-receipt
  fi
}

fge_init fg025b-witness-refinement
fge_context bead frankengit-fg025b-witness-evidence-zm8
main
