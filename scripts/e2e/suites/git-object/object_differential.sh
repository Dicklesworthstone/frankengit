#!/usr/bin/env bash
# FG-015B: byte-level object evidence from the separately pinned upstream-Git
# oracle. This suite is E3 corpus evidence only; a passing finite corpus is
# explicitly not a general Git-compatibility claim.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly CORPUS_GENERATOR="${REPOSITORY_ROOT}/scripts/e2e/oracle/object_corpus.sh"
readonly PIN_ID='git-2.54.0'

record_findings() {
  local finding_root="$1"
  local finding_path=''

  while IFS= read -r -d '' finding_path; do
    fge_artifact "${finding_path}" object-differential-finding
    fge_artifact "$(dirname "${finding_path}")/oracle.body" object-differential-oracle-bytes
    if [[ -f "$(dirname "${finding_path}")/frankengit.body" ]]; then
      fge_artifact "$(dirname "${finding_path}")/frankengit.body" \
        object-differential-frankengit-bytes
    fi
  done < <(find "${finding_root}" -type f -name finding.ndjson -print0)
}

run_algorithm() {
  local algorithm="$1"
  local corpus_root="$2"
  local finding_root="$3"
  local generation_exit=0
  local differential_exit=0
  local corpus_directory="${corpus_root}/corpus-${algorithm}"
  local verdict_path="${finding_root}/verdict.ndjson"

  mkdir -p "${corpus_root}" "${finding_root}"
  fge_capture "${algorithm}-corpus" "${CORPUS_GENERATOR}" generate "${PIN_ID}" \
    "${algorithm}" "${corpus_root}" || generation_exit=$?
  fge_assert_exit "FG-015B-E2E-${algorithm}-001" 0 "${generation_exit}" \
    "the pinned ${algorithm} oracle generated the declared corpus"
  fge_assert_file "FG-015B-E2E-${algorithm}-002" "${corpus_directory}/receipt.tsv" \
    "the ${algorithm} corpus carries its oracle attestation receipt"
  fge_assert_file "FG-015B-E2E-${algorithm}-003" "${corpus_directory}/manifest.tsv" \
    "the ${algorithm} corpus maps exact object bytes to native OIDs"

  if [[ "${generation_exit}" -ne 0 ]]; then
    fge_fail "FG-015B-E2E-${algorithm}-004" \
      "pinned ${algorithm} corpus unavailable; no ambient Git fallback is permitted"
    return 0
  fi

  fge_capture "${algorithm}-differential" \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    "FGIT_OBJECT_DIFFERENTIAL_CORPUS=${corpus_directory}" \
    "FGIT_OBJECT_DIFFERENTIAL_ARTIFACT_DIR=${finding_root}" \
    cargo test --locked -p fgit-git-object --test differential_oracle -- --ignored || \
    differential_exit=$?
  fge_assert_exit "FG-015B-E2E-${algorithm}-004" 0 "${differential_exit}" \
    "FrankenGit byte-round-trips every declared ${algorithm} oracle object"
  record_findings "${finding_root}"
  fge_assert_file "FG-015B-E2E-${algorithm}-005" "${verdict_path}" \
    "the ${algorithm} differential run emits a bounded verdict receipt"
  fge_assert_ndjson "FG-015B-E2E-${algorithm}-006" "${verdict_path}" \
    "the ${algorithm} verdict receipt is parseable NDJSON"
  if [[ -f "${verdict_path}" ]]; then
    local verdict=''
    verdict="$(<"${verdict_path}")"
    fge_assert_contains "FG-015B-E2E-${algorithm}-007" "${verdict}" \
      "\"algorithm\":\"${algorithm}\"" "the verdict names its hash domain"
    fge_assert_contains "FG-015B-E2E-${algorithm}-008" "${verdict}" \
      '"corpus_denominator":6' "the verdict states the corpus denominator"
    fge_assert_contains "FG-015B-E2E-${algorithm}-009" "${verdict}" \
      'E3 corpus evidence only' "the verdict preserves its non-claim boundary"
    fge_artifact "${verdict_path}" object-differential-verdict
  fi
}

fge_init fg015b-object-differential
fge_context bead frankengit-fg015b-object-differential-nsf
fge_context evidence_class E3
fge_context non_claim 'finite pinned corpus; not full Git compatibility'
fge_context oracle_pin "${PIN_ID}"
fge_phase setup

work_root="$(fge_tempdir object-differential)"

fge_phase action
run_algorithm sha1 "${work_root}/sha1" "${work_root}/findings-sha1"
run_algorithm sha256 "${work_root}/sha256" "${work_root}/findings-sha256"
