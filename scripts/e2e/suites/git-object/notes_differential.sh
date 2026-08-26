#!/usr/bin/env bash
# FG-084a: byte-level notes evidence from the separately pinned upstream-Git
# oracle (frankengit-pbui). E3 corpus evidence only; a passing finite corpus
# is explicitly not a general Git-compatibility claim.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly CORPUS_GENERATOR="${REPOSITORY_ROOT}/scripts/e2e/oracle/notes_corpus.sh"
readonly PIN_ID='git-2.54.0'

run_algorithm() {
  local algorithm="$1"
  local corpus_root="$2"
  local finding_root="$3"
  local corpus_directory="${corpus_root}/corpus-${algorithm}"
  local generation_exit=0

  mkdir -p "${corpus_root}" "${finding_root}"
  fge_capture "${algorithm}-notes-corpus" "${CORPUS_GENERATOR}" generate \
    "${PIN_ID}" "${algorithm}" "${corpus_root}" \
    "$(oracle_run_dir_for "${algorithm}")" || generation_exit=$?
  if [[ "${generation_exit}" -ne 0 ]]; then
    fge_fail "FG084A-E2E-${algorithm}-001" \
      "pinned ${algorithm} notes corpus unavailable; no ambient Git fallback is permitted"
    return 0
  fi
  fge_assert_file "FG084A-E2E-${algorithm}-002" \
    "${corpus_directory}/receipt.tsv" \
    "the ${algorithm} notes corpus carries its oracle attestation receipt"

  FGIT_NOTES_DIFFERENTIAL_CORPUS="${corpus_directory}" \
    cargo test -p fgit-git-object --test notes_differential -- --ignored
  fge_assert_exit "FG084A-E2E-${algorithm}-003" 0 "$?" \
    "differential test matches the pinned ${algorithm} oracle"
}

oracle_run_dir_for() {
  # Run directories are operator-created via `oracle.sh create-run`; the
  # suite accepts the location through the environment so operators can pin
  # one verified run per lane.
  echo "${FGIT_NOTES_ORACLE_RUN_DIR:?set FGIT_NOTES_ORACLE_RUN_DIR to an oracle.sh create-run directory}"
}

if [[ "${1:-}" == "--list-cases" ]]; then
  printf 'FG084A-E2E-sha1-001..003\nFG084A-E2E-sha256-001..003\n'
  exit 0
fi

ALGORITHMS=("${@:-sha1 sha256}")
CORPUS_ROOT="${FGIT_NOTES_CORPUS_ROOT:-$(mktemp -d)}"
FINDING_ROOT="${FGIT_NOTES_FINDING_ROOT:-$(mktemp -d)}"

for algorithm in "${ALGORITHMS[@]}"; do
  run_algorithm "${algorithm}" "${CORPUS_ROOT}" "${FINDING_ROOT}"
done
