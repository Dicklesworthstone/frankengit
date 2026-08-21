#!/usr/bin/env bash
# FG-015c: bounded deterministic object-parser fuzz smoke evidence.
#
# The strict epoch-zero row is deliberately classified as a Git-accepts / our-
# strict-profile-refuses divergence.  The pinned upstream Git oracle checks
# that classification; it is not an ambient-Git fallback.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly PIN_ID='git-2.54.0'
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-/data/tmp/frankengit-oracle}"
readonly CORPUS="${REPOSITORY_ROOT}/crates/fgit-git-object/tests/corpus/adversarial-refusals.tsv"

main() {
  local work_root=''
  local run_directory=''
  local create_exit=0
  local init_exit=0
  local hash_exit=0
  local fsck_exit=0
  local fuzz_exit=0
  local epoch_body=''
  local epoch_oid=''

  fge_phase setup
  work_root="$(fge_tempdir object-fuzz-smoke)"
  epoch_body="${work_root}/epoch-zero.commit"
  fge_assert_file 'FG-015C-E2E-001' "${CORPUS}" \
    'the committed adversarial refusal corpus is present'
  fge_assert_contains 'FG-015C-E2E-002' "$(<"${CORPUS}")" \
    'epoch-zero-strict-divergence' \
    'the corpus explicitly retains the Git-accepts strict-profile divergence'
  fge_assert_contains 'FG-015C-E2E-003' "$(<"${CORPUS}")" \
    'git-2.54.0-fsck-strict-accepts' \
    'the divergence is bound to the pinned Git oracle observation'
  fge_capture write-epoch-zero-body bash -c \
    'printf "%s\\n" "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904" "author Epoch Zero <epoch@example.com> 0 +0000" "committer Epoch Zero <epoch@example.com> 0 +0000" "" "message" > "$1"' \
    _ "${epoch_body}"
  fge_assert_exit 'FG-015C-E2E-004' 0 "${FGE_LAST_EXIT}" \
    'the exact epoch-zero commit fixture is retained for the oracle probe'
  fge_assert_file 'FG-015C-E2E-005' "${epoch_body}" \
    'the epoch-zero probe body was written before oracle invocation'

  fge_phase action
  fge_capture oracle-create-run env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" create-run "${PIN_ID}" object-fuzz-smoke || create_exit=$?
  fge_assert_exit 'FG-015C-E2E-006' 0 "${create_exit}" \
    'the pinned Git oracle is verified before the divergence probe'
  if [[ "${create_exit}" -ne 0 ]]; then
    return 0
  fi
  run_directory="$(tr -d '\r\n' < "${FGE_LAST_STDOUT_FILE}")"

  fge_capture oracle-init env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" run "${PIN_ID}" "${run_directory}" . -- init --quiet repo || init_exit=$?
  fge_assert_exit 'FG-015C-E2E-007' 0 "${init_exit}" \
    'the pinned oracle initializes the isolated epoch-zero repository'
  if [[ "${init_exit}" -ne 0 ]]; then
    return 0
  fi
  fge_run stage-epoch-zero cp -- "${epoch_body}" "${run_directory}/work/repo/epoch-zero.commit"
  fge_assert_file 'FG-015C-E2E-008' "${run_directory}/work/repo/epoch-zero.commit" \
    'the exact fixture is staged inside the oracle workspace'

  fge_capture oracle-hash-epoch-zero env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo epoch-zero-hash -- \
    hash-object -w -t commit epoch-zero.commit || hash_exit=$?
  fge_assert_exit 'FG-015C-E2E-009' 0 "${hash_exit}" \
    'pinned Git admits the bare epoch-zero timestamp commit'
  epoch_oid="$(tr -d '\r\n' < "${run_directory}/transcripts/epoch-zero-hash/stdout.bin")"
  fge_assert_eq 'FG-015C-E2E-010' 'ad9ebc4102db7fd671a2fcdb2f7f1f62b7e90f60' "${epoch_oid}" \
    'the oracle probe retains the epoch-zero native object identity'

  fge_capture oracle-fsck-epoch-zero env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo epoch-zero-fsck -- \
    fsck --strict --no-dangling || fsck_exit=$?
  fge_assert_exit 'FG-015C-E2E-011' 0 "${fsck_exit}" \
    'pinned Git strict fsck accepts the bare epoch-zero timestamp commit'
  fge_artifact "${run_directory}/transcripts/epoch-zero-fsck/receipt.tsv" object-fuzz-oracle-receipt

  fge_capture deterministic-object-fuzz env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-git-object --test adversarial_refusal -- --nocapture || fuzz_exit=$?
  fge_assert_exit 'FG-015C-E2E-012' 0 "${fuzz_exit}" \
    'the bounded deterministic parser campaign completes without a panic'
  fge_assert_contains 'FG-015C-E2E-013' "${FGE_LAST_STDOUT}" \
    'FG-015C-FUZZ-EVIDENCE schema=frankengit.object-fuzz-evidence.v1' \
    'the test emits its fuzz evidence artifact summary'
  fge_assert_match 'FG-015C-E2E-014' "${FGE_LAST_STDOUT}" \
    'campaign_inputs=[1-9][0-9]*.*parser_calls=[1-9][0-9]*.*duration_ms=[0-9]+' \
    'the retained fuzz evidence states corpus executions and duration'
  fge_artifact "${FGE_LAST_STDOUT_FILE}" object-fuzz-evidence
}

fge_init fg015c-object-fuzz-smoke
fge_context bead frankengit-fg015c-object-fuzz-4zf
fge_context oracle_pin "${PIN_ID}"
fge_context evidence_class E3
fge_context non_claim 'bounded deterministic structured mutation and one pinned-oracle divergence probe; not coverage-guided fuzzing or full Git compatibility'
main
