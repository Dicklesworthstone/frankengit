#!/usr/bin/env bash
# FG-044c: bounded E3 evidence for fgit-diff against the separately pinned
# upstream-Git oracle. This suite never invokes an ambient Git executable.
#
# Equivalence policy (deliberately narrow): upstream patch scripts are retained
# as artifacts, but are not byte-compared. For every declared fgit-diff
# profile, applying the owned edit script must recreate the target bytes.
# `DiffProfile::Histogram` is explicitly not Git's histogram implementation;
# its semantic-only comparison is recorded as FG-044C-HISTOGRAM-PROFILE-V1.
# Git's unspecified `merge-base --all` order is similarly compared as a set to
# fgit-diff's documented ascending-ID order (FG-044C-MERGEBASE-ORDER-V1).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly PIN_ID='git-2.54.0'
readonly TEST_NAME='differential_pinned_oracle'
readonly CORPUS_SCHEMA='frankengit.diff-merge-differential-corpus.v1'
readonly DIFF_DENOMINATOR=6
readonly MERGE_DENOMINATOR=6
readonly MERGE_BASE_DENOMINATOR=2

CAPTURED_OID=''

record_findings() {
  local finding_root="$1"
  local finding_path=''
  local finding_directory=''

  while IFS= read -r -d '' finding_path; do
    finding_directory="$(dirname "${finding_path}")"
    fge_artifact "${finding_path}" diff-merge-differential-finding
    find "${finding_directory}" -maxdepth 1 -type f ! -name finding.ndjson -print0 | \
      while IFS= read -r -d '' artifact; do
        fge_artifact "${artifact}" diff-merge-differential-bytes
      done
  done < <(find "${finding_root}" -type f -name finding.ndjson -print0)
}

read_oracle_line() {
  local transcript="$1"
  local value=''

  [[ -f "${transcript}" ]] || return 1
  IFS= read -r value < "${transcript}" || return 1
  printf '%s\n' "${value}"
}

copy_if_regular() {
  local source="$1"
  local destination="$2"
  local acceptance_id="$3"
  local description="$4"

  if [[ -f "${source}" ]]; then
    cp -- "${source}" "${destination}"
    fge_assert_file "${acceptance_id}" "${destination}" "${description}"
  else
    fge_fail "${acceptance_id}" "${description}; upstream oracle transcript is missing"
  fi
}

capture_diff_profile() {
  local run_directory="$1"
  local case_name="$2"
  local profile_name="$3"
  local destination="$4"
  local exit_code=0
  local transcript=''

  fge_capture "git-diff-${profile_name}-${case_name}" \
    "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo \
    "diff-${profile_name}-${case_name}" -- \
    diff --no-index "--${profile_name}" "diff-input/${case_name}/old" \
    "diff-input/${case_name}/new" || exit_code=$?
  fge_assert_exit "FG-044C-DIFF-${case_name}-${profile_name}-001" 1 "${exit_code}" \
    "pinned Git reports the changed ${case_name} pair for ${profile_name} evidence"
  transcript="${run_directory}/transcripts/diff-${profile_name}-${case_name}/stdout.bin"
  copy_if_regular "${transcript}" "${destination}" \
    "FG-044C-DIFF-${case_name}-${profile_name}-002" \
    "the pinned Git ${profile_name} patch for ${case_name} is preserved byte-exactly"
}

register_diff_case() {
  local run_directory="$1"
  local corpus_directory="$2"
  local case_name="$3"
  local source_directory="${run_directory}/work/repo/diff-input/${case_name}"
  local corpus_case_directory="${corpus_directory}/diff/${case_name}"

  mkdir -p "${corpus_case_directory}"
  copy_if_regular "${source_directory}/old" "${corpus_case_directory}/old" \
    "FG-044C-DIFF-${case_name}-001" "the ${case_name} old bytes enter the declared corpus"
  copy_if_regular "${source_directory}/new" "${corpus_case_directory}/new" \
    "FG-044C-DIFF-${case_name}-002" "the ${case_name} new bytes enter the declared corpus"
  capture_diff_profile "${run_directory}" "${case_name}" minimal \
    "${corpus_case_directory}/git-minimal.patch"
  capture_diff_profile "${run_directory}" "${case_name}" histogram \
    "${corpus_case_directory}/git-histogram.patch"
  printf '%s\tdiff/%s/old\tdiff/%s/new\tdiff/%s/git-minimal.patch\tdiff/%s/git-histogram.patch\n' \
    "${case_name}" "${case_name}" "${case_name}" "${case_name}" "${case_name}" \
    >> "${corpus_directory}/diff-manifest.tsv"
}

prepare_diff_inputs() {
  local run_directory="$1"
  local input_root="${run_directory}/work/repo/diff-input"

  mkdir -p "${input_root}" \
    "${input_root}/crlf" "${input_root}/no-newline" "${input_root}/unicode" \
    "${input_root}/binary-ish" "${input_root}/huge-line" "${input_root}/text-edit"

  printf 'alpha\nbeta\ngamma\n' > "${input_root}/text-edit/old"
  printf 'alpha\nBETA\ngamma\ndelta\n' > "${input_root}/text-edit/new"
  printf 'one\r\ntwo\r\nthree\r\n' > "${input_root}/crlf/old"
  printf 'zero\r\none\r\ntwo\r\nthree\r\n' > "${input_root}/crlf/new"
  printf 'left\nlast' > "${input_root}/no-newline/old"
  printf 'left\nchanged' > "${input_root}/no-newline/new"
  printf 'café\n雪\n' > "${input_root}/unicode/old"
  printf 'café\n月\n雪\n' > "${input_root}/unicode/new"
  printf 'head\0middle\n' > "${input_root}/binary-ish/old"
  printf 'head\0changed\n' > "${input_root}/binary-ish/new"
  {
    printf 'prefix\n'
    head -c 16384 /dev/zero | tr '\0' x
    printf '\ntail-old\n'
  } > "${input_root}/huge-line/old"
  {
    printf 'prefix\n'
    head -c 16384 /dev/zero | tr '\0' x
    printf '\ntail-new\n'
  } > "${input_root}/huge-line/new"
}

capture_merge_case() {
  local run_directory="$1"
  local corpus_directory="$2"
  local case_name="$3"
  local expected_exit="$4"
  local source_directory="${run_directory}/work/repo/merge-input/${case_name}"
  local corpus_case_directory="${corpus_directory}/merge/${case_name}"
  local exit_code=0
  local transcript=''

  mkdir -p "${corpus_case_directory}"
  copy_if_regular "${source_directory}/base" "${corpus_case_directory}/base" \
    "FG-044C-MERGE-${case_name}-001" "the ${case_name} base bytes enter the corpus"
  copy_if_regular "${source_directory}/ours" "${corpus_case_directory}/ours" \
    "FG-044C-MERGE-${case_name}-002" "the ${case_name} ours bytes enter the corpus"
  copy_if_regular "${source_directory}/theirs" "${corpus_case_directory}/theirs" \
    "FG-044C-MERGE-${case_name}-003" "the ${case_name} theirs bytes enter the corpus"
  fge_capture "git-merge-file-${case_name}" \
    "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo "merge-${case_name}" -- \
    merge-file -p --diff3 "merge-input/${case_name}/ours" \
    "merge-input/${case_name}/base" "merge-input/${case_name}/theirs" || exit_code=$?
  fge_assert_exit "FG-044C-MERGE-${case_name}-004" "${expected_exit}" "${exit_code}" \
    "pinned Git classifies ${case_name} with the declared clean/conflict outcome"
  transcript="${run_directory}/transcripts/merge-${case_name}/stdout.bin"
  copy_if_regular "${transcript}" "${corpus_case_directory}/git-merge-file.out" \
    "FG-044C-MERGE-${case_name}-005" "the pinned Git merge-file output is preserved"
  printf '%s\t%s\tmerge/%s/base\tmerge/%s/ours\tmerge/%s/theirs\tmerge/%s/git-merge-file.out\n' \
    "${case_name}" "${expected_exit}" "${case_name}" "${case_name}" "${case_name}" "${case_name}" \
    >> "${corpus_directory}/merge-manifest.tsv"
}

prepare_merge_inputs() {
  local run_directory="$1"
  local input_root="${run_directory}/work/repo/merge-input"

  mkdir -p "${input_root}" \
    "${input_root}/clean-text" "${input_root}/crlf" "${input_root}/unicode" \
    "${input_root}/no-newline" "${input_root}/huge-line" "${input_root}/conflict"

  printf 'alpha\nbeta\ngamma\n' > "${input_root}/clean-text/base"
  printf 'ALPHA\nbeta\ngamma\n' > "${input_root}/clean-text/ours"
  printf 'alpha\nbeta\nGAMMA\n' > "${input_root}/clean-text/theirs"

  printf 'one\r\ntwo\r\nthree\r\n' > "${input_root}/crlf/base"
  printf 'ONE\r\ntwo\r\nthree\r\n' > "${input_root}/crlf/ours"
  printf 'one\r\ntwo\r\nTHREE\r\n' > "${input_root}/crlf/theirs"

  printf 'café\n雪\n' > "${input_root}/unicode/base"
  printf 'café\n月\n' > "${input_root}/unicode/ours"
  printf 'café\n雪\nfin\n' > "${input_root}/unicode/theirs"

  printf 'left\nright' > "${input_root}/no-newline/base"
  printf 'LEFT\nright' > "${input_root}/no-newline/ours"
  printf 'left\nright\nend' > "${input_root}/no-newline/theirs"

  {
    printf 'prefix\n'
    head -c 8192 /dev/zero | tr '\0' x
    printf '\ntail\n'
  } > "${input_root}/huge-line/base"
  {
    printf 'OURS\n'
    head -c 8192 /dev/zero | tr '\0' x
    printf '\ntail\n'
  } > "${input_root}/huge-line/ours"
  {
    printf 'prefix\n'
    head -c 8192 /dev/zero | tr '\0' x
    printf '\nTHEIRS\n'
  } > "${input_root}/huge-line/theirs"

  printf 'shared\n' > "${input_root}/conflict/base"
  printf 'ours\n' > "${input_root}/conflict/ours"
  printf 'theirs\n' > "${input_root}/conflict/theirs"
}

capture_commit() {
  local run_directory="$1"
  local label="$2"
  shift 2
  local exit_code=0
  local transcript="${run_directory}/transcripts/${label}/stdout.bin"
  local oid=''

  fge_capture "git-${label}" "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo \
    "${label}" -- "$@" || exit_code=$?
  fge_assert_exit "FG-044C-MERGEBASE-${label}-001" 0 "${exit_code}" \
    "the pinned oracle creates graph node ${label}"
  oid="$(read_oracle_line "${transcript}" || true)"
  fge_assert_match "FG-044C-MERGEBASE-${label}-002" "${oid}" '^[0-9a-f]{40}$' \
    "the pinned oracle emits a SHA-1 object ID for ${label}"
  CAPTURED_OID="${oid}"
}

prepare_merge_base_corpus() {
  local run_directory="$1"
  local corpus_directory="$2"
  local empty_tree=''
  local root=''
  local left=''
  local right=''
  local ours=''
  local theirs=''
  local exit_code=0
  local transcript=''

  fge_capture git-empty-index "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- \
    read-tree --empty || exit_code=$?
  fge_assert_exit FG-044C-MERGEBASE-EMPTYINDEX-001 0 "${exit_code}" \
    'the pinned oracle prepares an empty index without reading ambient stdin'
  exit_code=0
  fge_capture git-empty-tree "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo \
    empty-tree -- write-tree || exit_code=$?
  fge_assert_exit FG-044C-MERGEBASE-EMPTYTREE-001 0 "${exit_code}" \
    'the pinned oracle creates the empty tree required by the generated DAG'
  empty_tree="$(read_oracle_line "${run_directory}/transcripts/empty-tree/stdout.bin" || true)"
  fge_assert_match FG-044C-MERGEBASE-EMPTYTREE-002 "${empty_tree}" '^[0-9a-f]{40}$' \
    'the generated DAG starts from a pinned-oracle tree object'

  capture_commit "${run_directory}" graph-root commit-tree "${empty_tree}" -m root
  root="${CAPTURED_OID}"
  capture_commit "${run_directory}" graph-left commit-tree "${empty_tree}" -p "${root}" -m left
  left="${CAPTURED_OID}"
  capture_commit "${run_directory}" graph-right commit-tree "${empty_tree}" -p "${root}" -m right
  right="${CAPTURED_OID}"
  capture_commit "${run_directory}" graph-ours commit-tree "${empty_tree}" -p "${left}" -p "${right}" -m ours
  ours="${CAPTURED_OID}"
  capture_commit "${run_directory}" graph-theirs commit-tree "${empty_tree}" -p "${right}" -p "${left}" -m theirs
  theirs="${CAPTURED_OID}"

  mkdir -p "${corpus_directory}/merge-base"
  {
    printf '# id\toid\tparents\n'
    printf 'root\t%s\t-\n' "${root}"
    printf 'left\t%s\t%s\n' "${left}" "${root}"
    printf 'right\t%s\t%s\n' "${right}" "${root}"
    printf 'ours\t%s\t%s,%s\n' "${ours}" "${left}" "${right}"
    printf 'theirs\t%s\t%s,%s\n' "${theirs}" "${right}" "${left}"
  } > "${corpus_directory}/merge-base/graph.tsv"

  fge_capture git-merge-base-linear "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo \
    merge-base-linear -- merge-base --all "${ours}" "${left}" || exit_code=$?
  fge_assert_exit FG-044C-MERGEBASE-LINEAR-001 0 "${exit_code}" \
    'the pinned oracle resolves the generated linear merge-base query'
  transcript="${run_directory}/transcripts/merge-base-linear/stdout.bin"
  copy_if_regular "${transcript}" "${corpus_directory}/merge-base/git-linear.out" \
    FG-044C-MERGEBASE-LINEAR-002 'the pinned linear merge-base output is preserved'

  exit_code=0
  fge_capture git-merge-base-criss-cross "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo \
    merge-base-criss-cross -- merge-base --all "${ours}" "${theirs}" || exit_code=$?
  fge_assert_exit FG-044C-MERGEBASE-CRISSCROSS-001 0 "${exit_code}" \
    'the pinned oracle resolves all bases for the generated criss-cross DAG'
  transcript="${run_directory}/transcripts/merge-base-criss-cross/stdout.bin"
  copy_if_regular "${transcript}" "${corpus_directory}/merge-base/git-criss-cross.out" \
    FG-044C-MERGEBASE-CRISSCROSS-002 'the pinned criss-cross merge-base output is preserved'

  {
    printf '# label\tleft\tright\toracle_output\n'
    printf 'linear\t%s\t%s\tmerge-base/git-linear.out\n' "${ours}" "${left}"
    printf 'criss-cross\t%s\t%s\tmerge-base/git-criss-cross.out\n' "${ours}" "${theirs}"
  } > "${corpus_directory}/merge-base/query-manifest.tsv"
}

write_corpus_receipt() {
  local corpus_directory="$1"
  local run_directory="$2"
  local oracle_receipt="${run_directory%/runs/*}/installs/${PIN_ID}/receipt.tsv"

  [[ -f "${oracle_receipt}" ]] || {
    fge_fail FG-044C-RECEIPT-001 'the oracle installation receipt is available for corpus provenance'
    return
  }
  cp -- "${oracle_receipt}" "${corpus_directory}/oracle-receipt.tsv"
  {
    printf 'schema=%s\n' "${CORPUS_SCHEMA}"
    printf 'pin_id=%s\n' "${PIN_ID}"
    printf 'diff_case_denominator=%s\n' "${DIFF_DENOMINATOR}"
    printf 'merge_case_denominator=%s\n' "${MERGE_DENOMINATOR}"
    printf 'merge_base_case_denominator=%s\n' "${MERGE_BASE_DENOMINATOR}"
    printf 'equivalence_policy=apply_to target bytes; Git patches retained but not byte-compared\n'
    printf 'accepted_divergence=FG-044C-HISTOGRAM-PROFILE-V1: owned Histogram differs by design from Git histogram; semantic replay only\n'
    printf 'accepted_divergence=FG-044C-MERGEBASE-ORDER-V1: compare Git merge-base --all as a set to ascending owned ID order\n'
    printf 'accepted_divergence=FG-044C-CRISSCROSS-VIRTUALBASE-V1: RecursiveConflictPreservingV1 may conflict where Git resolves cleanly\n'
    printf 'non_claim=finite E3 corpus evidence; not full Git diff or merge compatibility\n'
  } > "${corpus_directory}/receipt.tsv"
}

run_worker() {
  local corpus_directory="$1"
  local finding_directory="$2"
  local receipt_path="${finding_directory}/verdict.ndjson"
  local worker_exit=0
  local receipt=''

  fge_capture fgit-diff-differential \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    "FGIT_DIFF_DIFFERENTIAL_CORPUS=${corpus_directory}" \
    "FGIT_DIFF_DIFFERENTIAL_ARTIFACT_DIR=${finding_directory}" \
    cargo test --locked -p fgit-diff --test "${TEST_NAME}" -- --ignored || worker_exit=$?
  fge_assert_exit FG-044C-WORKER-001 0 "${worker_exit}" \
    'the pure-Rust engine replays every declared diff, merge-base, merge, and refusal cell'
  record_findings "${finding_directory}"
  fge_assert_file FG-044C-WORKER-002 "${receipt_path}" \
    'the differential worker emits a typed bounded receipt'
  fge_assert_ndjson FG-044C-WORKER-003 "${receipt_path}" \
    'the differential receipt is parseable NDJSON'
  if [[ -f "${receipt_path}" ]]; then
    receipt="$(<"${receipt_path}")"
    fge_assert_contains FG-044C-WORKER-004 "${receipt}" '"diff_case_denominator":6' \
      'the receipt states the exact diff corpus denominator'
    fge_assert_contains FG-044C-WORKER-005 "${receipt}" '"merge_case_denominator":6' \
      'the receipt states the exact merge corpus denominator'
    fge_assert_contains FG-044C-WORKER-006 "${receipt}" '"merge_base_case_denominator":2' \
      'the receipt states the exact generated-DAG denominator'
    fge_assert_contains FG-044C-WORKER-007 "${receipt}" \
      'FG-044C-HISTOGRAM-PROFILE-V1' \
      'the histogram non-isomorphism is retained as an explicit semantic declaration'
    fge_assert_contains FG-044C-WORKER-008 "${receipt}" \
      'FG-044C-CRISSCROSS-VIRTUALBASE-V1' \
      'the criss-cross virtual-base divergence is explicit rather than silently widened'
    fge_artifact "${receipt_path}" diff-merge-differential-verdict
  fi
}

main() {
  local work_root=''
  local run_directory=''
  local corpus_directory=''
  local finding_directory=''
  local create_exit=0
  local init_exit=0

  fge_phase setup
  work_root="$(fge_tempdir diff-merge-differential)"
  corpus_directory="${work_root}/corpus"
  finding_directory="${FGE_ARTIFACT_DIR}/diff-merge-differential"
  mkdir -p "${corpus_directory}/diff" "${corpus_directory}/merge" "${finding_directory}"
  printf '# case\told\tnew\tgit_minimal_patch\tgit_histogram_patch\n' > "${corpus_directory}/diff-manifest.tsv"
  printf '# case\texpected_exit\tbase\tours\ttheirs\tgit_output\n' > "${corpus_directory}/merge-manifest.tsv"

  fge_phase action
  fge_capture create-pinned-oracle-run "${ORACLE}" create-run "${PIN_ID}" diff-merge || create_exit=$?
  fge_assert_exit FG-044C-ORACLE-001 0 "${create_exit}" \
    'the pinned upstream-Git oracle is fully verified before corpus generation'
  if [[ "${create_exit}" -ne 0 ]]; then
    fge_fail FG-044C-ORACLE-002 'the E3 corpus cannot fall back to an ambient Git executable'
    return 0
  fi
  run_directory="$(tr -d '\r\n' < "${FGE_LAST_STDOUT_FILE}")"
  fge_assert_match FG-044C-ORACLE-003 "${run_directory}" '^/.+/.+$' \
    'the oracle supplies a private absolute run directory'

  fge_capture initialize-oracle-repository "${ORACLE}" run "${PIN_ID}" "${run_directory}" . -- \
    init --quiet repo || init_exit=$?
  fge_assert_exit FG-044C-ORACLE-004 0 "${init_exit}" \
    'the pinned oracle initializes the generated differential repository'
  if [[ "${init_exit}" -ne 0 ]]; then
    return 0
  fi
  fge_capture configure-oracle-user "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- \
    config user.name 'FrankenGit Differential Oracle' || true
  fge_assert_exit FG-044C-ORACLE-005 0 "${FGE_LAST_EXIT}" \
    'the generated history has deterministic oracle identity metadata'
  fge_capture configure-oracle-email "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- \
    config user.email 'diff-oracle@invalid.example' || true
  fge_assert_exit FG-044C-ORACLE-006 0 "${FGE_LAST_EXIT}" \
    'the generated history has deterministic oracle email metadata'

  prepare_diff_inputs "${run_directory}"
  register_diff_case "${run_directory}" "${corpus_directory}" text-edit
  register_diff_case "${run_directory}" "${corpus_directory}" crlf
  register_diff_case "${run_directory}" "${corpus_directory}" no-newline
  register_diff_case "${run_directory}" "${corpus_directory}" unicode
  register_diff_case "${run_directory}" "${corpus_directory}" binary-ish
  register_diff_case "${run_directory}" "${corpus_directory}" huge-line

  prepare_merge_inputs "${run_directory}"
  capture_merge_case "${run_directory}" "${corpus_directory}" clean-text 0
  capture_merge_case "${run_directory}" "${corpus_directory}" crlf 0
  capture_merge_case "${run_directory}" "${corpus_directory}" unicode 1
  capture_merge_case "${run_directory}" "${corpus_directory}" no-newline 1
  capture_merge_case "${run_directory}" "${corpus_directory}" huge-line 0
  capture_merge_case "${run_directory}" "${corpus_directory}" conflict 1

  prepare_merge_base_corpus "${run_directory}" "${corpus_directory}"
  write_corpus_receipt "${corpus_directory}" "${run_directory}"
  fge_assert_file FG-044C-CORPUS-001 "${corpus_directory}/receipt.tsv" \
    'the corpus receipt names all denominators and accepted divergences'
  fge_assert_eq FG-044C-CORPUS-002 "${DIFF_DENOMINATOR}" \
    "$(grep -cv '^#' "${corpus_directory}/diff-manifest.tsv")" \
    'the source-derived diff manifest has the declared denominator'
  fge_assert_eq FG-044C-CORPUS-003 "${MERGE_DENOMINATOR}" \
    "$(grep -cv '^#' "${corpus_directory}/merge-manifest.tsv")" \
    'the source-derived merge manifest has the declared denominator'
  fge_assert_eq FG-044C-CORPUS-004 "${MERGE_BASE_DENOMINATOR}" \
    "$(grep -cv '^#' "${corpus_directory}/merge-base/query-manifest.tsv")" \
    'the source-derived merge-base manifest has the declared denominator'

  run_worker "${corpus_directory}" "${finding_directory}"
}

fge_init fg044c-merge-evidence
fge_context bead frankengit-fg044c-merge-evidence-utkg
fge_context evidence_class E3
fge_context oracle_pin "${PIN_ID}"
fge_context equivalence_policy 'apply owned edit scripts to reproduce target bytes; retain Git patch bytes without claiming script identity'
fge_context accepted_divergences 'FG-044C-HISTOGRAM-PROFILE-V1,FG-044C-MERGEBASE-ORDER-V1,FG-044C-CRISSCROSS-VIRTUALBASE-V1'
fge_context non_claim 'finite pinned corpus; not full Git diff, merge-base, or merge compatibility'
main
