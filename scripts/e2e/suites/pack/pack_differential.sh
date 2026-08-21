#!/usr/bin/env bash
# FG-016c E3 pack differential evidence. The generator uses only the pinned,
# Bubblewrap-isolated Git oracle; the Rust test consumes its emitted bytes and
# never shells out to Git.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly PIN_ID='git-2.54.0'

oracle_oid() {
  local transcript=$1
  local oid=''
  IFS= read -r oid < "${transcript}/stdout.bin"
  [[ "${oid}" =~ ^[0-9a-f]{40}$ || "${oid}" =~ ^[0-9a-f]{64}$ ]] || {
    printf 'pack differential: oracle emitted invalid OID\n' >&2
    return 64
  }
  printf '%s\n' "${oid}"
}

write_similar_blob() {
  local path=$1
  local suffix=$2
  local index=0
  : > "${path}"
  for ((index = 0; index < 1024; index++)); do
    printf 'shared differential line %04d\n' "${index}" >> "${path}"
  done
  printf 'variant=%s\n' "${suffix}" >> "${path}"
}

capture_hash_object() {
  local run_directory=$1
  local label=$2
  local object_type=$3
  local body_path=$4
  "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo "${label}" -- \
    hash-object -w -t "${object_type}" --stdin < "${body_path}"
  oracle_oid "${run_directory}/transcripts/${label}"
}

record_object() {
  local run_directory=$1
  local corpus=$2
  local label=$3
  local object_type=$4
  local oid=$5
  local output="bodies/${label}.body"

  "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo "body-${label}" -- \
    cat-file "${object_type}" "${oid}"
  cp -- "${run_directory}/transcripts/body-${label}/stdout.bin" "${corpus}/${output}"
  printf '%s\t%s\t%s\n' "${oid}" "${object_type}" "${output}" >> "${corpus}/manifest.tsv"
}

generate_case() {
  local algorithm=$1
  local delta_kind=$2
  local corpus=$3
  local run_directory=''
  local base_blob=''
  local head_blob=''
  local base_tree=''
  local head_tree=''
  local base_commit=''
  local head_commit=''
  local output_hash=''
  local delta_flag=''
  local oracle_root=''
  local -a pack_arguments=()

  case "${algorithm}" in sha1|sha256) ;; *) return 64 ;; esac
  case "${delta_kind}" in ofs) delta_flag='--delta-base-offset' ;; ref) ;; *) return 64 ;; esac
  [[ "${corpus}" == /* && "${corpus}" != / && ! -e "${corpus}" ]] || return 64
  mkdir -p "${corpus}/bodies" "${corpus}/inputs"
  run_directory="$("${ORACLE}" create-run "${PIN_ID}" "pack-${algorithm}-${delta_kind}")"
  mkdir -p "${run_directory}/work/repo/packs"
  "${ORACLE}" run "${PIN_ID}" "${run_directory}" . -- init --quiet "--object-format=${algorithm}" repo
  "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- config user.name 'FrankenGit Pack Oracle'
  "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- config user.email 'pack-oracle@invalid.example'

  write_similar_blob "${corpus}/inputs/base.blob" base
  base_blob="$(capture_hash_object "${run_directory}" base-blob blob "${corpus}/inputs/base.blob")"
  printf '100644 blob %s\tpayload\n' "${base_blob}" > "${corpus}/inputs/base.tree"
  "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo base-tree -- mktree < "${corpus}/inputs/base.tree"
  base_tree="$(oracle_oid "${run_directory}/transcripts/base-tree")"
  {
    printf 'tree %s\n' "${base_tree}"
    printf 'author Pack Oracle <pack-oracle@invalid.example> 0 +0000\n'
    printf 'committer Pack Oracle <pack-oracle@invalid.example> 0 +0000\n\n'
    printf 'base commit\n'
  } > "${corpus}/inputs/base.commit"
  base_commit="$(capture_hash_object "${run_directory}" base-commit commit "${corpus}/inputs/base.commit")"

  write_similar_blob "${corpus}/inputs/head.blob" head
  head_blob="$(capture_hash_object "${run_directory}" head-blob blob "${corpus}/inputs/head.blob")"
  printf '100644 blob %s\tpayload\n' "${head_blob}" > "${corpus}/inputs/head.tree"
  "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo head-tree -- mktree < "${corpus}/inputs/head.tree"
  head_tree="$(oracle_oid "${run_directory}/transcripts/head-tree")"
  {
    printf 'tree %s\nparent %s\n' "${head_tree}" "${base_commit}"
    printf 'author Pack Oracle <pack-oracle@invalid.example> 1 +0000\n'
    printf 'committer Pack Oracle <pack-oracle@invalid.example> 1 +0000\n\n'
    printf 'head commit\n'
  } > "${corpus}/inputs/head.commit"
  head_commit="$(capture_hash_object "${run_directory}" head-commit commit "${corpus}/inputs/head.commit")"
  "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- update-ref refs/heads/main "${head_commit}"

  pack_arguments=(pack-objects --all --window=10 --depth=10)
  [[ -n "${delta_flag}" ]] && pack_arguments+=("${delta_flag}")
  pack_arguments+=("packs/${delta_kind}")
  "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo "pack-${delta_kind}" -- \
    "${pack_arguments[@]}"
  output_hash="$(oracle_oid "${run_directory}/transcripts/pack-${delta_kind}")"
  cp -- "${run_directory}/work/repo/packs/${delta_kind}-${output_hash}.pack" "${corpus}/pack.pack"
  cp -- "${run_directory}/work/repo/packs/${delta_kind}-${output_hash}.idx" "${corpus}/pack.idx"

  printf '# fgit-pack-differential-manifest-v1\n' > "${corpus}/manifest.tsv"
  record_object "${run_directory}" "${corpus}" base-blob blob "${base_blob}"
  record_object "${run_directory}" "${corpus}" base-tree tree "${base_tree}"
  record_object "${run_directory}" "${corpus}" base-commit commit "${base_commit}"
  record_object "${run_directory}" "${corpus}" head-blob blob "${head_blob}"
  record_object "${run_directory}" "${corpus}" head-tree tree "${head_tree}"
  record_object "${run_directory}" "${corpus}" head-commit commit "${head_commit}"
  oracle_root="${run_directory%/runs/*}"
  cp -- "${oracle_root}/installs/${PIN_ID}/receipt.tsv" "${corpus}/oracle-receipt.tsv"
  {
    printf 'schema=frankengit.pack-differential-corpus.v1\n'
    printf 'algorithm=%s\n' "${algorithm}"
    printf 'delta_kind=%s\n' "${delta_kind}"
    printf 'corpus_denominator=6\n'
    printf 'oracle_pin=%s\n' "${PIN_ID}"
    printf 'oracle_attestation=operator-receipt-copied\n'
    printf 'oracle_run_directory=%s\n' "${run_directory}"
    printf 'non_claim=E3 corpus evidence only; no full Git compatibility claim\n'
  } > "${corpus}/receipt.tsv"
}

receipt_value() {
  local receipt=$1
  local key=$2
  local line=''
  while IFS= read -r line || [[ -n "${line}" ]]; do
    case "${line}" in "${key}"=*) printf '%s\n' "${line#*=}"; return 0 ;; esac
  done < "${receipt}"
  return 64
}

manifest_oid() {
  local manifest=$1
  local expected_body=$2
  local oid=''
  local object_type=''
  local body=''
  while IFS=$'\t' read -r oid object_type body; do
    [[ "${body}" == "${expected_body}" ]] && { printf '%s\n' "${oid}"; return 0; }
  done < "${manifest}"
  return 64
}

generate_thin_case() {
  local full_corpus=$1
  local thin_corpus=$2
  local run_directory=''
  local algorithm=''
  local base_oid=''
  local head_oid=''
  local oracle_root=''

  [[ -f "${full_corpus}/receipt.tsv" && ! -e "${thin_corpus}" ]] || return 64
  run_directory="$(receipt_value "${full_corpus}/receipt.tsv" oracle_run_directory)"
  algorithm="$(receipt_value "${full_corpus}/receipt.tsv" algorithm)"
  base_oid="$(manifest_oid "${full_corpus}/manifest.tsv" bodies/base-blob.body)"
  head_oid="$(manifest_oid "${full_corpus}/manifest.tsv" bodies/head-blob.body)"
  mkdir -p "${thin_corpus}/bodies"
  printf '%s\n^%s\n' "${head_oid}" "${base_oid}" | \
    "${ORACLE}" capture "${PIN_ID}" "${run_directory}" repo pack-thin -- \
      pack-objects --thin --stdout --revs --window=10 --depth=10
  cp -- "${run_directory}/transcripts/pack-thin/stdout.bin" "${thin_corpus}/thin.pack"
  cp -- "${full_corpus}/bodies/base-blob.body" "${thin_corpus}/bodies/base-blob.body"
  cp -- "${full_corpus}/bodies/head-blob.body" "${thin_corpus}/bodies/head-blob.body"
  printf '%s\tblob\tbodies/head-blob.body\n' "${head_oid}" > "${thin_corpus}/thin-manifest.tsv"
  printf '%s\tblob\tbodies/base-blob.body\n' "${base_oid}" > "${thin_corpus}/external-base.tsv"
  oracle_root="${run_directory%/runs/*}"
  cp -- "${oracle_root}/installs/${PIN_ID}/receipt.tsv" "${thin_corpus}/oracle-receipt.tsv"
  {
    printf 'schema=frankengit.pack-differential-corpus.v1\n'
    printf 'algorithm=%s\n' "${algorithm}"
    printf 'case_kind=thin_ref_delta\n'
    printf 'corpus_denominator=1\n'
    printf 'oracle_pin=%s\n' "${PIN_ID}"
    printf 'oracle_attestation=operator-receipt-copied\n'
    printf 'non_claim=E3 corpus evidence only; no full Git compatibility claim\n'
  } > "${thin_corpus}/receipt.tsv"
}

if [[ "${1:-}" == 'generate-case' ]]; then
  [[ "$#" -eq 4 ]] || exit 64
  generate_case "$2" "$3" "$4"
  exit 0
fi

if [[ "${1:-}" == 'generate-thin' ]]; then
  [[ "$#" -eq 3 ]] || exit 64
  generate_thin_case "$2" "$3"
  exit 0
fi

run_case() {
  local algorithm=$1
  local delta_kind=$2
  local work_root=$3
  local corpus="${work_root}/${algorithm}-${delta_kind}"
  local artifact_directory="${work_root}/findings-${algorithm}-${delta_kind}"
  local generation_exit=0
  local differential_exit=0
  local prefix="FG-016C-E2E-${algorithm}-${delta_kind}"

  fge_capture "generate-${algorithm}-${delta_kind}" "$0" generate-case "${algorithm}" "${delta_kind}" "${corpus}" || generation_exit=$?
  fge_assert_exit "${prefix}-001" 0 "${generation_exit}" \
    "the attested pinned oracle generated the ${algorithm} ${delta_kind} corpus"
  fge_assert_file "${prefix}-002" "${corpus}/oracle-receipt.tsv" \
    'the corpus records its operator/build oracle attestation'
  fge_assert_file "${prefix}-003" "${corpus}/pack.pack" \
    'the corpus retains exact upstream Git pack bytes'
  fge_assert_file "${prefix}-004" "${corpus}/pack.idx" \
    'the corpus retains the matching upstream Git idx bytes'

  if [[ "${generation_exit}" -ne 0 ]]; then
    fge_fail "${prefix}-005" 'pinned oracle unavailable; no ambient Git fallback is permitted'
    return 0
  fi

  mkdir -p -- "${artifact_directory}"
  fge_capture "differential-${algorithm}-${delta_kind}" \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    "FGIT_PACK_DIFFERENTIAL_CORPUS=${corpus}" \
    "FGIT_PACK_DIFFERENTIAL_ARTIFACT_DIR=${artifact_directory}" \
    cargo test --locked -p fgit-pack --test differential_oracle \
      pinned_oracle_pack_matches_all_manifest_bytes_oids_and_idx_entries -- --ignored --nocapture || differential_exit=$?
  fge_assert_exit "${prefix}-005" 0 "${differential_exit}" \
    'the Rust reader reproduces every oracle object, OID, and idx association'
  fge_assert_file "${prefix}-006" "${artifact_directory}/verdict.ndjson" \
    'the differential run records its denominator receipt'
  if [[ -f "${artifact_directory}/verdict.ndjson" ]]; then
    local verdict=''
    verdict="$(<"${artifact_directory}/verdict.ndjson")"
    fge_assert_contains "${prefix}-007" "${verdict}" '"corpus_denominator":6' \
      'the receipt states the exact six-object corpus denominator'
    fge_assert_contains "${prefix}-008" "${verdict}" 'E3 corpus evidence only' \
      'the receipt preserves the finite-corpus non-claim'
    fge_artifact "${artifact_directory}/verdict.ndjson" pack-differential-verdict
  fi
}

run_thin_case() {
  local algorithm=$1
  local full_corpus=$2
  local work_root=$3
  local corpus="${work_root}/${algorithm}-thin"
  local artifact_directory="${work_root}/findings-${algorithm}-thin"
  local generation_exit=0
  local differential_exit=0
  local prefix="FG-016C-E2E-${algorithm}-thin"

  fge_capture "generate-${algorithm}-thin" "$0" generate-thin "${full_corpus}" "${corpus}" || generation_exit=$?
  fge_assert_exit "${prefix}-001" 0 "${generation_exit}" \
    "the pinned oracle generated the ${algorithm} thin-pack corpus"
  fge_assert_file "${prefix}-002" "${corpus}/thin.pack" \
    'the thin corpus retains exact upstream Git pack bytes'
  fge_assert_file "${prefix}-003" "${corpus}/external-base.tsv" \
    'the thin corpus records the caller-supplied base'
  if [[ "${generation_exit}" -ne 0 ]]; then
    fge_fail "${prefix}-004" 'pinned oracle unavailable; no ambient Git fallback is permitted'
    return 0
  fi
  mkdir -p -- "${artifact_directory}"
  fge_capture "differential-${algorithm}-thin" \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    "FGIT_PACK_DIFFERENTIAL_CORPUS=${corpus}" \
    "FGIT_PACK_DIFFERENTIAL_ARTIFACT_DIR=${artifact_directory}" \
    cargo test --locked -p fgit-pack --test differential_oracle \
      pinned_oracle_thin_pack_requires_its_caller_supplied_base -- --ignored --nocapture || differential_exit=$?
  fge_assert_exit "${prefix}-004" 0 "${differential_exit}" \
    'the reader reconstructs the thin target only through its external base'
  fge_assert_file "${prefix}-005" "${artifact_directory}/verdict.ndjson" \
    'the thin differential records its denominator receipt'
}

run_large_offset_case() {
  local algorithm=$1
  local corpus=$2
  local work_root=$3
  local artifact_directory="${work_root}/findings-${algorithm}-large-offset"
  local differential_exit=0
  local prefix="FG-016C-E2E-${algorithm}-large-offset"

  mkdir -p -- "${artifact_directory}"
  fge_capture "differential-${algorithm}-large-offset" \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    "FGIT_PACK_DIFFERENTIAL_CORPUS=${corpus}" \
    "FGIT_PACK_DIFFERENTIAL_ARTIFACT_DIR=${artifact_directory}" \
    cargo test --locked -p fgit-pack --test differential_oracle \
      attested_oracle_entry_exercises_idx_v2_large_offset_indirection -- --ignored --nocapture || differential_exit=$?
  fge_assert_exit "${prefix}-001" 0 "${differential_exit}" \
    'an attested upstream entry survives a synthetic idx-v2 large-offset indirection'
  fge_assert_file "${prefix}-002" "${artifact_directory}/verdict.ndjson" \
    'the large-offset indirection cell records its scope-limited receipt'
  if [[ -f "${artifact_directory}/verdict.ndjson" ]]; then
    local verdict=''
    verdict="$(<"${artifact_directory}/verdict.ndjson")"
    fge_assert_contains "${prefix}-003" "${verdict}" \
      'synthetic_idx_v2_large_offset_indirection' \
      'the receipt states that the cell is idx indirection, not a >2GiB pack claim'
  fi
}

fge_init fg016c-pack-differential
fge_context bead frankengit-fg016c-pack-differential-md7
fge_context evidence_class E3
fge_context non_claim 'finite pinned corpus; not full Git compatibility'
fge_context oracle_pin "${PIN_ID}"
fge_phase setup
work_root="$(fge_tempdir pack-differential)"

fge_phase action
run_case sha1 ofs "${work_root}"
run_case sha1 ref "${work_root}"
run_case sha256 ofs "${work_root}"
run_case sha256 ref "${work_root}"
run_thin_case sha1 "${work_root}/sha1-ref" "${work_root}"
run_thin_case sha256 "${work_root}/sha256-ref" "${work_root}"
run_large_offset_case sha1 "${work_root}/sha1-ofs" "${work_root}"
run_large_offset_case sha256 "${work_root}/sha256-ofs" "${work_root}"

fuzz_exit=0
fge_capture deterministic-pack-fuzz \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-pack --test fuzz_deterministic -- --nocapture || fuzz_exit=$?

fge_phase assert
fge_assert_exit FG-016C-E2E-FUZZ-001 0 "${fuzz_exit}" \
  'the signed seeded pack mutation corpus returns only acceptance or typed refusal'
fuzz_output=$FGE_LAST_STDOUT$'\n'$FGE_LAST_STDERR
fge_assert_contains FG-016C-E2E-FUZZ-002 "${fuzz_output}" \
  '"corpus_denominator":256' 'the fuzz receipt states its exact denominator'
fge_assert_contains FG-016C-E2E-FUZZ-003 "${fuzz_output}" \
  '"re_signed_structural_cases":205' \
  'every non-trailer case carried a recomputed native pack trailer'
fge_assert_contains FG-016C-E2E-FUZZ-004 "${fuzz_output}" \
  '"delta_resolver_cases":52' \
  're-signed payload mutations traversed inflation and the OFS delta resolver'
