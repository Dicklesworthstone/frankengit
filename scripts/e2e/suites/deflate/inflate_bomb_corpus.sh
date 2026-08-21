#!/usr/bin/env bash
# FG-092: real loose-object interoperability and bounded decompression evidence.
#
# This suite intentionally has no host-Git or fixture-only fallback. Its object
# corpus and both reader/writer observations are produced through the separately
# pinned, Bubblewrap-isolated upstream-Git oracle.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly ORACLE="$REPOSITORY_ROOT/scripts/e2e/oracle/oracle.sh"
readonly CORPUS_GENERATOR="$REPOSITORY_ROOT/scripts/e2e/oracle/object_corpus.sh"
readonly PIN_ID='git-2.54.0'
readonly TEST_NAME='loose_object_differential'

copy_oracle_objects() {
  local corpus_directory="$1"
  local run_directory="$2"
  local manifest_path="$3"
  local worker_manifest="$4"
  local label=''
  local object_type=''
  local oid=''
  local relative_body=''
  local extra=''
  local body_path=''
  local input_path=''
  local loose_path=''
  local transcript_path=''
  local oid_prefix=''
  local oid_suffix=''
  local actual_oid=''
  local object_count=0
  local row_number=0

  mkdir -p "$run_directory/work/repo/input"
  : > "$worker_manifest"
  while IFS=$'\t' read -r label object_type oid relative_body extra; do
    [[ -n "$label" ]] || continue
    [[ "$label" == \#* ]] && continue
    row_number=$((row_number + 1))
    if [[ -z "$object_type" || -z "$oid" || -z "$relative_body" || -n "$extra" ]]; then
      fge_fail "FG-092-E2E-MANIFEST-$row_number" \
        'the pinned corpus manifest has exactly four object fields'
      continue
    fi
    if [[ ! "$oid" =~ ^[0-9a-f]{40}$ || "$relative_body" != objects/* || "$relative_body" == *..* ]]; then
      fge_fail "FG-092-E2E-MANIFEST-$row_number" \
        'the pinned corpus manifest has a safe SHA-1 object path'
      continue
    fi
    body_path="$corpus_directory/$relative_body"
    input_path="$run_directory/work/repo/input/$label.body"
    fge_run "stage-$label" cp -- "$body_path" "$input_path" || true
    fge_assert_file "FG-092-E2E-$label-001" "$input_path" \
      "the pinned oracle $label body is staged inside its sandbox"

    fge_capture "materialize-$label" "$ORACLE" capture "$PIN_ID" "$run_directory" repo \
      "materialize-$label" -- hash-object -w -t "$object_type" "input/$label.body" || true
    transcript_path="$run_directory/transcripts/materialize-$label/stdout.bin"
    actual_oid="$(tr -d '\r\n' < "$transcript_path")"
    fge_assert_eq "FG-092-E2E-$label-002" "$oid" "$actual_oid" \
      "the pinned oracle materializes the declared $label loose object"

    oid_prefix="$(printf '%s' "$oid" | cut -c1-2)"
    oid_suffix="$(printf '%s' "$oid" | cut -c3-)"
    loose_path="$run_directory/work/repo/.git/objects/$oid_prefix/$oid_suffix"
    fge_assert_file "FG-092-E2E-$label-003" "$loose_path" \
      "the pinned oracle wrote a zlib loose member for $label"
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$label" "$object_type" "$oid" "$body_path" "$loose_path" >> "$worker_manifest"
    object_count=$((object_count + 1))
  done < "$manifest_path"
  printf '%s\n' "$object_count"
}

publish_owned_members_to_oracle() {
  local worker_manifest="$1"
  local worker_artifacts="$2"
  local run_directory="$3"
  local label=''
  local object_type=''
  local oid=''
  local body_path=''
  local loose_path=''
  local encoded_path=''
  local target_path=''
  local oid_prefix=''
  local oid_suffix=''
  local transcript_path=''

  fge_capture 'owned-output-repository' "$ORACLE" run "$PIN_ID" "$run_directory" . -- \
    init --quiet encoded-repo || true
  fge_assert_exit 'FG-092-E2E-014' 0 "$FGE_LAST_EXIT" \
    'the pinned oracle created the encoder cross-acceptance repository'

  while IFS=$'\t' read -r label object_type oid body_path loose_path; do
    encoded_path="$worker_artifacts/encoded/$oid"
    oid_prefix="$(printf '%s' "$oid" | cut -c1-2)"
    oid_suffix="$(printf '%s' "$oid" | cut -c3-)"
    target_path="$run_directory/work/encoded-repo/.git/objects/$oid_prefix/$oid_suffix"
    mkdir -p "$(dirname "$target_path")"
    fge_run "install-owned-$label" cp -- "$encoded_path" "$target_path" || true
    fge_assert_file "FG-092-E2E-$label-004" "$target_path" \
      "the owned encoder member is installed under its native object id"

    fge_capture "oracle-read-$label" "$ORACLE" capture "$PIN_ID" "$run_directory" encoded-repo \
      "owned-$label" -- cat-file "$object_type" "$oid" || true
    transcript_path="$run_directory/transcripts/owned-$label/stdout.bin"
    fge_assert_exit "FG-092-E2E-$label-005" 0 "$FGE_LAST_EXIT" \
      "the pinned oracle accepts the owned zlib member for $label"
    fge_assert_cmd "FG-092-E2E-$label-006" \
      "the pinned oracle returns the original $label bytes from the owned member" \
      cmp --silent -- "$transcript_path" "$body_path"
  done < "$worker_manifest"
}

main() {
  local work_root=''
  local corpus_root=''
  local corpus_directory=''
  local generation_exit=0
  local run_directory=''
  local create_exit=0
  local init_exit=0
  local worker_manifest=''
  local worker_artifacts=''
  local worker_exit=0
  local object_count=0

  fge_phase setup
  work_root="$(fge_tempdir deflate-loose-object)"
  corpus_root="$work_root/corpus"
  corpus_directory="$corpus_root/corpus-sha1"
  worker_manifest="$work_root/loose-members.tsv"
  worker_artifacts="$FGE_ARTIFACT_DIR/deflate-codec"
  mkdir -p "$corpus_root" "$worker_artifacts"

  fge_phase action
  fge_capture 'generate-pinned-corpus' "$CORPUS_GENERATOR" generate "$PIN_ID" sha1 "$corpus_root" || \
    generation_exit=$?
  fge_assert_exit 'FG-092-E2E-001' 0 "$generation_exit" \
    'the verified pinned oracle generated the real SHA-1 loose-object corpus'
  fge_assert_file 'FG-092-E2E-002' "$corpus_directory/receipt.tsv" \
    'the loose-object corpus carries its pinned-oracle receipt'
  fge_assert_file 'FG-092-E2E-003' "$corpus_directory/manifest.tsv" \
    'the loose-object corpus maps native object ids to exact body bytes'
  if [[ "$generation_exit" -ne 0 ]]; then
    fge_fail 'FG-092-E2E-004' \
      'the pinned oracle corpus is unavailable; no ambient Git or fixture-only fallback is allowed'
    return 0
  fi

  fge_capture 'create-loose-run' "$ORACLE" create-run "$PIN_ID" deflate-loose || create_exit=$?
  fge_assert_exit 'FG-092-E2E-005' 0 "$create_exit" \
    'the separately pinned upstream-Git oracle is verified before differential work'
  if [[ "$create_exit" -ne 0 ]]; then
    return 0
  fi
  run_directory="$(tr -d '\r\n' < "$FGE_LAST_STDOUT_FILE")"

  fge_capture 'initialize-loose-repository' "$ORACLE" run "$PIN_ID" "$run_directory" . -- \
    init --quiet repo || init_exit=$?
  fge_assert_exit 'FG-092-E2E-006' 0 "$init_exit" \
    'the pinned oracle initializes the source loose-object repository'
  if [[ "$init_exit" -ne 0 ]]; then
    return 0
  fi

  object_count="$(copy_oracle_objects "$corpus_directory" "$run_directory" \
    "$corpus_directory/manifest.tsv" "$worker_manifest")"
  fge_assert_match 'FG-092-E2E-007' "$object_count" '^[1-9][0-9]*$' \
    'the source-derived corpus has at least one materialized loose object'

  fge_capture 'owned-codec-worker' env RCH_CARGO_WRAPPER_BYPASS=1 \
    "FGIT_DEFLATE_LOOSE_MANIFEST=$worker_manifest" \
    "FGIT_DEFLATE_DIFFERENTIAL_ARTIFACT_DIR=$worker_artifacts" \
    cargo test --locked -p fgit-deflate --test "$TEST_NAME" -- --ignored || worker_exit=$?
  fge_assert_exit 'FG-092-E2E-008' 0 "$worker_exit" \
    'the owned inflater matches each pinned-oracle loose member and the planted bomb hits OutputBytes'
  fge_assert_file 'FG-092-E2E-009' "$worker_artifacts/receipt.ndjson" \
    'the codec worker emits a bounded differential receipt'
  fge_assert_ndjson 'FG-092-E2E-010' "$worker_artifacts/receipt.ndjson" \
    'the codec differential receipt is parseable NDJSON'
  if [[ -f "$worker_artifacts/receipt.ndjson" ]]; then
    local receipt=''
    receipt="$(<"$worker_artifacts/receipt.ndjson")"
    fge_assert_contains 'FG-092-E2E-011' "$receipt" \
      "\"oracle_object_count\":$object_count" \
      'the codec receipt binds its oracle corpus denominator'
    fge_assert_contains 'FG-092-E2E-012' "$receipt" '"bomb_refusal":"OutputBytes"' \
      'the planted decompression bomb records the explicit output budget refusal'
    fge_assert_contains 'FG-092-E2E-013' "$receipt" 'no zlib bit-compatibility claim' \
      'the differential receipt retains the encoder non-claim boundary'
    fge_artifact "$worker_artifacts/receipt.ndjson" deflate-loose-object-receipt
  fi

  if [[ "$worker_exit" -eq 0 ]]; then
    publish_owned_members_to_oracle "$worker_manifest" "$worker_artifacts" "$run_directory"
  fi
}

fge_init fg092-inflate-bomb-corpus
fge_context bead frankengit-fg092-inflate-codec-ff3u
fge_context evidence_class E3
fge_context oracle_pin "$PIN_ID"
fge_context decoder_classification 'pinned zlib members decode to Git canonical loose-object bytes'
fge_context encoder_classification 'pinned Git cross-accepts owned members; no zlib bit-compatibility claim'
fge_context non_claim 'finite pinned corpus; not general Git or zlib bit compatibility'
main
