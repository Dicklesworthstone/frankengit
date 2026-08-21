#!/usr/bin/env bash
# FG-018b E3 conformance evidence for shallow and partial-clone closure.
#
# Git is invoked only through the pinned, Bubblewrap-isolated oracle. This
# suite is a finite semantic corpus, not a general Git compatibility claim.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly PIN_ID='git-2.54.0'
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-/data/tmp/frankengit-oracle}"
readonly CORPUS_DENOMINATOR=15

RUN_DIRECTORY=''

oracle_run() {
  local label="$1"
  local work_directory="$2"
  shift 2
  fge_capture "oracle-${label}" env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" run "${PIN_ID}" "${RUN_DIRECTORY}" "${work_directory}" -- "$@"
}

oracle_capture() {
  local label="$1"
  local work_directory="$2"
  shift 2
  fge_capture "oracle-${label}" env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" capture "${PIN_ID}" "${RUN_DIRECTORY}" "${work_directory}" \
    "${label}" -- "$@"
}

oracle_stdout() {
  local label="$1"
  tr -d '\r\n' < "${RUN_DIRECTORY}/transcripts/${label}/stdout.bin"
}

prepare_oracle_repository() {
  mkdir -p "${RUN_DIRECTORY}/work/source"
  printf 'one\n' > "${RUN_DIRECTORY}/work/source/README"
  oracle_run source-init . init --quiet source || return
  oracle_run source-name source config user.name 'FrankenGit shallow corpus' || return
  oracle_run source-email source config user.email 'shallow-corpus@invalid.example' || return
  oracle_run source-add-one source add README || return
  oracle_run source-commit-one source commit --quiet -m one || return

  printf 'two\n' > "${RUN_DIRECTORY}/work/source/README"
  oracle_run source-add-two source add README || return
  oracle_run source-commit-two source commit --quiet -m two || return

  printf 'three\n' > "${RUN_DIRECTORY}/work/source/README"
  oracle_run source-add-three source add README || return
  oracle_run source-commit-three source commit --quiet -m three || return
  oracle_run source-bare . clone --quiet --bare source source.git || return
  oracle_run source-allow-filter source.git config uploadpack.allowFilter true || return
  oracle_run source-allow-want source.git config uploadpack.allowAnySHA1InWant true || return
}

write_oracle_receipt() {
  local path="$1"
  local depth_count="$2"
  local depth_shallow="$3"
  local missing_before="$4"
  local missing_after="$5"
  local tree_filter="$6"

  {
    printf 'schema=frankengit.shallow-partial-oracle-corpus.v1\n'
    printf 'oracle_pin=%s\n' "${PIN_ID}"
    printf 'corpus_denominator=%s\n' "${CORPUS_DENOMINATOR}"
    printf 'depth_commit_count=%s\n' "${depth_count}"
    printf 'depth_is_shallow=%s\n' "${depth_shallow}"
    printf 'blob_missing_before=%s\n' "${missing_before}"
    printf 'blob_missing_after=%s\n' "${missing_after}"
    printf 'tree_filter=%s\n' "${tree_filter}"
    printf 'oracle_run_directory=%s\n' "${RUN_DIRECTORY}"
    printf 'non_claim=deepen-since,deepen-not,and unshallow have no equivalent one-shot clone depth/filter invocation\n'
    printf 'non_claim=E3 finite pinned corpus; not a general Git compatibility claim\n'
  } > "${path}"
}

fge_init fg018b-shallow-partial-corpus
fge_context bead frankengit-fg018b-shallow-partial-9tl
fge_context evidence_class E3
fge_context oracle_pin "${PIN_ID}"
fge_context corpus_denominator "${CORPUS_DENOMINATOR}"
fge_context oracle_non_claim 'deepen-since,deepen-not,unshallow lack one-shot clone depth/filter cells'
fge_context non_claim 'finite pinned corpus; not a general Git compatibility claim'
fge_phase setup

work_root="$(fge_tempdir shallow-partial-corpus)"
reference_exit=0
fge_capture pure-reference-closure \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-wire --test shallow_partial_corpus -- --nocapture || reference_exit=$?
fge_assert_exit FG-018B-E2E-001 0 "${reference_exit}" \
  'the pure reference DAG corpus agrees with the production closure'

create_exit=0
fge_capture oracle-create-run env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
  "${ORACLE}" create-run "${PIN_ID}" shallow-partial || create_exit=$?
fge_assert_exit FG-018B-E2E-002 0 "${create_exit}" \
  'the pinned Bubblewrap oracle creates the shallow/partial corpus run'

if [[ "${create_exit}" -ne 0 ]]; then
  fge_fail FG-018B-E2E-003 'source setup could not run without the pinned oracle'
  fge_fail FG-018B-E2E-004 'depth-two clone could not run without the pinned oracle'
  fge_fail FG-018B-E2E-005 'depth count could not run without the pinned oracle'
  fge_fail FG-018B-E2E-006 'depth count comparison could not run without the pinned oracle'
  fge_fail FG-018B-E2E-007 'shallow metadata command could not run without the pinned oracle'
  fge_fail FG-018B-E2E-008 'shallow metadata comparison could not run without the pinned oracle'
  fge_fail FG-018B-E2E-009 'blob:none clone could not run without the pinned oracle'
  fge_fail FG-018B-E2E-010 'promisor omission check could not run without the pinned oracle'
  fge_fail FG-018B-E2E-011 'lazy completion command could not run without the pinned oracle'
  fge_fail FG-018B-E2E-012 'lazy completion content check could not run without the pinned oracle'
  fge_fail FG-018B-E2E-013 'tree-depth clone could not run without the pinned oracle'
  fge_fail FG-018B-E2E-014 'tree-depth configuration check could not run without the pinned oracle'
  fge_fail FG-018B-E2E-015 'Rust/oracle bridge could not run without the pinned oracle'
  exit 0
fi

RUN_DIRECTORY="$(tr -d '\r\n' < "${FGE_LAST_STDOUT_FILE}")"
setup_exit=0
prepare_oracle_repository || setup_exit=$?
fge_assert_exit FG-018B-E2E-003 0 "${setup_exit}" \
  'the pinned oracle created a three-commit filter-capable local upload-pack source'

if [[ "${setup_exit}" -ne 0 ]]; then
  fge_fail FG-018B-E2E-004 'depth-two clone could not run after source setup failed'
  fge_fail FG-018B-E2E-005 'depth count could not run after source setup failed'
  fge_fail FG-018B-E2E-006 'depth count comparison could not run after source setup failed'
  fge_fail FG-018B-E2E-007 'shallow metadata command could not run after source setup failed'
  fge_fail FG-018B-E2E-008 'shallow metadata comparison could not run after source setup failed'
  fge_fail FG-018B-E2E-009 'blob:none clone could not run after source setup failed'
  fge_fail FG-018B-E2E-010 'promisor omission check could not run after source setup failed'
  fge_fail FG-018B-E2E-011 'lazy completion command could not run after source setup failed'
  fge_fail FG-018B-E2E-012 'lazy completion content check could not run after source setup failed'
  fge_fail FG-018B-E2E-013 'tree-depth clone could not run after source setup failed'
  fge_fail FG-018B-E2E-014 'tree-depth configuration check could not run after source setup failed'
  fge_fail FG-018B-E2E-015 'Rust/oracle bridge could not run after source setup failed'
  exit 0
fi

depth_clone_exit=0
oracle_capture depth-clone . clone --quiet --no-local --depth=2 source.git depth-client || depth_clone_exit=$?
fge_assert_exit FG-018B-E2E-004 0 "${depth_clone_exit}" \
  'pinned Git completes a depth-two clone through upload-pack'

if [[ "${depth_clone_exit}" -ne 0 ]]; then
  fge_fail FG-018B-E2E-005 'depth count is unavailable because the depth clone failed'
  fge_fail FG-018B-E2E-006 'depth count comparison is unavailable because the depth clone failed'
  fge_fail FG-018B-E2E-007 'shallow metadata is unavailable because the depth clone failed'
  fge_fail FG-018B-E2E-008 'shallow metadata comparison is unavailable because the depth clone failed'
  fge_fail FG-018B-E2E-009 'blob:none clone was not attempted after depth clone failure'
  fge_fail FG-018B-E2E-010 'promisor omission check was not attempted after depth clone failure'
  fge_fail FG-018B-E2E-011 'lazy completion command was not attempted after depth clone failure'
  fge_fail FG-018B-E2E-012 'lazy completion content check was not attempted after depth clone failure'
  fge_fail FG-018B-E2E-013 'tree-depth clone was not attempted after depth clone failure'
  fge_fail FG-018B-E2E-014 'tree-depth configuration check was not attempted after depth clone failure'
  fge_fail FG-018B-E2E-015 'Rust/oracle bridge was not attempted after depth clone failure'
  exit 0
fi

depth_count_exit=0
oracle_capture depth-count depth-client rev-list --count HEAD || depth_count_exit=$?
depth_count="$(oracle_stdout depth-count)"
fge_assert_exit FG-018B-E2E-005 0 "${depth_count_exit}" \
  'depth-two clone has a readable bounded history count'
fge_assert_eq FG-018B-E2E-006 '2' "${depth_count}" \
  'depth-two clone contains exactly two commits'

depth_shallow_exit=0
oracle_capture depth-shallow depth-client rev-parse --is-shallow-repository || depth_shallow_exit=$?
depth_shallow="$(oracle_stdout depth-shallow)"
fge_assert_exit FG-018B-E2E-007 0 "${depth_shallow_exit}" \
  'depth-two clone reports shallow metadata through pinned Git'
fge_assert_eq FG-018B-E2E-008 true "${depth_shallow}" \
  'depth-two clone is observably shallow'

blob_clone_exit=0
oracle_capture blob-none-clone . clone --quiet --no-local --depth=1 --filter=blob:none source.git blob-none || blob_clone_exit=$?
fge_assert_exit FG-018B-E2E-009 0 "${blob_clone_exit}" \
  'pinned Git completes a depth-one blob:none clone'

blob_missing_before=false
blob_missing_after=false
tree_filter=''
if [[ "${blob_clone_exit}" -eq 0 ]]; then
  oracle_capture blob-none-missing blob-none rev-list --objects --missing=print HEAD || true
  if [[ "$(<"${RUN_DIRECTORY}/transcripts/blob-none-missing/stdout.bin")" == *'?'* ]]; then
    blob_missing_before=true
  fi
  fge_assert_eq FG-018B-E2E-010 true "${blob_missing_before}" \
    'blob:none clone retains a promised missing object before lazy access'

  lazy_exit=0
  oracle_capture blob-none-lazy blob-none show HEAD:README || lazy_exit=$?
  lazy_value="$(oracle_stdout blob-none-lazy)"
  fge_assert_exit FG-018B-E2E-011 0 "${lazy_exit}" \
    'promised blob is lazily fetched through the pinned oracle remote'
  fge_assert_eq FG-018B-E2E-012 three "${lazy_value}" \
    'lazy fetch returns the requested promised blob bytes'

  oracle_capture blob-none-after blob-none rev-list --objects --missing=print HEAD || true
  if [[ "$(<"${RUN_DIRECTORY}/transcripts/blob-none-after/stdout.bin")" != *'?'* ]]; then
    blob_missing_after=true
  fi
else
  fge_fail FG-018B-E2E-010 'promisor omission cell unavailable because blob:none clone failed'
  fge_fail FG-018B-E2E-011 'lazy completion cell unavailable because blob:none clone failed'
  fge_fail FG-018B-E2E-012 'lazy result cell unavailable because blob:none clone failed'
fi

tree_clone_exit=0
oracle_capture tree-zero-clone . clone --quiet --no-local --depth=1 --filter=tree:0 source.git tree-zero || tree_clone_exit=$?
fge_assert_exit FG-018B-E2E-013 0 "${tree_clone_exit}" \
  'pinned Git completes a tree:0 filtered clone'

if [[ "${tree_clone_exit}" -eq 0 ]]; then
  oracle_capture tree-zero-filter tree-zero config --get remote.origin.partialclonefilter || true
  tree_filter="$(oracle_stdout tree-zero-filter)"
  fge_assert_eq FG-018B-E2E-014 tree:0 "${tree_filter}" \
    'tree:0 clone records its exact partial-clone filter'
else
  fge_fail FG-018B-E2E-014 'tree-depth configuration unavailable because tree:0 clone failed'
fi

corpus_receipt="${work_root}/oracle-results.tsv"
write_oracle_receipt "${corpus_receipt}" "${depth_count}" "${depth_shallow}" \
  "${blob_missing_before}" "${blob_missing_after}" "${tree_filter}"
fge_artifact "${corpus_receipt}" shallow-partial-oracle-corpus
fge_artifact "${RUN_DIRECTORY}/transcripts/depth-clone/receipt.tsv" shallow-depth-oracle-transcript
fge_artifact "${RUN_DIRECTORY}/transcripts/blob-none-clone/receipt.tsv" blob-none-oracle-transcript
fge_artifact "${RUN_DIRECTORY}/transcripts/tree-zero-clone/receipt.tsv" tree-depth-oracle-transcript

bridge_exit=0
fge_capture oracle-closure-bridge \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  "FGIT_SHALLOW_PARTIAL_ORACLE_RECEIPT=${corpus_receipt}" \
  cargo test --locked -p fgit-wire --test shallow_partial_corpus \
    pinned_oracle_clone_cells_match_the_pure_closure -- --ignored --nocapture || bridge_exit=$?
fge_assert_exit FG-018B-E2E-015 0 "${bridge_exit}" \
  'the pure Rust closure agrees with the recorded pinned-Git shallow/filter observations'
