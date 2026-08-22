#!/usr/bin/env bash
# FG-085b: mode-160000 identity preservation and cross-repository non-delegation.
#
# The pinned Git binary is a sandboxed differential oracle only.  The
# credential boundary is exercised by the pure-Rust TreeFS corpus: a
# `TreeCapability` is repository-scoped, so the foreign view refuses a parent
# capability before it can read a foreign object.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly PIN_ID='git-2.54.0'
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-/data/tmp/frankengit-oracle}"
readonly CORPUS_SEED="${FGIT_SUBMODULE_NONDELEGATION_SEED:-85085}"

RUN_DIRECTORY=''

oracle_run() {
  local label=$1
  local work_directory=$2
  shift 2
  fge_capture "oracle-${label}" env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" run "${PIN_ID}" "${RUN_DIRECTORY}" "${work_directory}" -- "$@"
}

oracle_capture() {
  local label=$1
  local work_directory=$2
  shift 2
  fge_capture "oracle-${label}" env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" capture "${PIN_ID}" "${RUN_DIRECTORY}" "${work_directory}" \
    "${label}" -- "$@"
}

oracle_stdout() {
  local label=$1
  tr -d '\r\n' < "${RUN_DIRECTORY}/transcripts/${label}/stdout.bin"
}

prepare_oracle_repositories() {
  mkdir -p "${RUN_DIRECTORY}/work/parent" "${RUN_DIRECTORY}/work/private"
  printf 'private source\n' > "${RUN_DIRECTORY}/work/private/README"
  printf 'parent source\n' > "${RUN_DIRECTORY}/work/parent/README"

  oracle_run private-init . init --quiet private || return
  oracle_run private-name private config user.name 'FrankenGit private oracle' || return
  oracle_run private-email private config user.email 'private@invalid.example' || return
  oracle_run private-add private add README || return
  oracle_run private-commit private commit --quiet -m private || return
  oracle_capture private-head private rev-parse HEAD || return

  oracle_run parent-init . init --quiet parent || return
  oracle_run parent-name parent config user.name 'FrankenGit parent oracle' || return
  oracle_run parent-email parent config user.email 'parent@invalid.example' || return
  oracle_run parent-add parent add README || return
  oracle_run parent-initial parent commit --quiet -m parent || return

  local private_oid
  private_oid="$(oracle_stdout private-head)"
  [[ "${private_oid}" =~ ^[0-9a-f]{40}$ ]] || return 1
  oracle_run parent-gitlink parent update-index --add --cacheinfo "160000,${private_oid},vendor" || return
  oracle_run parent-commit parent commit --quiet -m gitlink || return
  oracle_capture parent-tree parent rev-parse 'HEAD^{tree}' || return
  oracle_capture parent-entry parent ls-tree HEAD vendor || return

  oracle_run parent-bare . init --quiet --bare parent.git || return
  oracle_run parent-push parent push --quiet ../parent.git HEAD:refs/heads/main || return
  oracle_capture clone-parent . clone --quiet --no-local --no-recurse-submodules --branch main parent.git checkout || return
  oracle_capture clone-tree checkout rev-parse 'HEAD^{tree}' || return
  oracle_capture clone-index checkout ls-files -s vendor
}

export FGE_SEED="${CORPUS_SEED}"
fge_init fg085b-submodule-nondelegation
fge_context bead frankengit-fg085b-submodule-nondelegation-s87u
fge_context evidence_class 'E1 differential oracle + E3 pure-Rust negative control'
fge_context oracle_pin "${PIN_ID}"
fge_context corpus_seed "${CORPUS_SEED}"
fge_context method 'pinned Git creates, pushes, and no-recurse clones a mode-160000 gitlink; a pure-Rust TreeFS test then proves repository-scoped capabilities refuse foreign reads and catches an intentionally seeded parent-credential delegation branch'
fge_context production_boundary 'the oracle never runs in production; TreeFS has no recursive submodule checkout, no credential inheritance, and no cross-repository fetch path'
fge_context non_claim 'finite SHA-1 corpus against one pinned Git version; it does not claim SHA-256 coverage, transport authentication, or a general proof of arbitrary submodule policy'
fge_phase setup

work_root="$(fge_tempdir submodule-nondelegation)"
create_exit=0
fge_capture oracle-create-run env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
  "${ORACLE}" create-run "${PIN_ID}" submodule-nondelegation || create_exit=$?
fge_assert_exit FG-085B-E2E-001 0 "${create_exit}" \
  'the pinned Bubblewrap oracle creates the deterministic non-delegation corpus run'

if [[ "${create_exit}" -ne 0 ]]; then
  fge_fail FG-085B-E2E-002 'the parent/private repositories could not be created'
  fge_fail FG-085B-E2E-003 'the private gitlink identity could not be captured'
  fge_fail FG-085B-E2E-004 'the no-recurse clone could not be compared'
  fge_fail FG-085B-E2E-005 'the parent mode-160000 record could not be checked'
  fge_fail FG-085B-E2E-006 'the clone mode-160000 index record could not be checked'
  fge_fail FG-085B-E2E-007 'the pure-Rust non-delegation corpus could not run'
  fge_fail FG-085B-E2E-008 'gitlink data preservation could not be observed'
  fge_fail FG-085B-E2E-009 'recursive authorization refusal could not be observed'
  fge_fail FG-085B-E2E-010 'foreign repository refusal could not be observed'
  fge_fail FG-085B-E2E-011 'the seeded credential-delegation negative control could not be observed'
  exit 0
fi

RUN_DIRECTORY="$(tr -d '\r\n' < "${FGE_LAST_STDOUT_FILE}")"
setup_exit=0
prepare_oracle_repositories || setup_exit=$?
fge_assert_exit FG-085B-E2E-002 0 "${setup_exit}" \
  'pinned Git creates a private commit and a parent gitlink without cloning the private repository'

if [[ "${setup_exit}" -ne 0 ]]; then
  fge_fail FG-085B-E2E-003 'the private gitlink identity could not be captured after setup failed'
  fge_fail FG-085B-E2E-004 'the no-recurse clone could not be compared after setup failed'
  fge_fail FG-085B-E2E-005 'the parent mode-160000 record could not be checked after setup failed'
  fge_fail FG-085B-E2E-006 'the clone mode-160000 index record could not be checked after setup failed'
  fge_fail FG-085B-E2E-007 'the pure-Rust non-delegation corpus could not run after setup failed'
  fge_fail FG-085B-E2E-008 'gitlink data preservation could not be observed after setup failed'
  fge_fail FG-085B-E2E-009 'recursive authorization refusal could not be observed after setup failed'
  fge_fail FG-085B-E2E-010 'foreign repository refusal could not be observed after setup failed'
  fge_fail FG-085B-E2E-011 'the seeded credential-delegation negative control could not be observed after setup failed'
  exit 0
fi

fge_phase assert
private_oid="$(oracle_stdout private-head)"
parent_tree="$(oracle_stdout parent-tree)"
clone_tree="$(oracle_stdout clone-tree)"
parent_entry="$(oracle_stdout parent-entry)"
clone_index="$(oracle_stdout clone-index)"
expected_parent_entry=$'160000 commit '"${private_oid}"$'\tvendor'
expected_clone_index=$'160000 '"${private_oid}"$' 0\tvendor'
private_oid_is_sha1=false
if [[ "${private_oid}" =~ ^[0-9a-f]{40}$ ]]; then
  private_oid_is_sha1=true
fi

fge_assert_eq FG-085B-E2E-003 true "${private_oid_is_sha1}" \
  'the private oracle repository produced a native SHA-1 commit identity'
fge_assert_eq FG-085B-E2E-004 "${parent_tree}" "${clone_tree}" \
  'a no-recurse fetch/checkout preserves the parent tree identity'
fge_assert_eq FG-085B-E2E-005 "${expected_parent_entry}" "${parent_entry}" \
  'the parent tree records mode 160000 and the exact private commit bytes'
fge_assert_eq FG-085B-E2E-006 "${expected_clone_index}" "${clone_index}" \
  'the no-recurse checkout retains the exact mode-160000 gitlink index entry'

treefs_exit=0
fge_capture pure-rust-nondelegation \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-treefs --test submodule_nondelegation -- --nocapture || treefs_exit=$?
fge_assert_exit FG-085B-E2E-007 0 "${treefs_exit}" \
  'the pure-Rust TreeFS corpus passes without Git, a transport client, or credential delegation'

treefs_stdout="$(<"${FGE_LAST_STDOUT_FILE}")"
treefs_stderr="$(<"${FGE_LAST_STDERR_FILE}")"
treefs_output="${treefs_stdout}"$'\n'"${treefs_stderr}"
fge_assert_contains FG-085B-E2E-008 "${treefs_output}" gitlink_oid_round_trips_as_parent_tree_data \
  'the corpus proves byte-exact gitlink identity stays parent-tree data'
fge_assert_contains FG-085B-E2E-009 "${treefs_output}" recursive_submodule_path_is_refused_without_reading_the_gitlink_oid \
  'the corpus proves recursive submodule traversal is a typed non-directory refusal'
fge_assert_contains FG-085B-E2E-010 "${treefs_output}" parent_capability_is_refused_by_foreign_repository_before_object_read \
  'the corpus proves a parent capability is rejected before a foreign read'
fge_assert_contains FG-085B-E2E-011 "${treefs_output}" seeded_parent_credential_delegation_is_detected_by_read_audit \
  'the seeded over-permissive parent-credential branch is caught by the read audit'

receipt="${work_root}/submodule-nondelegation-receipt.tsv"
{
  printf 'schema=frankengit.submodule-nondelegation.v1\n'
  printf 'oracle_pin=%s\n' "${PIN_ID}"
  printf 'corpus_seed=%s\n' "${CORPUS_SEED}"
  printf 'private_commit=%s\n' "${private_oid}"
  printf 'parent_tree=%s\n' "${parent_tree}"
  printf 'clone_tree=%s\n' "${clone_tree}"
  printf 'parent_entry=%s\n' "${parent_entry}"
  printf 'clone_index=%s\n' "${clone_index}"
  printf 'typed_refusal=RepositoryMismatch before foreign source read; NotADirectory for recursive gitlink traversal\n'
  printf 'seeded_negative_control=parent ReadGrant directly read foreign commit and the audit observed it\n'
  printf 'non_claim=finite SHA-1 corpus; no recursive checkout, credential forwarding, SHA-256 lane, or transport authentication\n'
} > "${receipt}"
fge_artifact "${receipt}" submodule-nondelegation-receipt
