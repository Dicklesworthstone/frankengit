#!/usr/bin/env bash
# FG-085: gitlink preservation and non-delegation against pinned Git 2.54.0.
#
# This finite corpus checks one SHA-1 superproject/private-repository pair. It
# does not claim recursive submodule support, credential forwarding, or a
# general compatibility proof. The pinned Git binary runs only inside the
# differential oracle; FrankenGit's production boundary is the pure-Rust test
# bridge at the end of this suite.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly PIN_ID='git-2.54.0'
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-/data/tmp/frankengit-oracle}"

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
  oracle_capture parent-entry parent ls-tree HEAD -- vendor || return
  oracle_capture parent-tree-body parent cat-file tree 'HEAD^{tree}' || return

  oracle_run parent-bare . init --quiet --bare parent.git || return
  oracle_run parent-push parent push --quiet ../parent.git HEAD:refs/heads/main || return
  oracle_capture clone-parent . clone --quiet --no-local --no-recurse-submodules --branch main parent.git checkout || return
  oracle_capture clone-tree checkout rev-parse 'HEAD^{tree}' || return
  oracle_capture clone-index checkout ls-files -s -- vendor
}

fge_init fg085-submodule-gitlink
fge_context bead frankengit-fg085-submodules-w2q9
fge_context evidence_class differential
fge_context oracle_pin "${PIN_ID}"
fge_context method 'create a private commit and a parent mode-160000 gitlink with pinned Git; push the parent to a bare remote and fetch it through a no-local clone; compare parent and checkout tree/index records; parse the raw oracle tree bytes in the pure-Rust closure bridge while recording that no gitlink target read occurs'
fge_context non_claim 'finite SHA-1 corpus against one pinned Git version; does not implement recursive submodule checkout, credential forwarding, or cross-repository authorization'
fge_context production_boundary 'the oracle is sandboxed conformance evidence only; fgit-wire and TreeFS remain pure-Rust and never invoke Git'
fge_phase setup

work_root="$(fge_tempdir submodule-gitlink)"
create_exit=0
fge_capture oracle-create-run env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
  "${ORACLE}" create-run "${PIN_ID}" submodule-gitlink || create_exit=$?
fge_assert_exit FG-085-E2E-001 0 "${create_exit}" \
  'the pinned Bubblewrap oracle creates the submodule corpus run'

if [[ "${create_exit}" -ne 0 ]]; then
  fge_fail FG-085-E2E-002 'the private and parent repositories could not be created'
  fge_fail FG-085-E2E-003 'the oracle gitlink identity could not be captured'
  fge_fail FG-085-E2E-004 'the clone preservation cell could not run'
  fge_fail FG-085-E2E-005 'the parent gitlink tree record could not be checked'
  fge_fail FG-085-E2E-006 'the clone gitlink index record could not be checked'
  fge_fail FG-085-E2E-007 'the exact parent tree bytes could not be bridged into Rust'
  fge_fail FG-085-E2E-008 'the pure-Rust parent-closure non-delegation check could not run'
  exit 0
fi

RUN_DIRECTORY="$(tr -d '\r\n' < "${FGE_LAST_STDOUT_FILE}")"
setup_exit=0
prepare_oracle_repositories || setup_exit=$?
fge_assert_exit FG-085-E2E-002 0 "${setup_exit}" \
  'pinned Git creates private and parent repositories with an explicit gitlink'

if [[ "${setup_exit}" -ne 0 ]]; then
  fge_fail FG-085-E2E-003 'the oracle gitlink identity could not be captured after setup failed'
  fge_fail FG-085-E2E-004 'the clone preservation cell could not run after setup failed'
  fge_fail FG-085-E2E-005 'the parent gitlink tree record could not be checked after setup failed'
  fge_fail FG-085-E2E-006 'the clone gitlink index record could not be checked after setup failed'
  fge_fail FG-085-E2E-007 'the exact parent tree bytes could not be bridged after setup failed'
  fge_fail FG-085-E2E-008 'the pure-Rust parent-closure non-delegation check could not run after setup failed'
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
tree_body_path="${RUN_DIRECTORY}/transcripts/parent-tree-body/stdout.bin"
tree_body_hex="$(od -An -tx1 -v "${tree_body_path}" | tr -d ' \n')"
private_oid_is_sha1=false
if [[ "${private_oid}" =~ ^[0-9a-f]{40}$ ]]; then
  private_oid_is_sha1=true
fi

fge_assert_eq FG-085-E2E-003 true "${private_oid_is_sha1}" \
  'the pinned private repository produced a native SHA-1 commit identity'
fge_assert_eq FG-085-E2E-004 "${parent_tree}" "${clone_tree}" \
  'clone preserves the parent tree identity containing the gitlink'
fge_assert_eq FG-085-E2E-005 "${expected_parent_entry}" "${parent_entry}" \
  'the oracle parent tree records mode 160000, exact commit OID, and path'
fge_assert_eq FG-085-E2E-006 "${expected_clone_index}" "${clone_index}" \
  'checkout keeps the exact mode-160000 gitlink in the cloned index without recursive initialization'
fge_assert_cmd FG-085-E2E-007 'the raw parent tree bytes are available for the pure-Rust differential bridge' \
  test -n "${tree_body_hex}"

bridge_exit=0
fge_capture pure-rust-gitlink-bridge \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  "FGIT_SUBMODULE_GITLINK_TREE_BODY_HEX=${tree_body_hex}" \
  "FGIT_SUBMODULE_GITLINK_TREE_OID=${parent_tree}" \
  "FGIT_SUBMODULE_GITLINK_OID=${private_oid}" \
  cargo test --locked -p fgit-wire --test submodule_gitlink \
    pinned_git_gitlink_tree_preserves_oid_without_cross_repository_lookup \
    -- --ignored --exact --nocapture || bridge_exit=$?
fge_assert_exit FG-085-E2E-008 0 "${bridge_exit}" \
  'the pure-Rust closure parses the oracle gitlink and refuses parent-repository traversal or recursive completion'

receipt="${work_root}/submodule-gitlink-oracle.tsv"
{
  printf 'schema=frankengit.submodule-gitlink-oracle.v1\n'
  printf 'oracle_pin=%s\n' "${PIN_ID}"
  printf 'private_commit=%s\n' "${private_oid}"
  printf 'parent_tree=%s\n' "${parent_tree}"
  printf 'clone_tree=%s\n' "${clone_tree}"
  printf 'parent_entry=%s\n' "${parent_entry}"
  printf 'clone_index=%s\n' "${clone_index}"
  printf 'non_claim=finite SHA-1 corpus; no recursive submodule checkout or credential delegation is implemented\n'
} > "${receipt}"
fge_artifact "${receipt}" submodule-gitlink-oracle-result
fge_artifact "${RUN_DIRECTORY}/transcripts/parent-entry/receipt.tsv" submodule-parent-entry-oracle-transcript
fge_artifact "${RUN_DIRECTORY}/transcripts/clone-index/receipt.tsv" submodule-clone-index-oracle-transcript
