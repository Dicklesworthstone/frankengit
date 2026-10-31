#!/usr/bin/env bash
# FG-097: live annotated and lightweight tag advertisement through `fg serve`.
#
# This is a compatibility lane, not a production dependency on Git.  The
# pinned clients check the live node's v1 service; the same oracle below
# supplies the hostile dangling-tag control. It is deliberately separate from
# first_clone.sh so its tag advertisement assertions cannot be hidden by a
# branch-only clone success.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REPO_ROOT="$(cd "${E2E_ROOT}/../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

readonly ORACLE="${REPO_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly ORACLE_PIN='git-2.54.0'
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-${HOME}/.cache/frankengit/git-oracle}"

fge_init fg097-tag-lifecycle
fge_kind e2e-binary
fge_context bead frankengit-fg097-tags-wsi1
fge_context evidence_class E3
fge_context oracle_pin "${ORACLE_PIN}"
fge_context non_claim 'SSH push, REST, CLI, and MCP schemas remain outside fg097'

FG_BIN=${FG_BIN:-}
fge_phase setup
fge_assert_cmd FG-097-TAGS-001 'a prebuilt fg binary is supplied for the live node lane' \
  test -n "${FG_BIN}"
fge_assert_cmd FG-097-TAGS-002 'the supplied fg binary is executable' test -x "${FG_BIN}"

WORK="$(fge_tempdir fg097-tags)"
CLIENT_RUN="$(env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" create-run "${ORACLE_PIN}" fg097-client)"
SRC="${CLIENT_RUN}/work/source"
STORAGE="${WORK}/storage"
fge_context oracle_client_run "${CLIENT_RUN}"
fge_context oracle_client_protocol v1
TENANT=11111111111111111111111111111111
REPOSITORY=22222222222222222222222222222222
PRINCIPAL=44444444444444444444444444444444

# Fixture construction, observations and the live client all use the same pin.
tag_client_git() {
  local label="$1" directory="$2"
  shift 2
  env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" capture "${ORACLE_PIN}" \
    "${CLIENT_RUN}" "${directory}" "${label}" -- "$@"
}
tag_client_oid() {
  local label="$1" directory="$2" reference="$3"
  tag_client_git "${label}" "${directory}" rev-parse "${reference}" || return
  tr -d '\r\n' < "${CLIENT_RUN}/transcripts/${label}/stdout.bin"
}
tag_client_git client-init . init -q -b main source
tag_client_git client-email source config user.email fg097@invalid.example
tag_client_git client-name source config user.name 'FrankenGit FG-097 E2E'
printf 'tag lifecycle\n' > "${SRC}/README"
tag_client_git client-add source add README
tag_client_git client-commit source commit -qm 'tag lifecycle fixture'
tag_client_git client-light source tag light main
tag_client_git client-annotated source tag -a annotated -m 'annotated fixture' main

ANNOTATED_OID="$(tag_client_oid source-annotated source refs/tags/annotated)"
ANNOTATED_PEELED_OID="$(tag_client_oid source-peeled source 'refs/tags/annotated^{}')"
LIGHT_OID="$(tag_client_oid source-light source refs/tags/light)"

fge_phase action
init_exit=0
fge_capture fg097-init "${FG_BIN}" init "${STORAGE}" "${TENANT}" "${REPOSITORY}" || init_exit=$?
fge_assert_exit FG-097-TAGS-003 0 "${init_exit}" 'fg initializes the repository'

import_exit=0
fge_capture fg097-import "${FG_BIN}" import "${STORAGE}" "${TENANT}" "${REPOSITORY}" "${PRINCIPAL}" \
  fg097-tag-import "${SRC}" || import_exit=$?
fge_assert_exit FG-097-TAGS-004 0 "${import_exit}" \
  'fg import publishes both lightweight and annotated tag refs'

PORT_BASE=$((22000 + ($$ % 10000)))
SERVE_NAME=''
SERVE_PORT=''
for offset in 0 1 2 3 4 5 6 7; do
  candidate=$((PORT_BASE + offset))
  candidate_name="fg097-serve-${candidate}"
  fge_spawn "${candidate_name}" bash -c \
    'exec "$1" serve "$2" "$3" "$4" "127.0.0.1:$5" --max-sessions 4 --max-in-flight 1 2>"$6"' _ \
    "${FG_BIN}" "${STORAGE}" "${TENANT}" "${REPOSITORY}" "${candidate}" \
    "${WORK}/serve-${candidate}.err"
  sleep 1
  if kill -0 "${FGE_LAST_PID}" 2>/dev/null; then
    SERVE_NAME="${candidate_name}"
    SERVE_PORT="${candidate}"
    break
  fi
  fge_reap "${candidate_name}"
done
fge_assert_cmd FG-097-TAGS-005 'fg serve accepts one loopback listener' test -n "${SERVE_PORT}"

endpoint="127.0.0.1:${SERVE_PORT}"
repository_path="/${REPOSITORY}.git"
ls_remote_exit=0
env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" ls-remote-tags-loopback \
  "${ORACLE_PIN}" "${CLIENT_RUN}" client-ls-remote "${endpoint}" "${repository_path}" || ls_remote_exit=$?
fge_assert_exit FG-097-TAGS-006 0 "${ls_remote_exit}" \
  'a real git ls-remote accepts the live fg tag advertisement'

ls_remote=''
if [[ -f "${CLIENT_RUN}/transcripts/client-ls-remote/stdout.bin" ]]; then
  ls_remote="$(<"${CLIENT_RUN}/transcripts/client-ls-remote/stdout.bin")"
fi
fge_assert_contains FG-097-TAGS-007 "${ls_remote}" \
  "${ANNOTATED_OID}"$'\t'"refs/tags/annotated" \
  'annotated tag object is advertised at its native object OID'
fge_assert_contains FG-097-TAGS-008 "${ls_remote}" \
  "${ANNOTATED_PEELED_OID}"$'\t'"refs/tags/annotated^{}" \
  'annotated tag has exactly Git-form peeled-ref evidence'
fge_assert_contains FG-097-TAGS-009 "${ls_remote}" \
  "${LIGHT_OID}"$'\t'"refs/tags/light" \
  'lightweight tag is advertised at the directly named object OID'
fge_assert_not_contains FG-097-TAGS-010 "${ls_remote}" 'refs/tags/light^{}' \
  'lightweight tags never synthesize an annotated-tag peeled line'

clone_exit=0
env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" clone-v1-loopback \
  "${ORACLE_PIN}" "${CLIENT_RUN}" client-clone "${endpoint}" "${repository_path}" clone || clone_exit=$?
fge_reap "${SERVE_NAME}"
fge_assert_exit FG-097-TAGS-011 0 "${clone_exit}" \
  'a real git clone completes through fg serve with both tag kinds'
fge_assert_cmd FG-097-TAGS-012 'clone retains the annotated tag object' \
  test "$(tag_client_oid clone-annotated clone refs/tags/annotated)" = "${ANNOTATED_OID}"
fge_assert_cmd FG-097-TAGS-013 'clone resolves the annotated tag through the advertised peel' \
  test "$(tag_client_oid clone-peeled clone 'refs/tags/annotated^{}')" = "${ANNOTATED_PEELED_OID}"
fge_assert_cmd FG-097-TAGS-014 'clone retains the lightweight tag without a synthetic object' \
  test "$(tag_client_oid clone-light clone refs/tags/light)" = "${LIGHT_OID}"

# Retain live-client transcripts beside native init/import capture files.
for label in client-ls-remote client-clone; do
  for stream in stdout.bin stderr.bin receipt.tsv; do
    transcript="${CLIENT_RUN}/transcripts/${label}/${stream}"
    if [[ -f "${transcript}" ]]; then
      retained="$(fge_artifact_path "oracle-client/${label}/${stream}")"
      cp -- "${transcript}" "${retained}"
      fge_artifact "${retained}" pinned-git-client
    fi
  done
done

# The hostile control is constructed and observed exclusively through the
# pinned Bubblewrap oracle.  The tag object exists, but its declared target
# (the null object ID) does not.  Observed at git-2.54.0 (2026-10-19, the first
# time this control executed): upstream upload-pack ADVERTISES the dangling tag
# with its declared peel and exits 0; it does not refuse it.  These assertions
# record that oracle behaviour.  This suite asserts nothing about how
# FrankenGit handles the same state.
# The oracle accepts only run directories it created under its own runs/
# directory, and maps <run>/work to the sandbox's /work.
oracle_setup_exit=0
ORACLE_RUN="$(env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" create-run "${ORACLE_PIN}" fg097-oracle)" ||
  oracle_setup_exit=$?
if [[ "${oracle_setup_exit}" -eq 0 ]]; then
  printf 'object %040d\ntype commit\ntag dangling\ntagger FG <fg097@invalid.example> 1 +0000\n\n' 0 \
    > "${ORACLE_RUN}/work/dangling-tag.body"
  env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" . \
    -- init --quiet --bare dangling.git || oracle_setup_exit=$?
fi
fge_assert_exit FG-097-TAGS-015 0 "${oracle_setup_exit}" \
  'pinned Git oracle creates the isolated dangling-tag repository'
if [[ "${oracle_setup_exit}" -eq 0 ]]; then
  store_exit=0
  env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" capture "${ORACLE_PIN}" "${ORACLE_RUN}" \
    dangling.git fg097-store-dangling -- hash-object -t tag -w ../dangling-tag.body || store_exit=$?
  fge_assert_exit FG-097-TAGS-016 0 "${store_exit}" \
    'pinned Git stores an annotated tag whose target is absent'
  if [[ "${store_exit}" -eq 0 ]]; then
    tag_oid="$(tr -d '\r\n' < "${ORACLE_RUN}/transcripts/fg097-store-dangling/stdout.bin")"
    ref_exit=0
    env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" \
      dangling.git -- update-ref refs/tags/dangling "${tag_oid}" || ref_exit=$?
    fge_assert_exit FG-097-TAGS-017 0 "${ref_exit}" \
      'pinned Git permits the hostile dangling tag ref to be installed for the server control'
    if [[ "${ref_exit}" -eq 0 ]]; then
      advertisement_exit=0
      env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" capture "${ORACLE_PIN}" "${ORACLE_RUN}" \
        dangling.git dangling-advertisement -- upload-pack --advertise-refs . || advertisement_exit=$?
      advertisement_output=''
      if [[ -f "${ORACLE_RUN}/transcripts/dangling-advertisement/stdout.bin" ]]; then
        advertisement_output="$(<"${ORACLE_RUN}/transcripts/dangling-advertisement/stdout.bin")"
      fi
      fge_assert_contains FG-097-TAGS-018 \
        "${advertisement_output}" \
        "0000000000000000000000000000000000000000 refs/tags/dangling^{}" \
        'pinned Git advertises the dangling annotated tag with its declared null peel'
      fge_assert_exit FG-097-TAGS-019 0 "${advertisement_exit}" \
        'pinned Git completes the dangling-tag advertisement successfully'
    fi
  fi
fi

fge_phase assert
