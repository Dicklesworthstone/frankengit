#!/usr/bin/env bash
# FG-097: live annotated and lightweight tag advertisement through `fg serve`.
#
# This is a compatibility lane, not a production dependency on Git.  The
# ordinary client checks the live node's v1 service; the pinned oracle below
# supplies the hostile dangling-tag control.  It is deliberately separate from
# first_clone.sh so its tag advertisement assertions cannot be hidden by a
# branch-only clone success.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REPO_ROOT="$(cd "${E2E_ROOT}/../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

readonly ORACLE="${REPO_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly ORACLE_PIN='git-2.54.0'
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-/data/tmp/frankengit-oracle}"

fge_init fg097-tag-lifecycle
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
SRC="${WORK}/source"
STORAGE="${WORK}/storage"
CLONE="${WORK}/clone"
TENANT=11111111111111111111111111111111
REPOSITORY=22222222222222222222222222222222
PRINCIPAL=44444444444444444444444444444444

mkdir -p "${SRC}"
git -C "${SRC}" init -q -b main
git -C "${SRC}" config user.email fg097@invalid.example
git -C "${SRC}" config user.name 'FrankenGit FG-097 E2E'
printf 'tag lifecycle\n' > "${SRC}/README"
git -C "${SRC}" add README
git -C "${SRC}" commit -qm 'tag lifecycle fixture'
git -C "${SRC}" tag light main
git -C "${SRC}" tag -a annotated -m 'annotated fixture' main

ANNOTATED_OID="$(git -C "${SRC}" rev-parse refs/tags/annotated)"
ANNOTATED_PEELED_OID="$(git -C "${SRC}" rev-parse 'refs/tags/annotated^{}')"
LIGHT_OID="$(git -C "${SRC}" rev-parse refs/tags/light)"

fge_phase action
init_exit=0
"${FG_BIN}" init "${STORAGE}" "${TENANT}" "${REPOSITORY}" >/dev/null 2>&1 || init_exit=$?
fge_assert_exit FG-097-TAGS-003 0 "${init_exit}" 'fg initializes the repository'

import_exit=0
"${FG_BIN}" import "${STORAGE}" "${TENANT}" "${REPOSITORY}" "${PRINCIPAL}" \
  fg097-tag-import "${SRC}" >/dev/null 2>&1 || import_exit=$?
fge_assert_exit FG-097-TAGS-004 0 "${import_exit}" \
  'fg import publishes both lightweight and annotated tag refs'

PORT_BASE=$((22000 + ($$ % 10000)))
SERVE_NAME=''
SERVE_PORT=''
for offset in 0 1 2 3 4 5 6 7; do
  candidate=$((PORT_BASE + offset))
  candidate_name="fg097-serve-${candidate}"
  fge_spawn "${candidate_name}" bash -c \
    'exec "$1" serve "$2" "$3" "$4" "127.0.0.1:$5" 2>"$6"' _ \
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

remote="git://127.0.0.1:${SERVE_PORT}/${REPOSITORY}.git"
ls_remote_exit=0
git -c protocol.version=1 ls-remote --tags "${remote}" > "${WORK}/ls-remote.out" 2>&1 || ls_remote_exit=$?
fge_assert_exit FG-097-TAGS-006 0 "${ls_remote_exit}" \
  'a real git ls-remote accepts the live fg tag advertisement'

ls_remote="$(<"${WORK}/ls-remote.out")"
fge_assert_contains FG-097-TAGS-007 "${ls_remote}" \
  "${ANNOTATED_OID}\trefs/tags/annotated" \
  'annotated tag object is advertised at its native object OID'
fge_assert_contains FG-097-TAGS-008 "${ls_remote}" \
  "${ANNOTATED_PEELED_OID}\trefs/tags/annotated^{}" \
  'annotated tag has exactly Git-form peeled-ref evidence'
fge_assert_contains FG-097-TAGS-009 "${ls_remote}" \
  "${LIGHT_OID}\trefs/tags/light" \
  'lightweight tag is advertised at the directly named object OID'
fge_assert_not_contains FG-097-TAGS-010 "${ls_remote}" 'refs/tags/light^{}' \
  'lightweight tags never synthesize an annotated-tag peeled line'

clone_exit=0
git -c protocol.version=1 clone -q "${remote}" "${CLONE}" > "${WORK}/clone.out" 2>&1 || clone_exit=$?
fge_reap "${SERVE_NAME}"
fge_assert_exit FG-097-TAGS-011 0 "${clone_exit}" \
  'a real git clone completes through fg serve with both tag kinds'
fge_assert_cmd FG-097-TAGS-012 'clone retains the annotated tag object' \
  test "$(git -C "${CLONE}" rev-parse refs/tags/annotated)" = "${ANNOTATED_OID}"
fge_assert_cmd FG-097-TAGS-013 'clone resolves the annotated tag through the advertised peel' \
  test "$(git -C "${CLONE}" rev-parse 'refs/tags/annotated^{}')" = "${ANNOTATED_PEELED_OID}"
fge_assert_cmd FG-097-TAGS-014 'clone retains the lightweight tag without a synthetic object' \
  test "$(git -C "${CLONE}" rev-parse refs/tags/light)" = "${LIGHT_OID}"

# The hostile control is constructed and observed exclusively through the
# pinned Bubblewrap oracle.  The tag object exists, but its declared target
# does not; upstream upload-pack refuses its advertisement rather than
# presenting an unpeelable `refs/tags/*` record.
ORACLE_RUN="$(fge_tempdir fg097-oracle)"
printf 'object %040d\ntype commit\ntag dangling\ntagger FG <fg097@invalid.example> 1 +0000\n\n' 0 \
  > "${ORACLE_RUN}/dangling-tag.body"
oracle_setup_exit=0
env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" . \
  -- init --quiet --bare dangling.git || oracle_setup_exit=$?
fge_assert_exit FG-097-TAGS-015 0 "${oracle_setup_exit}" \
  'pinned Git oracle creates the isolated dangling-tag repository'
if [[ "${oracle_setup_exit}" -eq 0 ]]; then
  alias_exit=0
  env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" \
    dangling.git -- config alias.fg097-store-dangling \
    '!$GIT_EXEC_PATH/git-hash-object -t tag -w --stdin < ../dangling-tag.body' || alias_exit=$?
  fge_assert_exit FG-097-TAGS-016 0 "${alias_exit}" \
    'pinned Git stores an annotated tag whose target is absent'
  if [[ "${alias_exit}" -eq 0 ]]; then
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
      fge_assert_not_contains FG-097-TAGS-018 \
        "$(<"${ORACLE_RUN}/transcripts/dangling-advertisement/stdout.bin")" \
        'refs/tags/dangling' \
        'pinned Git never advertises a dangling annotated tag'
      fge_assert_cmd FG-097-TAGS-019 \
        'pinned Git gives a typed non-success outcome for a dangling tag advertisement' \
        test "${advertisement_exit}" -ne 0
    fi
  fi
fi

fge_phase assert
