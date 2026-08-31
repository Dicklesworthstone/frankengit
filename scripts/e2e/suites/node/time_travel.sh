#!/usr/bin/env bash
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init fg038-time-travel
fge_context bead frankengit-fg038-time-travel-0hb.1
fge_context evidence_class E3
fge_context non_claim 'capsule checkpoints and positions inside a multi-decision batch remain unsupported'

FG_BIN=${FG_BIN:-}
fge_phase setup
fge_assert_cmd FG-038-AT-001 'a prebuilt fg binary is supplied' test -n "${FG_BIN}"
fge_assert_cmd FG-038-AT-002 'the supplied fg binary is executable' test -x "${FG_BIN}"

WORK="$(fge_tempdir fg038-time-travel)"
SRC="${WORK}/source"
STORAGE="${WORK}/storage"
TENANT=11111111111111111111111111111111
REPOSITORY=22222222222222222222222222222222
PRINCIPAL=44444444444444444444444444444444

mkdir -p "${SRC}"
git -C "${SRC}" init -q -b main
git -C "${SRC}" config user.email fg038@invalid.example
git -C "${SRC}" config user.name 'FrankenGit FG-038 E2E'
printf 'authenticated history\n' > "${SRC}/README"
git -C "${SRC}" add README
git -C "${SRC}" commit -qm 'historical fixture'
TIP="$(git -C "${SRC}" rev-parse HEAD)"

fge_phase action
init_exit=0
"${FG_BIN}" init "${STORAGE}" "${TENANT}" "${REPOSITORY}" >"${WORK}/init.out" 2>"${WORK}/init.err" || init_exit=$?
fge_assert_exit FG-038-AT-003 0 "${init_exit}" 'fg initializes durable authority state'

import_exit=0
"${FG_BIN}" import "${STORAGE}" "${TENANT}" "${REPOSITORY}" "${PRINCIPAL}" \
  fg038-import-1 "${SRC}" >"${WORK}/import-1.out" 2>"${WORK}/import-1.err" || import_exit=$?
fge_assert_exit FG-038-AT-004 0 "${import_exit}" 'the first import publishes decision one'

refusal_exit=0
"${FG_BIN}" import "${STORAGE}" "${TENANT}" "${REPOSITORY}" "${PRINCIPAL}" \
  fg038-import-2 "${SRC}" >"${WORK}/import-2.out" 2>"${WORK}/import-2.err" || refusal_exit=$?
fge_assert_exit FG-038-AT-005 2 "${refusal_exit}" 'a distinct stale import publishes a later terminal refusal'

refs_exit=0
"${FG_BIN}" at "${STORAGE}" "${TENANT}" "${REPOSITORY}" decision:1 refs \
  >"${WORK}/decision-1-refs.out" 2>"${WORK}/decision-1-refs.err" || refs_exit=$?
fge_assert_exit FG-038-AT-006 0 "${refs_exit}" 'fg at replays a non-latest committed decision'
refs_output="$(<"${WORK}/decision-1-refs.out")"
fge_assert_contains FG-038-AT-007 "${refs_output}" "refs/heads/main -> ${TIP}" \
  'historical replay returns the authority-selected ref identity'

summary_exit=0
"${FG_BIN}" at "${STORAGE}" "${TENANT}" "${REPOSITORY}" decision:1 \
  >"${WORK}/decision-1-summary.out" 2>"${WORK}/decision-1-summary.err" || summary_exit=$?
fge_assert_exit FG-038-AT-008 0 "${summary_exit}" 'historical summary reports its reusable head identity'
HEAD_TOKEN="$(sed -n 's/^snapshot at decision:1 (head \([^,]*\), decision.*$/\1/p' "${WORK}/decision-1-summary.out")"
fge_assert_cmd FG-038-AT-009 'the rendered historical head token is present' test -n "${HEAD_TOKEN}"

head_exit=0
"${FG_BIN}" at "${STORAGE}" "${TENANT}" "${REPOSITORY}" "head:${HEAD_TOKEN}" refs \
  >"${WORK}/head-refs.out" 2>"${WORK}/head-refs.err" || head_exit=$?
fge_assert_exit FG-038-AT-010 0 "${head_exit}" 'a rendered head identity round-trips through fg at'
fge_assert_contains FG-038-AT-011 "$(<"${WORK}/head-refs.out")" "refs/heads/main -> ${TIP}" \
  'head-addressed replay returns the same historical ref'

diff_exit=0
"${FG_BIN}" at "${STORAGE}" "${TENANT}" "${REPOSITORY}" decision:1 diff latest \
  >"${WORK}/diff.out" 2>"${WORK}/diff.err" || diff_exit=$?
fge_assert_exit FG-038-AT-012 0 "${diff_exit}" 'fg at independently projects both diff endpoints'
fge_assert_contains FG-038-AT-013 "$(<"${WORK}/diff.out")" '0 ref changes, 0 pull request changes' \
  'the later refusal does not fabricate repository changes'

missing_exit=0
"${FG_BIN}" at "${STORAGE}" "${TENANT}" "${REPOSITORY}" decision:3 refs \
  >"${WORK}/missing.out" 2>"${WORK}/missing.err" || missing_exit=$?
fge_assert_exit FG-038-AT-014 2 "${missing_exit}" 'a position ahead of authority is a typed non-success'
fge_assert_contains FG-038-AT-015 "$(<"${WORK}/missing.err")" 'ahead of authority head sequence' \
  'the refusal identifies the unavailable position without latest-state fallback'

fge_phase assert
