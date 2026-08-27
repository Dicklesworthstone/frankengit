#!/usr/bin/env bash
# e2e: FG-028b real pinned-client incremental-fetch campaign.
#
# This is deliberately a live transport test, not an in-process pack-planner
# test.  Every Git invocation goes through the checked-in pinned oracle: its
# only network exception is the exact loopback git:// endpoint passed here.
# Push cases are represented below as a counted transport-status field until
# fg047/hh37 publishes its authenticated SSH interface; this suite never
# substitutes the caller-authenticated in-process receive path.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-${E2E_ROOT}/lib.sh}"

fge_init node-incremental-fetch

readonly TENANT=11111111111111111111111111111111
readonly REPOSITORY=22222222222222222222222222222222
readonly PRINCIPAL=44444444444444444444444444444444
readonly ORACLE="${FGIT_ORACLE:-${E2E_ROOT}/oracle/oracle.sh}"
readonly ORACLE_PIN="${FGIT_ORACLE_PIN:-git-2.54.0}"
readonly FG_BIN="${FG_BIN:-}"

fge_phase setup
fge_assert_cmd FG-028B-FETCH-001 'FG_BIN names a supplied prebuilt fg binary' test -n "${FG_BIN}"
fge_assert_cmd FG-028B-FETCH-002 'the supplied fg binary is executable' test -x "${FG_BIN}"
fge_assert_cmd FG-028B-FETCH-ORACLE-COMMAND 'the pinned oracle command is executable' test -x "${ORACLE}"
[ -x "${FG_BIN}" ] || fge_die 'FG_BIN must name a prebuilt executable; this suite does not silently build or reuse another binary'
[ -x "${ORACLE}" ] || fge_die 'the checked-in pinned oracle command is unavailable'
fge_note FG-028B-FETCH-BINARY "uses prebuilt FG_BIN sha256=$(fge_digest_file "${FG_BIN}"); this suite does not build cargo targets"
fge_field push_transport_status unsupported
fge_field push_transport_scenarios 5
fge_note FG-028B-FETCH-PUSH-STATUS 'five push cases remain typed unsupported until fg047/hh37 publishes authenticated SSH receive-pack'

fge_run oracle-verify "${ORACLE}" verify "${ORACLE_PIN}" || true
ORACLE_VERIFY_RC=${FGE_LAST_EXIT}
fge_assert_eq FG-028B-FETCH-003 0 "${ORACLE_VERIFY_RC}" 'the exact pinned Git oracle is verified before any client command'
[ "${ORACLE_VERIFY_RC}" -eq 0 ] || fge_die 'pinned oracle is unavailable; no ambient Git fallback is permitted'

fge_capture oracle-create-run "${ORACLE}" create-run "${ORACLE_PIN}" incremental-fetch || true
ORACLE_RUN_RC=${FGE_LAST_EXIT}
fge_assert_eq FG-028B-FETCH-004 0 "${ORACLE_RUN_RC}" 'the pinned client received an isolated oracle run directory'
[ "${ORACLE_RUN_RC}" -eq 0 ] || fge_die 'unable to create the pinned oracle run'
ORACLE_RUN="$(tr -d '\n' <"${FGE_LAST_STDOUT_FILE}")"
fge_assert_cmd FG-028B-FETCH-005 'the oracle run directory is absolute and exists' test -d "${ORACLE_RUN}/work"

WORK="$(fge_tempdir incremental-fetch)"
STORAGE="${WORK}/storage"
SOURCE="${ORACLE_RUN}/work/source"
ADVANCE="${ORACLE_RUN}/work/advance"

oracle_git() { # STEP WORKDIR git args...
  local step=$1 workdir=$2
  shift 2
  fge_run "${step}" "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" "${workdir}" -- "$@"
}

oracle_git_capture() { # STEP WORKDIR git args...
  local step=$1 workdir=$2
  shift 2
  fge_capture "${step}" "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" "${workdir}" -- "$@"
}

oracle_loopback_clone() { # STEP LABEL PORT DESTINATION
  local step=$1 label=$2 port=$3 destination=$4
  fge_run "${step}" "${ORACLE}" clone-loopback "${ORACLE_PIN}" "${ORACLE_RUN}" "${label}" \
    "127.0.0.1:${port}" "/${REPOSITORY}.git" "${destination}"
}

oracle_loopback_fetch() { # STEP LABEL PORT WORKDIR PROTOCOL REFSPEC
  local step=$1 label=$2 port=$3 workdir=$4 protocol=$5 refspec=$6
  fge_run "${step}" "${ORACLE}" fetch-loopback "${ORACLE_PIN}" "${ORACLE_RUN}" "${label}" \
    "127.0.0.1:${port}" "/${REPOSITORY}.git" "${workdir}" "${protocol}" "${refspec}"
}

OBJECT_COUNT=''

object_count() { # LABEL WORKDIR; writes OBJECT_COUNT
  local label=$1 workdir=$2
  oracle_git_capture "${label}" "${workdir}" cat-file --batch-all-objects --batch-check='%(objectname)' || return $?
  OBJECT_COUNT=$(wc -l <"${FGE_LAST_STDOUT_FILE}" | tr -d ' ')
}

pack_bytes() { # path to a local Git worktree
  local repository=$1 pack_file bytes total=0
  while IFS= read -r pack_file; do
    bytes=$(wc -c <"${pack_file}")
    bytes=${bytes// /}
    total=$((total + bytes))
  done < <(find "${repository}/.git/objects/pack" -type f -name '*.pack' -print | LC_ALL=C sort)
  printf '%s\n' "${total}"
}

pack_names() { # path, output file
  find "$1/.git/objects/pack" -type f -name '*.pack' -printf '%f\n' | LC_ALL=C sort >"$2"
}

incremental_bytes_since() { # local worktree, before-names file
  local repository=$1 before=$2 pack_file loose_file name bytes total=0
  while IFS= read -r pack_file; do
    name=${pack_file##*/}
    if ! grep -Fqx -- "${name}" "${before}"; then
      bytes=$(wc -c <"${pack_file}")
      bytes=${bytes// /}
      total=$((total + bytes))
    fi
  done < <(find "${repository}/.git/objects/pack" -type f -name '*.pack' -print | LC_ALL=C sort)
  while IFS= read -r loose_file; do
    bytes=$(wc -c <"${loose_file}")
    bytes=${bytes// /}
    total=$((total + bytes))
  done < <(find "${repository}/.git/objects" -maxdepth 2 -type f ! -path '*/pack/*' ! -name 'pack*' ! -name '*.idx' ! -name '*.rev' -print | LC_ALL=C sort)
  printf '%s\n' "${total}"
}

is_incremental_pack() { # incremental bytes, full-clone bytes
  [ "$2" -gt 0 ] && [ "$1" -gt 0 ] && [ $(( $1 * 4 )) -lt "$2" ]
}

SERVER_OFFSET=$((16#${FGE_SEED:0:4} % 20000))
SERVER_PID=''
SERVER_NAME=''
SERVER_PORT=''
SERVER_LOG=''

start_server() { # name live-acceptance-id session-count in-flight-count
  local name=$1 live_id=$2 sessions=$3 in_flight=$4 attempt port log alive=0
  for attempt in $(seq 0 31); do
    port=$((20000 + ((SERVER_OFFSET + attempt) % 20000)))
    log="${WORK}/${name}-${port}.stderr"
    fge_spawn "${name}-${port}" bash -c 'exec "$@" >"$0" 2>&1' "${log}" \
      "${FG_BIN}" serve "${STORAGE}" "${TENANT}" "${REPOSITORY}" "127.0.0.1:${port}" \
      --max-sessions "${sessions}" --max-in-flight "${in_flight}"
    SERVER_PID=${FGE_LAST_PID}
    SERVER_NAME="${name}-${port}"
    SERVER_PORT=${port}
    SERVER_LOG=${log}
    sleep 0.1
    if kill -0 "${SERVER_PID}" 2>/dev/null; then
      alive=1
      break
    fi
    fge_reap "${SERVER_NAME}" TERM
  done
  SERVER_OFFSET=$((SERVER_OFFSET + 37))
  fge_assert_eq "${live_id}" 1 "${alive}" "${name} binds a live bounded listener"
  [ "${alive}" -eq 1 ] || fge_die "${name} never became a live listener"
}

drain_server() { # stable acceptance ID, expected accepted/completed count
  local id=$1 expected=$2 rc=0
  wait "${SERVER_PID}" || rc=$?
  fge_note "${id}-receipt" "server ${SERVER_NAME} exited ${rc} after accepting its bounded session count"
  fge_reap "${SERVER_NAME}" TERM
  fge_assert_eq "${id}" 0 "${rc}" 'bounded fg serve drains admitted sessions before exit'
  fge_assert_contains "${id}-SERVICE-RECEIPT" "$(cat "${SERVER_LOG}")" \
    "accepted=${expected}, completed=${expected}, refused=0" \
    'fg serve reports the exact drained bounded-session receipt'
}

wait_spawned() { # stable acceptance ID, name, pid
  local id=$1 name=$2 pid=$3 rc=0
  wait "${pid}" || rc=$?
  fge_note "${id}-receipt" "client ${name} exited ${rc}"
  fge_reap "${name}" TERM
  fge_assert_eq "${id}" 0 "${rc}" 'pinned client fetch exits successfully'
}

fge_phase action

oracle_git seed-init . init -b main source || true
fge_assert_eq FG-028B-FETCH-006 0 "${FGE_LAST_EXIT}" 'the pinned client creates the source repository'
oracle_git seed-email source config user.email fg028b@invalid.example || true
fge_assert_eq FG-028B-FETCH-007 0 "${FGE_LAST_EXIT}" 'source fixture has deterministic author email'
oracle_git seed-name source config user.name 'FG-028b pinned oracle fixture' || true
fge_assert_eq FG-028B-FETCH-008 0 "${FGE_LAST_EXIT}" 'source fixture has deterministic author name'

mkdir -p "${SOURCE}/tree"
printf 'seed=%s\n' "$(fge_seed)" >"${SOURCE}/README"
seq 1 700000 >"${SOURCE}/tree/baseline-a.txt"
seq 700001 1400000 >"${SOURCE}/tree/baseline-b.txt"
oracle_git seed-add source add -A || true
fge_assert_eq FG-028B-FETCH-009 0 "${FGE_LAST_EXIT}" 'the base source files are staged through the pinned client'
oracle_git seed-commit source commit -m base || true
fge_assert_eq FG-028B-FETCH-010 0 "${FGE_LAST_EXIT}" 'the base source history is committed through the pinned client'
oracle_git_capture source-tip source rev-parse main || true
fge_assert_eq FG-028B-FETCH-011 0 "${FGE_LAST_EXIT}" 'the base source tip is resolved by the pinned client'
BASE_TIP="$(tr -d '[:space:]' <"${FGE_LAST_STDOUT_FILE}")"

fge_run fg-init "${FG_BIN}" init "${STORAGE}" "${TENANT}" "${REPOSITORY}" || true
fge_assert_eq FG-028B-FETCH-012 0 "${FGE_LAST_EXIT}" 'fg init publishes the repository authority root'
fge_run fg-import-base "${FG_BIN}" import "${STORAGE}" "${TENANT}" "${REPOSITORY}" "${PRINCIPAL}" \
  fg028b-base "${SOURCE}" || true
fge_assert_eq FG-028B-FETCH-013 0 "${FGE_LAST_EXIT}" 'fg import publishes the initial oracle source history'
[ "${FGE_LAST_EXIT}" -eq 0 ] || fge_die 'initial source import is required before a real fetch can be exercised'

start_server clone-baseline FG-028B-FETCH-014-LIVE 7 4
BASELINE_PORT=${SERVER_PORT}
for client in client-v1 client-v2 concurrent-1 concurrent-2 concurrent-3 client-kill server-kill; do
  oracle_loopback_clone "clone-${client}" "clone-${client}" "${BASELINE_PORT}" "${client}" || true
  fge_assert_eq "FG-028B-FETCH-CLONE-${client}" 0 "${FGE_LAST_EXIT}" "pinned client ${client} completes a real baseline clone"
done
drain_server FG-028B-FETCH-014 7

cp -a "${SOURCE}" "${ADVANCE}"
oracle_git advance-rename advance branch -m main next || true
fge_assert_eq FG-028B-FETCH-015 0 "${FGE_LAST_EXIT}" 'advance source exposes a new ref rather than re-importing main'
mkdir -p "${ADVANCE}/tree"
seq 1 120000 >"${ADVANCE}/tree/incremental.txt"
printf 'advance=%s\n' "$(fge_seed)" >>"${ADVANCE}/README"
oracle_git advance-add advance add -A || true
fge_assert_eq FG-028B-FETCH-016 0 "${FGE_LAST_EXIT}" 'incremental source files are staged by the pinned client'
oracle_git advance-commit advance commit -m incremental-next || true
fge_assert_eq FG-028B-FETCH-017 0 "${FGE_LAST_EXIT}" 'incremental source history is committed by the pinned client'
oracle_git_capture advance-new-objects advance rev-list --objects --no-object-names next "^${BASE_TIP}" || true
fge_assert_eq FG-028B-FETCH-018 0 "${FGE_LAST_EXIT}" 'the exact introduced object set is enumerated before publication'
EXPECTED_NEW_OBJECTS=$(LC_ALL=C sort -u "${FGE_LAST_STDOUT_FILE}" | wc -l | tr -d ' ')
fge_assert_cmd FG-028B-FETCH-019 'the advance introduces at least one object' test "${EXPECTED_NEW_OBJECTS}" -gt 0

fge_run fg-import-advance "${FG_BIN}" import "${STORAGE}" "${TENANT}" "${REPOSITORY}" "${PRINCIPAL}" \
  fg028b-next "${ADVANCE}" || true
fge_assert_eq FG-028B-FETCH-020 0 "${FGE_LAST_EXIT}" 'fg import advances the served repository through a distinct next ref'
[ "${FGE_LAST_EXIT}" -eq 0 ] || fge_die 'the required post-clone fg import advance did not publish'

for client in client-v1 client-v2 concurrent-1 concurrent-2 concurrent-3; do
  object_count "${client}-objects-before" "${client}" || fge_die "cannot count objects in ${client} before fetch"
  printf '%s\n' "${OBJECT_COUNT}" >"${WORK}/${client}.objects-before"
  pack_names "${ORACLE_RUN}/work/${client}" "${WORK}/${client}.packs-before"
  full_bytes=$(pack_bytes "${ORACLE_RUN}/work/${client}")
  printf '%s\n' "${full_bytes}" >"${WORK}/${client}.full-bytes"
  fge_assert_cmd "FG-028B-FETCH-FULL-PACK-${client}" 'baseline clone materialized a non-empty full pack' test "${full_bytes}" -gt 0
done

start_server fetch-v1-v2-and-concurrent FG-028B-FETCH-023-LIVE 5 4
FETCH_PORT=${SERVER_PORT}

for client in concurrent-1 concurrent-2 concurrent-3; do
  fge_spawn "fetch-${client}" bash -c 'exec "$@"' _ "${ORACLE}" fetch-loopback "${ORACLE_PIN}" "${ORACLE_RUN}" \
    "fetch-${client}" "127.0.0.1:${FETCH_PORT}" "/${REPOSITORY}.git" "${client}" v2 \
    refs/heads/next:refs/remotes/origin/next
  eval "FETCH_PID_${client//-/_}=${FGE_LAST_PID}"
done
oracle_loopback_fetch fetch-v1 fetch-v1 "${FETCH_PORT}" client-v1 v1 refs/heads/next:refs/remotes/origin/next || true
fge_assert_eq FG-028B-FETCH-021 0 "${FGE_LAST_EXIT}" 'pinned Git protocol v1 performs an incremental fetch'
oracle_loopback_fetch fetch-v2 fetch-v2 "${FETCH_PORT}" client-v2 v2 refs/heads/next:refs/remotes/origin/next || true
fge_assert_eq FG-028B-FETCH-022 0 "${FGE_LAST_EXIT}" 'pinned Git protocol v2 performs an incremental fetch'
for client in concurrent-1 concurrent-2 concurrent-3; do
  variable="FETCH_PID_${client//-/_}"
  wait_spawned "FG-028B-FETCH-CONCURRENT-${client}" "fetch-${client}" "${!variable}"
done
drain_server FG-028B-FETCH-023 5

for protocol in v1 v2; do
  fge_assert_contains "FG-028B-FETCH-PROTOCOL-${protocol}" "$(cat "${ORACLE_RUN}/transcripts/fetch-${protocol}/receipt.tsv")" \
    "protocol=${protocol}" "the pinned fetch receipt binds protocol ${protocol}"
done

for client in client-v1 client-v2 concurrent-1 concurrent-2 concurrent-3; do
  client_root="${ORACLE_RUN}/work/${client}"
  before=$(tr -d ' ' <"${WORK}/${client}.objects-before")
  object_count "${client}-objects-after" "${client}" || fge_die "cannot count objects in ${client} after fetch"
  actual_new=$((OBJECT_COUNT - before))
  fge_assert_eq "FG-028B-FETCH-OBJECTS-${client}" "${EXPECTED_NEW_OBJECTS}" "${actual_new}" \
    'the client received exactly the new Git objects, not a full-object replay'
  incremental=$(incremental_bytes_since "${client_root}" "${WORK}/${client}.packs-before")
  full=$(tr -d ' ' <"${WORK}/${client}.full-bytes")
  fge_assert_cmd "FG-028B-FETCH-INCREMENTAL-${client}" 'new negotiated pack is strictly less than one quarter of the full clone pack' \
    is_incremental_pack "${incremental}" "${full}"
  if is_incremental_pack "${full}" "${full}"; then
    fge_fail "FG-028B-FETCH-NEGATIVE-${client}" 'a full-clone-sized fetch incorrectly satisfies the incremental threshold'
  else
    fge_pass "FG-028B-FETCH-NEGATIVE-${client}" 'planted negative: a full-clone-sized fetch is rejected by the incremental threshold'
  fi
  oracle_git "${client}-fsck" "${client}" fsck --strict || true
  fge_assert_eq "FG-028B-FETCH-FSCK-${client}" 0 "${FGE_LAST_EXIT}" 'pinned strict fsck accepts every transferred object'
  oracle_git "${client}-checkout-next" "${client}" checkout -B next refs/remotes/origin/next || true
  fge_assert_eq "FG-028B-FETCH-CHECKOUT-${client}" 0 "${FGE_LAST_EXIT}" 'the fetched next ref checks out through the pinned client'
  diff_rc=0
  diff -r --exclude=.git "${ADVANCE}" "${client_root}" >/dev/null 2>&1 || diff_rc=$?
  fge_assert_eq "FG-028B-FETCH-WORKTREE-${client}" 0 "${diff_rc}" 'fetched worktree is byte-identical to the oracle source'
done

fge_phase failpoint

# A large branch keeps a client actively transferring at the named kill point.
# The name is part of the seeded receipt; a client that has already exited is
# not credited as an in-flight kill and fails the check before restart/retry.
CLIENT_FAULT="${ORACLE_RUN}/work/client-fault"
cp -a "${ADVANCE}" "${CLIENT_FAULT}"
oracle_git client-fault-rename client-fault branch -m next client-fault || true
fge_assert_eq FG-028B-FETCH-024 0 "${FGE_LAST_EXIT}" 'client-kill source uses a new absent branch'
seq 1 900000 >"${CLIENT_FAULT}/tree/client-kill.txt"
oracle_git client-fault-add client-fault add -A || true
oracle_git client-fault-commit client-fault commit -m client-kill-fault || true
fge_run fg-import-client-fault "${FG_BIN}" import "${STORAGE}" "${TENANT}" "${REPOSITORY}" "${PRINCIPAL}" \
  fg028b-client-fault "${CLIENT_FAULT}" || true
fge_assert_eq FG-028B-FETCH-025 0 "${FGE_LAST_EXIT}" 'client-kill branch is advanced through fg import'
[ "${FGE_LAST_EXIT}" -eq 0 ] || fge_die 'client-kill branch did not publish'

start_server client-kill FG-028B-FETCH-026-LIVE 1 1
CLIENT_KILL_PORT=${SERVER_PORT}
fge_spawn client-kill-fetch bash -c 'exec "$@"' _ "${ORACLE}" fetch-loopback "${ORACLE_PIN}" "${ORACLE_RUN}" \
  client-kill-fetch "127.0.0.1:${CLIENT_KILL_PORT}" "/${REPOSITORY}.git" client-kill v2 \
  refs/heads/client-fault:refs/remotes/origin/client-fault
CLIENT_KILL_PID=${FGE_LAST_PID}
sleep 0.1
fge_assert_cmd FG-028B-FETCH-026 'client SIGKILL is injected while the named client-fault fetch process is live' \
  kill -0 "${CLIENT_KILL_PID}"
fge_reap client-kill-fetch KILL
fge_reap "${SERVER_NAME}" TERM

start_server client-kill-retry FG-028B-FETCH-028-LIVE 1 1
oracle_loopback_fetch client-kill-retry client-kill-retry "${SERVER_PORT}" client-kill v2 \
  refs/heads/client-fault:refs/remotes/origin/client-fault || true
fge_assert_eq FG-028B-FETCH-027 0 "${FGE_LAST_EXIT}" 'restart after client SIGKILL retries to one convergent branch outcome'
drain_server FG-028B-FETCH-028 1
oracle_git client-kill-fsck client-kill fsck --strict || true
fge_assert_eq FG-028B-FETCH-029 0 "${FGE_LAST_EXIT}" 'client-kill retry repository remains strict-fsck clean'
oracle_git client-kill-checkout client-kill checkout -B client-fault refs/remotes/origin/client-fault || true
fge_assert_eq FG-028B-FETCH-CLIENT-KILL-CHECKOUT 0 "${FGE_LAST_EXIT}" 'client-kill retry checks out the retried branch'
client_diff_rc=0
diff -r --exclude=.git "${CLIENT_FAULT}" "${ORACLE_RUN}/work/client-kill" >/dev/null 2>&1 || client_diff_rc=$?
fge_assert_eq FG-028B-FETCH-CLIENT-KILL-WORKTREE 0 "${client_diff_rc}" 'client-kill retry worktree is byte-identical to its oracle source'

SERVER_FAULT="${ORACLE_RUN}/work/server-fault"
cp -a "${ADVANCE}" "${SERVER_FAULT}"
oracle_git server-fault-rename server-fault branch -m next server-fault || true
fge_assert_eq FG-028B-FETCH-030 0 "${FGE_LAST_EXIT}" 'server-kill source uses a new absent branch'
seq 1 900000 >"${SERVER_FAULT}/tree/server-kill.txt"
oracle_git server-fault-add server-fault add -A || true
oracle_git server-fault-commit server-fault commit -m server-kill-fault || true
fge_run fg-import-server-fault "${FG_BIN}" import "${STORAGE}" "${TENANT}" "${REPOSITORY}" "${PRINCIPAL}" \
  fg028b-server-fault "${SERVER_FAULT}" || true
fge_assert_eq FG-028B-FETCH-031 0 "${FGE_LAST_EXIT}" 'server-kill branch is advanced through fg import'
[ "${FGE_LAST_EXIT}" -eq 0 ] || fge_die 'server-kill branch did not publish'

start_server server-kill FG-028B-FETCH-032-LIVE 1 1
SERVER_KILL_PORT=${SERVER_PORT}
fge_spawn server-kill-fetch bash -c 'exec "$@"' _ "${ORACLE}" fetch-loopback "${ORACLE_PIN}" "${ORACLE_RUN}" \
  server-kill-fetch "127.0.0.1:${SERVER_KILL_PORT}" "/${REPOSITORY}.git" server-kill v2 \
  refs/heads/server-fault:refs/remotes/origin/server-fault
SERVER_KILL_CLIENT_PID=${FGE_LAST_PID}
sleep 0.1
fge_assert_cmd FG-028B-FETCH-032 'server SIGKILL is injected while the named fetch client is live' \
  kill -0 "${SERVER_KILL_CLIENT_PID}"
fge_reap "${SERVER_NAME}" KILL
fge_reap server-kill-fetch TERM

start_server server-kill-retry FG-028B-FETCH-034-LIVE 1 1
oracle_loopback_fetch server-kill-retry server-kill-retry "${SERVER_PORT}" server-kill v2 \
  refs/heads/server-fault:refs/remotes/origin/server-fault || true
fge_assert_eq FG-028B-FETCH-033 0 "${FGE_LAST_EXIT}" 'restart after server SIGKILL retries to one convergent branch outcome'
drain_server FG-028B-FETCH-034 1
oracle_git server-kill-fsck server-kill fsck --strict || true
fge_assert_eq FG-028B-FETCH-035 0 "${FGE_LAST_EXIT}" 'server-kill retry repository remains strict-fsck clean'
oracle_git server-kill-checkout server-kill checkout -B server-fault refs/remotes/origin/server-fault || true
fge_assert_eq FG-028B-FETCH-036 0 "${FGE_LAST_EXIT}" 'server-kill retry checks out the retried branch'
server_diff_rc=0
diff -r --exclude=.git "${SERVER_FAULT}" "${ORACLE_RUN}/work/server-kill" >/dev/null 2>&1 || server_diff_rc=$?
fge_assert_eq FG-028B-FETCH-037 0 "${server_diff_rc}" 'server-kill retry worktree is byte-identical to its oracle source'

fge_phase assert
fge_note FG-028B-FETCH-038 'clone, v1/v2 incremental fetch, concurrent fetch, client/server SIGKILL restart-and-retry, strict fsck, and worktree equality were exercised through real pinned clients'
