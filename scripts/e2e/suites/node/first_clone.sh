#!/usr/bin/env bash
# e2e: FG-028b FIRST CLONE -- a pinned upstream Git client clones from a live
# fgit-node git-daemon. The client remains development-only and is executed
# only through the constrained oracle clone-loopback command; production never
# invokes Git.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
E2E_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
REPOSITORY_ROOT="$(cd "${E2E_ROOT}/../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-${E2E_ROOT}/lib.sh}"

readonly ORACLE="${E2E_ROOT}/oracle/oracle.sh"
readonly ORACLE_PIN="${FGIT_FIRST_CLONE_ORACLE_PIN:-git-2.54.0}"
readonly TENANT_ID='11111111111111111111111111111111'
readonly REPOSITORY_ID='22222222222222222222222222222222'
readonly PRINCIPAL_ID='33333333333333333333333333333333'
readonly REPOSITORY_PATH="/${REPOSITORY_ID}.git"

fge_init first-clone
fge_context bead frankengit-ipo5
fge_context oracle_pin "${ORACLE_PIN}"
fge_context network_profile loopback-git-only
fge_context non_claim 'one bounded upload-pack clone only; no push, HTTP smart transport, multi-tenant service profile, or general networked oracle runner'

WORK_ROOT="$(fge_tempdir first-clone)"
STORAGE_ROOT="${WORK_ROOT}/node"
ORACLE_RUN=''
SERVER_PID=''
FG_BINARY=''

fg_command() {
  "${FG_BINARY}" "$@"
}

wait_for_listener() {
  local port="$1"
  local pid="$2"
  local endpoint=''
  local attempt=0

  [[ -r /proc/net/tcp ]] || return 1
  printf -v endpoint '0100007F:%04X' "$((10#${port}))"
  for attempt in $(seq 1 200); do
    if grep -E \
      "^[[:space:]]*[0-9]+:[[:space:]]+${endpoint}[[:space:]]+00000000:0000[[:space:]]+0A([[:space:]]|$)" \
      /proc/net/tcp >/dev/null; then
      return 0
    fi
    kill -0 "${pid}" 2>/dev/null || return 1
    sleep 0.025
  done
  return 1
}

wait_for_clone_connection() {
  local port="$1"
  local clone_pid="$2"
  local endpoint=''
  local attempt=0

  [[ -r /proc/net/tcp ]] || return 1
  printf -v endpoint '0100007F:%04X' "$((10#${port}))"
  for attempt in $(seq 1 200); do
    if grep -E \
      "^[[:space:]]*[0-9]+:[[:space:]]+${endpoint}[[:space:]]+[^[:space:]]+[[:space:]]+01([[:space:]]|$)" \
      /proc/net/tcp >/dev/null; then
      return 0
    fi
    kill -0 "${clone_pid}" 2>/dev/null || return 1
    sleep 0.025
  done
  return 1
}

wait_for_exit() {
  local pid="$1"
  local attempt=0

  for attempt in $(seq 1 200); do
    kill -0 "${pid}" 2>/dev/null || return 0
    sleep 0.025
  done
  return 1
}

listen_port="$((40000 + (BASHPID % 20000)))"
listen_endpoint="127.0.0.1:${listen_port}"

fge_phase setup
set +e
ORACLE_RUN="$("${ORACLE}" create-run "${ORACLE_PIN}" first-clone)"
oracle_create_exit=$?
set -e
fge_assert_exit FG-028B-CLONE-001 0 "${oracle_create_exit}" \
  'the pinned Git oracle creates a receipted isolated run'
if [[ "${oracle_create_exit}" -ne 0 ]]; then
  exit 0
fi

SOURCE_REPOSITORY="${ORACLE_RUN}/work/source"
CLONE_REPOSITORY="${ORACLE_RUN}/work/clone"
mkdir -p "${SOURCE_REPOSITORY}"
printf 'first clone source\n' > "${SOURCE_REPOSITORY}/README"
# The incompressible object keeps the cancellation connection observable long
# enough to kill the server after it has accepted the second clone.
dd if=/dev/urandom of="${SOURCE_REPOSITORY}/payload.bin" bs=1M count=16 status=none

fge_phase action
if [[ -n "${FGIT_FG_BIN:-}" ]]; then
  FG_BINARY="${FGIT_FG_BIN}"
else
  target_directory="${CARGO_TARGET_DIR:-${REPOSITORY_ROOT}/target}"
  if [[ "${target_directory}" != /* ]]; then
    target_directory="${REPOSITORY_ROOT}/${target_directory}"
  fi
  fg_build_exit=0
  fge_run first-clone-build-fg \
    env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="${target_directory}" \
    cargo build --quiet --locked --manifest-path "${REPOSITORY_ROOT}/Cargo.toml" \
      -p fgit-cli --bin fg || fg_build_exit=$?
  fge_assert_exit FG-028B-CLONE-002 0 "${fg_build_exit}" \
    'the E2E lane builds the exact fg executable it will later reap'
  if [[ "${fg_build_exit}" -ne 0 ]]; then
    exit 0
  fi
  FG_BINARY="${target_directory}/debug/fg"
fi
fge_assert_cmd FG-028B-CLONE-003 \
  'the E2E lane has an absolute executable non-symlinked fg server binary' \
  test "${FG_BINARY}" != "${FG_BINARY#/}" -a -x "${FG_BINARY}" -a ! -L "${FG_BINARY}"

source_init_exit=0
fge_run first-clone-source-init \
  "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" source -- \
  init --initial-branch=main || source_init_exit=$?
fge_assert_exit FG-028B-CLONE-004 0 "${source_init_exit}" \
  'the pinned Git oracle creates the source repository'
if [[ "${source_init_exit}" -ne 0 ]]; then
  exit 0
fi

source_config_name_exit=0
fge_run first-clone-source-config-name \
  "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" source -- \
  config user.name 'FrankenGit First Clone' || source_config_name_exit=$?
fge_assert_exit FG-028B-CLONE-005 0 "${source_config_name_exit}" \
  'the source repository has an oracle-local author identity'
if [[ "${source_config_name_exit}" -ne 0 ]]; then
  exit 0
fi

source_config_email_exit=0
fge_run first-clone-source-config-email \
  "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" source -- \
  config user.email first-clone@invalid.example || source_config_email_exit=$?
fge_assert_exit FG-028B-CLONE-006 0 "${source_config_email_exit}" \
  'the source repository has an oracle-local author email'
if [[ "${source_config_email_exit}" -ne 0 ]]; then
  exit 0
fi

source_add_exit=0
fge_run first-clone-source-add \
  "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" source -- \
  add README payload.bin || source_add_exit=$?
fge_assert_exit FG-028B-CLONE-007 0 "${source_add_exit}" \
  'the source history stages every byte-comparison fixture'
if [[ "${source_add_exit}" -ne 0 ]]; then
  exit 0
fi

source_commit_exit=0
fge_run first-clone-source-commit \
  "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" source -- \
  commit -m 'first clone history' || source_commit_exit=$?
fge_assert_exit FG-028B-CLONE-008 0 "${source_commit_exit}" \
  'the source history is a real pinned-Git loose-object commit'
if [[ "${source_commit_exit}" -ne 0 ]]; then
  exit 0
fi

node_init_exit=0
fge_run first-clone-node-init \
  fg_command init "${STORAGE_ROOT}" "${TENANT_ID}" "${REPOSITORY_ID}" || node_init_exit=$?
fge_assert_exit FG-028B-CLONE-009 0 "${node_init_exit}" \
  'fg init creates the durable authority head for the live node'
if [[ "${node_init_exit}" -ne 0 ]]; then
  exit 0
fi

node_import_exit=0
fge_run first-clone-node-import \
  fg_command import "${STORAGE_ROOT}" "${TENANT_ID}" "${REPOSITORY_ID}" \
  "${PRINCIPAL_ID}" first-clone-import "${SOURCE_REPOSITORY}/.git" || node_import_exit=$?
fge_assert_exit FG-028B-CLONE-010 0 "${node_import_exit}" \
  'fg import publishes the pinned-Git loose history through durable admission'
if [[ "${node_import_exit}" -ne 0 ]]; then
  exit 0
fi

fge_spawn first-clone-server \
  "${FG_BINARY}" serve "${STORAGE_ROOT}" "${TENANT_ID}" "${REPOSITORY_ID}" "${listen_endpoint}"
SERVER_PID="${FGE_LAST_PID}"
listener_ready=no
if wait_for_listener "${listen_port}" "${SERVER_PID}"; then
  listener_ready=yes
fi
fge_assert_eq FG-028B-CLONE-011 yes "${listener_ready}" \
  'the live fgit-node listens only on the chosen loopback endpoint'
if [[ "${listener_ready}" != yes ]]; then
  fge_reap first-clone-server TERM || true
  exit 0
fi

clone_exit=0
fge_run first-clone-pinned-client \
  "${ORACLE}" clone-loopback "${ORACLE_PIN}" "${ORACLE_RUN}" clone \
  "${listen_endpoint}" "${REPOSITORY_PATH}" clone || clone_exit=$?
fge_assert_exit FG-028B-CLONE-012 0 "${clone_exit}" \
  'a pinned Git client completes a real git:// clone against the live node'
server_reap_exit=0
fge_reap first-clone-server TERM || server_reap_exit=$?
fge_assert_exit FG-028B-CLONE-013 0 "${server_reap_exit}" \
  'the bounded live clone server drains and reaps after its one session'

fge_phase assert
fge_assert_file FG-028B-CLONE-014 "${ORACLE_RUN}/transcripts/clone/receipt.tsv" \
  'the clone transcript receipt is retained outside the source checkout'
fge_assert_cmd FG-028B-CLONE-015 \
  'the clone receipt binds the pinned Git identity' \
  grep -Fqx "oracle_id=${ORACLE_PIN}" "${ORACLE_RUN}/transcripts/clone/receipt.tsv"
fge_assert_cmd FG-028B-CLONE-016 \
  'the clone receipt binds the sole allowed loopback endpoint' \
  grep -Fqx "allowed_endpoint=${listen_endpoint}" "${ORACLE_RUN}/transcripts/clone/receipt.tsv"
fge_assert_cmd FG-028B-CLONE-017 \
  'the clone receipt declares the approved loopback-only network profile' \
  grep -Fqx 'network_profile=loopback-git-only' "${ORACLE_RUN}/transcripts/clone/receipt.tsv"

clone_fsck_exit=0
fge_run first-clone-fsck \
  "${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" clone -- \
  fsck --no-dangling || clone_fsck_exit=$?
fge_assert_exit FG-028B-CLONE-018 0 "${clone_fsck_exit}" \
  'the cloned repository passes pinned-Git fsck with no dangling objects'

set +e
source_head="$("${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" source -- rev-parse HEAD)"
source_head_exit=$?
clone_head="$("${ORACLE}" run "${ORACLE_PIN}" "${ORACLE_RUN}" clone -- rev-parse HEAD)"
clone_head_exit=$?
set -e
fge_assert_exit FG-028B-CLONE-019 0 "${source_head_exit}" \
  'the source head is available through the pinned Git oracle'
fge_assert_exit FG-028B-CLONE-020 0 "${clone_head_exit}" \
  'the clone head is available through the pinned Git oracle'
fge_assert_eq FG-028B-CLONE-021 "${source_head}" "${clone_head}" \
  'the clone retains the exact source commit identity'
tree_compare_exit=0
fge_run first-clone-byte-compare \
  diff --recursive --exclude=.git "${SOURCE_REPOSITORY}" "${CLONE_REPOSITORY}" || tree_compare_exit=$?
fge_assert_exit FG-028B-CLONE-022 0 "${tree_compare_exit}" \
  'the cloned worktree is byte-identical to the pinned-Git source worktree'

# A second bounded server proves cancellation containment. The client is a
# tracked pinned-Git oracle child; after its TCP session is observable, the
# node is terminated and both children must be reaped. A subsequent authority
# read proves the interrupted clone did not publish partial state.
fge_phase action
fge_spawn interrupted-clone-server \
  "${FG_BINARY}" serve "${STORAGE_ROOT}" "${TENANT_ID}" "${REPOSITORY_ID}" "${listen_endpoint}"
SERVER_PID="${FGE_LAST_PID}"
interruption_listener_ready=no
if wait_for_listener "${listen_port}" "${SERVER_PID}"; then
  interruption_listener_ready=yes
fi
fge_assert_eq FG-028B-CLONE-023 yes "${interruption_listener_ready}" \
  'the second live node listener is available for the interruption drill'
if [[ "${interruption_listener_ready}" != yes ]]; then
  fge_reap interrupted-clone-server TERM || true
  exit 0
fi

fge_spawn interrupted-clone-client \
  "${ORACLE}" clone-loopback "${ORACLE_PIN}" "${ORACLE_RUN}" interrupted \
  "${listen_endpoint}" "${REPOSITORY_PATH}" interrupted-clone
INTERRUPTED_CLIENT_PID="${FGE_LAST_PID}"
clone_connection_ready=no
if wait_for_clone_connection "${listen_port}" "${INTERRUPTED_CLIENT_PID}"; then
  clone_connection_ready=yes
fi
fge_assert_eq FG-028B-CLONE-024 yes "${clone_connection_ready}" \
  'the pinned client has an active clone connection before server termination'
if [[ "${clone_connection_ready}" != yes ]]; then
  fge_reap interrupted-clone-client TERM || true
  fge_reap interrupted-clone-server TERM || true
  exit 0
fi

server_kill_exit=0
fge_reap interrupted-clone-server TERM || server_kill_exit=$?
fge_assert_ne FG-028B-CLONE-025 0 "${server_kill_exit}" \
  'terminating the live server mid-clone yields a non-successful server outcome'
interrupted_client_completed=no
interrupted_client_exit=0
if wait_for_exit "${INTERRUPTED_CLIENT_PID}"; then
  fge_reap interrupted-clone-client TERM || interrupted_client_exit=$?
  interrupted_client_completed=yes
else
  fge_reap interrupted-clone-client TERM || true
fi
fge_assert_eq FG-028B-CLONE-026 yes "${interrupted_client_completed}" \
  'the interrupted pinned-Git client exits within the bounded reap window'
fge_assert_ne FG-028B-CLONE-027 0 "${interrupted_client_exit}" \
  'the pinned Git client receives a typed non-success outcome after server termination'

node_doctor_exit=0
fge_run first-clone-post-interruption-doctor \
  fg_command doctor "${STORAGE_ROOT}" "${TENANT_ID}" "${REPOSITORY_ID}" || node_doctor_exit=$?
fge_assert_exit FG-028B-CLONE-028 0 "${node_doctor_exit}" \
  'the interrupted read-only clone leaves the authenticated authority head usable and unchanged'
fge_assert_file FG-028B-CLONE-029 "${ORACLE_RUN}/transcripts/interrupted/receipt.tsv" \
  'the interrupted clone retains a pinned-client transcript receipt for diagnosis'

fge_artifact "${ORACLE_RUN}/transcripts/clone/receipt.tsv" first-clone-pinned-client-receipt
fge_artifact "${ORACLE_RUN}/transcripts/interrupted/receipt.tsv" first-clone-interrupted-client-receipt
