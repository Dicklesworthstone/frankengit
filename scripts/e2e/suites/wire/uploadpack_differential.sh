#!/usr/bin/env bash
# FG-018c: byte differential for the upload-pack protocol surface owned by
# fgit-wire.  Upstream Git runs only through the pinned, Bubblewrap-isolated
# oracle; no production binary invokes it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "${REPOSITORY_ROOT}/scripts/e2e/lib.sh"

readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly PIN_ID='git-2.54.0'
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-/data/tmp/frankengit-oracle}"
readonly CORPUS_ENV='FGIT_UPLOADPACK_DIFFERENTIAL_CORPUS'
readonly OUTPUT_ENV='FGIT_UPLOADPACK_DIFFERENTIAL_OUTPUT'

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

fail_after_create() {
  fge_fail FG-018C-E2E-002 'the generated oracle repository could not be created'
  fge_fail FG-018C-E2E-003 'the Git-accepted epoch-0 object could not be stored and advertised'
  fge_fail FG-018C-E2E-004 'the v0/v1 advertisement transcript could not be captured'
  fge_fail FG-018C-E2E-005 'the v0/v1 fetch transcript could not be captured'
  fge_fail FG-018C-E2E-006 'the v2 advertisement transcript could not be captured'
  fge_fail FG-018C-E2E-007 'the v2 ls-refs transcript could not be captured'
  fge_fail FG-018C-E2E-008 'the v2 fetch transcript could not be captured'
  fge_fail FG-018C-E2E-009 'the differential corpus could not be assembled'
  fge_fail FG-018C-E2E-010 'fgit-wire could not consume the pinned Git corpus'
  fge_fail FG-018C-E2E-011 'the fgit-wire transcript verdict could not be written'
  fge_fail FG-018C-E2E-012 'the match classifications could not be checked'
  fge_fail FG-018C-E2E-013 'the accepted-divergence classifications could not be checked'
  fge_fail FG-018C-E2E-014 'a defect-free classified verdict could not be established'
}

fail_after_setup() {
  fge_fail FG-018C-E2E-003 'the Git-accepted epoch-0 object could not be stored and advertised'
  fge_fail FG-018C-E2E-004 'the v0/v1 advertisement transcript could not be captured'
  fge_fail FG-018C-E2E-005 'the v0/v1 fetch transcript could not be captured'
  fge_fail FG-018C-E2E-006 'the v2 advertisement transcript could not be captured'
  fge_fail FG-018C-E2E-007 'the v2 ls-refs transcript could not be captured'
  fge_fail FG-018C-E2E-008 'the v2 fetch transcript could not be captured'
  fge_fail FG-018C-E2E-009 'the differential corpus could not be assembled'
  fge_fail FG-018C-E2E-010 'fgit-wire could not consume the pinned Git corpus'
  fge_fail FG-018C-E2E-011 'the fgit-wire transcript verdict could not be written'
  fge_fail FG-018C-E2E-012 'the match classifications could not be checked'
  fge_fail FG-018C-E2E-013 'the accepted-divergence classifications could not be checked'
  fge_fail FG-018C-E2E-014 'a defect-free classified verdict could not be established'
}

fail_after_epoch0() {
  fge_fail FG-018C-E2E-004 'the v0/v1 advertisement transcript could not be captured'
  fge_fail FG-018C-E2E-005 'the v0/v1 fetch transcript could not be captured'
  fge_fail FG-018C-E2E-006 'the v2 advertisement transcript could not be captured'
  fge_fail FG-018C-E2E-007 'the v2 ls-refs transcript could not be captured'
  fge_fail FG-018C-E2E-008 'the v2 fetch transcript could not be captured'
  fge_fail FG-018C-E2E-009 'the differential corpus could not be assembled'
  fge_fail FG-018C-E2E-010 'fgit-wire could not consume the pinned Git corpus'
  fge_fail FG-018C-E2E-011 'the fgit-wire transcript verdict could not be written'
  fge_fail FG-018C-E2E-012 'the match classifications could not be checked'
  fge_fail FG-018C-E2E-013 'the accepted-divergence classifications could not be checked'
  fge_fail FG-018C-E2E-014 'a defect-free classified verdict could not be established'
}

prepare_repository() {
  mkdir -p "${RUN_DIRECTORY}/work/source"
  printf 'ordinary object\n' > "${RUN_DIRECTORY}/work/source/README"
  oracle_run source-init . init --quiet source || return
  oracle_run source-name source config user.name 'FrankenGit FG-018c oracle' || return
  oracle_run source-email source config user.email 'fg018c-oracle@invalid.example' || return
  oracle_run source-add source add README || return
  oracle_run source-commit source commit --quiet -m ordinary || return
  oracle_run source-bare . clone --quiet --bare source source.git || return
  oracle_capture source-tree source rev-parse 'HEAD^{tree}' || return
}

store_epoch0_object() {
  local tree_oid=''
  local epoch0_oid=''

  tree_oid="$(oracle_stdout source-tree)"
  [[ "${tree_oid}" =~ ^[0-9a-f]{40}$ ]] || return 1
  # This body has no header/message separator.  Git stores and advertises it;
  # fgit-git-object accepts it only under GitCompatibleImport, not StrictCreate.
  printf 'tree %s\nauthor Epoch Zero <epoch0@invalid.example> 1 +0000\ncommitter Epoch Zero <epoch0@invalid.example> 1 +0000\n' \
    "${tree_oid}" > "${RUN_DIRECTORY}/work/epoch0-commit.body"

  # oracle.sh deliberately accepts Git argv only.  These repo-local aliases
  # bridge controlled stdin to the already-pinned executable inside its bwrap
  # sandbox; they never appear in a FrankenGit production process.
  oracle_run epoch0-alias source.git config alias.fg018c-store-epoch0 \
    '!$GIT_EXEC_PATH/git-hash-object -t commit -w --stdin < ../epoch0-commit.body' || return
  oracle_capture epoch0-store source.git fg018c-store-epoch0 || return
  epoch0_oid="$(oracle_stdout epoch0-store)"
  [[ "${epoch0_oid}" =~ ^[0-9a-f]{40}$ ]] || return 1
  oracle_run epoch0-ref source.git update-ref refs/heads/epoch0 "${epoch0_oid}"
}

capture_transcripts() {
  local advertisement=''
  local prefix=''
  local head_oid=''
  local v1_payload=''

  oracle_capture v1-advertisement source.git upload-pack --advertise-refs . || return
  advertisement="${RUN_DIRECTORY}/transcripts/v1-advertisement/stdout.bin"
  prefix="$(head -c 44 "${advertisement}")"
  head_oid="${prefix:4:40}"
  [[ "${head_oid}" =~ ^[0-9a-f]{40}$ ]] || return 1

  v1_payload="want ${head_oid} multi_ack_detailed side-band-64k ofs-delta"
  printf '%04x%s\n00000009done\n' "$((5 + ${#v1_payload}))" "${v1_payload}" \
    > "${RUN_DIRECTORY}/work/v1-fetch-request.pkt"
  oracle_run v1-alias source.git config alias.fg018c-v1 \
    '!$GIT_EXEC_PATH/git-upload-pack --stateless-rpc . < ../v1-fetch-request.pkt' || return
  oracle_capture v1-fetch-response source.git fg018c-v1 || return

  printf '0014command=ls-refs\n00010000' > "${RUN_DIRECTORY}/work/v2-ls-refs-request.pkt"
  printf '0012command=fetch\n00010032want %s\n0009done\n0000' "${head_oid}" \
    > "${RUN_DIRECTORY}/work/v2-fetch-request.pkt"
  oracle_run v2-advertise-alias source.git config alias.fg018c-v2-advertise \
    '!GIT_PROTOCOL=version=2 $GIT_EXEC_PATH/git-upload-pack --advertise-refs .' || return
  oracle_run v2-ls-refs-alias source.git config alias.fg018c-v2-ls-refs \
    '!GIT_PROTOCOL=version=2 $GIT_EXEC_PATH/git-upload-pack --stateless-rpc . < ../v2-ls-refs-request.pkt' || return
  oracle_run v2-fetch-alias source.git config alias.fg018c-v2-fetch \
    '!GIT_PROTOCOL=version=2 $GIT_EXEC_PATH/git-upload-pack --stateless-rpc . < ../v2-fetch-request.pkt' || return
  oracle_capture v2-advertisement source.git fg018c-v2-advertise || return
  oracle_capture v2-ls-refs-response source.git fg018c-v2-ls-refs || return
  oracle_capture v2-fetch-response source.git fg018c-v2-fetch
}

packet_prefix() {
  local source=$1
  local destination=$2
  local header=''
  local declared=0

  header="$(head -c 4 "${source}")"
  [[ "${header}" =~ ^[0-9a-f]{4}$ ]] || return 1
  declared=$((16#${header}))
  [[ "${declared}" -ge 4 ]] || return 1
  head -c "${declared}" "${source}" > "${destination}"
}

assemble_corpus() {
  local corpus=$1

  mkdir -p "${corpus}"
  cp -- "${RUN_DIRECTORY}/transcripts/v1-advertisement/stdout.bin" \
    "${corpus}/v1-advertisement.pkt"
  cp -- "${RUN_DIRECTORY}/work/v1-fetch-request.pkt" "${corpus}/v1-fetch-request.pkt"
  packet_prefix "${RUN_DIRECTORY}/transcripts/v1-fetch-response/stdout.bin" \
    "${corpus}/v1-negotiation-prefix.pkt" || return
  cp -- "${RUN_DIRECTORY}/transcripts/v2-advertisement/stdout.bin" \
    "${corpus}/v2-advertisement.pkt"
  cp -- "${RUN_DIRECTORY}/work/v2-ls-refs-request.pkt" "${corpus}/v2-ls-refs-request.pkt"
  cp -- "${RUN_DIRECTORY}/transcripts/v2-ls-refs-response/stdout.bin" \
    "${corpus}/v2-ls-refs-response.pkt"
  cp -- "${RUN_DIRECTORY}/work/v2-fetch-request.pkt" "${corpus}/v2-fetch-request.pkt"
  packet_prefix "${RUN_DIRECTORY}/transcripts/v2-fetch-response/stdout.bin" \
    "${corpus}/v2-fetch-prefix.pkt" || return
  cp -- "${RUN_DIRECTORY}/work/epoch0-commit.body" "${corpus}/epoch0-commit.body"
}

fge_init fg018c-uploadpack-differential
fge_context bead frankengit-fg018c-uploadpack-differential-ehn
fge_context evidence_class E3
fge_context oracle_pin "${PIN_ID}"
fge_context oracle_root "${ORACLE_ROOT}"
fge_context non_claim 'the SANS-I/O wire layer does not claim a network server, clone completion, or pack-byte equivalence'
fge_phase setup

work_root="$(fge_tempdir uploadpack-differential)"
create_exit=0
fge_capture oracle-create-run env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
  "${ORACLE}" create-run "${PIN_ID}" uploadpack-differential || create_exit=$?
fge_assert_exit FG-018C-E2E-001 0 "${create_exit}" \
  'the receipted Git 2.54.0 oracle creates the generated-repository run'
if [[ "${create_exit}" -ne 0 ]]; then
  fail_after_create
  exit 0
fi
RUN_DIRECTORY="$(tr -d '\r\n' < "${FGE_LAST_STDOUT_FILE}")"

setup_exit=0
prepare_repository || setup_exit=$?
fge_assert_exit FG-018C-E2E-002 0 "${setup_exit}" \
  'the pinned oracle creates a bare repository with an ordinary reachable commit'
if [[ "${setup_exit}" -ne 0 ]]; then
  fail_after_setup
  exit 0
fi

epoch0_exit=0
store_epoch0_object || epoch0_exit=$?
fge_assert_exit FG-018C-E2E-003 0 "${epoch0_exit}" \
  'Git stores and advertises the epoch-0 body that StrictCreate intentionally refuses'
if [[ "${epoch0_exit}" -ne 0 ]]; then
  fail_after_epoch0
  exit 0
fi

capture_exit=0
capture_transcripts || capture_exit=$?
fge_assert_exit FG-018C-E2E-004 0 "${capture_exit}" \
  'the pinned oracle captures v0/v1 and v2 upload-pack transcripts over the generated repository'
if [[ "${capture_exit}" -ne 0 ]]; then
  fge_fail FG-018C-E2E-005 'the v0/v1 fetch transcript was not available after capture failure'
  fge_fail FG-018C-E2E-006 'the v2 advertisement transcript was not available after capture failure'
  fge_fail FG-018C-E2E-007 'the v2 ls-refs transcript was not available after capture failure'
  fge_fail FG-018C-E2E-008 'the v2 fetch transcript was not available after capture failure'
  fge_fail FG-018C-E2E-009 'the differential corpus could not be assembled after capture failure'
  fge_fail FG-018C-E2E-010 'fgit-wire could not consume the unavailable corpus'
  fge_fail FG-018C-E2E-011 'the fgit-wire transcript verdict could not be written'
  fge_fail FG-018C-E2E-012 'the match classifications could not be checked'
  fge_fail FG-018C-E2E-013 'the accepted-divergence classifications could not be checked'
  fge_fail FG-018C-E2E-014 'a defect-free classified verdict could not be established'
  exit 0
fi

fge_assert_file FG-018C-E2E-005 "${RUN_DIRECTORY}/transcripts/v1-fetch-response/stdout.bin" \
  'the captured v0/v1 fetch response has exact raw bytes'
fge_assert_file FG-018C-E2E-006 "${RUN_DIRECTORY}/transcripts/v2-advertisement/stdout.bin" \
  'the captured v2 capability advertisement has exact raw bytes'
fge_assert_file FG-018C-E2E-007 "${RUN_DIRECTORY}/transcripts/v2-ls-refs-response/stdout.bin" \
  'the captured v2 ls-refs response has exact raw bytes'
fge_assert_file FG-018C-E2E-008 "${RUN_DIRECTORY}/transcripts/v2-fetch-response/stdout.bin" \
  'the captured v2 fetch response has exact raw bytes'

fge_phase action
corpus_directory="${work_root}/corpus"
output_directory="${work_root}/fgit-output"
corpus_exit=0
assemble_corpus "${corpus_directory}" || corpus_exit=$?
fge_assert_exit FG-018C-E2E-009 0 "${corpus_exit}" \
  'every compared request, response, and epoch-0 body is copied into the bridge corpus'
if [[ "${corpus_exit}" -ne 0 ]]; then
  fge_fail FG-018C-E2E-010 'fgit-wire could not consume the incomplete corpus'
  fge_fail FG-018C-E2E-011 'the fgit-wire transcript verdict could not be written'
  fge_fail FG-018C-E2E-012 'the match classifications could not be checked'
  fge_fail FG-018C-E2E-013 'the accepted-divergence classifications could not be checked'
  fge_fail FG-018C-E2E-014 'a defect-free classified verdict could not be established'
  exit 0
fi

bridge_exit=0
fge_capture fgit-wire-bridge env RCH_CARGO_WRAPPER_BYPASS=1 \
  "${CORPUS_ENV}=${corpus_directory}" \
  "${OUTPUT_ENV}=${output_directory}" \
  cargo test --locked -p fgit-wire --test uploadpack_differential -- --ignored --nocapture || bridge_exit=$?
fge_assert_exit FG-018C-E2E-010 0 "${bridge_exit}" \
  'fgit-wire matches every owned generated-repository transcript and classifies its seams'
if [[ "${bridge_exit}" -ne 0 ]]; then
  fge_fail FG-018C-E2E-011 'the fgit-wire transcript verdict could not be written'
  fge_fail FG-018C-E2E-012 'the match classifications could not be checked'
  fge_fail FG-018C-E2E-013 'the accepted-divergence classifications could not be checked'
  fge_fail FG-018C-E2E-014 'a defect-free classified verdict could not be established'
  exit 0
fi

verdict="${output_directory}/verdict.tsv"
fge_assert_file FG-018C-E2E-011 "${verdict}" \
  'the bridge writes an artifact with one classification per observed divergence'
fge_assert_cmd FG-018C-E2E-012 'the owned v1/v2 transcript cells are byte matches' \
  grep -Fqx 'oracle_v2_fetch_prefix=match' "${verdict}"
fge_assert_cmd FG-018C-E2E-013 'every intentional boundary is named as an accepted divergence with rationale' \
  grep -Fqx 'epoch0_strict_create=accepted-divergence-with-rationale:GitCompatibleImport-preserves-the-bounded-Git-accepted-body;StrictCreate-refuses-new-noncanonical-objects' "${verdict}"
fge_assert_not_contains FG-018C-E2E-014 "$(<"${verdict}")" '=defect' \
  'the classified verdict contains no unresolved defect'

fge_artifact "${verdict}" uploadpack-differential-verdict
fge_artifact "${output_directory}/fgit-v1-advertisement.pkt" fgit-v1-advertisement
fge_artifact "${output_directory}/fgit-v1-negotiation-prefix.pkt" fgit-v1-negotiation-prefix
fge_artifact "${output_directory}/fgit-v2-ls-refs-response.pkt" fgit-v2-ls-refs-response
fge_artifact "${output_directory}/fgit-v2-fetch-prefix.pkt" fgit-v2-fetch-prefix
