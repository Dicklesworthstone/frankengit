#!/usr/bin/env bash
# FG-019c: report-status on a real push, differentially against pinned Git.
#
# Companion to receivepack_differential.sh, which compares the ADVERTISEMENT.
# This one compares what each server says after a push. Upstream Git is a
# pinned, sandboxed differential ORACLE only (AGENTS.md 3.1).
#
# THREE THINGS THIS SUITE LEARNED THE HARD WAY, recorded so they are not
# rediscovered:
#
#   * THE PAYLOAD CANNOT BE BUILT IN SHELL. A receive command line is
#     <old> SP <new> SP <ref> NUL <caps>, and bash $(...) SILENTLY DROPS NUL.
#     A shell-built payload sent Git a ref named refs/heads/doomedreport-status
#     and Git answered with NO report-status at all -- a lane wired that way
#     would have compared two empty sections and called it a match. The Rust
#     bridge emits the bytes; this suite only pipes them.
#   * A DELETE WITH AN UNRESOLVABLE OLD OID IS NOT A MISMATCH. Git answers `ok`
#     with `warning: allowing deletion of corrupt ref`. To reach the
#     expected-old check the old oid must be a REAL object that is simply not
#     the ref's current value; then Git answers
#     `ng <ref> incorrect old value provided`.
#   * GIT DOES NOT REQUIRE THE CLIENT TO NEGOTIATE delete-refs. Our machine
#     does, and refuses DeleteRefsNotNegotiated. That divergence is MEASURED by
#     a third push rather than avoided by a narrower corpus.
#
# Oracle unavailability is a FAILURE, never a skip.
# No jq/python/perl/awk anywhere (FG-000A-PORT-019); coreutils only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-/data/tmp/frankengit-oracle}"
readonly PIN_ID='git-2.54.0'
readonly CORPUS_ENV='FGIT_PUSH_DIFF_CORPUS_DIR'
readonly OUTPUT_ENV='FGIT_PUSH_DIFF_OUTPUT_DIR'
readonly EXPECTED_CELLS=11

RUN_DIRECTORY=''

oracle_run() {
  local label=$1 work=$2
  shift 2
  fge_capture "oracle-${label}" env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" run "${PIN_ID}" "${RUN_DIRECTORY}" "${work}" -- "$@"
}

oracle_capture() {
  local label=$1 work=$2
  shift 2
  fge_capture "oracle-${label}" env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" capture "${PIN_ID}" "${RUN_DIRECTORY}" "${work}" "${label}" -- "$@"
}

transcript_text() {
  tr -d '\r\n' < "${RUN_DIRECTORY}/transcripts/$1/stdout.bin"
}

# Two distinct commits so the refusal case can use a REAL object that is not the
# ref's value. One commit would make "wrong old oid" and "unresolvable oid"
# indistinguishable, and only the first reaches the expected-old check.
prepare_repository() {
  oracle_run source-init . init --quiet source || return
  oracle_run source-name source config user.name 'FrankenGit FG-019c oracle' || return
  oracle_run source-email source config user.email 'fg019c-oracle@invalid.example' || return
  oracle_run source-first source commit --quiet --allow-empty -m first || return
  oracle_capture first-oid source rev-parse HEAD || return
  oracle_run source-second source commit --quiet --allow-empty -m second || return
  oracle_capture second-oid source rev-parse HEAD || return
  oracle_run target-clone . clone --quiet --bare source target.git || return
}

seed_refs() {
  local second=$1
  oracle_run ref-accepted target.git update-ref refs/heads/accepted "${second}" || return
  oracle_run ref-refused target.git update-ref refs/heads/refused "${second}" || return
  oracle_run ref-unnegotiated target.git update-ref refs/heads/unnegotiated "${second}" || return
}

# The bridge reads these; the shell can write them safely because an oid is hex
# with no NUL anywhere.
write_oids() {
  local corpus=$1 first=$2 second=$3
  mkdir -p "${corpus}"
  {
    printf 'refs/heads/accepted\t%s\n' "${second}"
    printf 'refs/heads/refused\t%s\n' "${second}"
    printf 'other-commit\t%s\n' "${first}"
    printf 'unnegotiated-commit\t%s\n' "${second}"
  } > "${corpus}/oids.tsv"
}

push_case() {
  local corpus=$1 case=$2
  fge_capture "oracle-push-${case}" env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" run "${PIN_ID}" "${RUN_DIRECTORY}" target.git -- receive-pack . \
    < "${corpus}/push-${case}.pkt" || return
  cp -- "${FGE_LAST_STDOUT_FILE}" "${corpus}/oracle-${case}.bin"
}

fail_from() {
  local first=$1
  local id
  for id in FG-019C-PUSH-004 FG-019C-PUSH-005 FG-019C-PUSH-006 FG-019C-PUSH-007 \
            FG-019C-PUSH-008 FG-019C-PUSH-009 FG-019C-PUSH-010 FG-019C-PUSH-011; do
    [[ "${id}" < "${first}" ]] || fge_fail "${id}" 'a prerequisite step failed'
  done
}

main() {
  local work_root='' corpus='' output='' verdict=''
  local verify_exit=0 create_exit=0 prepare_exit=0 seed_exit=0
  local emit_exit=0 push_exit=0 compare_exit=0 cells=0
  local created_oid='' landed_exit=0
  local first='' second=''

  fge_phase setup
  work_root="$(fge_tempdir receivepack-push-differential)"
  corpus="${work_root}/corpus"
  output="${work_root}/fgit-output"

  fge_capture oracle-verify env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" verify "${PIN_ID}" || verify_exit=$?
  verify_exit=${verify_exit:-0}
  fge_assert_exit FG-019C-PUSH-001 0 "${verify_exit}" \
    'the pinned Git 2.54.0 oracle is present with matching source and binary digests'
  fge_assert_contains FG-019C-PUSH-002 "${FGE_LAST_STDERR:-}" 'FGIT_ORACLE_OK' \
    'the oracle reports verified rather than unavailable'
  if [[ "${verify_exit}" -ne 0 ]]; then
    fge_fail FG-019C-PUSH-003 'no oracle run directory could be created'
    fail_from FG-019C-PUSH-004
    return
  fi

  fge_capture oracle-create-run env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" create-run "${PIN_ID}" receivepack-push-differential || create_exit=$?
  create_exit=${create_exit:-0}
  fge_assert_exit FG-019C-PUSH-003 0 "${create_exit}" \
    'the receipted oracle creates a run directory'
  if [[ "${create_exit}" -ne 0 ]]; then
    fail_from FG-019C-PUSH-004
    return
  fi
  RUN_DIRECTORY="$(tr -d '\r\n' < "${FGE_LAST_STDOUT_FILE}")"

  fge_phase action
  prepare_repository || prepare_exit=$?
  prepare_exit=${prepare_exit:-0}
  fge_assert_exit FG-019C-PUSH-004 0 "${prepare_exit}" \
    'the oracle builds a bare repository with two distinct commits'
  if [[ "${prepare_exit}" -ne 0 ]]; then
    fail_from FG-019C-PUSH-005
    return
  fi
  first="$(transcript_text first-oid)"
  second="$(transcript_text second-oid)"

  seed_refs "${second}" || seed_exit=$?
  seed_exit=${seed_exit:-0}
  fge_assert_exit FG-019C-PUSH-005 0 "${seed_exit}" \
    'the three target refs are seeded at the second commit'
  if [[ "${seed_exit}" -ne 0 ]]; then
    fail_from FG-019C-PUSH-006
    return
  fi

  write_oids "${corpus}" "${first}" "${second}"

  # Phase 1: Rust writes the payloads, because a NUL cannot survive the shell.
  fge_capture bridge-emit env RCH_CARGO_WRAPPER_BYPASS=1 \
    "${CORPUS_ENV}=${corpus}" "${OUTPUT_ENV}=${output}" \
    cargo test --locked -p fgit-wire --test receivepack_push_differential \
    -- --ignored --exact emit_push_payloads_for_the_oracle || emit_exit=$?
  emit_exit=${emit_exit:-0}
  fge_assert_exit FG-019C-PUSH-006 0 "${emit_exit}" \
    'the bridge writes four NUL-correct push payloads and a pack over a real object closure'
  if [[ "${emit_exit}" -ne 0 ]]; then
    fail_from FG-019C-PUSH-007
    return
  fi

  push_case "${corpus}" accepted || push_exit=$?
  push_case "${corpus}" refused || push_exit=$?
  push_case "${corpus}" unnegotiated || push_exit=$?
  push_case "${corpus}" created || push_exit=$?
  push_exit=${push_exit:-0}
  fge_assert_exit FG-019C-PUSH-007 0 "${push_exit}" \
    'the pinned oracle answers all four pushes over stdin, including the pack-carrying create'
  if [[ "${push_exit}" -ne 0 ]]; then
    fail_from FG-019C-PUSH-008
    return
  fi

  # Phase 2: compare.
  fge_capture bridge-compare env RCH_CARGO_WRAPPER_BYPASS=1 \
    "${CORPUS_ENV}=${corpus}" "${OUTPUT_ENV}=${output}" \
    cargo test --locked -p fgit-wire --test receivepack_push_differential \
    -- --ignored --exact our_report_status_frames_what_git_frames || compare_exit=$?
  compare_exit=${compare_exit:-0}
  fge_assert_exit FG-019C-PUSH-008 0 "${compare_exit}" \
    'fgit-wire frames report-status the way the pinned oracle frames it'

  fge_phase assert
  verdict="${output}/verdict.tsv"
  fge_assert_file FG-019C-PUSH-009 "${verdict}" \
    'the bridge writes one classification per comparison cell'
  if [[ ! -s "${verdict}" ]]; then
    fge_fail FG-019C-PUSH-010 'the divergence cell could not be checked'
    fge_fail FG-019C-PUSH-011 'the cell count could not be checked'
    return
  fi

  fge_assert_cmd FG-019C-PUSH-010 'the stricter-than-Git delete-refs divergence is recorded as OBSERVED AND PENDING the fgit-wire owner ruling, not as accepted compatibility' \
    grep -Fq 'delete_without_negotiated_capability=observed-divergence-pending-owner-ruling:' "${verdict}"
  fge_assert_not_contains FG-019C-PUSH-017 "$(<"${verdict}")" \
    'delete_without_negotiated_capability=accepted-divergence' \
    'the pending divergence is never labelled accepted while its owner review is open'
  fge_assert_cmd FG-019C-PUSH-013 'pinned Git accepts a pack fgit-pack wrote, pushed through receive-pack rather than only index-pack' \
    grep -Fqx 'git_accepts_a_pack_our_writer_produced=match' "${verdict}"
  fge_assert_cmd FG-019C-PUSH-014 'our own machine accepts the very push Git accepted, pack included' \
    grep -Fqx 'our_machine_accepts_the_same_push=match' "${verdict}"

  # `ok` is Git SAYING it updated the ref. This is Git's repository actually
  # containing our commit afterwards, which is the difference between trusting
  # a status line and observing the effect it claims. It also proves the pack
  # was genuinely unpacked and connectivity-checked rather than merely framed.
  created_oid="$(tr -d '\r\n' < "${corpus}/created-oid.txt")"
  landed_exit=0
  oracle_capture created-landed target.git rev-parse refs/heads/created || landed_exit=$?
  landed_exit=${landed_exit:-0}
  fge_assert_exit FG-019C-PUSH-015 0 "${landed_exit}" \
    'the pushed ref resolves in the oracle repository after the push'
  if [[ "${landed_exit}" -eq 0 ]]; then
    fge_assert_eq FG-019C-PUSH-016 "${created_oid}" "$(transcript_text created-landed)" \
      'the oracle repository now holds our commit at the ref we created, so the pack was really unpacked'
  else
    fge_fail FG-019C-PUSH-016 'the pushed ref did not resolve, so its oid could not be compared'
  fi
  fge_assert_not_contains FG-019C-PUSH-011 "$(<"${verdict}")" '=defect' \
    'the classified verdict contains no unresolved defect'

  cells="$(grep -c '=' "${verdict}" || printf '0')"
  fge_assert_eq FG-019C-PUSH-012 "${EXPECTED_CELLS}" "${cells}" \
    'every comparison cell was classified, so the corpus did not shrink'

  fge_artifact "${verdict}" push-differential-verdict
  fge_artifact "${corpus}/oracle-accepted.bin" oracle-push-accepted
  fge_artifact "${corpus}/oracle-refused.bin" oracle-push-refused
  fge_artifact "${corpus}/oracle-unnegotiated.bin" oracle-push-unnegotiated
  fge_artifact "${corpus}/oracle-created.bin" oracle-push-created
  fge_artifact "${corpus}/push-created.pkt" fgit-push-created-payload
}

fge_init fg019c-receivepack-push-differential
fge_context bead frankengit-fg019c-receivepack-adversarial-sht
fge_context evidence_class differential
fge_context oracle_pin "${PIN_ID}"
fge_context method 'emit NUL-correct push payloads from the Rust bridge, pipe each into a sandboxed pinned git receive-pack over stdin, capture its report-status, and compare framing against fgit report_status for the verdict GIT reached'
fge_context claim_boundary 'FRAMING, NOT DECISIONS. report_status encodes a verdict; it does not decide one. Deciding needs the authority stack and the still-absent head-bound projection. The verdicts here come from GIT precisely so no fixture of ours stages the outcome. This lane must NEVER be cited as evidence that fgit and Git agree about WHETHER a push should succeed'
fge_context measured_divergence 'Git 2.54.0 accepts a delete whose client omitted delete-refs; fgit refuses DeleteRefsNotNegotiated. fgit is STRICTER. Classified observed-divergence-pending-owner-ruling, NOT accepted: ProudJaguar owns fgit-wire and is reviewing the normative Git-protocol contracts before ruling, and calling it accepted in an artifact other people read would pre-empt that. fgit-wire source is unchanged. The cell flips to a DEFECT if our machine ever starts accepting it, so the record cannot go stale either way'
fge_context measured_git_behaviour 'a delete with an UNRESOLVABLE old oid is not an expected-old mismatch: Git answers ok with warning: allowing deletion of corrupt ref. Only a resolvable-but-wrong oid reaches the check and yields ng <ref> incorrect old value provided. The corpus uses the latter'
fge_context pack_carrying_push 'a CREATE carrying a real commit/tree/blob closure, planned and written by fgit-pack PackWriter, is pushed through the pinned receive-pack. Git accepting it is evidence about OUR pack bytes on the PUSH path, which index-pack --strict (fg017b) does not cover. The same bytes are then driven through our own ReceivePack and must surface all three closure objects, so the statement is two-sided'
fge_context non_claim 'FRAMING for delete verdicts, plus object-level acceptance for the create. This lane still does not claim fgit and Git agree about WHETHER any given push should succeed. Agreement is with ONE pinned Git version, not the protocol'
main
