#!/usr/bin/env bash
# FG-019c: receive-pack advertisement, differentially against pinned upstream Git.
#
# The receive-pack counterpart to FG-018c's uploadpack_differential.sh, and it
# borrows that suite's shape deliberately: capture transcripts from the
# sandboxed pinned oracle, hand them to a Rust bridge, and assert over the
# classified verdict the bridge writes. Upstream Git is a pinned, sandboxed
# differential ORACLE only; no production binary invokes it (AGENTS.md 3.1).
#
# WHAT IS COMPARED, AND WHY NOT EVERYTHING. Git advertises the capabilities Git
# implements, including agent=git/2.54.0-Linux; we advertise ours. Byte equality
# over the whole advertisement would therefore be red for a reason that says
# nothing about compatibility, and the only way to make it green would be to
# claim Git's feature set. So the capability section is classified as an
# accepted divergence with rationale, and the comparison runs over the framing a
# real client actually breaks on: the pre-NUL <oid> <refname> segment, the
# pkt-line length landing exactly on the flush, the NUL, the trailing LF, and
# the terminator.
#
# ORACLE UNAVAILABILITY IS A FAILURE, NOT A SKIP. oracle.sh distinguishes
# UNAVAILABLE from success by design; a differential suite that quietly passed
# on a machine with no oracle would be the worst outcome this file could have.
#
# No jq/python/perl/awk anywhere (FG-000A-PORT-019); coreutils only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-/data/tmp/frankengit-oracle}"
readonly PIN_ID='git-2.54.0'
readonly CORPUS_ENV='FGIT_RECEIVEPACK_CORPUS_DIR'
readonly OUTPUT_ENV='FGIT_RECEIVEPACK_OUTPUT_DIR'

# Every cell the bridge must classify. Pinned as a NUMBER so a bridge that
# silently stopped comparing would fail this lane instead of shrinking quietly.
readonly EXPECTED_CELLS=10

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
    "${ORACLE}" capture "${PIN_ID}" "${RUN_DIRECTORY}" "${work_directory}" "${label}" -- "$@"
}

# A repository with one ordinary commit, and a second with no refs at all.
# The empty one is not an edge case bolted on: `capabilities^{}` against an
# all-zero id is how Git advertises an empty repository, and it is the shape a
# server is most likely to get wrong by inventing a branch instead.
prepare_repositories() {
  oracle_run source-init . init --quiet source || return
  oracle_run source-name source config user.name 'FrankenGit FG-019c oracle' || return
  oracle_run source-email source config user.email 'fg019c-oracle@invalid.example' || return
  oracle_run source-commit source commit --quiet --allow-empty -m ordinary || return
  oracle_run source-bare . clone --quiet --bare source source.git || return
  oracle_run empty-init . init --quiet --bare empty.git || return
}

capture_advertisements() {
  oracle_capture populated source.git receive-pack --advertise-refs . || return
  oracle_capture empty empty.git receive-pack --advertise-refs . || return
}

assemble_corpus() {
  local corpus=$1
  mkdir -p "${corpus}"
  cp -- "${RUN_DIRECTORY}/transcripts/populated/stdout.bin" "${corpus}/oracle-populated.pkt" || return
  cp -- "${RUN_DIRECTORY}/transcripts/empty/stdout.bin" "${corpus}/oracle-empty.pkt" || return
}

fail_remaining() {
  fge_fail FG-019C-DIFF-005 'the oracle advertisements were not captured'
  fge_fail FG-019C-DIFF-006 'the differential corpus could not be assembled'
  fge_fail FG-019C-DIFF-007 'fgit-wire could not consume the corpus'
  fge_fail FG-019C-DIFF-008 'the verdict artifact was not written'
  fge_fail FG-019C-DIFF-009 'the framing cells could not be checked'
  fge_fail FG-019C-DIFF-010 'the empty-repository cell could not be checked'
  fge_fail FG-019C-DIFF-011 'the capability divergence could not be checked'
  fge_fail FG-019C-DIFF-012 'no defect-free classified verdict could be established'
  fge_fail FG-019C-DIFF-013 'the cell count could not be checked'
}

main() {
  local work_root='' corpus_directory='' output_directory='' verdict=''
  local verify_exit=0 create_exit=0 prepare_exit=0 capture_exit=0
  local corpus_exit=0 bridge_exit=0 cells=0

  fge_phase setup
  work_root="$(fge_tempdir receivepack-differential)"

  fge_capture oracle-verify env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" verify "${PIN_ID}" || verify_exit=$?
  verify_exit=${verify_exit:-0}
  fge_assert_exit FG-019C-DIFF-001 0 "${verify_exit}" \
    'the pinned Git 2.54.0 oracle is present with matching source and binary digests'
  # The marker goes to STDERR, and oracle.sh exits 69 (UNAVAILABLE) rather than
  # 0 when there is no receipted binary — so DIFF-001 already rejects an absent
  # oracle. This is the second, independent check that the run was verified and
  # not merely exit-zero for some other reason. An earlier version read
  # FGE_LAST_STDOUT, where this marker never appears, and could only ever fail.
  fge_assert_contains FG-019C-DIFF-002 "${FGE_LAST_STDERR:-}" 'FGIT_ORACLE_OK' \
    'the oracle reports verified rather than unavailable'
  if [[ "${verify_exit}" -ne 0 ]]; then
    fge_fail FG-019C-DIFF-003 'no oracle run directory could be created'
    fge_fail FG-019C-DIFF-004 'the oracle repositories were not prepared'
    fail_remaining
    return
  fi

  fge_capture oracle-create-run env "FGIT_ORACLE_ROOT=${ORACLE_ROOT}" \
    "${ORACLE}" create-run "${PIN_ID}" receivepack-differential || create_exit=$?
  create_exit=${create_exit:-0}
  fge_assert_exit FG-019C-DIFF-003 0 "${create_exit}" \
    'the receipted oracle creates a run directory'
  if [[ "${create_exit}" -ne 0 ]]; then
    fge_fail FG-019C-DIFF-004 'the oracle repositories were not prepared'
    fail_remaining
    return
  fi
  RUN_DIRECTORY="$(tr -d '\r\n' < "${FGE_LAST_STDOUT_FILE}")"

  fge_phase action
  prepare_repositories || prepare_exit=$?
  prepare_exit=${prepare_exit:-0}
  fge_assert_exit FG-019C-DIFF-004 0 "${prepare_exit}" \
    'the oracle builds a bare repository with one commit and a second with no refs'
  if [[ "${prepare_exit}" -ne 0 ]]; then
    fail_remaining
    return
  fi

  capture_advertisements || capture_exit=$?
  capture_exit=${capture_exit:-0}
  fge_assert_exit FG-019C-DIFF-005 0 "${capture_exit}" \
    'the pinned oracle emits both receive-pack advertisements'
  if [[ "${capture_exit}" -ne 0 ]]; then
    fge_fail FG-019C-DIFF-006 'the differential corpus could not be assembled'
    fge_fail FG-019C-DIFF-007 'fgit-wire could not consume the corpus'
    fge_fail FG-019C-DIFF-008 'the verdict artifact was not written'
    fge_fail FG-019C-DIFF-009 'the framing cells could not be checked'
    fge_fail FG-019C-DIFF-010 'the empty-repository cell could not be checked'
    fge_fail FG-019C-DIFF-011 'the capability divergence could not be checked'
    fge_fail FG-019C-DIFF-012 'no defect-free classified verdict could be established'
    fge_fail FG-019C-DIFF-013 'the cell count could not be checked'
    return
  fi

  corpus_directory="${work_root}/corpus"
  output_directory="${work_root}/fgit-output"
  assemble_corpus "${corpus_directory}" || corpus_exit=$?
  corpus_exit=${corpus_exit:-0}
  fge_assert_exit FG-019C-DIFF-006 0 "${corpus_exit}" \
    'both captured advertisements are copied into the bridge corpus'
  if [[ "${corpus_exit}" -ne 0 ]]; then
    fge_fail FG-019C-DIFF-007 'fgit-wire could not consume the corpus'
    fge_fail FG-019C-DIFF-008 'the verdict artifact was not written'
    fge_fail FG-019C-DIFF-009 'the framing cells could not be checked'
    fge_fail FG-019C-DIFF-010 'the empty-repository cell could not be checked'
    fge_fail FG-019C-DIFF-011 'the capability divergence could not be checked'
    fge_fail FG-019C-DIFF-012 'no defect-free classified verdict could be established'
    fge_fail FG-019C-DIFF-013 'the cell count could not be checked'
    return
  fi

  # RCH_CARGO_WRAPPER_BYPASS is pinned HERE rather than inherited: without it
  # the wrapper offloads the build, the bridge runs and passes remotely, and its
  # artifacts land on the wrong host while this suite fails on a missing file.
  fge_capture fgit-wire-bridge env RCH_CARGO_WRAPPER_BYPASS=1 \
    "${CORPUS_ENV}=${corpus_directory}" \
    "${OUTPUT_ENV}=${output_directory}" \
    cargo test --locked -p fgit-wire --test receivepack_differential -- --ignored --nocapture \
    || bridge_exit=$?
  bridge_exit=${bridge_exit:-0}
  fge_assert_exit FG-019C-DIFF-007 0 "${bridge_exit}" \
    'fgit-wire frames both advertisements the way the pinned oracle frames them'

  fge_phase assert
  verdict="${output_directory}/verdict.tsv"
  fge_assert_file FG-019C-DIFF-008 "${verdict}" \
    'the bridge writes one classification per comparison cell'
  if [[ ! -s "${verdict}" ]]; then
    fge_fail FG-019C-DIFF-009 'the framing cells could not be checked'
    fge_fail FG-019C-DIFF-010 'the empty-repository cell could not be checked'
    fge_fail FG-019C-DIFF-011 'the capability divergence could not be checked'
    fge_fail FG-019C-DIFF-012 'no defect-free classified verdict could be established'
    fge_fail FG-019C-DIFF-013 'the cell count could not be checked'
    return
  fi

  # Named cells, not just "no defects": a verdict that stopped emitting a cell
  # would contain no defect either.
  fge_assert_cmd FG-019C-DIFF-009 'the advertised oid and ref name are byte-identical to Git, and the pkt length lands on the flush' \
    grep -Fqx 'populated_ref_identity_and_name=match' "${verdict}"
  fge_assert_cmd FG-019C-DIFF-010 'the empty repository advertises Git'"'"'s capabilities^{} pseudo-ref rather than an invented branch' \
    grep -Fqx 'empty_repository_pseudo_ref=match' "${verdict}"
  fge_assert_cmd FG-019C-DIFF-011 'the capability difference is classified as an accepted divergence with its rationale, not silently matched' \
    grep -Fq 'capability_set=accepted-divergence-with-rationale:' "${verdict}"
  fge_assert_not_contains FG-019C-DIFF-012 "$(<"${verdict}")" '=defect' \
    'the classified verdict contains no unresolved defect'

  cells="$(grep -c '=' "${verdict}" || printf '0')"
  fge_assert_eq FG-019C-DIFF-013 "${EXPECTED_CELLS}" "${cells}" \
    'every comparison cell was classified, so the corpus did not shrink'

  fge_artifact "${verdict}" receivepack-differential-verdict
  fge_artifact "${output_directory}/fgit-populated.pkt" fgit-receivepack-populated
  fge_artifact "${output_directory}/fgit-empty.pkt" fgit-receivepack-empty
  fge_artifact "${corpus_directory}/oracle-populated.pkt" oracle-receivepack-populated
  fge_artifact "${corpus_directory}/oracle-empty.pkt" oracle-receivepack-empty
}

fge_init fg019c-receivepack-differential
fge_context bead frankengit-fg019c-receivepack-adversarial-sht
fge_context evidence_class differential
fge_context oracle_pin "${PIN_ID}"
fge_context oracle_root "${ORACLE_ROOT}"
fge_context method 'capture git receive-pack --advertise-refs from a sandboxed pinned oracle over two repository states, produce the fgit-wire advertisement for the same state, and classify each framing cell as match, accepted-divergence-with-rationale, or defect'
fge_context compared 'pre-NUL <oid> <refname> segment byte for byte; the pkt-line declared length landing exactly on the terminating flush; presence of the capability NUL; trailing LF; flush terminator; and the capabilities^{} pseudo-ref an empty repository advertises'
fge_context accepted_divergence 'capability SETS differ by design and are classified rather than compared. Git advertises what Git implements including agent=git/2.54.0-Linux; fgit advertises what fgit implements. Making them byte-equal would mean claiming support we do not have, so an identical capability string is treated as a DEFECT rather than a pass'
fge_context comparator_can_fail 'the bridge carries a non-oracle probe that corrupts its own advertisement by lowering the declared pkt length one byte and requires the framing cell to classify it a defect, so a verdict of all-match rests on a comparator observed rejecting something'
fge_context non_claim 'ADVERTISEMENT ONLY. Nothing here pushes. Differential push behaviour - feeding one client command stream and pack to both servers and comparing report-status - is a larger slice and is NOT attempted or claimed. Agreement is with ONE pinned Git version, not with the protocol in general'
main
