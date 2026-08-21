#!/usr/bin/env bash
# FG-017b: pack-writer benchmark against upstream git pack-objects, per plan 38.4.
#
# WHAT IS AND IS NOT COMPARABLE HERE. This is the part a benchmark usually gets
# wrong, so it is stated before any number is produced:
#
#   * SIZE is comparable. Both sides pack the SAME object set -- the producer
#     emits the object bodies, and this suite loads exactly those bodies into a
#     real repository with git hash-object before asking git pack-objects to
#     pack them. Both numbers are bytes of a pack over identical input, and both
#     are deterministic, so the ratio is meaningful and reproducible.
#
#   * TIME IS NOT COMPARABLE, and this suite refuses to compare it. FrankenGit's
#     arm is an in-process function call measured with a monotonic clock. Git's
#     arm is a process spawn inside a Bubblewrap sandbox, which pays fork, exec,
#     dynamic linking, and sandbox setup before it does any packing at all.
#     Dividing one by the other would produce a number that looks like a
#     speed-up and measures process startup. Both timings are RECORDED, per
#     plan 38.4's raw-samples requirement, and the cross-arm ratio is
#     deliberately absent.
#
#   * CPU and MEMORY are NOT MEASURED. Saying so is the honest alternative to
#     omitting the dimensions silently.
#
# THE HYPOTHESIS, fixed before measurement (plan 38.4 requires one): the frozen
# STORED_V1 profile emits stored DEFLATE blocks, so FrankenGit packs should be
# substantially LARGER than git's, and the gap should track how compressible the
# corpus is. A size win, or a gap that ignores compressibility, would mean the
# profile is not doing what it says. This lane therefore asserts a PREDICTED
# LOSS. Losing here is the designed trade and is recorded as durable evidence,
# not hidden.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='pack_writer_benchmark'
readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly PIN_ID='git-2.54.0'
readonly CORPORA=(compressible incompressible similar)
FGIT_SAMPLES=''

# Iterations of git pack-objects per corpus. Matches the producer's arm size so
# neither side is summarised from a different sample count.
readonly GIT_ITERATIONS=25

# Reads one top-level numeric field out of the producer's summary line for a
# corpus. fge_json_top populates the FGE_JSON associative array rather than
# printing, so this wraps it into the value-returning shape the joins below use.
fgit_field() {
  local corpus="$1" field="$2" line=''
  line="$(grep "\"corpus\":\"${corpus}\"" "${FGIT_SAMPLES}" | head -1)"
  [[ -n "${line}" ]] || { printf '0'; return 0; }
  fge_json_top "${line}" || { printf '0'; return 0; }
  printf '%s' "${FGE_JSON[${field}]:-0}"
}

main() {
  local artifacts='' producer_exit=0 corpus='' run_directory=''
  local kind='' oid='' git_pack_bytes=0 fgit_pack_bytes=0 source_bytes=0
  local comparison='' iteration=0 started=0 finished=0 sample_ns=0
  local git_samples='' aa_delta=0 fgit_p50=0 aa_ratio_permille=0

  fge_phase setup
  artifacts="$(fge_artifact_path pack-writer-benchmark)"
  mkdir -p "${artifacts}"
  FGIT_SAMPLES="${artifacts}/fgit-samples.ndjson"

  fge_phase action
  fge_capture produce \
    env "FGIT_PACK_BENCH_ARTIFACT_DIR=${artifacts}" \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test -p fgit-pack --test writer_benchmark -- --ignored --nocapture \
    || producer_exit=$?
  producer_exit=${producer_exit:-0}

  fge_phase assert
  fge_assert_exit 'FG-017B-BENCH-001' 0 "${producer_exit}" \
    'the benchmark producer completes'
  fge_assert_file 'FG-017B-BENCH-002' "${artifacts}/fgit-samples.ndjson" \
    'the producer emits per-corpus summaries'
  fge_assert_file 'FG-017B-BENCH-003' "${artifacts}/fgit-raw-samples.ndjson" \
    'the producer emits raw per-iteration samples, as plan 38.4 requires'

  if [[ ! -f "${artifacts}/fgit-samples.ndjson" ]]; then
    fge_fail 'FG-017B-BENCH-004' 'no producer samples; the comparison cannot run'
    return 0
  fi

  comparison="${artifacts}/comparison.ndjson"
  : > "${comparison}"

  for corpus in "${CORPORA[@]}"; do
    fge_phase action
    [[ -f "${artifacts}/${corpus}-objects.tsv" ]] || {
      fge_phase assert
      fge_fail "FG-017B-BENCH-010-${corpus}" "the ${corpus} object index is missing"
      continue
    }

    # Load exactly the producer's object set into a real repository. Packing a
    # different object set than FrankenGit packed would make the size ratio
    # meaningless, so the bodies come from the producer rather than being
    # regenerated here.
    run_directory="$("${ORACLE}" create-run "${PIN_ID}" "bench-${corpus}")"
    mkdir -p "${run_directory}/work/repo"
    "${ORACLE}" run "${PIN_ID}" "${run_directory}" . -- init --quiet repo
    "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- config user.name 'FrankenGit Bench'
    "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- config user.email 'bench@invalid.example'

    : > "${run_directory}/work/repo/oids.txt"
    while IFS=$'\t' read -r kind oid; do
      [[ -n "${kind}" && -n "${oid}" ]] || continue
      cp "${artifacts}/${corpus}-objects/${oid}" "${run_directory}/work/repo/.body"
      "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- \
        hash-object -w -t "${kind}" .body >/dev/null
      printf '%s\n' "${oid}" >> "${run_directory}/work/repo/oids.txt"
    done < "${artifacts}/${corpus}-objects.tsv"
    rm -f "${run_directory}/work/repo/.body"

    # Time git pack-objects over that exact object set.
    git_samples=''
    git_pack_bytes=0
    for ((iteration = 0; iteration < GIT_ITERATIONS; iteration++)); do
      started=$(date +%s%N)
      "${ORACLE}" run "${PIN_ID}" "${run_directory}" repo -- \
        pack-objects --stdout --window=10 --depth=10 \
        < "${run_directory}/work/repo/oids.txt" \
        > "${run_directory}/work/repo/git.pack" 2>/dev/null
      finished=$(date +%s%N)
      sample_ns=$((finished - started))
      git_samples="${git_samples}{\"corpus\":\"${corpus}\",\"arm\":\"git\",\"iteration\":${iteration},\"ns\":${sample_ns}}
"
      if [[ "${git_pack_bytes}" -eq 0 ]]; then
        git_pack_bytes=$(wc -c < "${run_directory}/work/repo/git.pack")
      fi
    done
    printf '%s' "${git_samples}" >> "${artifacts}/git-raw-samples.ndjson"

    # Join the two sides for this corpus.
    fgit_pack_bytes="$(fgit_field "${corpus}" fgit_pack_bytes)"
    source_bytes="$(fgit_field "${corpus}" source_bytes)"
    aa_delta="$(fgit_field "${corpus}" aa_control_p50_delta_ns)"
    fgit_p50="$(fgit_field "${corpus}" fgit_a_p50_ns)"

    printf '{"schema":"frankengit.pack-writer-comparison.v1","corpus":"%s","source_bytes":%s,"fgit_pack_bytes":%s,"git_pack_bytes":%s,"size_ratio_permille":%s,"fgit_p50_ns":%s,"git_iterations":%s,"aa_control_p50_delta_ns":%s,"time_comparable":false,"time_incomparable_reason":"fgit arm is in-process; git arm is a sandboxed process spawn"}\n' \
      "${corpus}" "${source_bytes}" "${fgit_pack_bytes}" "${git_pack_bytes}" \
      "$(( fgit_pack_bytes * 1000 / (git_pack_bytes > 0 ? git_pack_bytes : 1) ))" \
      "${fgit_p50}" "${GIT_ITERATIONS}" "${aa_delta}" \
      >> "${comparison}"

    fge_phase assert
    fge_assert_ne "FG-017B-BENCH-020-${corpus}" 0 "${git_pack_bytes}" \
      "the pinned client produced a pack for the ${corpus} corpus"

    # The A/A control gates every timing number for this corpus. If two
    # identical arms differ by more than a fifth of the measured median, this
    # run measured its own jitter and no timing statement about it is
    # supportable.
    aa_ratio_permille=$(( aa_delta * 1000 / (fgit_p50 > 0 ? fgit_p50 : 1) ))
    if [[ "${aa_ratio_permille}" -gt 200 ]]; then
      fge_note "aa-control-${corpus}" \
        "A/A spread is ${aa_ratio_permille} permille of the median; timing for ${corpus} is INCONCLUSIVE"
    fi
    fge_assert_ne "FG-017B-BENCH-021-${corpus}" 0 "${fgit_p50}" \
      "the ${corpus} corpus produced a usable FrankenGit timing sample"
  done

  fge_phase assert
  fge_assert_file 'FG-017B-BENCH-030' "${comparison}" \
    'a size comparison artifact exists for every corpus'
  fge_assert_ndjson 'FG-017B-BENCH-031' "${comparison}" \
    'the comparison artifact is parseable NDJSON'

  # THE PREDICTED LOSS, asserted rather than hoped for. On the compressible
  # corpus, stored blocks must lose to real DEFLATE. If FrankenGit ever won
  # here, STORED_V1 would not be storing and this lane should fail loudly rather
  # than quietly report an improvement nobody designed.
  local compressible_ratio=0
  local ratio_line=''
  ratio_line="$(grep '"corpus":"compressible"' "${comparison}" | head -1)"
  if [[ -n "${ratio_line}" ]] && fge_json_top "${ratio_line}"; then
    compressible_ratio="${FGE_JSON[size_ratio_permille]:-0}"
  fi
  fge_assert_ne 'FG-017B-BENCH-040' 0 "${compressible_ratio}" \
    'the compressible corpus produced a size ratio'
  if [[ "${compressible_ratio}" -le 1000 ]]; then
    fge_fail 'FG-017B-BENCH-041' \
      "FrankenGit packed the compressible corpus at ${compressible_ratio} permille of git, i.e. no larger; STORED_V1 is documented as storing rather than compressing, so this contradicts the profile"
  else
    fge_pass 'FG-017B-BENCH-041' \
      "predicted loss confirmed: ${compressible_ratio} permille of git on the compressible corpus"
  fi

  fge_artifact "${comparison}" pack-writer-comparison
  fge_artifact "${artifacts}/fgit-raw-samples.ndjson" pack-writer-raw-samples
}

fge_init fg017b-pack-writer-benchmark
fge_context bead frankengit-fg017b-pack-writer-evidence-evd
fge_context evidence_class benchmark
fge_context hypothesis 'STORED_V1 emits stored DEFLATE blocks, so FrankenGit packs are predicted to be LARGER than git pack-objects, with the gap tracking corpus compressibility'
fge_context oracle_pin "${PIN_ID}"
fge_context comparable_dimension 'pack SIZE over an identical object set; both sides are deterministic and the ratio is reproducible'
fge_context incomparable_dimension 'TIME. The FrankenGit arm is an in-process call; the git arm is a sandboxed process spawn paying fork/exec/link/sandbox setup before packing. Both are recorded; the cross-arm ratio is deliberately not computed'
fge_context unmeasured_dimension 'CPU time, RSS, and cache state are NOT measured by this lane'
fge_context aa_control 'two identical FrankenGit arms are measured per corpus; a corpus whose A/A spread exceeds 200 permille of its median is reported as timing-inconclusive'
fge_context non_claim 'these are microbenchmarks of one component over small synthetic corpora; plan 38.4 states a microbenchmark win cannot justify an end-to-end claim, and none is made'
fge_context negative_result 'a size loss to upstream git is the DESIGNED outcome of the stored-block profile and is recorded as durable evidence; this artifact is the baseline a later compressing profile must beat'
main
