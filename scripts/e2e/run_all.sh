#!/usr/bin/env bash
# =============================================================================
# FrankenGit e2e suite runner  --  scripts/e2e/run_all.sh
# Owner bead: frankengit-fg000a-e2e-harness-4ci
#
# Discovers e2e scripts, runs each one without hiding its stderr, VALIDATES the
# NDJSON evidence every script produced, aggregates exact ID sets, and returns
# nonzero on any non-pass disposition.
#
# usage: run_all.sh [OPTIONS] [SCRIPT...]
#
#   --dir DIR        discovery root (default: scripts/e2e/suites)
#   --out DIR        receipt/artifact root
#                    (default: target/e2e-artifacts/run_all/<run id>)
#   --timeout SECS   per-script wall budget (default 900; 0 disables)
#   --attempts N     max attempts per script (default 1)
#   --list           print the discovered script ids and exit
#   --help
#
# Explicit SCRIPT arguments bypass discovery and are used verbatim.
#
# -----------------------------------------------------------------------------
# WHAT MAKES A SCRIPT NON-PASS
# -----------------------------------------------------------------------------
# Exactly one disposition is recorded per script, first match wins:
#
#   not_executable        discovered but not an executable regular file
#   missing_log           no NDJSON log was produced
#   truncated_log         the log does not end with a newline, or the seq values
#                         do not form exactly {1..N} -- a lost record
#   malformed_log         some line is not a complete JSON object, or is missing
#                         a required base key, or carries the wrong schema
#   missing_terminal      no terminal record
#   multiple_terminal     more than one terminal record, or it is not last
#   exit_mismatch         the process exit status disagrees with the status the
#                         terminal record claims
#   zero_assertions       the script discovered no assertions at all
#   duplicate_ids         an acceptance ID was emitted twice in one script
#   cross_duplicate_id    two scripts claim the same acceptance ID
#   timeout               the script hit its wall budget
#   containment           orphaned child processes or unresolved obligations
#   skipped / unsupported the script reported a skipped or unsupported assertion
#   failed                at least one assertion failed
#   flaky                 a later attempt passed but the FIRST attempt failed
#   ok                    everything above is clear
#
# `--attempts N > 1` never launders a first-attempt failure into a green: the
# first attempt's log is preserved, its status is reported, and the suite is
# non-pass. Retrying is for observing flakiness, not for hiding it.
#
# -----------------------------------------------------------------------------
# RECEIPT
# -----------------------------------------------------------------------------
# <out>/receipt.ndjson, schema "frankengit.e2e.suite.v1", three record kinds:
#   suite_begin     invocation, discovery root, environment identity
#   suite_script    one per script: dispositions, exact ID sets, digests, paths
#   suite_terminal  exact discovered / selected / started / passed / failed /
#                   skipped / unsupported / timed_out / malformed_log /
#                   missing_terminal / zero_assertion / duplicate_id /
#                   containment_failed / not_run ID sets, plus the union of
#                   acceptance IDs and any claimed by more than one script.
#
# SEAM FOR FG-091: FG-091 owns the checked-in expected-suite manifest and the
# required==passed set-equality gate, and layers them on this receipt. This
# runner deliberately has NO manifest, NO allowlist generated from discovery
# and NO minimum script count: each is a documented false-green mechanism, and
# a runner that invented its own expected set would make the manifest
# unfalsifiable.
# =============================================================================

set -euo pipefail

RA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$RA_DIR/lib.sh"

fge__detect_digest_tool || {
  printf 'run_all: unsupported: no sha-256 helper found\n' >&2
  exit 4
}

RA_REPO_ROOT=$(fge__repo_root "$RA_DIR")
RA_SUITE_DIR="$RA_DIR/suites"
RA_OUT=''
RA_TIMEOUT=900
RA_ATTEMPTS=1
RA_LIST=0
declare -a RA_EXPLICIT=()

RA_SCHEMA='frankengit.e2e.suite.v1'
RA_SCHEMA_VERSION=1

usage() {
  sed -n '/^# usage:/,/^#   --help/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
  case $1 in
    --dir)
      RA_SUITE_DIR=${2-}
      shift 2
      ;;
    --out)
      RA_OUT=${2-}
      shift 2
      ;;
    --timeout)
      RA_TIMEOUT=${2-}
      shift 2
      ;;
    --attempts)
      RA_ATTEMPTS=${2-}
      shift 2
      ;;
    --list)
      RA_LIST=1
      shift
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    --)
      shift
      while [ "$#" -gt 0 ]; do
        RA_EXPLICIT+=("$1")
        shift
      done
      ;;
    -*)
      printf 'run_all: unknown option %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      RA_EXPLICIT+=("$1")
      shift
      ;;
  esac
done

[[ $RA_TIMEOUT =~ ^[0-9]+$ ]] || {
  printf 'run_all: --timeout must be a non-negative integer\n' >&2
  exit 2
}
{ [[ $RA_ATTEMPTS =~ ^[0-9]+$ ]] && [ "$RA_ATTEMPTS" -ge 1 ]; } || {
  printf 'run_all: --attempts must be a positive integer\n' >&2
  exit 2
}

# =============================================================================
# Discovery
# =============================================================================

# Deterministic aggregation order: LC_ALL=C sort of repo-relative paths. Two
# runs over the same tree therefore produce receipts whose sets are in the same
# order, which is what makes two receipts diffable.
ra_discover() {
  local root=$1
  [ -d "$root" ] || return 0
  local -a found=()
  local f
  while IFS= read -r -d '' f; do found+=("$f"); done < <(
    find "$root" -type f -name '*.sh' -print0 2>/dev/null | LC_ALL=C sort -z
  )
  printf '%s\0' "${found[@]+"${found[@]}"}"
}

ra_script_id() {
  local p=$1 id
  case $p in
    "$RA_REPO_ROOT"/*) id=${p#"$RA_REPO_ROOT"/} ;;
    *) id=$p ;;
  esac
  id=${id#scripts/e2e/}
  id=${id%.sh}
  id=${id//\//-}
  id=${id//[^A-Za-z0-9._-]/-}
  printf '%s' "$id"
}

declare -a RA_SCRIPTS=()
if [ "${#RA_EXPLICIT[@]}" -gt 0 ]; then
  RA_SCRIPTS=("${RA_EXPLICIT[@]}")
else
  while IFS= read -r -d '' f; do
    [ -n "$f" ] || continue
    RA_SCRIPTS+=("$f")
  done < <(ra_discover "$RA_SUITE_DIR")
fi

if [ "$RA_LIST" -eq 1 ]; then
  for f in "${RA_SCRIPTS[@]+"${RA_SCRIPTS[@]}"}"; do
    printf '%s\t%s\n' "$(ra_script_id "$f")" "$f"
  done
  exit 0
fi

# =============================================================================
# Receipt output
# =============================================================================

RA_START_NS=$(fge__now_ns)
fge__iso_ts "$RA_START_NS"
RA_STAMP=${FGE__TS%%.*}
RA_STAMP=${RA_STAMP//[:-]/}
RA_RUN_ID="${RA_STAMP}-$$"

if [ -z "$RA_OUT" ]; then
  RA_OUT="${FGE_ARTIFACT_ROOT:-$RA_REPO_ROOT/target/e2e-artifacts}/run_all/$RA_RUN_ID"
fi
mkdir -p "$RA_OUT/scripts"
RA_RECEIPT="$RA_OUT/receipt.ndjson"
: >"$RA_RECEIPT"
exec {RA_FD}>>"$RA_RECEIPT"

RA_SEQ=0

# ra_emit KIND EXTRA_JSON
ra_emit() {
  local kind=$1 extra=${2-}
  local ns
  ns=$(fge__now_ns)
  fge__iso_ts "$ns"
  RA_SEQ=$((RA_SEQ + 1))
  FGE__J='{'
  fge__jstr schema "$RA_SCHEMA"
  FGE__J+=','
  fge__jnum schema_version "$RA_SCHEMA_VERSION"
  FGE__J+=','
  fge__jstr kind "$kind"
  FGE__J+=','
  fge__jstr ts "$FGE__TS"
  FGE__J+=','
  fge__jnum epoch_ns "$ns"
  FGE__J+=','
  fge__jnum seq "$RA_SEQ"
  FGE__J+=','
  fge__jstr run_id "$RA_RUN_ID"
  FGE__J+=','
  fge__jraw env "$FGE_ENV_JSON"
  [ -n "$extra" ] && FGE__J+=",$extra"
  FGE__J+='}'
  printf '%s\n' "$FGE__J" >&2
  printf '%s\n' "$FGE__J" >&"$RA_FD"
}

# The suite runner reports the same environment identity its scripts do.
FGE_REPO_ROOT=$RA_REPO_ROOT
fge__build_env_json

# =============================================================================
# Per-script validation
# =============================================================================

# Base keys every record must carry. Their presence is not decoration: a
# validator that only checks the keys it happens to need cannot tell a
# truncated writer from a complete one.
RA_REQUIRED_KEYS='schema schema_version kind ts epoch_ns elapsed_ms seq run_id attempt script script_id acceptance_id phase step env determinism cmd result position resources obligations artifacts fields replay'

# Set by ra_validate_log:
RA_V_DISPOSITION=''
RA_V_DETAIL=''
RA_V_RECORDS=0
RA_V_TERMINAL=''
declare -a RA_V_IDS=() RA_V_PASSED=() RA_V_FAILED=() RA_V_SKIPPED=()
declare -a RA_V_UNSUPPORTED=() RA_V_ERRORS=() RA_V_DUPS=()
RA_V_STATUS=''
RA_V_EXIT=''
RA_V_CONTAINMENT=''
RA_V_CLEANUP=''
RA_V_ZERO=''
RA_V_FIRST=''
RA_V_WALL=''

ra_validate_log() {
  local log=$1
  RA_V_DISPOSITION=''
  RA_V_DETAIL=''
  RA_V_RECORDS=0
  RA_V_TERMINAL=''
  RA_V_IDS=()
  RA_V_PASSED=()
  RA_V_FAILED=()
  RA_V_SKIPPED=()
  RA_V_UNSUPPORTED=()
  RA_V_ERRORS=()
  RA_V_DUPS=()
  RA_V_STATUS=''
  RA_V_EXIT=''
  RA_V_CONTAINMENT=''
  RA_V_CLEANUP=''
  RA_V_ZERO=''
  RA_V_FIRST=''
  RA_V_WALL=''

  if [ ! -f "$log" ] || [ ! -s "$log" ]; then
    RA_V_DISPOSITION=missing_log
    RA_V_DETAIL="no NDJSON log at $log"
    return 1
  fi

  # A log whose last byte is not a newline was cut off mid-write.
  local lastbyte
  lastbyte=$(tail -c 1 "$log")
  if [ -n "$lastbyte" ]; then
    RA_V_DISPOSITION=truncated_log
    RA_V_DETAIL='log does not end with a newline'
    return 1
  fi

  local line n=0 termline=0 termcount=0 maxseq=0 k kind seq
  local -A seqseen=()
  while IFS= read -r line; do
    n=$((n + 1))
    [ -n "$line" ] || {
      RA_V_DISPOSITION=malformed_log
      RA_V_DETAIL="line $n is empty"
      return 1
    }
    if ! fge_json_top "$line"; then
      RA_V_DISPOSITION=malformed_log
      RA_V_DETAIL="line $n is not one well-formed JSON object with unique keys"
      return 1
    fi
    for k in $RA_REQUIRED_KEYS; do
      if [ -z "${FGE_JSON[$k]+x}" ]; then
        RA_V_DISPOSITION=malformed_log
        RA_V_DETAIL="line $n is missing required key '$k'"
        return 1
      fi
    done
    if [ "${FGE_JSON[schema]}" != "\"$FGE_SCHEMA\"" ]; then
      RA_V_DISPOSITION=malformed_log
      RA_V_DETAIL="line $n has schema ${FGE_JSON[schema]}, expected \"$FGE_SCHEMA\""
      return 1
    fi
    if [ "${FGE_JSON[schema_version]}" != "$FGE_SCHEMA_VERSION" ]; then
      RA_V_DISPOSITION=malformed_log
      RA_V_DETAIL="line $n has schema_version ${FGE_JSON[schema_version]}"
      return 1
    fi
    seq=${FGE_JSON[seq]}
    if ! [[ $seq =~ ^[0-9]+$ ]] || [ "$seq" -lt 1 ]; then
      RA_V_DISPOSITION=malformed_log
      RA_V_DETAIL="line $n has a non-positive seq"
      return 1
    fi
    if [ -n "${seqseen[$seq]+x}" ]; then
      RA_V_DISPOSITION=malformed_log
      RA_V_DETAIL="seq $seq appears more than once"
      return 1
    fi
    seqseen[$seq]=1
    [ "$seq" -gt "$maxseq" ] && maxseq=$seq
    kind=$(fge_json_unquote "${FGE_JSON[kind]}")
    if [ "$kind" = terminal ]; then
      termcount=$((termcount + 1))
      termline=$n
      RA_V_TERMINAL=${FGE_JSON[terminal]:-}
    fi
  done <"$log"

  RA_V_RECORDS=$n

  if [ "$termcount" -eq 0 ]; then
    RA_V_DISPOSITION=missing_terminal
    RA_V_DETAIL="no terminal record in $n records"
    return 1
  fi
  if [ "$termcount" -gt 1 ] || [ "$termline" -ne "$n" ]; then
    RA_V_DISPOSITION=multiple_terminal
    RA_V_DETAIL="terminal records: $termcount, last at line $termline of $n"
    return 1
  fi

  # seq values must be exactly {1..N}. Allocation happens under a lock, so a
  # gap means a record was written and then lost -- the concurrency-safe way to
  # detect truncation when records may be appended out of order.
  if [ "$maxseq" -ne "$n" ]; then
    RA_V_DISPOSITION=truncated_log
    RA_V_DETAIL="highest seq is $maxseq but only $n records are present"
    return 1
  fi

  if [ -z "$RA_V_TERMINAL" ]; then
    RA_V_DISPOSITION=malformed_log
    RA_V_DETAIL='terminal record carries no terminal object'
    return 1
  fi

  local termraw=$RA_V_TERMINAL
  if ! fge_json_top "$termraw"; then
    RA_V_DISPOSITION=malformed_log
    RA_V_DETAIL='terminal object is not parseable'
    return 1
  fi
  local -A T=()
  for k in "${!FGE_JSON[@]}"; do T[$k]=${FGE_JSON[$k]}; done

  local need
  for need in status exit_code assertions_discovered assertion_ids passed_ids \
    failed_ids skipped_ids unsupported_ids error_ids duplicate_ids \
    first_attempt_status cleanup_state containment zero_assertions wall_ms; do
    if [ -z "${T[$need]+x}" ]; then
      RA_V_DISPOSITION=malformed_log
      RA_V_DETAIL="terminal object is missing '$need'"
      return 1
    fi
  done

  RA_V_STATUS=$(fge_json_unquote "${T[status]}")
  RA_V_EXIT=${T[exit_code]}
  RA_V_CONTAINMENT=$(fge_json_unquote "${T[containment]}")
  RA_V_CLEANUP=$(fge_json_unquote "${T[cleanup_state]}")
  RA_V_ZERO=${T[zero_assertions]}
  RA_V_FIRST=$(fge_json_unquote "${T[first_attempt_status]}")
  RA_V_WALL=${T[wall_ms]}

  local field
  for field in assertion_ids passed_ids failed_ids skipped_ids unsupported_ids \
    error_ids duplicate_ids; do
    if ! fge_json_array_strings "${T[$field]}"; then
      RA_V_DISPOSITION=malformed_log
      RA_V_DETAIL="terminal.$field is not an array of strings"
      return 1
    fi
    case $field in
      assertion_ids) RA_V_IDS=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}") ;;
      passed_ids) RA_V_PASSED=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}") ;;
      failed_ids) RA_V_FAILED=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}") ;;
      skipped_ids) RA_V_SKIPPED=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}") ;;
      unsupported_ids) RA_V_UNSUPPORTED=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}") ;;
      error_ids) RA_V_ERRORS=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}") ;;
      duplicate_ids) RA_V_DUPS=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}") ;;
    esac
  done

  # The declared assertion count must match the declared ID set. A summary that
  # disagrees with its own evidence is a malformed summary, not a small count.
  local declared=${T[assertions_discovered]}
  if [ "$declared" != "${#RA_V_IDS[@]}" ]; then
    RA_V_DISPOSITION=malformed_log
    RA_V_DETAIL="terminal claims $declared assertions but lists ${#RA_V_IDS[@]} ids"
    return 1
  fi

  return 0
}

# =============================================================================
# Execution
# =============================================================================

ra_run_one() {
  local script=$1 rundir=$2 attempt=$3 secs=$4
  local errlog="$rundir/stderr.log" outlog="$rundir/stdout.log"
  local fifo_e="$rundir/.stderr.fifo" fifo_o="$rundir/.stdout.fifo"
  mkdir -p "$rundir"
  rm -f "$fifo_e" "$fifo_o"
  mkfifo "$fifo_e" "$fifo_o"

  # stderr is teed live, never swallowed; a named pipe with an explicit wait is
  # used instead of process substitution so the tee is known to have finished
  # before the log is digested.
  tee "$errlog" <"$fifo_e" >&2 &
  local tee_e=$!
  tee "$outlog" <"$fifo_o" &
  local tee_o=$!

  local rc=0 timed_out=false
  local -a cmd=()
  if [ "$secs" -gt 0 ] && [ "$FGE_TIMEOUT_IMPL" = coreutils ]; then
    cmd=(timeout -k 5 "$secs" "$script")
  else
    cmd=("$script")
  fi

  if [ "$secs" -gt 0 ] && [ "$FGE_TIMEOUT_IMPL" != coreutils ]; then
    local sentinel="$rundir/.timed_out"
    rm -f "$sentinel"
    (
      FGE_RUN_DIR=$rundir FGE_ATTEMPT=$attempt "${cmd[@]}" >"$fifo_o" 2>"$fifo_e"
    ) &
    local child=$!
    (
      left=$((secs * 10))
      while [ "$left" -gt 0 ] && kill -0 "$child" 2>/dev/null; do
        sleep 0.1
        left=$((left - 1))
      done
      if kill -0 "$child" 2>/dev/null; then
        : >"$sentinel"
        kill -TERM "$child" 2>/dev/null || true
        sleep 2
        kill -KILL "$child" 2>/dev/null || true
      fi
    ) &
    local wd=$!
    wait "$child" || rc=$?
    kill "$wd" 2>/dev/null || true
    wait "$wd" 2>/dev/null || true
    [ -e "$sentinel" ] && timed_out=true
  else
    FGE_RUN_DIR=$rundir FGE_ATTEMPT=$attempt "${cmd[@]}" >"$fifo_o" 2>"$fifo_e" || rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then timed_out=true; fi
  fi

  wait "$tee_e" 2>/dev/null || true
  wait "$tee_o" 2>/dev/null || true
  rm -f "$fifo_e" "$fifo_o"

  RA_RUN_EXIT=$rc
  RA_RUN_TIMED_OUT=$timed_out
  return 0
}
RA_RUN_EXIT=0
RA_RUN_TIMED_OUT=false

# =============================================================================
# Main
# =============================================================================

declare -a S_DISCOVERED=() S_SELECTED=() S_STARTED=() S_PASSED=() S_FAILED=()
declare -a S_SKIPPED=() S_UNSUPPORTED=() S_TIMEDOUT=() S_MALFORMED=()
declare -a S_MISSINGTERM=() S_ZEROASSERT=() S_DUPID=() S_CONTAINMENT=()
declare -a S_NOTRUN=() S_FLAKY=() S_EXITMISMATCH=() S_TRUNCATED=()
declare -a S_CLEANUPFAILED=()
declare -a ALL_IDS=() CROSS_DUP=()
declare -A ID_OWNER=()

for f in "${RA_SCRIPTS[@]+"${RA_SCRIPTS[@]}"}"; do
  S_DISCOVERED+=("$(ra_script_id "$f")")
done

FGE__J=''
fge__jstr suite_dir "$RA_SUITE_DIR"
FGE__J+=','
fge__jstr out_dir "$RA_OUT"
FGE__J+=','
fge__jnum timeout_seconds "$RA_TIMEOUT"
FGE__J+=','
fge__jnum max_attempts "$RA_ATTEMPTS"
FGE__J+=','
fge__esc discovered
FGE__J+="\"$FGE__E\":"
fge__jarr_str_into "${S_DISCOVERED[@]+"${S_DISCOVERED[@]}"}"
FGE__J+=','
fge__jnum discovered_count "${#S_DISCOVERED[@]}"
ra_emit suite_begin "$FGE__J"

for f in "${RA_SCRIPTS[@]+"${RA_SCRIPTS[@]}"}"; do
  sid=$(ra_script_id "$f")
  S_SELECTED+=("$sid")

  if [ ! -f "$f" ] || [ ! -x "$f" ]; then
    S_NOTRUN+=("$sid")
    FGE__J=''
    fge__jstr script "$f"
    FGE__J+=','
    fge__jstr script_id "$sid"
    FGE__J+=','
    fge__jstr disposition not_executable
    FGE__J+=','
    fge__jstr detail 'not an executable regular file'
    ra_emit suite_script "$FGE__J"
    continue
  fi

  S_STARTED+=("$sid")

  first_status=''
  final_disposition=''
  final_detail=''
  attempts_run=0
  last_rundir=''
  last_exit=0
  last_wall=0
  declare -a a_ids=() a_passed=() a_failed=() a_skipped=() a_unsupported=()
  declare -a a_errors=() a_dups=()

  for ((attempt = 1; attempt <= RA_ATTEMPTS; attempt++)); do
    attempts_run=$attempt
    rundir="$RA_OUT/scripts/$sid/attempt-$attempt"
    last_rundir=$rundir
    ra_run_one "$f" "$rundir" "$attempt" "$RA_TIMEOUT"
    exit_code=$RA_RUN_EXIT
    timed_out=$RA_RUN_TIMED_OUT
    last_exit=$exit_code

    disposition=''
    detail=''
    a_ids=()
    a_passed=()
    a_failed=()
    a_skipped=()
    a_unsupported=()
    a_errors=()
    a_dups=()
    # A timeout outranks every log-derived disposition. The log of a killed
    # script is legitimately stunted, and `timeout` reports 124 while the
    # terminal record the script managed to write says 143: reading that
    # disagreement as an exit mismatch would misname the actual defect.
    if [ "$timed_out" = true ]; then
      ra_validate_log "$rundir/e2e.ndjson" || true
      disposition=timeout
      detail="exceeded the ${RA_TIMEOUT}s wall budget"
    elif ! ra_validate_log "$rundir/e2e.ndjson"; then
      disposition=$RA_V_DISPOSITION
      detail=$RA_V_DETAIL
    else
      last_wall=$RA_V_WALL
      a_ids=("${RA_V_IDS[@]+"${RA_V_IDS[@]}"}")
      a_passed=("${RA_V_PASSED[@]+"${RA_V_PASSED[@]}"}")
      a_failed=("${RA_V_FAILED[@]+"${RA_V_FAILED[@]}"}")
      a_skipped=("${RA_V_SKIPPED[@]+"${RA_V_SKIPPED[@]}"}")
      a_unsupported=("${RA_V_UNSUPPORTED[@]+"${RA_V_UNSUPPORTED[@]}"}")
      a_errors=("${RA_V_ERRORS[@]+"${RA_V_ERRORS[@]}"}")
      a_dups=("${RA_V_DUPS[@]+"${RA_V_DUPS[@]}"}")

      # The process exit status and the terminal record must agree. A script
      # that exits 0 while its own summary says fail is a broken harness
      # contract and is never credited as a pass.
      if [ "$exit_code" != "$RA_V_EXIT" ]; then
        disposition=exit_mismatch
        detail="process exited $exit_code, terminal record claims $RA_V_EXIT"
      elif [ "$RA_V_ZERO" = true ]; then
        disposition=zero_assertions
        detail='the script discovered no assertions'
      elif [ "${#a_dups[@]}" -gt 0 ]; then
        disposition=duplicate_ids
        detail="duplicate acceptance ids: ${a_dups[*]}"
      elif [ "$RA_V_CONTAINMENT" != ok ]; then
        disposition=containment
        detail='orphaned processes or unresolved obligations'
      elif [ "$RA_V_CLEANUP" = failed ]; then
        disposition=cleanup_failed
        detail='a registered cleanup action failed'
      elif [ "${#a_errors[@]}" -gt 0 ]; then
        disposition=failed
        detail="assertion errors: ${a_errors[*]}"
      elif [ "${#a_failed[@]}" -gt 0 ]; then
        disposition=failed
        detail="failed assertions: ${a_failed[*]}"
      elif [ "${#a_unsupported[@]}" -gt 0 ]; then
        disposition=unsupported
        detail="unsupported assertions: ${a_unsupported[*]}"
      elif [ "${#a_skipped[@]}" -gt 0 ]; then
        disposition=skipped
        detail="skipped assertions: ${a_skipped[*]}"
      elif [ "$RA_V_STATUS" != pass ] || [ "$exit_code" -ne 0 ]; then
        disposition=failed
        detail="terminal status $RA_V_STATUS, exit $exit_code"
      else
        disposition=ok
        detail=''
      fi
    fi

    [ -n "$first_status" ] || first_status=$disposition
    final_disposition=$disposition
    final_detail=$detail
    [ "$disposition" = ok ] && break
  done

  # A retry that passes does not erase a first attempt that did not.
  if [ "$final_disposition" = ok ] && [ "$first_status" != ok ]; then
    final_disposition=flaky
    final_detail="first attempt disposition was '$first_status'; a later attempt passed"
    S_FLAKY+=("$sid")
  fi

  case $final_disposition in
    ok) S_PASSED+=("$sid") ;;
    failed) S_FAILED+=("$sid") ;;
    skipped) S_SKIPPED+=("$sid") ;;
    unsupported) S_UNSUPPORTED+=("$sid") ;;
    timeout) S_TIMEDOUT+=("$sid") ;;
    malformed_log) S_MALFORMED+=("$sid") ;;
    truncated_log) S_TRUNCATED+=("$sid") ;;
    missing_log | missing_terminal | multiple_terminal) S_MISSINGTERM+=("$sid") ;;
    zero_assertions) S_ZEROASSERT+=("$sid") ;;
    duplicate_ids) S_DUPID+=("$sid") ;;
    containment) S_CONTAINMENT+=("$sid") ;;
    cleanup_failed) S_CLEANUPFAILED+=("$sid") ;;
    exit_mismatch) S_EXITMISMATCH+=("$sid") ;;
    flaky) : ;;
    *) S_FAILED+=("$sid") ;;
  esac

  # One acceptance ID has exactly one owning script. Two scripts claiming the
  # same ID make the aggregate set ambiguous and is reported as its own defect.
  for aid in "${a_ids[@]+"${a_ids[@]}"}"; do
    if [ -n "${ID_OWNER[$aid]+x}" ] && [ "${ID_OWNER[$aid]}" != "$sid" ]; then
      CROSS_DUP+=("$aid")
    else
      ID_OWNER[$aid]=$sid
      ALL_IDS+=("$aid")
    fi
  done

  logdigest=''
  errdigest=''
  [ -f "$last_rundir/e2e.ndjson" ] && logdigest=$(fge_digest_file "$last_rundir/e2e.ndjson")
  [ -f "$last_rundir/stderr.log" ] && errdigest=$(fge_digest_file "$last_rundir/stderr.log")

  FGE__J=''
  fge__jstr script "$f"
  FGE__J+=','
  fge__jstr script_id "$sid"
  FGE__J+=','
  fge__jstr disposition "$final_disposition"
  FGE__J+=','
  fge__jstrn detail "$final_detail"
  FGE__J+=','
  fge__jstr first_attempt_disposition "$first_status"
  FGE__J+=','
  fge__jnum attempts_run "$attempts_run"
  FGE__J+=','
  fge__jnum exit_code "$last_exit"
  FGE__J+=','
  fge__jnum wall_ms "$last_wall"
  FGE__J+=','
  fge__jnum records "$RA_V_RECORDS"
  FGE__J+=','
  fge__jstr artifact_dir "$last_rundir"
  FGE__J+=','
  fge__jstr log_path "$last_rundir/e2e.ndjson"
  FGE__J+=','
  fge__jstrn log_digest "${logdigest:+sha256:$logdigest}"
  FGE__J+=','
  fge__jstr stderr_path "$last_rundir/stderr.log"
  FGE__J+=','
  fge__jstrn stderr_digest "${errdigest:+sha256:$errdigest}"
  FGE__J+=','
  fge__esc assertion_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${a_ids[@]+"${a_ids[@]}"}"
  FGE__J+=','
  fge__esc passed_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${a_passed[@]+"${a_passed[@]}"}"
  FGE__J+=','
  fge__esc failed_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${a_failed[@]+"${a_failed[@]}"}"
  FGE__J+=','
  fge__esc skipped_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${a_skipped[@]+"${a_skipped[@]}"}"
  FGE__J+=','
  fge__esc unsupported_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${a_unsupported[@]+"${a_unsupported[@]}"}"
  FGE__J+=','
  fge__esc error_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${a_errors[@]+"${a_errors[@]}"}"
  FGE__J+=','
  fge__esc duplicate_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${a_dups[@]+"${a_dups[@]}"}"
  ra_emit suite_script "$FGE__J"
done

# --- suite terminal ---------------------------------------------------------

suite_status=pass
[ "${#S_FAILED[@]}" -gt 0 ] && suite_status=fail
[ "${#S_SKIPPED[@]}" -gt 0 ] && suite_status=fail
[ "${#S_UNSUPPORTED[@]}" -gt 0 ] && suite_status=fail
[ "${#S_TIMEDOUT[@]}" -gt 0 ] && suite_status=fail
[ "${#S_MALFORMED[@]}" -gt 0 ] && suite_status=fail
[ "${#S_TRUNCATED[@]}" -gt 0 ] && suite_status=fail
[ "${#S_MISSINGTERM[@]}" -gt 0 ] && suite_status=fail
[ "${#S_ZEROASSERT[@]}" -gt 0 ] && suite_status=fail
[ "${#S_DUPID[@]}" -gt 0 ] && suite_status=fail
[ "${#S_CONTAINMENT[@]}" -gt 0 ] && suite_status=fail
[ "${#S_EXITMISMATCH[@]}" -gt 0 ] && suite_status=fail
[ "${#S_CLEANUPFAILED[@]}" -gt 0 ] && suite_status=fail
[ "${#S_NOTRUN[@]}" -gt 0 ] && suite_status=fail
[ "${#S_FLAKY[@]}" -gt 0 ] && suite_status=fail
[ "${#CROSS_DUP[@]}" -gt 0 ] && suite_status=fail
# A suite that selected nothing proves nothing. Zero selected scripts is a
# structural failure, not a vacuous pass.
[ "${#S_SELECTED[@]}" -eq 0 ] && suite_status=fail

FGE__J=''
fge__jstr status "$suite_status"
FGE__J+=','
fge__jnum wall_ms "$((($(fge__now_ns) - RA_START_NS) / 1000000))"
FGE__J+=','
fge__jstr receipt_path "$RA_RECEIPT"
FGE__J+=','
fge__jstr artifact_dir "$RA_OUT"
for pair in \
  "discovered:S_DISCOVERED" "selected:S_SELECTED" "started:S_STARTED" \
  "passed:S_PASSED" "failed:S_FAILED" "skipped:S_SKIPPED" \
  "unsupported:S_UNSUPPORTED" "timed_out:S_TIMEDOUT" \
  "malformed_log:S_MALFORMED" "truncated_log:S_TRUNCATED" \
  "missing_terminal:S_MISSINGTERM" "zero_assertion:S_ZEROASSERT" \
  "duplicate_id:S_DUPID" "containment_failed:S_CONTAINMENT" \
  "exit_mismatch:S_EXITMISMATCH" "cleanup_failed:S_CLEANUPFAILED" \
  "not_run:S_NOTRUN" "flaky:S_FLAKY"; do
  name=${pair%%:*}
  var=${pair#*:}
  declare -n arr=$var
  FGE__J+=','
  fge__esc "$name"
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${arr[@]+"${arr[@]}"}"
  FGE__J+=','
  fge__jnum "${name}_count" "${#arr[@]}"
  unset -n arr
done
FGE__J+=','
fge__esc acceptance_ids
FGE__J+="\"$FGE__E\":"
fge__jarr_str_into "${ALL_IDS[@]+"${ALL_IDS[@]}"}"
FGE__J+=','
fge__jnum acceptance_id_count "${#ALL_IDS[@]}"
FGE__J+=','
fge__esc cross_script_duplicate_ids
FGE__J+="\"$FGE__E\":"
fge__jarr_str_into "${CROSS_DUP[@]+"${CROSS_DUP[@]}"}"
ra_emit suite_terminal "$FGE__J"

printf 'run_all: status=%s selected=%d passed=%d failed=%d skipped=%d unsupported=%d timeout=%d malformed=%d truncated=%d missing_terminal=%d zero_assertion=%d duplicate_id=%d containment=%d exit_mismatch=%d not_run=%d flaky=%d cross_dup_ids=%d\n' \
  "$suite_status" "${#S_SELECTED[@]}" "${#S_PASSED[@]}" "${#S_FAILED[@]}" \
  "${#S_SKIPPED[@]}" "${#S_UNSUPPORTED[@]}" "${#S_TIMEDOUT[@]}" \
  "${#S_MALFORMED[@]}" "${#S_TRUNCATED[@]}" "${#S_MISSINGTERM[@]}" \
  "${#S_ZEROASSERT[@]}" "${#S_DUPID[@]}" "${#S_CONTAINMENT[@]}" \
  "${#S_EXITMISMATCH[@]}" "${#S_NOTRUN[@]}" "${#S_FLAKY[@]}" \
  "${#CROSS_DUP[@]}" >&2
printf 'run_all: receipt: %s\n' "$RA_RECEIPT" >&2

[ "$suite_status" = pass ] || exit 1
exit 0
