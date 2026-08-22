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
# HOW A SUITE GETS RUN  --  read this before asking for a registration seam
# -----------------------------------------------------------------------------
# SUITES ARE DISCOVERED, NOT REGISTERED. There is no manifest file, no
# registration interface, no approval step and nothing to publish. Put an
# executable `.sh` anywhere under `scripts/e2e/suites/<area>/` and it runs.
# That is the entire mechanism.
#
#   scripts/e2e/suites/<area>/<name>.sh   ->   id `suites-<area>-<name>`
#
# Discovery is recursive, restricted to executable regular files ending in
# `.sh`, and ordered by an LC_ALL=C sort of repo-relative paths so aggregation
# is deterministic across hosts.
#
# ANYTHING OUTSIDE `suites/` IS NOT DISCOVERED AND RUNS NOWHERE.
# This is the failure mode worth knowing about, because it is silent: a script
# at the `scripts/e2e/` root is never found by this runner, and unless some
# other file invokes it by name it simply never executes. Its assertions still
# read as coverage on a bead record. One such script currently exists in the
# tree with 30 assertions, zero invokers, and a bead that has already closed.
#
# Note that wiring this runner into `scripts/verify.sh` (FG-091) does NOT
# rescue such a script: that wires the RUNNER into the lane, and the runner
# still only walks `suites/**`. A root-level script needs an explicit invoker,
# and if it deliberately lives outside `suites/` it should say why in its own
# header -- `self_test.sh` does, because it drives this runner and would
# otherwise recurse into itself.
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
#                   containment_failed / not_run ID sets, profile manifest
#                   coverage (including uncovered areas), plus the union of
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

# Normalise collation before anything sorts.
#
# `lib.sh` does this inside `fge_init`, but the runner sources lib.sh and never
# calls `fge_init` -- so without this line the runner inherited the ambient
# locale and its discovery order became host-dependent. On a host whose
# collation folds case, `a` sorts before `B` and the aggregation order changes
# for reasons that have nothing to do with the suite. That is a real defect that
# reached a closed bead, so the normalisation is explicit here and asserted by
# FG-000A-PORT-013/031 rather than left to whatever `sort` happens to inherit.
if [ -z "${FGE_KEEP_LOCALE:-}" ]; then
  LC_ALL=C
  export LC_ALL
fi

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
# FG-091: an expected-suite manifest, enforced as SET EQUALITY against what
# discovery found. Empty means no profile was selected and no set check runs.
RA_PROFILE=''
RA_MANIFEST=''
# Whether --dir was supplied. Script ids are named relative to an explicitly
# requested discovery root, and relative to the repository for the default one;
# see ra_script_id.
RA_DIR_EXPLICIT=0
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
      RA_DIR_EXPLICIT=1
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
    --profile)
      RA_PROFILE=${2-}
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
  local p=$1 id=''
  # An explicitly requested discovery root wins, because the caller has just
  # said which tree it is asking about and expects to be answered in those
  # terms. Testing the repository first instead meant that a --dir anywhere
  # inside the repo -- an artifact fixture tree under target/, say -- matched the
  # repo branch and mangled its entire path into the id. That was FG-000A-PORT-013.
  #
  # The default root deliberately does NOT take this branch. Its ids are
  # repo-relative (`suites-<area>-<name>`), they are published in the suite
  # receipt, and FG-091 layers set-equality on those exact strings, so renaming
  # them to make one test pass would break a downstream contract to fix a local
  # symptom.
  if [ "${RA_DIR_EXPLICIT:-0}" -eq 1 ]; then
    case $p in
      "$RA_SUITE_DIR"/*) id=${p#"$RA_SUITE_DIR"/} ;;
    esac
  fi
  if [ -z "$id" ]; then
    case $p in
      "$RA_REPO_ROOT"/*) id=${p#"$RA_REPO_ROOT"/} ;;
      "$RA_SUITE_DIR"/*) id=${p#"$RA_SUITE_DIR"/} ;;
      *) id=$(basename "$p") ;;
    esac
  fi
  id=${id#scripts/e2e/}
  id=${id%.sh}
  id=${id//\//-}
  id=${id//[^A-Za-z0-9._-]/-}
  printf '%s' "$id"
}

# Set membership without a subshell or a pipe, so `set -o pipefail` cannot turn
# a lookup into a spurious failure the way it did in the orphan gate.
ra_in_set() {
  local needle=$1
  shift
  local candidate
  for candidate in "$@"; do
    [ "$candidate" = "$needle" ] && return 0
  done
  return 1
}

# A profile pins the RELEASE SURFACE, which is named in full-corpus ids. `--dir`
# deliberately scopes ids to the requested root (see ra_script_id), so the two
# together compare `harness_json` against `suites-harness-harness_json` and
# report every entry as simultaneously missing AND unregistered -- three
# confusing failures from one contradiction. Refused explicitly rather than
# allowed to produce that.
if [ -n "$RA_PROFILE" ] && [ "$RA_DIR_EXPLICIT" -eq 1 ]; then
  printf 'run_all: --profile pins full-corpus suite ids and cannot be combined with --dir\n' >&2
  exit 2
fi

# The discovered set is captured BEFORE any profile narrowing. Without this,
# S_DISCOVERED is built from the already-narrowed RA_SCRIPTS and the receipt
# reports the selected suites as though they were everything discovery found --
# a receipt quietly agreeing with whatever the profile chose, which is the one
# thing it must not do.
declare -a RA_ALL_DISCOVERED=()

declare -a RA_SCRIPTS=()
if [ "${#RA_EXPLICIT[@]}" -gt 0 ]; then
  RA_SCRIPTS=("${RA_EXPLICIT[@]}")
else
  while IFS= read -r -d '' f; do
    [ -n "$f" ] || continue
    RA_SCRIPTS+=("$f")
  done < <(ra_discover "$RA_SUITE_DIR")
fi

for f in "${RA_SCRIPTS[@]+"${RA_SCRIPTS[@]}"}"; do
  RA_ALL_DISCOVERED+=("$(ra_script_id "$f")")
done

# ---------------------------------------------------------------------------
# FG-091: load the profile manifest and enforce STRUCTURE before running.
#
# "FAIL outranks INCOMPLETE; structurally invalid suites fail before reporting
# missing coverage." A profile whose required set is not present is broken
# regardless of how the suites that DO exist behave, so it is refused here --
# before spending a full corpus run to arrive at the same answer.
# ---------------------------------------------------------------------------
declare -a S_MANIFEST_REQUIRED=()
declare -a S_MANIFEST_TERM=()
declare -a S_MANIFEST_WRONGTERM=()
declare -a S_MANIFEST_OPTIONAL=()
declare -a S_MANIFEST_MISSING=()
declare -a S_MANIFEST_UNREGISTERED=()
declare -a S_MANIFEST_UNCOVERED_AREAS=()
declare -a S_MANIFEST_NOTPASSED=()
if [ -n "$RA_PROFILE" ]; then
  declare -a RA_MANIFEST_TERM=()
  RA_MANIFEST="$RA_DIR/manifests/$RA_PROFILE.tsv"
  if [ ! -f "$RA_MANIFEST" ]; then
    printf 'run_all: profile %s has no manifest at %s\n' "$RA_PROFILE" "$RA_MANIFEST" >&2
    exit 2
  fi
  # THE MANIFEST IS VALIDATED BEFORE IT IS TRUSTED. "Stale manifest" is a
  # non-pass condition in its own right, and a manifest that is malformed can
  # weaken the gate silently: a row with a mistyped classification simply drops
  # out of the required set, so a suite stops being required without anyone
  # deciding that. Each defect below is refused by name.
  ra_manifest_line=0
  declare -a RA_MANIFEST_SEEN=()
  while IFS=$'\t' read -r m_id m_bead m_gate m_path m_targets m_class m_proof m_term; do
    ra_manifest_line=$((ra_manifest_line + 1))
    case $m_id in ''|'#'*) continue ;; esac
    if [ -z "$m_bead" ] || [ -z "$m_gate" ] || [ -z "$m_path" ] || [ -z "$m_targets" ] ||
      [ -z "$m_class" ] || [ -z "$m_proof" ] || [ -z "$m_term" ]; then
      printf 'run_all: manifest %s line %d: incomplete row for %s\n' \
        "$RA_MANIFEST" "$ra_manifest_line" "$m_id" >&2
      exit 2
    fi
    case $m_class in
      required | optional) ;;
      *)
        # A mistyped classification would silently drop the row from the
        # required set. Refused rather than ignored.
        printf 'run_all: manifest %s line %d: %s has classification %s, expected required|optional\n' \
          "$RA_MANIFEST" "$ra_manifest_line" "$m_id" "$m_class" >&2
        exit 2
        ;;
    esac
    # THE DECLARED PATH MUST DERIVE TO THE DECLARED ID. Both columns describe
    # the same suite, so they can disagree -- and a row whose path points at one
    # suite while its id names another would require the id (satisfied by
    # whatever is discovered under that name) while documenting a different file
    # entirely. Recomputing the id from the path is the only thing that keeps
    # the two columns honest, and it is exactly the renamed-alias case the bead
    # names: after a rename, one column gets updated and the other does not.
    m_derived=$(ra_script_id "$RA_REPO_ROOT/$m_path")
    if [ "$m_derived" != "$m_id" ]; then
      printf 'run_all: manifest %s line %d: path %s derives id %s, row declares %s\n' \
        "$RA_MANIFEST" "$ra_manifest_line" "$m_path" "$m_derived" "$m_id" >&2
      exit 2
    fi
    if ra_in_set "$m_id" "${RA_MANIFEST_SEEN[@]+"${RA_MANIFEST_SEEN[@]}"}"; then
      printf 'run_all: manifest %s line %d: duplicate entry %s\n' \
        "$RA_MANIFEST" "$ra_manifest_line" "$m_id" >&2
      exit 2
    fi
    RA_MANIFEST_SEEN+=("$m_id")
    # The declared terminal status, kept rather than discarded. It was parsed
    # and checked for non-emptiness and then thrown away, which made it a column
    # the manifest advertised and the runner never consulted -- the same
    # declared-but-not-consulted shape this gate exists to catch, in the gate's
    # own input.
    RA_MANIFEST_TERM+=("$m_id=$m_term")
    if [ "$m_class" != required ]; then
      # OPTIONAL ENTRIES ARE RECORDED, NOT DISCARDED. "Optional-by-accident" is
      # a non-pass condition in the bead, and an optional row nobody ever sees
      # is exactly how a suite becomes optional by accident: it stops being
      # required, appears in no receipt set, and no reviewer is ever prompted to
      # ask whether that was intended. Naming them in the receipt is what makes
      # the choice re-examinable.
      S_MANIFEST_OPTIONAL+=("$m_id")
      continue
    fi
    S_MANIFEST_REQUIRED+=("$m_id")
  done <"$RA_MANIFEST"

  # A manifest declaring nothing required would make every profile pass.
  if [ "${#S_MANIFEST_REQUIRED[@]}" -eq 0 ]; then
    printf 'run_all: profile %s declares no required suite\n' "$RA_PROFILE" >&2
    exit 2
  fi


  declare -a RA_PROFILE_AREAS=()
  for m_id in "${S_MANIFEST_REQUIRED[@]}"; do
    area=${m_id%-*}
    ra_in_set "$area" "${RA_PROFILE_AREAS[@]+"${RA_PROFILE_AREAS[@]}"}" ||
      RA_PROFILE_AREAS+=("$area")
  done

  for m_id in "${S_MANIFEST_REQUIRED[@]}"; do
    ra_in_set "$m_id" "${RA_ALL_DISCOVERED[@]+"${RA_ALL_DISCOVERED[@]}"}" ||
      S_MANIFEST_MISSING+=("$m_id")
  done
  # UNREGISTERED IS SCOPED TO THE AREAS THE PROFILE CLAIMS. A harness profile
  # must not report the other forty-odd suites as unregistered -- they are
  # outside it. What it MUST catch is a NEW suite appearing inside an area it
  # owns, because that is the release surface growing without the manifest being
  # updated to approve it. The omitted areas are nevertheless evidence: record
  # them separately so a release-facing profile cannot look corpus-complete
  # merely because its set equality covers only its own rows.
  for d_id in "${RA_ALL_DISCOVERED[@]+"${RA_ALL_DISCOVERED[@]}"}"; do
    d_area=${d_id%-*}
    if ! ra_in_set "$d_area" "${RA_PROFILE_AREAS[@]+"${RA_PROFILE_AREAS[@]}"}"; then
      ra_in_set "$d_area" "${S_MANIFEST_UNCOVERED_AREAS[@]+"${S_MANIFEST_UNCOVERED_AREAS[@]}"}" ||
        S_MANIFEST_UNCOVERED_AREAS+=("$d_area")
      continue
    fi
    ra_in_set "$d_id" "${S_MANIFEST_REQUIRED[@]}" || S_MANIFEST_UNREGISTERED+=("$d_id")
  done

  if [ "${#S_MANIFEST_MISSING[@]}" -gt 0 ] || [ "${#S_MANIFEST_UNREGISTERED[@]}" -gt 0 ]; then
    # A RENAME LOOKS LIKE TWO UNRELATED FAILURES unless it is named. One missing
    # and one unregistered in the same area is far more likely a renamed suite
    # than simultaneous deletion and creation, and saying so turns a puzzle into
    # a one-line manifest edit. Reported as a hint, never as an excuse: the run
    # still fails, because a rename IS a change to the release surface and the
    # manifest is where it gets approved.
    if [ "${#S_MANIFEST_MISSING[@]}" -eq 1 ] && [ "${#S_MANIFEST_UNREGISTERED[@]}" -eq 1 ] &&
      [ "${S_MANIFEST_MISSING[0]%-*}" = "${S_MANIFEST_UNREGISTERED[0]%-*}" ]; then
      printf 'run_all: profile %s: %s appears renamed to %s -- update the manifest to approve it\n' \
        "$RA_PROFILE" "${S_MANIFEST_MISSING[0]}" "${S_MANIFEST_UNREGISTERED[0]}" >&2
    fi
    printf 'run_all: profile %s set mismatch -- missing:[%s] unregistered:[%s]\n' \
      "$RA_PROFILE" "${S_MANIFEST_MISSING[*]-}" "${S_MANIFEST_UNREGISTERED[*]-}" >&2
    exit 1
  fi

  # A PROFILE SELECTS ITS DECLARED SCRIPTS. The set check above has already
  # proved discovery and the manifest agree, so narrowing selection here cannot
  # hide a missing suite -- it would have failed before reaching this line. What
  # it does is make the profile mean "run exactly this surface" rather than "run
  # everything and then grade a subset", which is what "exact set equality for
  # the selected profile" asks for.
  declare -a RA_PROFILE_SCRIPTS=()
  for f in "${RA_SCRIPTS[@]+"${RA_SCRIPTS[@]}"}"; do
    ra_in_set "$(ra_script_id "$f")" "${S_MANIFEST_REQUIRED[@]}" &&
      RA_PROFILE_SCRIPTS+=("$f")
  done
  RA_SCRIPTS=("${RA_PROFILE_SCRIPTS[@]+"${RA_PROFILE_SCRIPTS[@]}"}")
fi

declare -a RA_SELECTED_IDS=()
for f in "${RA_SCRIPTS[@]+"${RA_SCRIPTS[@]}"}"; do
  RA_SELECTED_IDS+=("$(ra_script_id "$f")")
done

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
RA_V_TIMEOUTS=0
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
  RA_V_TIMEOUTS=0
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
    first_attempt_status cleanup_state containment zero_assertions timeouts wall_ms; do
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
  RA_V_TIMEOUTS=${T[timeouts]}
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

S_DISCOVERED=("${RA_ALL_DISCOVERED[@]+"${RA_ALL_DISCOVERED[@]}"}")
# FILTERED: discovered, then excluded by the selected profile. Recorded because
# a narrowing that leaves no trace is indistinguishable from a corpus that never
# had those suites -- and "we ran three of fifty-three" is a materially
# different claim from "we ran everything".
declare -a S_FILTERED=()
for d_id in "${S_DISCOVERED[@]+"${S_DISCOVERED[@]}"}"; do
  ra_in_set "$d_id" "${RA_SELECTED_IDS[@]+"${RA_SELECTED_IDS[@]}"}" || S_FILTERED+=("$d_id")
done

FGE__J=''
fge__jstr suite_dir "$RA_SUITE_DIR"
FGE__J+=','
# suite_profile, NOT profile: env.profile already carries the CARGO profile
# ("debug"). A receipt that answered "profile" with "debug" while a --profile
# harness run was in progress would look like it named its suite profile and
# would not -- and a reader grepping for it would draw exactly the wrong
# conclusion. The empty string means no profile was selected and no set check
# ran, which is a different claim from a profile that passed.
fge__jstr suite_profile "$RA_PROFILE"
FGE__J+=','
fge__jstr manifest_path "$RA_MANIFEST"
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
      elif [ "$RA_V_TIMEOUTS" != 0 ]; then
        # The script's own budget fired even though the runner's did not. Both
        # are timeouts; conflating either with a plain assertion failure would
        # hide the resource story behind a correctness story.
        disposition=timeout
        detail='the script reported its own timeout'
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

# ---------------------------------------------------------------------------
# FG-091: exact-set enforcement against a checked-in manifest
#
# A MINIMUM COUNT IS FORBIDDEN, and this is why: a count is satisfied by the
# right NUMBER of the wrong suites. What must hold is set equality between the
# suites a profile declares required and the suites discovery actually found and
# ran. Three distinct failures fall out of that and each is reported by name
# rather than folded into one:
#
#   missing       declared required, not discovered -- coverage silently gone
#   unregistered  discovered, not declared          -- release surface grew
#                                                      without approval
#   required_not_passed  declared required, discovered, did not pass
#
# `required == passed` is the only green condition. A required suite that
# skipped, was unsupported, timed out, or was filtered is NON-PASS: those are
# all ways of not having the evidence, and treating any of them as acceptable is
# how a gate stops gating.
# ---------------------------------------------------------------------------
# required == passed is the only green condition. A required suite that skipped,
# was unsupported, timed out or was filtered is NON-PASS: each is a way of not
# having the evidence, and accepting any of them is how a gate stops gating.
for m_id in "${S_MANIFEST_REQUIRED[@]+"${S_MANIFEST_REQUIRED[@]}"}"; do
  ra_in_set "$m_id" "${S_PASSED[@]+"${S_PASSED[@]}"}" || S_MANIFEST_NOTPASSED+=("$m_id")
done

# A row declaring expected_terminal=pass must actually have passed. A row
# declaring anything else is asserting the suite is EXPECTED to be non-pass --
# a documented capability gap rather than a regression -- and the runner has to
# tell those apart, or a suite silently flipping from pass to unsupported reads
# the same as one that was always unsupported.
for pair in "${RA_MANIFEST_TERM[@]+"${RA_MANIFEST_TERM[@]}"}"; do
  term_id=${pair%%=*}
  term_want=${pair#*=}
  ra_in_set "$term_id" "${S_MANIFEST_REQUIRED[@]+"${S_MANIFEST_REQUIRED[@]}"}" || continue
  if [ "$term_want" = pass ]; then
    ra_in_set "$term_id" "${S_PASSED[@]+"${S_PASSED[@]}"}" ||
      S_MANIFEST_WRONGTERM+=("$term_id:want=$term_want")
  else
    # Declared non-pass: passing is ALSO a mismatch, because the gap the row
    # documents has evidently closed and the manifest now understates the suite.
    ra_in_set "$term_id" "${S_PASSED[@]+"${S_PASSED[@]}"}" &&
      S_MANIFEST_WRONGTERM+=("$term_id:want=$term_want,got=pass")
  fi
done
[ "${#S_MANIFEST_WRONGTERM[@]}" -gt 0 ] && suite_status=fail
[ "${#S_MANIFEST_NOTPASSED[@]}" -gt 0 ] && suite_status=fail

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
  "not_run:S_NOTRUN" "flaky:S_FLAKY" "filtered:S_FILTERED" \
  "manifest_required:S_MANIFEST_REQUIRED" "manifest_optional:S_MANIFEST_OPTIONAL" \
  "manifest_missing:S_MANIFEST_MISSING" \
  "manifest_unregistered:S_MANIFEST_UNREGISTERED" \
  "manifest_uncovered_areas:S_MANIFEST_UNCOVERED_AREAS" \
  "manifest_required_not_passed:S_MANIFEST_NOTPASSED" \
  "manifest_wrong_terminal:S_MANIFEST_WRONGTERM"; do
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
if [ -n "$RA_PROFILE" ]; then
  printf 'run_all: profile=%s uncovered_areas=[%s]\n' \
    "$RA_PROFILE" "${S_MANIFEST_UNCOVERED_AREAS[*]-}" >&2
fi
printf 'run_all: receipt: %s\n' "$RA_RECEIPT" >&2

[ "$suite_status" = pass ] || exit 1
exit 0
