#!/usr/bin/env bash
# e2e: FG-028c one-node performance and economics baseline.
#
# Produces the ANCHOR artifact later regression beads compare against. The
# comparison the acceptance requires -- "upstream git daemon on the same
# corpus" -- has exactly one honest shape: ONE client binary, TWO servers. The
# variable under test is the server. Baseline is upstream `git daemon`,
# candidate is `fg serve`, and the A/A control re-runs the baseline so this
# host's noise floor is measured rather than assumed.
#
# The bead names `scripts/e2e/` for its script; `run_all.sh` discovers
# executable scripts under `suites/`, so this registers as
# `suites-benchmark-perf_baseline` without a hand-maintained list.
#
# GRANT: GoldLotus 2026-08-24 permits, for fg028c only, one release build of
# fgit-cli plus repeated measurement runs. The benchmark driver is frozen
# before measurement from FG_BENCH_DRIVER_BINARY when supplied; otherwise this
# historical harness still builds it once. It is a no-build lane only when
# both executable inputs are supplied, and it caps the sample count either way.
#
# ================== HOW TO USE THIS AS A REGRESSION ANCHOR ==================
#
# Not every metric here is comparable across runs, and treating them alike would
# manufacture regressions. Measured over four independent clone runs on this
# host, five samples per variant:
#
#   egress      EXACT. One value per arm across all four runs, identical to the
#               byte (baseline 639,823; candidate 39,788,709). Compare directly;
#               any change at all is a real change.
#   pack CPU    STABLE to about 5% (observed spread 4.1% and 4.6%). Compare with
#               a band, not an equality.
#   peak RSS    stable in the same way; same treatment as CPU.
#   latency     NOT COMPARABLE ACROSS RUNS. Observed spread between runs of the
#               same arm was 194% (baseline) and 142% (candidate) on this shared
#               128-core host. A latency number from one run says nothing about
#               another. Compare it ONLY within a single run, against that run's
#               own A/A control: a candidate-baseline gap smaller than the
#               measured aa_noise p95 is not a result.
#
# The A/A floor itself varies by an order of magnitude with host load -- 187ms
# on one cold run, 1418ms on a warm one -- which is why it is measured every run
# instead of being assumed once.
#
# ---------------- THE ANCHOR NUMBERS ARE BOUND TO A REVISION ----------------
#
# The candidate figures above were measured at binary SHA 8aff66d, which
# PREDATES the frankengit-x7ja fixes:
#
#   e72612a  x7ja: add compressed pack profile
#   efa569a  x7ja: negotiate compact incremental packs
#
# Those two exist BECAUSE of this harness -- it measured a clone sending
# 39,788,709 bytes against upstream's 639,823, and a fetch sending 39,790,922,
# within 2 KB of a full clone of the same corpus.
#
# So on any build after x7ja, expect candidate egress to fall SHARPLY. That is
# the fix landing, not a broken harness and not an anomaly. The rule two
# paragraphs up -- "compare egress directly; any change at all is a real
# change" -- is still right about egress being exact, but a reader applying it
# across the x7ja boundary would read a repair as a regression, or conclude the
# measurement broke.
#
# When someone re-measures on a post-x7ja build, the honest move is to record a
# NEW anchor and say which revision each set belongs to, rather than editing
# these numbers: the old pair is the evidence that motivated the fix, and it
# stops being reproducible the moment the fix lands.
# ============================================================================
set -euo pipefail

PB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PB_REPO=$(cd "$PB_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$PB_REPO/scripts/e2e/lib.sh"

fge_init fg028c-perf-baseline
fge_context bead frankengit-fg028c-perf-baseline-adh
fge_context crate fgit-benchmark
fge_context claim_class one_node_transport_baseline_anchor

# Deliberately small by default. A nearest-rank p99 over N samples is the
# observed maximum whenever N < 100, and the artifact says so rather than
# letting "p99" imply a hundred-sample tail estimate. Raise FG_BENCH_SAMPLES
# for a real tail run; the 20-minute grant bound is the ceiling.
SAMPLES=${FG_BENCH_SAMPLES:-5}
# The scope asks for COLD AND WARM states. Cold is a real page-cache eviction,
# not a label: the served corpus is evicted with posix_fadvise before every
# sample. Run the cell twice, once per state, to get both.
CACHE_STATE=${FG_BENCH_CACHE_STATE:-warm}
# The default matches clone and stale-fetch measurements against the same
# source revision and corpus.  Explicit clone/fetch runs remain useful for
# diagnosis, but cannot establish the fetch-versus-clone acceptance inequality
# on their own.
OPERATION=${FG_BENCH_OPERATION:-matched}
# How far behind the stale clones start, in commits, for a fetch run.
STALE_BEHIND=${FG_BENCH_STALE_BEHIND:-3}
PYTHON_BIN=${FG_BENCH_PYTHON:-$(command -v python3 || echo /usr/bin/python3)}
# Tenant, repository and principal are 32-character identifiers; fg refuses
# anything else ("TenantId: length 13 outside [32, 32]"), which is how the first
# run of this script failed.
TENANT=11111111111111111111111111111111
REPOID=22222222222222222222222222222222
# Any valid principal; import needs one and the transport measurement does not
# depend on which.
PRINCIPAL=44444444444444444444444444444444

fge_phase setup

artifact_dir=$(fge_tempdir perf-baseline-artifact)
work=$(fge_tempdir perf-baseline-work)
fge_context artifact_directory "$artifact_dir"
fge_context samples_per_variant "$SAMPLES"
fge_context cache_state "$CACHE_STATE"
fge_context operation "$OPERATION"

case "$OPERATION" in
  clone|fetch|matched) ;;
  *)
    fge_unsupported FG-028C-E2E-026 \
      'operation must be clone, fetch, or matched; no unrecognized operation is measured'
    exit 0
    ;;
esac

fge_assert_file FG-028C-E2E-001 "$PB_REPO/crates/fgit-benchmark/src/transport.rs" \
  'the transport workload module is present'

# Matched clone/fetch evidence needs the content identities of both executable
# images. A shared target directory is mutable while the two sequential arms
# run, so a pathname alone is not a revision-bound execution identity.
SHA256_BIN=${FG_BENCH_SHA256SUM:-$(command -v sha256sum || true)}
if [ -z "$SHA256_BIN" ] || [ ! -x "$SHA256_BIN" ]; then
  fge_unsupported FG-028C-E2E-032 \
    'sha256sum is unavailable, so this run cannot bind its candidate and driver images immutably'
  exit 0
fi
sha256_file() { # PATH
  "$SHA256_BIN" "$1" | awk '{print $1}'
}
copy_run_image() { # SOURCE DESTINATION
  cp -- "$1" "$2"
  chmod u=rx,go=rx "$2"
  test -s "$2"
}

# The client, and the reference server, are the SAME upstream binary. Using one
# binary for both arms is what makes the differential a server comparison
# rather than a client comparison.
# The pinned oracle install lives OUTSIDE the repository, at
# ${FGIT_ORACLE_ROOT:-~/.cache/frankengit/git-oracle}/installs/<pin> -- oracle.sh
# refuses a root inside the source tree. It is also relocated out of its
# configure-time prefix, so GIT_EXEC_PATH must be set explicitly or `git daemon`
# resolves to "not a git command" and the baseline arm silently has no server.
ORACLE_ROOT=${FGIT_ORACLE_ROOT:-$HOME/.cache/frankengit/git-oracle}
PIN=git-2.54.0
PINNED_GIT="$ORACLE_ROOT/installs/$PIN/bin/git"
GIT_BIN=${FG_BENCH_GIT_BINARY:-}
GIT_EXEC=${FG_BENCH_GIT_EXEC_PATH:-}
if [ -z "$GIT_BIN" ]; then
  if [ -x "$PINNED_GIT" ]; then
    GIT_BIN="$PINNED_GIT"
    GIT_EXEC="$ORACLE_ROOT/installs/$PIN/libexec/git-core"
  else
    # Ambient git is a documented fallback, not the preferred path: it makes
    # the differential unpinned. The run records which of the two it used so a
    # later reader can tell an unpinned anchor from a pinned one.
    GIT_BIN=$(command -v git || true)
    [ -n "$GIT_BIN" ] && GIT_EXEC=$("$GIT_BIN" --exec-path 2>/dev/null || true)
  fi
fi

# A missing upstream Git is UNSUPPORTED, never a pass. An anchor artifact with
# no differential in it would satisfy no acceptance line while looking green.
if [ -z "$GIT_BIN" ] || [ ! -x "$GIT_BIN" ]; then
  fge_unsupported FG-028C-E2E-002 \
    'no upstream git binary is available, so the required differential cannot be measured'
  fge_note 'perf baseline requires an upstream git for both the client and the reference server'
  exit 0
fi
fge_pass FG-028C-E2E-002 'an upstream git binary is available for the client and reference server'
fge_context git_binary "$GIT_BIN"
fge_context git_exec_path "$GIT_EXEC"
if [ -x "$PINNED_GIT" ]; then
  GIT_PROVENANCE="pinned-oracle-$PIN"
else
  GIT_PROVENANCE='ambient-path-git-UNPINNED'
  fge_note 'the pinned oracle install is absent; this differential used an ambient git and is UNPINNED'
fi
GIT_BINARY_SHA256=$(sha256_file "$GIT_BIN")
fge_context git_provenance "$GIT_PROVENANCE"
fge_context git_binary_sha256 "$GIT_BINARY_SHA256"

# A numeric matched-clone/fetch predicate is a pinned-upstream differential.
# Ambient Git remains a diagnostic fallback for explicitly selected one-arm
# runs, but it cannot establish E2E-029/E2E-030.
if [ "$OPERATION" = matched ] && [ "$GIT_PROVENANCE" != "pinned-oracle-$PIN" ]; then
  fge_unsupported FG-028C-E2E-035 \
    'the matched clone/fetch gate requires the pinned upstream Git oracle; ambient Git is diagnostic only'
  exit 0
fi

# `git daemon` is a separate executable in git-core; a git that cannot resolve
# it has no baseline server. Checked with the exec path this run will actually
# use, so the probe cannot pass while the real invocation fails.
if ! GIT_EXEC_PATH="$GIT_EXEC" "$GIT_BIN" daemon --help >/dev/null 2>&1; then
  fge_unsupported FG-028C-E2E-003 \
    'the available git has no daemon builtin, so the upstream baseline arm cannot be served'
  exit 0
fi
fge_pass FG-028C-E2E-003 'the upstream git provides the daemon used as the baseline server'

FG_BIN=${FG_BENCH_FG_BINARY:-}
if [ -z "$FG_BIN" ]; then
  if command -v cargo >/dev/null 2>&1; then
    RCH_CARGO_WRAPPER_BYPASS=1 cargo build -q --release -p fgit-cli >&2 || true
  fi
  for cand in \
    "${CARGO_TARGET_DIR:-$PB_REPO/target}/release/fg" \
    "$PB_REPO/target/release/fg" \
    "${CARGO_TARGET_DIR:-$PB_REPO/target}/debug/fg" \
    "$PB_REPO/target/debug/fg"; do
    [ -x "$cand" ] && FG_BIN=$cand && break
  done
fi
if [ -z "$FG_BIN" ] || [ ! -x "$FG_BIN" ]; then
  fge_unsupported FG-028C-E2E-004 'no fg binary is available to serve the candidate arm'
  exit 0
fi
fge_pass FG-028C-E2E-004 'an fg binary is available to serve the candidate arm'
fge_context fg_binary_source "$FG_BIN"

# Freeze the actual candidate once. Both matched arms receive this run-local
# copy, so a target-directory rebuild between clone and fetch cannot alter the
# measured server while leaving the caller-supplied source labels unchanged.
RUN_FG_BIN="$work/fgit-candidate"
copy_run_image "$FG_BIN" "$RUN_FG_BIN"
FG_BINARY_SHA256=$(sha256_file "$RUN_FG_BIN")
FG_BIN="$RUN_FG_BIN"
fge_context fg_binary_copy "$FG_BIN"
fge_context fg_binary_sha256 "$FG_BINARY_SHA256"

# Resolve/build the benchmark driver once, then copy it next to the candidate.
# In particular, do not use `cargo run` separately for clone and fetch: Cargo
# may rebuild its driver in the interval. Supplying FG_BENCH_DRIVER_BINARY
# makes this a no-build lane.
BENCH_DRIVER=${FG_BENCH_DRIVER_BINARY:-}
if [ -z "$BENCH_DRIVER" ]; then
  if command -v cargo >/dev/null 2>&1; then
    RCH_CARGO_WRAPPER_BYPASS=1 cargo build -q --release -p fgit-benchmark >&2 || true
  fi
  for cand in \
    "${CARGO_TARGET_DIR:-$PB_REPO/target}/release/fgit-benchmark" \
    "$PB_REPO/target/release/fgit-benchmark"; do
    [ -x "$cand" ] && BENCH_DRIVER=$cand && break
  done
fi
if [ -z "$BENCH_DRIVER" ] || [ ! -x "$BENCH_DRIVER" ]; then
  fge_unsupported FG-028C-E2E-034 \
    'no fgit-benchmark driver is available to freeze across matched transport arms'
  exit 0
fi
RUN_BENCH_DRIVER="$work/fgit-benchmark-driver"
copy_run_image "$BENCH_DRIVER" "$RUN_BENCH_DRIVER"
DRIVER_BINARY_SHA256=$(sha256_file "$RUN_BENCH_DRIVER")
fge_context benchmark_driver_source "$BENCH_DRIVER"
fge_context benchmark_driver_copy "$RUN_BENCH_DRIVER"
fge_context benchmark_driver_sha256 "$DRIVER_BINARY_SHA256"

# A cold run without a working interpreter would silently become a warm run
# wearing a cold label. Refuse instead; 3.1 forbids a silent fallback.
if [ "$CACHE_STATE" = cold ] && ! "$PYTHON_BIN" -c 'import os; os.posix_fadvise' >/dev/null 2>&1; then
  fge_unsupported FG-028C-E2E-021 \
    'cold state requested but no interpreter with posix_fadvise is available, so the page cache cannot be evicted'
  exit 0
fi

# The artifact's source_revision must name the revision the MEASURED BINARY was
# built from, not whatever HEAD happens to be when the script runs. Sixteen
# agents commit to this checkout continuously, so those two routinely differ,
# and a fingerprint naming the wrong revision would send a later regression
# bead diffing against source the anchor never executed. FG_BENCH_SOURCE_REVISION
# is therefore an input a caller who built out-of-band must supply.
SOURCE_REVISION=${FG_BENCH_SOURCE_REVISION:-$(cd "$PB_REPO" && git rev-parse HEAD)}
SOURCE_TREE=${FG_BENCH_SOURCE_TREE:-$(cd "$PB_REPO" && { git diff --quiet && git diff --cached --quiet && echo clean || echo dirty; })}
fge_context source_revision "$SOURCE_REVISION"
fge_context source_tree "$SOURCE_TREE"
HEAD_NOW=$(cd "$PB_REPO" && git rev-parse HEAD)
if [ "$SOURCE_REVISION" != "$HEAD_NOW" ]; then
  fge_note "measured binary was built at $SOURCE_REVISION; HEAD has since moved to $HEAD_NOW"
fi

fge_phase action

# One corpus, materialized once, served by both arms. Deterministic content so
# a rerun on another host measures the same bytes.
#
# THE SHAPE IS DELIBERATE: FEW OBJECTS, MANY BYTES. The two constraints on this
# corpus pull in different directions and were measured separately:
#
#   fg import must succeed        -> cost scales with OBJECT COUNT. A 25-commit
#                                    600-file corpus (~15,000 loose objects) is
#                                    refused: "authority store: ambiguous:
#                                    cancelled after transmission".
#   pack CPU must be measurable   -> cost scales with BYTES. USER_HZ is 100, so
#                                    anything under 10ms of server CPU reports
#                                    as 0 jiffies, and a 2KB corpus reported
#                                    cpu_ns = 0 for every sample in both arms.
#
# Because they are different axes, a handful of commits over a few very large
# files clears both where many small files cleared neither. Measured:
#
#   6 commits x 3 files x 200k lines   24 loose  import ok   server cpu  330ms
#   8 commits x 4 files x 300k lines   36 loose  import ok   server cpu  810ms
#  10 commits x 6 files x 400k lines   52 loose  import ok   server cpu 1640ms
#
# The middle row is used: two orders of magnitude above the CPU floor, and well
# inside what import accepts.
SRC="$work/src"
export GIT_EXEC_PATH="$GIT_EXEC"
"$GIT_BIN" init -q -b main "$SRC"
"$GIT_BIN" -C "$SRC" config user.email perf-baseline@invalid.example
"$GIT_BIN" -C "$SRC" config user.name 'FG-028c corpus'
"$GIT_BIN" -C "$SRC" config commit.gpgsign false
# gc.auto alone is NOT enough: modern git runs maintenance.auto independently,
# and a packed corpus is refused by fg import ("loose import refuses packed
# objects ... use the pack quarantine import path").
"$GIT_BIN" -C "$SRC" config gc.auto 0
"$GIT_BIN" -C "$SRC" config maintenance.auto false
CORPUS_COMMITS=${FG_BENCH_CORPUS_COMMITS:-8}
CORPUS_FILES=${FG_BENCH_CORPUS_FILES:-4}
CORPUS_LINES=${FG_BENCH_CORPUS_LINES:-300000}
for i in $(seq 1 "$CORPUS_COMMITS"); do
  for f in $(seq 1 "$CORPUS_FILES"); do
    seq $((i * f)) $((i * f + CORPUS_LINES)) > "$SRC/big$f.txt"
  done
  "$GIT_BIN" -C "$SRC" add -A
  GIT_AUTHOR_DATE="@$((1700000000 + i)) +0000" \
  GIT_COMMITTER_DATE="@$((1700000000 + i)) +0000" \
    "$GIT_BIN" -C "$SRC" commit -qm "commit $i"
done
fge_context corpus_shape "${CORPUS_COMMITS}c x ${CORPUS_FILES}f x ${CORPUS_LINES}l"
fge_context corpus_loose_objects "$(find "$SRC/.git/objects" -type f -not -path '*/pack/*' | wc -l)"

EXPECTED_HEAD=$("$GIT_BIN" -C "$SRC" rev-parse HEAD)
EXPECTED_COMMITS=$("$GIT_BIN" -C "$SRC" rev-list --count HEAD)
# §39.2's amplification denominator: the sum of every reachable object's
# UNCOMPRESSED size, taken from the corpus. Deriving it from the clone instead
# makes the ratio a tautology -- an earlier run reported exactly 1000000 ppm for
# all fifteen samples in both arms, which is what a metric that cannot come out
# any other way looks like.
LOGICAL_BYTES=$(
  "$GIT_BIN" -C "$SRC" rev-list --objects HEAD |
    cut -d' ' -f1 |
    "$GIT_BIN" -C "$SRC" cat-file --batch-check='%(objectsize)' |
    awk '{ total += $1 } END { print total + 0 }'
)
fge_context logical_reachable_bytes "$LOGICAL_BYTES"
fge_context expected_head "$EXPECTED_HEAD"
fge_context expected_commits "$EXPECTED_COMMITS"

# Baseline server's copy of the corpus.
UPSTREAM_BASE="$work/upstream"
mkdir -p "$UPSTREAM_BASE"
"$GIT_BIN" clone -q --bare "$SRC" "$UPSTREAM_BASE/$REPOID.git"
# git daemon refuses a repository without this marker unless --export-all is
# given; it is set anyway so the export is explicit rather than incidental.
: > "$UPSTREAM_BASE/$REPOID.git/git-daemon-export-ok"

# Candidate server's copy of the same corpus.
STORAGE="$work/storage"
INIT_RC=0
"$FG_BIN" init "$STORAGE" "$TENANT" "$REPOID" >/dev/null 2>&1 || INIT_RC=$?
fge_assert_eq FG-028C-E2E-005 0 "$INIT_RC" 'the node initializes storage for the candidate arm'

IMPORT_RC=0
"$FG_BIN" import "$STORAGE" "$TENANT" "$REPOID" "$PRINCIPAL" pb-corpus-001 "$SRC" \
  >"$work/import.out" 2>&1 || IMPORT_RC=$?
fge_assert_eq FG-028C-E2E-006 0 "$IMPORT_RC" 'the node imports the same corpus the baseline serves'

CLONES="$work/clones"
mkdir -p "$CLONES"
STALE="$work/stale"
mkdir -p "$STALE"
FETCH_REFSPEC="refs/heads/main:refs/remotes/origin/main"
LOGICAL_FOR_RUN="$LOGICAL_BYTES"
STALE_AT=not-applicable
STALE_BEHIND_PROVENANCE=not-applicable

# For a fetch run, materialize one stale clone PER SAMPLE PER ARM up front.
# A fetch ADVANCES the repository it runs in, so a reused copy would transfer
# nothing on every sample after the first and report as very fast. The runner
# reuses the baseline subject for the A/A pass, so that arm consumes 2*SAMPLES
# indices while the candidate arm consumes SAMPLES.
if [ "$OPERATION" = fetch ] || [ "$OPERATION" = matched ]; then
  STALE_AT=$("$GIT_BIN" -C "$SRC" rev-parse "HEAD~$STALE_BEHIND")
  STALE_BEHIND_PROVENANCE=$STALE_BEHIND
  fge_context stale_base "$STALE_AT"
  fge_context stale_behind_commits "$STALE_BEHIND"
  # The amplification denominator for a fetch is the DELTA's logical size, not
  # the whole corpus. Dividing a delta transfer by the full corpus would report
  # a flatteringly small ratio that says nothing about the fetch.
  LOGICAL_FOR_RUN=$(
    "$GIT_BIN" -C "$SRC" rev-list --objects "$STALE_AT..HEAD" |
      cut -d' ' -f1 |
      "$GIT_BIN" -C "$SRC" cat-file --batch-check='%(objectsize)' |
      awk '{ total += $1 } END { print total + 0 }'
  )
  fge_context fetch_delta_logical_bytes "$LOGICAL_FOR_RUN"
  # BARE, deliberately. A non-bare repo refuses the setup fetch with
  # "refusing to fetch into branch 'refs/heads/main' checked out at ...",
  # because git will not move a branch that has a working tree on it. Bare also
  # keeps the measured interval about transport rather than about writing a
  # checkout, which is the thing being compared.
  make_stale_clones() { # TAG COUNT
    local tag=$1 count=$2 n d
    for n in $(seq 0 $((count - 1))); do
      d="$STALE/$tag-$n"
      "$GIT_BIN" init -q --bare -b main "$d"
      "$GIT_BIN" -C "$d" config gc.auto 0
      "$GIT_BIN" -C "$d" config maintenance.auto false
      # KEEP THE TRANSFER AS A PACK. fetch.unpackLimit defaults to 100, and this
      # delta is roughly 20 objects, so git would explode the received pack into
      # loose objects. On-disk bytes would then be a function of OBJECT CONTENT
      # rather than of what the server sent -- measured: every arm reported
      # exactly 4,559,168 bytes, identical to the byte, which is what a
      # server-independent quantity looks like. With unpackLimit=1 the pack is
      # stored as received and its size tracks the wire.
      "$GIT_BIN" -C "$d" config fetch.unpackLimit 1
      "$GIT_BIN" -C "$d" config transfer.unpackLimit 1
      "$GIT_BIN" -C "$d" fetch -q --no-tags "$SRC" "$STALE_AT:refs/heads/main"
    done
  }
  make_stale_clones upstream-git-daemon $((SAMPLES * 2))
  make_stale_clones fgit-node-serve "$SAMPLES"
  fge_context stale_clones_created "$((SAMPLES * 3))"
fi
# Empty GIT_TEMPLATE_DIR: the relocated pinned install otherwise warns
# "templates not found in /prefix/share/git-core/templates" and copies whatever
# the host has, which changes the .git byte count feeding storage amplification.
TEMPLATE="$work/empty-template"
mkdir -p "$TEMPLATE"

# ---------------------------------------------------------------------------
# THE TYPED NON-CLAIMS ARE EMITTED HERE, BEFORE THE EXPERIMENT, ON PURPOSE.
#
# They used to sit ~150 lines below, after the assertions. Both are top-level
# and unconditional, and two readers (CobaltForest and me) certified from that
# structure that they "execute on every run". They do not. This script runs
# under `set -euo pipefail`, so any abort at or before the experiment ends it
# and every statement after that point is skipped. ChartreuseHorizon measured
# it on a failing run: unsupported_ids was empty, FG-028C-E2E-019 appeared zero
# times.
#
# That is backwards from what these markers are for. They are the only thing
# telling a reader that an operation the scope names went UNMEASURED rather
# than measured-and-passed, and they vanished in exactly the run where a
# reader needs them most.
#
# Push is always unavailable on this daemon lane. Fetch is unmeasured only in
# an explicit clone diagnostic: the default matched lane below measures it
# against its sibling clone artifact. Emit the applicable non-claims before
# either experiment so a later failure cannot hide them. See frankengit-nb98.
# ---------------------------------------------------------------------------

fge_phase assert
fge_unsupported FG-028C-E2E-019 \
  'push throughput is unmeasurable as a transport at this revision: the daemon refuses every service that is not git-upload-pack (GitDaemonTransportRefusal::UnsupportedService) and no receive-pack serve function exists. The gate is the absent daemon lane, tracked by frankengit-fg019; it is NOT frankengit-n6kg, whose production QuarantineValidator landed at 053176c while push stayed exactly as unmeasurable.'
if [ "$OPERATION" = clone ]; then
  fge_unsupported FG-028C-E2E-020 \
    'fetch is not measured in an explicit clone-only diagnostic run; use the matched lane for the clone-versus-fetch egress gate'
fi
fge_phase action

run_transport_operation() {
  local operation=$1 output=$2 port_base=$3
  local logical_bytes=$LOGICAL_FOR_RUN
  if [ "$operation" = clone ]; then
    logical_bytes=$LOGICAL_BYTES
  fi
  fge_run "perf-baseline-${operation}-experiment" \
    env \
      RCH_CARGO_WRAPPER_BYPASS=1 \
      FG_BENCH_FG_BINARY="$FG_BIN" \
      FG_BENCH_FG_BINARY_SHA256="$FG_BINARY_SHA256" \
      FG_BENCH_DRIVER_BINARY="$RUN_BENCH_DRIVER" \
      FG_BENCH_DRIVER_BINARY_SHA256="$DRIVER_BINARY_SHA256" \
      FG_BENCH_GIT_BINARY="$GIT_BIN" \
      FG_BENCH_GIT_EXEC_PATH="$GIT_EXEC" \
      FG_BENCH_GIT_PROVENANCE="$GIT_PROVENANCE" \
      FG_BENCH_GIT_BINARY_SHA256="$GIT_BINARY_SHA256" \
      FG_BENCH_TEMPLATE_DIR="$TEMPLATE" \
      FG_BENCH_STORAGE_ROOT="$STORAGE" \
      FG_BENCH_UPSTREAM_BASE_PATH="$UPSTREAM_BASE" \
      FG_BENCH_TENANT="$TENANT" \
      FG_BENCH_REPOSITORY="$REPOID" \
      FG_BENCH_WORK_ROOT="$CLONES" \
      FG_BENCH_PORT_BASE="$port_base" \
      FG_BENCH_EXPECTED_HEAD="$EXPECTED_HEAD" \
      FG_BENCH_EXPECTED_COMMITS="$EXPECTED_COMMITS" \
      FG_BENCH_LOGICAL_BYTES="$logical_bytes" \
      FG_BENCH_SAMPLES="$SAMPLES" \
      FG_BENCH_DATASET="fg028c-corpus ${CORPUS_COMMITS}cx${CORPUS_FILES}fx${CORPUS_LINES}l logical=${LOGICAL_BYTES}B head=$EXPECTED_HEAD" \
      FG_BENCH_OPERATION="$operation" \
      FG_BENCH_STALE_ROOT="$STALE" \
      FG_BENCH_STALE_BASE="$STALE_AT" \
      FG_BENCH_STALE_BEHIND="$STALE_BEHIND_PROVENANCE" \
      FG_BENCH_FETCH_REFSPEC="$FETCH_REFSPEC" \
      FG_BENCH_CACHE_STATE="$CACHE_STATE" \
      FG_BENCH_PYTHON="$PYTHON_BIN" \
      FG_BENCH_SOURCE_REVISION="$SOURCE_REVISION" \
      FG_BENCH_SOURCE_TREE="$SOURCE_TREE" \
      "$RUN_BENCH_DRIVER" transport-baseline --out "$output" \
    || true
  FGE_TRANSPORT_EXIT=$FGE_LAST_EXIT
}

PORT_BASE=$(( 21000 + ($$ % 20000) ))
CLONE_ARTIFACT_DIR="$artifact_dir"
FETCH_ARTIFACT_DIR=
if [ "$OPERATION" = matched ]; then
  CLONE_ARTIFACT_DIR="$artifact_dir/clone"
  FETCH_ARTIFACT_DIR="$artifact_dir/fetch"
  run_transport_operation clone "$CLONE_ARTIFACT_DIR" "$PORT_BASE"
  CLONE_EXPERIMENT_EXIT=$FGE_TRANSPORT_EXIT
  run_transport_operation fetch "$FETCH_ARTIFACT_DIR" "$(( PORT_BASE + 1000 ))"
  FETCH_EXPERIMENT_EXIT=$FGE_TRANSPORT_EXIT
else
  run_transport_operation "$OPERATION" "$CLONE_ARTIFACT_DIR" "$PORT_BASE"
  CLONE_EXPERIMENT_EXIT=$FGE_TRANSPORT_EXIT
  FETCH_EXPERIMENT_EXIT=
fi

fge_phase assert

ARTIFACT="$CLONE_ARTIFACT_DIR/benchmark.ndjson"
FETCH_ARTIFACT="$FETCH_ARTIFACT_DIR/benchmark.ndjson"

fge_assert_exit FG-028C-E2E-007 0 "$CLONE_EXPERIMENT_EXIT" \
  'the baseline/candidate/A-A experiment completes with every oracle satisfied'
fge_assert_file FG-028C-E2E-008 "$ARTIFACT" \
  'the anchor artifact is written'
fge_assert_file FG-028C-E2E-009 "$CLONE_ARTIFACT_DIR/replay-and-rollback.txt" \
  'the anchor artifact carries its reproduction command'
if [ "$OPERATION" = matched ]; then
  fge_assert_exit FG-028C-E2E-027 0 "$FETCH_EXPERIMENT_EXIT" \
    'the matched stale-fetch baseline/candidate/A-A experiment completes with every oracle satisfied'
  fge_assert_file FG-028C-E2E-028 "$FETCH_ARTIFACT" \
    'the matched stale-fetch artifact is written'
fi

# Acceptance line 2: the differential must actually be present. An artifact
# with only one server in it would satisfy nothing while still parsing.
fge_assert_cmd FG-028C-E2E-010 \
  'the artifact records the upstream git daemon arm' \
  grep -qF 'upstream-git-daemon' "$ARTIFACT"
fge_assert_cmd FG-028C-E2E-011 \
  'the artifact records the fgit-node arm' \
  grep -qF 'fgit-node-serve' "$ARTIFACT"

# The A/A control is what turns a delta into a classification. Without it any
# difference reads as a win.
fge_assert_cmd FG-028C-E2E-012 \
  'the artifact records an A/A noise floor measured on this host' \
  grep -qF '"aa_noise"' "$ARTIFACT"

# Every sample carries a correctness receipt, and the receipt is an equality
# against the corpus tip -- not merely a well-formedness check.
expected_samples=$(( SAMPLES * 3 ))
fge_assert_cmd FG-028C-E2E-013 \
  "every one of the $expected_samples measured samples carries a correctness receipt" \
  test "$(grep -cF '"oracle"' "$ARTIFACT")" -eq "$expected_samples"
fge_assert_cmd FG-028C-E2E-014 \
  'each receipt pins the cloned tip, so a valid clone of another history is not a fast sample' \
  grep -qF "head=$EXPECTED_HEAD" "$ARTIFACT"

# The economic metric families the scope names.
metric_id=100
for pair in \
  'cpu_ns:pack CPU' \
  'memory_bytes:server memory' \
  'egress_bytes:egress' \
  'object_requests:request count' \
  'amplification_ppm:storage amplification' \
  'decisions_per_cas_ppm:decisions per CAS'; do
  field=${pair%%:*}
  label=${pair#*:}
  metric_id=$(( metric_id + 1 ))
  fge_assert_cmd "FG-028C-E2E-$metric_id" \
    "the artifact carries the $label metric family" \
    grep -qF "\"$field\"" "$ARTIFACT"
done

# x7ja's transfer claims are numeric gates, not merely a promise that the
# artifact will contain metric-shaped fields. A full clone must retain less
# than one uncompressed reachable corpus on every candidate sample.
if [ "$OPERATION" != fetch ]; then
  fge_assert_cmd FG-028C-E2E-015 \
    'every fgit-node clone sample stays below 1.00x logical reachable bytes' \
    "$PYTHON_BIN" -c 'import json,sys
rows=[json.loads(line) for line in open(sys.argv[1])]
samples=[row for row in rows if row.get("kind")=="sample" and row.get("variant")=="candidate"]
sys.exit(0 if samples and all(sample["metrics"]["storage"]["amplification_ppm"] < 1_000_000 for sample in samples) else 1)' "$ARTIFACT"
fi

# A stale fetch earns its claim only when it is paired with a clone of this
# exact source revision and deterministic corpus. The comparison deliberately
# uses worst-case fetch against best-case clone, so one regressing sample cannot
# be hidden by an average. A standalone fetch remains diagnostic evidence, not
# proof of the fetch-versus-clone acceptance line.
if [ "$OPERATION" = matched ]; then
  fge_assert_cmd FG-028C-E2E-029 \
    'matched clone and fetch artifacts bind one frozen candidate, driver, pinned Git, stale base, and corpus fingerprint' \
    "$PYTHON_BIN" -c 'import json,sys
def begin(path):
    rows=[json.loads(line) for line in open(path)]
    matches=[row for row in rows if row.get("kind")=="begin"]
    if len(matches) != 1:
        raise SystemExit(1)
    return matches[0]
def common(begin):
    workload=dict(begin["workload"])
    environment=dict(workload.pop("environment_allowlist"))
    # Operation, port, and the operation-specific logical denominator are the
    # intentional clone/fetch differences. Every other execution input must
    # match, including the copied images and stale-fetch setup.
    for key in ("FG_BENCH_OPERATION", "FG_BENCH_PORT_BASE", "FG_BENCH_LOGICAL_BYTES"):
        environment.pop(key, None)
    workload.pop("workload", None)
    return {"fingerprint":begin["fingerprint"], "workload":workload,
            "admission":begin["admission"], "environment":environment}
clone,fetch=begin(sys.argv[1]),begin(sys.argv[2])
required=("FG_BENCH_FG_BINARY_SHA256", "FG_BENCH_DRIVER_BINARY_SHA256",
          "FG_BENCH_GIT_PROVENANCE", "FG_BENCH_GIT_BINARY_SHA256",
          "FG_BENCH_STALE_BASE", "FG_BENCH_STALE_BEHIND")
environment=common(clone)["environment"]
raise SystemExit(0 if common(clone) == common(fetch)
                 and all(environment.get(key) for key in required)
                 and environment.get("FG_BENCH_GIT_PROVENANCE") == "pinned-oracle-git-2.54.0"
                 else 1)' "$ARTIFACT" "$FETCH_ARTIFACT"
  fge_assert_cmd FG-028C-E2E-030 \
    'every matched stale-fetch candidate adds fewer bytes than every matched clone candidate' \
    "$PYTHON_BIN" -c 'import json,sys
def candidates(path):
    rows=[json.loads(line) for line in open(path)]
    return [row["metrics"]["egress_bytes"] for row in rows if row.get("kind")=="sample" and row.get("variant")=="candidate"]
clone,fetch=candidates(sys.argv[1]),candidates(sys.argv[2])
expected=int(sys.argv[3])
raise SystemExit(0 if len(clone)==expected and len(fetch)==expected and max(fetch) < min(clone) else 1)' "$ARTIFACT" "$FETCH_ARTIFACT" "$SAMPLES"
elif [ "$OPERATION" = fetch ]; then
  fge_unsupported FG-028C-E2E-031 \
    'a standalone stale-fetch artifact has no matched clone comparator; use the default matched lane for the egress inequality'
fi

# The measured CPU must be a real reading, not a defaulted zero. A zero would
# read as a free server and is exactly what the /proc probe returns None for.
fge_assert_cmd FG-028C-E2E-016 \
  'measured server CPU is a real reading rather than a defaulted zero' \
  grep -qE '"cpu_ns":[1-9][0-9]*' "$ARTIFACT"

# Honest labelling of the interval. Anyone reading a latency number later must
# see that it includes cold server start.
fge_assert_cmd FG-028C-E2E-017 \
  'the artifact states that the timed interval is not steady-state transport latency' \
  grep -qF 'NOT steady-state transport latency' "$ARTIFACT"

# Anchor semantics: this is a pre-optimization baseline, so a false
# speedup_admissible is the expected honest outcome and must be recorded either
# way rather than omitted.
fge_assert_cmd FG-028C-E2E-018 \
  'the artifact records an explicit admissibility verdict rather than omitting it' \
  grep -qE '"speedup_admissible":(true|false)' "$ARTIFACT"

if [ "$OPERATION" = matched ]; then
  fge_artifact "$ARTIFACT" perf-baseline-clone-anchor
  fge_artifact "$CLONE_ARTIFACT_DIR/replay-and-rollback.txt" perf-baseline-clone-replay
  fge_artifact "$FETCH_ARTIFACT" perf-baseline-fetch-anchor
  fge_artifact "$FETCH_ARTIFACT_DIR/replay-and-rollback.txt" perf-baseline-fetch-replay
  if [ -f "$CLONE_ARTIFACT_DIR/negative-evidence.ndjson" ]; then
    fge_artifact "$CLONE_ARTIFACT_DIR/negative-evidence.ndjson" perf-baseline-clone-negative-evidence
  fi
  if [ -f "$FETCH_ARTIFACT_DIR/negative-evidence.ndjson" ]; then
    fge_artifact "$FETCH_ARTIFACT_DIR/negative-evidence.ndjson" perf-baseline-fetch-negative-evidence
  fi
else
  fge_artifact "$ARTIFACT" perf-baseline-anchor
  fge_artifact "$CLONE_ARTIFACT_DIR/replay-and-rollback.txt" perf-baseline-replay
  if [ -f "$CLONE_ARTIFACT_DIR/negative-evidence.ndjson" ]; then
    fge_artifact "$CLONE_ARTIFACT_DIR/negative-evidence.ndjson" perf-baseline-negative-evidence
  fi
fi

# ---------------------------------------------------------------------------
# THE AUTHORITY ARM: decisions per compare-and-exchange.
#
# The scope line names decisions-per-CAS alongside the transport metrics, and
# it is a different subject rather than a column on the clone numbers: a clone
# is read-only and commits no decision, so an authority ratio taken from it
# would be a number with no measurement behind it.
#
# The differential here is BATCHING, not two implementations. Nothing upstream
# publishes a decision batch under a compare-and-exchange, so there is no second
# system to compare against; what the scope line is really asking is what
# batching buys, and this project can answer that against itself.
# ---------------------------------------------------------------------------

fge_phase action

authority_dir=$(fge_tempdir perf-baseline-authority)
authority_store=$(fge_tempdir perf-baseline-authority-store)
fge_context authority_artifact_directory "$authority_dir"

fge_run perf-baseline-authority-experiment \
  env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    FG_BENCH_AUTHORITY_STORE_ROOT="$authority_store" \
    FG_BENCH_AUTHORITY_DECISIONS="${FG_BENCH_AUTHORITY_DECISIONS:-8}" \
    FG_BENCH_SAMPLES="$SAMPLES" \
    FG_BENCH_SOURCE_REVISION="$SOURCE_REVISION" \
    FG_BENCH_SOURCE_TREE="$SOURCE_TREE" \
    "$RUN_BENCH_DRIVER" authority-baseline --out "$authority_dir" \
  || true
AUTHORITY_EXIT=$FGE_LAST_EXIT

fge_phase assert

AUTHORITY_ARTIFACT="$authority_dir/benchmark.ndjson"

fge_assert_exit FG-028C-E2E-022 0 "$AUTHORITY_EXIT" \
  'the authority publication experiment completes with every oracle satisfied'
fge_assert_file FG-028C-E2E-023 "$AUTHORITY_ARTIFACT" \
  'the authority arm writes its anchor artifact'

# The substantive one. An arm that reported the same ratio for both batch sizes
# would have measured nothing while still writing a well-formed artifact, and
# every assertion above would still pass. Requiring MORE THAN ONE distinct
# decisions-per-CAS value is what makes this arm falsifiable.
fge_assert_cmd FG-028C-E2E-024 \
  'the authority arm reports more than one distinct decisions-per-CAS value, so the ratio tracks the batch' \
  "$PYTHON_BIN" -c 'import json,sys
values={json.loads(line)["metrics"]["decisions_per_cas_ppm"] for line in open(sys.argv[1]) if json.loads(line).get("kind")=="sample"}
sys.exit(0 if len(values)>1 else 1)' "$AUTHORITY_ARTIFACT"

# An authority publication has no git object graph, so the amplification ratio
# does not describe it. Null is the honest rendering; a zero would read as a
# measured no-amplification result.
fge_assert_cmd FG-028C-E2E-025 \
  'the authority arm reports no storage amplification rather than a fabricated zero' \
  "$PYTHON_BIN" -c 'import json,sys
rows=[json.loads(line) for line in open(sys.argv[1])]
samples=[r for r in rows if r.get("kind")=="sample"]
sys.exit(0 if samples and all(r["metrics"]["storage"]["amplification_ppm"] is None for r in samples) else 1)' "$AUTHORITY_ARTIFACT"

fge_artifact "$AUTHORITY_ARTIFACT" perf-baseline-authority-anchor
fge_artifact "$authority_dir/replay-and-rollback.txt" perf-baseline-authority-replay
if [ -f "$authority_dir/negative-evidence.ndjson" ]; then
  fge_artifact "$authority_dir/negative-evidence.ndjson" perf-baseline-authority-negative-evidence
fi
