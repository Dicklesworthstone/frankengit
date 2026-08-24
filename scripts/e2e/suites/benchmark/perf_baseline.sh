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
# fgit-cli plus repeated measurement runs. This script honours the bound by
# building exactly once and by capping the sample count.
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
# clone or fetch. Both are measured identically, one arm per server; a fetch run
# consumes a pre-created stale clone per sample so materializing it stays
# outside the timed interval.
OPERATION=${FG_BENCH_OPERATION:-clone}
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

fge_assert_file FG-028C-E2E-001 "$PB_REPO/crates/fgit-benchmark/src/transport.rs" \
  'the transport workload module is present'

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
  fge_context git_provenance "pinned-oracle-$PIN"
else
  fge_context git_provenance 'ambient-path-git-UNPINNED'
  fge_note 'the pinned oracle install is absent; this differential used an ambient git and is UNPINNED'
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
fge_context fg_binary "$FG_BIN"

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

# For a fetch run, materialize one stale clone PER SAMPLE PER ARM up front.
# A fetch ADVANCES the repository it runs in, so a reused copy would transfer
# nothing on every sample after the first and report as very fast. The runner
# reuses the baseline subject for the A/A pass, so that arm consumes 2*SAMPLES
# indices while the candidate arm consumes SAMPLES.
if [ "$OPERATION" = fetch ]; then
  STALE_AT=$("$GIT_BIN" -C "$SRC" rev-parse "HEAD~$STALE_BEHIND")
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

fge_run perf-baseline-experiment \
  env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    FG_BENCH_FG_BINARY="$FG_BIN" \
    FG_BENCH_GIT_BINARY="$GIT_BIN" \
    FG_BENCH_GIT_EXEC_PATH="$GIT_EXEC" \
    FG_BENCH_TEMPLATE_DIR="$TEMPLATE" \
    FG_BENCH_STORAGE_ROOT="$STORAGE" \
    FG_BENCH_UPSTREAM_BASE_PATH="$UPSTREAM_BASE" \
    FG_BENCH_TENANT="$TENANT" \
    FG_BENCH_REPOSITORY="$REPOID" \
    FG_BENCH_WORK_ROOT="$CLONES" \
    FG_BENCH_PORT_BASE="$(( 21000 + ($$ % 20000) ))" \
    FG_BENCH_EXPECTED_HEAD="$EXPECTED_HEAD" \
    FG_BENCH_EXPECTED_COMMITS="$EXPECTED_COMMITS" \
    FG_BENCH_LOGICAL_BYTES="$LOGICAL_FOR_RUN" \
    FG_BENCH_SAMPLES="$SAMPLES" \
    FG_BENCH_DATASET="fg028c-corpus ${CORPUS_COMMITS}cx${CORPUS_FILES}fx${CORPUS_LINES}l logical=${LOGICAL_BYTES}B head=$EXPECTED_HEAD" \
    FG_BENCH_OPERATION="$OPERATION" \
    FG_BENCH_STALE_ROOT="$STALE" \
    FG_BENCH_FETCH_REFSPEC="$FETCH_REFSPEC" \
    FG_BENCH_CACHE_STATE="$CACHE_STATE" \
    FG_BENCH_PYTHON="$PYTHON_BIN" \
    FG_BENCH_SOURCE_REVISION="$SOURCE_REVISION" \
    FG_BENCH_SOURCE_TREE="$SOURCE_TREE" \
    cargo run -q --release -p fgit-benchmark -- transport-baseline --out "$artifact_dir" \
  || true
EXPERIMENT_EXIT=$FGE_LAST_EXIT

fge_phase assert

ARTIFACT="$artifact_dir/benchmark.ndjson"

fge_assert_exit FG-028C-E2E-007 0 "$EXPERIMENT_EXIT" \
  'the baseline/candidate/A-A experiment completes with every oracle satisfied'
fge_assert_file FG-028C-E2E-008 "$ARTIFACT" \
  'the anchor artifact is written'
fge_assert_file FG-028C-E2E-009 "$artifact_dir/replay-and-rollback.txt" \
  'the anchor artifact carries its reproduction command'

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

fge_artifact "$ARTIFACT" perf-baseline-anchor
fge_artifact "$artifact_dir/replay-and-rollback.txt" perf-baseline-replay
if [ -f "$artifact_dir/negative-evidence.ndjson" ]; then
  fge_artifact "$artifact_dir/negative-evidence.ndjson" perf-baseline-negative-evidence
fi

# PUSH IS NOT MEASURED, AND THE REASON IS RECORDED RATHER THAN OMITTED.
# The scope names clone/fetch/push. At this revision the git daemon accepts
# only git-upload-pack (crates/fgit-node/src/lib.rs, the service gate), the
# authenticated loopback receive path has zero binary callers, and `fg` exposes
# no push subcommand. An in-process library call is not the same operation as
# `git push` and reporting them side by side would be proof-class inflation.
fge_unsupported FG-028C-E2E-019 \
  'push throughput is unmeasurable as a transport at this revision: the daemon serves only git-upload-pack and the receive path has no binary caller (see frankengit-n6kg)'
fge_unsupported FG-028C-E2E-020 \
  'fetch is not measured through the sanctioned oracle lane, which implements clone-loopback only'
