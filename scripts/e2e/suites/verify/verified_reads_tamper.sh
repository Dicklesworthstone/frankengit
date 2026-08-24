#!/usr/bin/env bash
# e2e: FG-037b VERIFIED-READ TAMPER CAMPAIGN -- the mirror/CDN tamper corpus, the
# head-chain freshness policy, and the proof-cost invariants, receipted here
# (bead frankengit-fg037b-proofs-tamper-q7v).
#
# PATH NOTE: the bead text names scripts/e2e/verified_reads_tamper.sh "registered
# in run_all.sh". It lives here instead, because run_all walks suites/<area>/**
# and ANYTHING OUTSIDE suites/ IS NOT DISCOVERED -- a root-level script would need
# an explicit invoker and would silently run nowhere. Same discrepancy and same
# resolution as fg036b's cell; flagged on the bead rather than resolved silently.
#
# WHAT IS ASSERTED:
#   - the three verified-read targets pass;
#   - every case is present BY NAME. A green total cannot distinguish "ran and
#     passed" from "was renamed and silently stopped running", and this suite's
#     whole subject is a corpus whose value is its coverage;
#   - the case count per target matches, so a DELETED case fails here rather than
#     quietly shrinking the corpus. A name list alone would not catch a removal;
#   - the two load-bearing meta-assertions are present specifically: the
#     detection-spread check and the freshness-dependency check. Those are what
#     make "100% detection" a measurement rather than a slogan, and if either is
#     dropped the rate keeps reading 100% while meaning much less.
#
# NOT ASSERTED HERE: the detection rate itself. That is computed inside the Rust
# corpus, which knows the tamper classes; re-deriving it in bash would be a
# second, weaker oracle that could disagree with the real one.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init verified-reads-tamper

CRATE=fgit-verified-read

# target : expected case count
TARGETS=(
  "tamper_campaign:5"
  "head_chain_freshness:7"
  "proof_cost:5"
)

# The cases whose absence would hollow out this bead, asserted individually.
LOAD_BEARING=(
  detections_are_spread_across_distinct_checks_not_funnelled_through_one
  envelope_verification_alone_accepts_the_replay_which_is_why_freshness_exists
  the_honest_answer_is_accepted_so_the_rate_is_not_a_client_that_refuses_everything
  a_replayed_older_head_is_refused_even_though_it_is_perfectly_valid
  two_heads_claiming_one_generation_are_a_fork_and_not_staleness
  a_forged_head_at_a_higher_generation_is_caught_by_continuity
  a_membership_proof_carries_exactly_ceil_log2_siblings
)

fge_phase setup
fge_context suite verify-verified-reads-tamper
fge_note tooling "RCH_CARGO_WRAPPER_BYPASS=1 per AGENTS.md 16.2 so the rch offload wrapper is bypassed"

fge_phase action

# One capture per target so a failure names the target rather than the suite.
# --test-threads=1 keeps each case's output on its own line: under --nocapture
# cargo writes "test <name> ... " WITHOUT a newline, so concurrent cases can
# split a line and a name grep can miss a case that really ran.
declare -A EXIT_OF
declare -A OUT_OF
for entry in "${TARGETS[@]}"; do
  target=${entry%%:*}
  fge_capture "run-$target" env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test -p "$CRATE" --test "$target" -- --nocapture --test-threads=1 || true
  EXIT_OF[$target]=$FGE_LAST_EXIT
  OUT_OF[$target]=$FGE_LAST_STDOUT_FILE
  fge_artifact "$FGE_LAST_STDOUT_FILE"
done

fge_phase assert

idx=1
for entry in "${TARGETS[@]}"; do
  target=${entry%%:*}
  expected=${entry##*:}
  out=${OUT_OF[$target]}

  id=$(printf 'FG-037B-E2E-%03d' "$idx")
  fge_assert_exit "$id" 0 "${EXIT_OF[$target]}" "the $target target passes"
  idx=$((idx + 1))

  # Count reported cases from the full captured file, not FGE_LAST_STDOUT, which
  # lib.sh truncates at FGE_MAX_CAPTURE. A truncated haystack undercounts.
  # [a-z0-9_] and not [a-z_]: case names contain digits (ceil_log2), and the
  # narrower class silently undercounted by one. The count assertion caught that
  # in its own counter, which is the argument for counting rather than only
  # listing names -- a name list would have reported every case present while
  # the total was wrong.
  actual=$(grep -c '^test [a-z0-9_]* \.\.\. ok$' "$out" || true)
  id=$(printf 'FG-037B-E2E-%03d' "$idx")
  fge_assert_eq "$id" "$expected" "$actual" \
    "$target reports exactly $expected passing cases, so a deleted case fails here"
  idx=$((idx + 1))
done

# Load-bearing cases by name. Substring match, NOT anchored: cargo prefixes the
# line with "test " and may append " ... ok" on the same line.
for case_name in "${LOAD_BEARING[@]}"; do
  id=$(printf 'FG-037B-E2E-%03d' "$idx")
  found=no
  for entry in "${TARGETS[@]}"; do
    target=${entry%%:*}
    if grep -qF "$case_name" "${OUT_OF[$target]}"; then
      found=yes
      break
    fi
  done
  fge_assert_eq "$id" yes "$found" "load-bearing case present: $case_name"
  idx=$((idx + 1))
done
