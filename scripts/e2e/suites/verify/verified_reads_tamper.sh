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

# crate : target : expected case count
#
# The crate is per-entry rather than global because the strongest evidence on
# this bead does not live in fgit-verified-read at all: the production-path
# test drives OneNode, so it is an fgit-node target. Leaving it out would have
# meant the suite claiming to cover fg037b was blind to the only case that
# reads through a real serving path.
# Counts are MEASURED against the source, not guessed. They went stale once: a
# repair at 87e76ba took tamper_campaign 5 -> 6 and proof_cost 5 -> 7 and deleted
# a case this suite named, and I re-ran `cargo test --all-targets` but not this
# suite, so I shipped it red. The count assertion did its job; I just did not
# look. Changing a case count in those files means changing this list.
TARGETS=(
  "fgit-verified-read:tamper_campaign:8"
  "fgit-verified-read:head_chain_freshness:7"
  "fgit-verified-read:proof_cost:9"
  "fgit-node:verified_read_served_tamper:2"
)

# The corpus's declared tamper-class count, asserted separately from the
# test-function count above. Every class lives inside ONE function, so a
# function count cannot see a class being removed; the Rust denominator guard
# emits this
# marker and the assertion below reads it.
EXPECTED_TAMPER_CLASSES=13

# The cases whose absence would hollow out this bead, asserted individually.
LOAD_BEARING=(
  detections_are_spread_across_distinct_checks_not_funnelled_through_one
  envelope_verification_alone_accepts_the_replay_which_is_why_freshness_exists
  the_honest_answer_is_accepted_so_the_rate_is_not_a_client_that_refuses_everything
  a_replayed_older_head_is_refused_even_though_it_is_perfectly_valid
  two_heads_claiming_one_generation_are_a_fork_and_not_staleness
  a_forged_head_at_a_higher_generation_is_caught_by_continuity
  the_corpus_covers_every_declared_tamper_class_exactly_once
  an_outcome_envelope_is_checked_against_the_outcome_index_root_not_whichever_root_verifies
  a_v1_configuration_cannot_stand_in_for_the_incarnation_body_the_head_selected
  a_server_produced_envelope_verifies_and_the_same_envelope_tampered_does_not
  an_unproven_client_is_still_served_by_a_proof_capable_node
  every_leaf_at_every_size_carries_exactly_the_length_its_position_requires
  a_promoted_tail_really_does_shorten_a_path_so_the_model_is_not_decorative
  generation_reads_the_whole_state_while_verification_reads_only_the_path
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
  crate=${entry%%:*}
  rest=${entry#*:}
  target=${rest%%:*}
  fge_capture "run-$target" env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test -p "$crate" --test "$target" -- --nocapture --test-threads=1 || true
  EXIT_OF[$target]=$FGE_LAST_EXIT
  OUT_OF[$target]=$FGE_LAST_STDOUT_FILE
  fge_artifact "$FGE_LAST_STDOUT_FILE"
done

fge_phase assert

idx=1
for entry in "${TARGETS[@]}"; do
  rest=${entry#*:}
  target=${rest%%:*}
  expected=${entry##*:}
  out=${OUT_OF[$target]}

  id=$(printf 'FG-037B-E2E-%03d' "$idx")
  fge_assert_exit "$id" 0 "${EXIT_OF[$target]}" "the $target target passes"
  idx=$((idx + 1))

  # Read the harness's OWN summary line rather than reconstructing the count by
  # matching per-case lines. Two reasons, both learned the hard way here:
  #   - a case name containing a digit escaped a [a-z_] class and undercounted;
  #   - once a case PRINTS anything, --nocapture puts that output on the same
  #     line as "test <name> ... ", so a `... ok$` anchor stops matching it. My
  #     own class-count marker broke my own counter exactly that way.
  # "test result: ok. N passed" is the harness's authoritative total and is
  # immune to both.
  actual=$(grep -oE '^test result: ok\. [0-9]+ passed' "$out" | grep -oE '[0-9]+' | head -1)
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
    rest=${entry#*:}
    target=${rest%%:*}
    if grep -qF "$case_name" "${OUT_OF[$target]}"; then
      found=yes
      break
    fi
  done
  fge_assert_eq "$id" yes "$found" "load-bearing case present: $case_name"
  idx=$((idx + 1))
done

# The tamper-class count, read from the marker the denominator guard prints. This
# is the assertion that fails when a class is deleted from `corpus()` -- which the
# per-target function counts above cannot see.
classes=$(grep -oE 'fg037b\.tamper_classes=[0-9]+' "${OUT_OF[tamper_campaign]}" | tail -1 | cut -d= -f2)
id=$(printf 'FG-037B-E2E-%03d' "$idx")
fge_assert_eq "$id" "$EXPECTED_TAMPER_CLASSES" "${classes:-missing}" \
  'the corpus declares exactly the expected number of tamper classes'
