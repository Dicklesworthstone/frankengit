#!/usr/bin/env bash
# e2e: FG-036b DISTRIBUTED FAULT MATRIX -- the cell-level partition, region-loss
# and rolling-upgrade scenarios, receipted here (bead
# frankengit-fg036b-distributed-faults-3ab).
#
# WHAT IS ASSERTED:
#   - the distributed fault campaign passes, and the three cell-level scenarios
#     are present BY NAME rather than inferred from a passing total;
#   - those scenarios' evidence is IDENTICAL under two unrelated seeds. That is
#     the correct property for them specifically: they take no seed input (fixed
#     fault plans, fixed instance ids), so seed-independence is what they claim.
#     A replay-under-one-seed check would not distinguish them from the seeded
#     scenarios that share the same test binary;
#   - the twin that stops the above from being vacuous: the WHOLE evidence stream
#     DOES differ under those same two seeds. Without it, "identical" would be
#     equally satisfied by a stream that never varies at all, which is the
#     failure mode a determinism check is most likely to have;
#   - and the cell-level slice is non-empty, or the two digests above would agree
#     because both are the digest of an empty file;
#   - every evidence line the campaign emits is valid NDJSON.
#
# OVERLAP, DECLARED RATHER THAN LEFT FOR A REVIEWER TO FIND:
# scripts/e2e/suites/authority/faults.sh (FG-004c) already drives the same
# `cargo test -p fgit-authority --test fault_campaign` and asserts exit status,
# the evidence schema marker, and both lincheck verdicts. This cell deliberately
# re-asserts NONE of those four, and runs the binary twice rather than three
# times, because the expensive step is shared with a suite that already pays for
# it once.
#
# WHY THE SORT: cargo runs a binary's cases concurrently, so the ORDER of emitted
# evidence lines is scheduling, not content. Digests are taken over the sorted
# line set, so "same evidence" is a claim about what the campaign decided rather
# than about which thread finished first.
#
# NOT ASSERTED HERE: linearizability itself. That is checked inside the campaign
# by LinearizabilityChecker against the SequentialSpec, and re-deriving it in
# bash would be a second, weaker oracle that could disagree with the real one.
# This cell pins that the campaign RAN, which scenarios ran, and what varies.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init multicell-faults

# The campaign's own env knob, so a failure here replays exactly by exporting the
# same value to `cargo test` by hand. Overridable; logged either way.
SEED_A=${FG_AUTHORITY_FAULT_SEED:-0xF036B0000000A001}
SEED_B=${FG_MULTICELL_ALT_SEED:-0xF036B0000000B002}

CAMPAIGN=(cargo test -p fgit-authority --test fault_campaign -- --nocapture)

# The three cell-level scenarios this bead added. Asserted by name because a
# green total cannot distinguish "ran and passed" from "was renamed and silently
# stopped running".
SCENARIOS=(
  an_isolated_cell_cannot_label_a_drifted_answer_as_current
  an_isolated_cell_that_reconnects_observes_no_lost_write
  an_older_cell_cannot_roll_back_a_head_written_in_a_newer_format
)

fge_phase setup
fge_context suite node-multicell-faults
fge_step seeds "campaign seeds: primary=$SEED_A alternate=$SEED_B"
fge_note tooling "RCH_CARGO_WRAPPER_BYPASS=1 per AGENTS.md 16.2 so the rch offload wrapper is bypassed"

# Every evidence line the campaign emitted, sorted. Pure bash + coreutils: no
# jq, no python, per the lib.sh tooling contract.
evidence_digest() {
  local src=$1 dest=$2
  grep '^{' "$src" | LC_ALL=C sort | tee "$dest" >/dev/null || true
  fge_digest_file "$dest"
}

# Only the lines belonging to this bead's cell-level scenarios. The campaign
# stamps a human note on every record and these three notes are the stable
# discriminator; matching on the note rather than the test name keeps this
# working if the emitted record ever stops echoing function names.
cell_scenario_digest() {
  local src=$1 dest=$2
  grep '^{' "$src" \
    | grep -E 'isolated cell|rejoining after a real partition|rolling upgrade' \
    | LC_ALL=C sort | tee "$dest" >/dev/null || true
  fge_digest_file "$dest"
}

fge_phase action

RUN_A=$(fge_artifact_path "evidence/seed-a.ndjson")
RUN_B=$(fge_artifact_path "evidence/seed-b.ndjson")
CELLS_A=$(fge_artifact_path "evidence/cell-scenarios-seed-a.txt")
CELLS_B=$(fge_artifact_path "evidence/cell-scenarios-seed-b.txt")

fge_capture campaign-seed-a env RCH_CARGO_WRAPPER_BYPASS=1 \
  FG_AUTHORITY_FAULT_SEED="$SEED_A" "${CAMPAIGN[@]}" || true
RC_A=$FGE_LAST_EXIT
OUT_A=$FGE_LAST_STDOUT_FILE
DIGEST_A=$(evidence_digest "$OUT_A" "$RUN_A")
CELL_DIGEST_A=$(cell_scenario_digest "$OUT_A" "$CELLS_A")

fge_capture campaign-seed-b env RCH_CARGO_WRAPPER_BYPASS=1 \
  FG_AUTHORITY_FAULT_SEED="$SEED_B" "${CAMPAIGN[@]}" || true
RC_B=$FGE_LAST_EXIT
DIGEST_B=$(evidence_digest "$FGE_LAST_STDOUT_FILE" "$RUN_B")
CELL_DIGEST_B=$(cell_scenario_digest "$FGE_LAST_STDOUT_FILE" "$CELLS_B")

# fge_artifact takes NAME_OR_PATH [KIND] -- one positional, not name+path. Passing
# a name plus a path makes the path the KIND and looks up a file that does not
# exist, which returns 1 and, under set -e, kills the script before a single
# assertion runs. The suite then reports "assertions=0" with no cause. Path form.
fge_artifact "$RUN_A"
fge_artifact "$RUN_B"
fge_artifact "$CELLS_A"
fge_artifact "$CELLS_B"

fge_phase assert

fge_assert_exit FG-036B-E2E-001 0 "$RC_A" \
  'the distributed fault campaign passes under the primary seed'
fge_assert_exit FG-036B-E2E-002 0 "$RC_B" \
  'and under an unrelated seed, so the pass is not seed-specific'

# Scenario presence, grepped from the FULL captured file rather than
# FGE_LAST_STDOUT, which lib.sh truncates at FGE_MAX_CAPTURE (4096 bytes by
# default). A truncated haystack turns a present scenario into a silent false
# negative; the neighbouring FG-004c suite documents the same trap.
idx=3
for scenario in "${SCENARIOS[@]}"; do
  id=$(printf 'FG-036B-E2E-%03d' "$idx")
  fge_assert_cmd "$id" "cell-level scenario ran: $scenario" \
    grep -qF "$scenario" "$OUT_A"
  idx=$((idx + 1))
done

# The cell-level scenarios consume no seed, so their evidence must not move.
fge_assert_eq FG-036B-E2E-006 "$CELL_DIGEST_A" "$CELL_DIGEST_B" \
  'the cell-level scenarios take no seed input, so two seeds must produce identical evidence'

# The twin. If nothing in the stream varied with the seed, the assertion above
# would hold trivially and measure nothing.
fge_assert_ne FG-036B-E2E-007 "$DIGEST_A" "$DIGEST_B" \
  "the seed does change the campaign's evidence, so the check above is not vacuous"

# And the slice must be non-empty, or both digests above are the digest of an
# empty file and agree for the worst possible reason.
fge_assert_cmd FG-036B-E2E-008 'the cell-level evidence slice is non-empty' \
  test -s "$CELLS_A"

fge_assert_ndjson FG-036B-E2E-009 "$RUN_A" \
  'every evidence line the campaign emits is a valid JSON object'
