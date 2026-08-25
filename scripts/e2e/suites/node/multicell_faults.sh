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

# --test-threads=1 is load-bearing, not tidiness. With parallel cases and
# --nocapture, concurrent println! output INTERLEAVES: a long evidence line can be
# split by another case's output, and `grep '^{'` then silently drops the
# fragment. That is not a content difference but it moves the digest, so the
# seed-comparison assertions below would flake. Measured: one seed's slice came
# back with 5 evidence lines and the other's with 4, from identical content.
CAMPAIGN=(cargo test -p fgit-authority --test fault_campaign -- --nocapture --test-threads=1)

# The five cell-level scenarios this bead added. Asserted by name because a green
# total cannot distinguish "ran and passed" from "was renamed and silently stopped
# running". Note the clock-independence case emits no campaign NDJSON (it runs no
# linearizability check -- it compares two head histories directly), so it appears
# in the by-name assertions but NOT in the evidence slice digested below.
SCENARIOS=(
  an_isolated_cell_cannot_label_a_drifted_answer_as_current
  an_isolated_cell_that_reconnects_observes_no_lost_write
  an_older_cell_holding_a_superseded_token_cannot_replace_the_head
  a_head_from_a_newer_build_is_refused_by_version_and_the_cell_does_not_fall_back
  a_crash_during_a_head_transition_never_leaves_a_half_published_head
  the_head_history_is_a_pure_function_of_its_operations_not_of_the_clock
)

fge_phase setup
fge_context suite node-multicell-faults
fge_step seeds "campaign seeds: primary=$SEED_A alternate=$SEED_B"
fge_note tooling "RCH_CARGO_WRAPPER_BYPASS=1 per AGENTS.md 16.2 so the rch offload wrapper is bypassed"

# Every evidence record the campaign emitted, sorted. Pure bash + coreutils: no
# jq, no python, per the lib.sh tooling contract.
#
# EXTRACTED BY SCHEMA MARKER, NOT BY `^{`. Under --nocapture cargo writes
# "test <name> ... " WITHOUT a trailing newline before running the case, so the
# case's own println! lands on the SAME line and the JSON is prefixed. An
# anchored `grep '^{'` therefore finds only the few records that happened to
# start a line -- measured: 4 of them out of a 12-case run whose notes were all
# present in the file. `grep -o` from the marker strips whatever precedes it.
EVIDENCE_MARKER='{"schema":"fgit.authority.fault-campaign.v1"'

evidence_records() {
  grep -o "${EVIDENCE_MARKER}.*" "$1" || true
}

evidence_digest() {
  local src=$1 dest=$2
  evidence_records "$src" | LC_ALL=C sort | tee "$dest" >/dev/null
  fge_digest_file "$dest"
}

# Only the lines belonging to this bead's cell-level scenarios. The campaign
# stamps a human note on every record and these three notes are the stable
# discriminator; matching on the note rather than the test name keeps this
# working if the emitted record ever stops echoing function names.
cell_scenario_digest() {
  local src=$1 dest=$2
  evidence_records "$src" \
    | grep -E 'isolated cell|rejoining after a real partition|rolling upgrade|whole head' \
    | LC_ALL=C sort | tee "$dest" >/dev/null || true
  fge_digest_file "$dest"
}

# The cell-level scenarios emit exactly five records: one each for the isolation,
# reconnect and rolling-upgrade cases, and two for the torn-head case, which runs
# once per FaultPosition. Asserting the COUNT rather than non-emptiness is the
# point: `test -s` passed happily on a single record while four were being
# dropped by a broken extractor, and a digest comparison over one line agrees for
# reasons that have nothing to do with the property.
EXPECTED_CELL_RECORDS=5

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
#
# Scenario ids are allocated from 100 UP, and the fixed assertions below keep
# their low ids. That is deliberate: this loop used to start at 003 and run into
# the fixed 008, so every time SCENARIOS grew, two different checks silently
# shared an acceptance id. It happened once already -- the list went from three
# entries to five and the run reported "assertions=9 passed=10", nine distinct
# ids for ten records, with the duplicate masking which check failed. Separating
# the ranges removes the collision instead of postponing it by one more entry,
# so SCENARIOS can now grow without renumbering anything.
#
# 003..007 are deliberately left vacant: they were the old scenario range, and
# reusing them would make archived run logs read as though a different check had
# passed under that id.
idx=100
for scenario in "${SCENARIOS[@]}"; do
  id=$(printf 'FG-036B-E2E-%03d' "$idx")
  fge_assert_cmd "$id" "cell-level scenario ran: $scenario" \
    grep -qF "$scenario" "$OUT_A"
  idx=$((idx + 1))
done

# The cell-level scenarios consume no seed, so their evidence must not move.
fge_assert_eq FG-036B-E2E-008 "$CELL_DIGEST_A" "$CELL_DIGEST_B" \
  'the cell-level scenarios take no seed input, so two seeds must produce identical evidence'

# The twin. If nothing in the stream varied with the seed, the assertion above
# would hold trivially and measure nothing.
fge_assert_ne FG-036B-E2E-009 "$DIGEST_A" "$DIGEST_B" \
  "the seed does change the campaign's evidence, so the check above is not vacuous"

# And the slice must be non-empty, or both digests above are the digest of an
# empty file and agree for the worst possible reason.
CELL_COUNT_A=$(wc -l <"$CELLS_A")
CELL_COUNT_A=${CELL_COUNT_A// /}
fge_assert_eq FG-036B-E2E-010 "$EXPECTED_CELL_RECORDS" "$CELL_COUNT_A" \
  'every cell-level scenario emitted its evidence record, counted not assumed'

fge_assert_ndjson FG-036B-E2E-011 "$RUN_A" \
  'every evidence line the campaign emits is a valid JSON object'

# ---------------------------------------------------------------------------
# THE WRITE-SIDE CELL GATE, receipted here because this bead's scope names all
# three of §22.6's isolation responses and the campaign above covers none of
# them: the campaign runs against the authority store, and these run against a
# node. Added by GoldLotus's 11:32 ruling (staging-only) and their 23:40
# option (A) ruling (refuse before intake).
#
# SEPARATE CAPTURES, NOT ENTRIES IN `CAMPAIGN[@]`, and the reason is not tidiness.
# These targets live in a different crate and emit NO campaign NDJSON. Folding
# them into the campaign runs would put a second binary's output into OUT_A/OUT_B,
# which feeds evidence_records(): the marker grep would ignore it so the digests
# would not move, but RC_A/RC_B would then conflate two binaries' exit codes and
# a node-side failure would be reported as a campaign failure.
#
# ID ALLOCATION. Fixed assertions hold the low ids (001,002,008..011 and now
# 012..019); the scenario loop runs from 100 up. The two ranges collided once
# before and two checks silently shared an id, so they stay apart.
# ---------------------------------------------------------------------------

# THE ANCHOR IS THE EXPLICIT LIST BELOW, NOT THE SOURCE FILE.
#
# The first version of this block derived the expected case count by grepping
# `#[test]` out of the target's own source. That is the defect it was written to
# prevent: delete a case and BOTH the expectation and the observation drop by
# one, so the check passes while the property it guards is gone. An expectation
# computed from the same input as the observation cannot detect a change to that
# input.
#
# So the expected set is written out here, by name, and the source-derived count
# is used only in the opposite direction -- to catch a case ADDED to the file
# and never named here, which would otherwise be invisible.
STAGING_TARGET=staging_only_receive
STAGING_SOURCE="$E2E_ROOT/../../crates/fgit-node/tests/staging_only_receive.rs"
STAGING_CASE_NAMES=(
  a_staging_only_cell_refuses_publication_and_a_serving_cell_does_not
  healing_a_staging_only_cell_does_not_silently_publish_what_it_held
  a_cell_nobody_brought_into_service_refuses_receive_intake
  a_verified_read_only_cell_refuses_receive_intake
  the_cell_state_gate_runs_before_a_single_byte_is_parsed
  authentication_is_answered_ahead_of_the_cell_state_gate
  bringing_a_cell_into_service_audits_two_hops_under_an_honest_cause
)

TRANSPORT_TARGET=authenticated_receive_transport
TRANSPORT_SOURCE="$E2E_ROOT/../../crates/fgit-node/tests/authenticated_receive_transport.rs"
TRANSPORT_CASE_NAMES=(
  authenticated_loopback_session_admits_a_validated_push
  anonymous_loopback_session_is_refused_before_admission
  a_cell_nobody_brought_into_service_refuses_a_source_import
)

declared_cases() {
  local count
  count=$(grep -c '^#\[test\]' "$1")
  printf '%s' "${count// /}"
}

passed_cases() {
  # The harness's own summary line, not a per-case count: under --nocapture cargo
  # writes "test <name> ... " with NO newline, so a case that prints anything
  # lands on the same line and a `... ok$` anchor stops matching. A FAILED run
  # emits "test result: FAILED." and this yields nothing, which is why callers
  # substitute a non-numeric sentinel rather than an empty string.
  grep -oE '^test result: ok\. [0-9]+ passed' "$1" | grep -oE '[0-9]+' | head -1
}

missing_case_names() {
  local capture=$1 missing='' name
  shift
  for name in "$@"; do
    grep -qF "$name" "$capture" || missing="$missing $name"
  done
  printf '%s' "$missing"
}

fge_capture "run-$STAGING_TARGET" env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test -p fgit-node --test "$STAGING_TARGET" -- --nocapture --test-threads=1 || true
RC_STAGING=$FGE_LAST_EXIT
OUT_STAGING=$FGE_LAST_STDOUT_FILE
fge_artifact "$OUT_STAGING"

fge_capture "run-$TRANSPORT_TARGET" env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test -p fgit-node --test "$TRANSPORT_TARGET" -- --nocapture --test-threads=1 || true
RC_TRANSPORT=$FGE_LAST_EXIT
OUT_TRANSPORT=$FGE_LAST_STDOUT_FILE
fge_artifact "$OUT_TRANSPORT"

fge_assert_exit FG-036B-E2E-012 0 "$RC_STAGING" \
  'the write-side cell-gate slice passes'

# FIRES BY CONSTRUCTION ON A DELETED CASE: the expected value is the length of
# the literal list above and cannot move when the source file does.
staging_passed=$(passed_cases "$OUT_STAGING")
fge_assert_eq FG-036B-E2E-013 "${#STAGING_CASE_NAMES[@]}" "${staging_passed:-none-reported}" \
  'the write-side gate target reports exactly the cases named here, so a deleted or skipped case fails'

# Every case by NAME. A green total cannot tell "ran and passed" from "was
# renamed and silently stopped running", and §16.3 requires the permitted twin
# to be visible: asserting only the refusals would stay green if every twin were
# deleted, leaving a suite that proves cells refuse without proving any serves.
fge_assert_eq FG-036B-E2E-014 '' \
  "$(missing_case_names "$OUT_STAGING" "${STAGING_CASE_NAMES[@]}")" \
  'every write-side cell-gate case ran, named individually rather than inferred from a total'

# The other direction, and the reason this is not circular: a case ADDED to the
# source and never named above would be caught by nothing else here.
fge_assert_eq FG-036B-E2E-015 "$(declared_cases "$STAGING_SOURCE")" \
  "${#STAGING_CASE_NAMES[@]}" \
  'the named list covers every case the target declares, so 013 and 014 cannot go stale'

fge_assert_exit FG-036B-E2E-016 0 "$RC_TRANSPORT" \
  'the authenticated receive-transport slice passes'

transport_passed=$(passed_cases "$OUT_TRANSPORT")
fge_assert_eq FG-036B-E2E-017 "${#TRANSPORT_CASE_NAMES[@]}" "${transport_passed:-none-reported}" \
  'the receive-transport target reports exactly the cases named here'

# The source-import half of the gate is named individually because it is the ONE
# production construction site the workspace measurement for this ruling found:
# `fg import`, at fgit-cli/src/lib.rs. If it disappears, the gate still holds on
# paths nothing in production reaches, and nothing else here would say so.
fge_assert_eq FG-036B-E2E-018 '' \
  "$(missing_case_names "$OUT_TRANSPORT" "${TRANSPORT_CASE_NAMES[@]}")" \
  'the receive-transport cases ran, including the source-import gate at the one production site'

fge_assert_eq FG-036B-E2E-019 "$(declared_cases "$TRANSPORT_SOURCE")" \
  "${#TRANSPORT_CASE_NAMES[@]}" \
  'the receive-transport named list is complete against its source'
