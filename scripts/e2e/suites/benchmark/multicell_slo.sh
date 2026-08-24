#!/usr/bin/env bash
# e2e: FG-036c distributed SLO, capacity and economics evidence.
#
# Reproduces the multi-cell measurement and asserts the properties that are
# EXACT. The distinction is the whole point of this suite:
#
#   * storage amplification and the cross-layer admission differential are
#     counts, so they are asserted here with equality;
#   * per-read-mode latency is NOT asserted, because the measured A/A floor on
#     this substrate (3-34 ms) is the same size as the mode-to-mode spread
#     (6-13 ms). Asserting a latency ordering would encode noise as a
#     regression gate and fail randomly for whoever ran it next.
#
# `run_all.sh` discovers executable `.sh` under `suites/`, so this registers as
# `suites-benchmark-multicell_slo` with no hand-maintained list. Verified by
# reading run_all.sh, not by trusting a comment.
#
# GRANT: GoldLotus 2026-08-24 permits, for fg036c, release builds of the node
# path and repeated measurement runs bounded to 20 minutes.
set -euo pipefail

MS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MS_REPO=$(cd "$MS_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$MS_REPO/scripts/e2e/lib.sh"

fge_init fg036c-multicell-slo
fge_context bead frankengit-fg036c-slo-economics-v6n
fge_context crate fgit-slo
fge_context claim_class benchmark

# Deliberately small by default so the suite stays inside the grant's bound.
# A nearest-rank p99 over N samples is just the observed maximum when N < 100,
# so this suite reports medians and an A/A floor rather than implying a tail
# estimate it did not measure.
SAMPLES=${FG_SLO_SAMPLES:-5}
export FG_SLO_SAMPLES="$SAMPLES"

fge_phase setup
artifact_dir=$(fge_tempdir multicell-slo-artifact)
ARTIFACT="$artifact_dir/multicell-slo.ndjson"
fge_context artifact_directory "$artifact_dir"
fge_context samples_per_block "$SAMPLES"

fge_assert_file FG-036C-E2E-001 "$MS_REPO/crates/fgit-slo/src/lib.rs" \
  'the measurement crate is present in the tree'

# The measured binary's provenance. An evidence artifact that cannot name the
# revision it measured is not evidence.
SOURCE_REVISION=$(cd "$MS_REPO" && git rev-parse HEAD)
fge_context source_revision "$SOURCE_REVISION"
fge_context host_cores "$(nproc 2>/dev/null || echo unknown)"

fge_phase action
# Guarded: fge_run returns the command's status and the suite trap would die
# here on a nonzero exit before the assertions below could classify it.
fge_run slo-measure env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo run -q --release -p fgit-slo -- multicell >"$ARTIFACT" || true
MEASURE_EXIT=$FGE_LAST_EXIT

fge_phase assert
fge_assert_exit FG-036C-E2E-002 0 "$MEASURE_EXIT" \
  'the measurement command completes'
fge_assert_file FG-036C-E2E-003 "$ARTIFACT" \
  'the evidence artifact is written'

# PRESENCE FIRST. Every assertion below is of the form "all records satisfy X",
# which is vacuously true of an empty file. Pin a floor on the record count so
# the suite cannot pass by measuring nothing.
SAMPLE_ROWS=$(grep -c '"record":"read_mode_sample"' "$ARTIFACT" || true)
fge_context read_mode_sample_rows "$SAMPLE_ROWS"
fge_assert_cmd FG-036C-E2E-004 \
  'the artifact carries read-mode samples, so the checks below are not vacuous' \
  test "$SAMPLE_ROWS" -ge 40

STORAGE_ROWS=$(grep -c '"record":"storage_footprint"' "$ARTIFACT" || true)
fge_assert_eq FG-036C-E2E-005 3 "$STORAGE_ROWS" \
  'one storage record per cell count measured'

# EXACT PROPERTY 1: attaching cells to a shared backend adds no storage.
# Asserted with equality because it is a byte count, not a timing.
NONZERO_GROWTH=$(grep -c '"bytes_added_by_companions":[1-9]' "$ARTIFACT" || true)
fge_assert_eq FG-036C-E2E-006 0 "$NONZERO_GROWTH" \
  'cells sharing one authority backend add zero storage per cell'

# EXACT PROPERTY 2: the L0 vocabulary and the L4 node agree on which reads a
# cell state admits. A disagreement is a real defect, not a slow read.
DISAGREEMENTS=$(grep -c '"layers_agree":false' "$ARTIFACT" || true)
fge_assert_eq FG-036C-E2E-007 0 "$DISAGREEMENTS" \
  'fgit-types admission prediction matches fgit-node enforcement on every row'

# EXACT PROPERTY 3: every cell state is reachable by a legal path, so the
# sweep above covered the state space rather than an accident of loop order.
UNREACHABLE=$(grep -c '"record":"reachability_from_bootstrapping".*"reachable":false' "$ARTIFACT" || true)
fge_assert_eq FG-036C-E2E-008 0 "$UNREACHABLE" \
  'every cell state is reachable from Bootstrapping by a legal path'

# The A/A floor must be PRESENT on every latency row. It is what makes those
# numbers interpretable, and a row without it invites the reader to compare
# medians directly, which is exactly the error this suite exists to prevent.
MISSING_FLOOR=$(grep '"record":"read_mode_sample"' "$ARTIFACT" | grep -cv '"aa_floor_ns"' || true)
fge_assert_eq FG-036C-E2E-009 0 "$MISSING_FLOOR" \
  'every latency row carries the A/A noise floor measured on its own configuration'

# NOT ASSERTED, and deliberately so: no per-read-mode latency ordering. The
# measured spread between modes sits inside the measured A/A floor, so any
# ordering asserted here would be a noise gate. Recorded as negative evidence
# rather than encoded as a threshold.
fge_pass FG-036C-E2E-010 \
  'no per-read-mode latency ordering is asserted: the mode spread is inside the A/A floor'

fge_phase teardown
# Register the evidence for the harness to collect. There is no explicit
# finaliser to call: lib.sh installs an EXIT trap that emits the summary line
# and the exit status. I had invented `fge_finish` here; it does not exist, and
# the suite would have died on the last line with every assertion already
# passed -- a failure that looks like a harness bug rather than my error.
fge_artifact "$ARTIFACT" fg036c-multicell-slo-evidence
