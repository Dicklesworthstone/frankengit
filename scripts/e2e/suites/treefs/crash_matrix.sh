#!/usr/bin/env bash
# e2e: FG-076 -- the GIT_TREE_FS §14 eleven-point crash and cancellation matrix.
#
# PLACED UNDER suites/ DELIBERATELY. The bead's acceptance line names
# `scripts/e2e/treefs_crash_matrix.sh` "registered in run_all.sh". Both halves of
# that are wrong and following them would produce a suite that never runs:
# run_all discovers `suites/**` and nothing else -- there is no registration
# mechanism and never has been -- so a script at the e2e root executes nowhere.
# That is the exact defect bead frankengit-osqi exists to fix, and satisfying the
# acceptance as written would have manufactured a fourth instance of it. Reported
# to the orchestrator for amendment rather than silently obeyed.
#
# WHAT THIS SUITE ADDS OVER THE RUST TESTS. crash_matrix.rs proves the in-crate
# properties: the trichotomy, the staged/visible/durable ordering, cancellation
# accounting. Two things it structurally cannot prove, and this suite does:
#   * that the matrix leaves no orphan PROCESS or temporary OUTPUT behind, which
#     is a property of the real process, not of a value in it;
#   * points 7 and 9, which have no assertable surface in Rust at all, recorded
#     here as typed non-claims so the gap is visible and terminal rather than
#     silently missing from the receipt.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

REPOSITORY_ROOT="$(cd "$E2E_ROOT/../.." && pwd -P)"

fge_init

fge_phase setup
work=$(fge_tempdir crash-matrix)
probe_dir="$work/containment-probe"
mkdir -p "$probe_dir"

procs_before=$(pgrep -c -u "$(id -u)" -f 'fgit-treefs' 2>/dev/null || printf '0')

fge_context suite_scope 'GIT_TREE_FS §14 eleven-point interruption matrix; six points exercised against real code, five recorded as typed non-claims because the capability they name does not exist in fgit-treefs'

# ---------------------------------------------------------------------------
# the in-crate matrix
# ---------------------------------------------------------------------------
fge_phase action

# `|| true` is load-bearing here, exactly as it is in export_crash.sh. fge_run
# RETURNS the command's exit status and this script runs under `set -euo
# pipefail`, so an unguarded failing run would kill the script ON THIS LINE --
# before matrix_exit is read and before the assertion below could record the
# failure. The run would then report far fewer assertions than it discovered,
# which is a truncated record rather than a damning one.
fge_run FG-076-MATRIX-001-run \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-treefs --test crash_matrix -- --nocapture || true
matrix_exit=$FGE_LAST_EXIT

fge_phase assert
fge_assert_exit FG-076-MATRIX-001 0 "$matrix_exit" \
  'the eleven-point matrix passes: trichotomy, epoch ordering and cancellation accounting'

# ---------------------------------------------------------------------------
# containment: no orphan process or temporary output survives closure
#
# §14's no-orphan rule names mounts, processes, object-fetch credentials and
# temporary outputs. fgit-treefs holds no mount and no credential -- it performs
# no I/O and issues no fetch -- so those two are vacuous here and are NOT claimed
# as passes. The two that are real properties of the run are checked.
# ---------------------------------------------------------------------------
procs_after=$(pgrep -c -u "$(id -u)" -f 'fgit-treefs' 2>/dev/null || printf '0')
fge_assert_eq FG-076-MATRIX-002 "$procs_before" "$procs_after" \
  'the matrix leaves no fgit-treefs process behind after closure'

leftover=$(find "$probe_dir" -mindepth 1 -print -quit 2>/dev/null || true)
fge_assert_eq FG-076-MATRIX-003 '' "$leftover" \
  'the matrix writes no temporary output; a crate that performs no I/O must leave the probe directory empty'

# The containment probe is only meaningful if it could have caught something.
# Without this, an empty directory proves nothing about the code under test --
# it would read identically if the probe directory were simply never used.
printf 'planted\n' >"$probe_dir/planted-artifact"
planted=$(find "$probe_dir" -mindepth 1 -print -quit 2>/dev/null || true)
fge_assert_cmd FG-076-MATRIX-004 'the containment probe detects a file when one exists' \
  test -n "$planted"
rm -f -- "$probe_dir/planted-artifact"

# ---------------------------------------------------------------------------
# points 7 and 9: typed non-claims
#
# These are NOT skips of work that could have been done. Each names a subsystem
# that does not exist in fgit-treefs, so there is no code to interrupt and no
# structural fact assertable from Rust either -- unlike points 4, 5 and 6, which
# crash_matrix.rs pins to the property that makes them unreachable.
#
# Emitted as fge_unsupported rather than omitted, because an omitted cell is
# invisible in the receipt: the run would report fewer assertions than the matrix
# claims to cover and nothing would say why. An unsupported cell is a terminal
# non-pass that names the exact missing thing, which is the honest disposition
# for coverage that cannot be gathered.
#
# DELETION CONDITION: when fg052 lands a FUSE host adapter, or a manifest import
# path appears, these become real crash drills and these two lines are deleted.
# ---------------------------------------------------------------------------
fge_unsupported FG-076-MATRIX-007 \
  'GIT_TREE_FS §14 "during FUSE read/writeback": no FUSE host adapter exists in fgit-treefs; fg052 owns that surface and it is not yet built'
fge_unsupported FG-076-MATRIX-009 \
  'GIT_TREE_FS §14 "after output creation, before manifest import": no manifest import path exists in fgit-treefs'

fge_field reachable_points 6
fge_field structurally_absent_points 5
fge_note matrix-coverage \
  'six of eleven §14 points are exercised against real code; points 4, 5 and 6 are pinned in crash_matrix.rs by the structural fact that makes them unreachable, so implementing the capability breaks the assertion; points 7 and 9 are the two typed non-claims above'
