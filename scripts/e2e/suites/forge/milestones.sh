#!/usr/bin/env bash
# e2e: Canonical milestone lifecycle, issue membership, pinned progress and retry recovery.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-milestones
fge_kind e2e-binary
fge_context bead frankengit-fg045-issues-notifications-n70
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name the prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir native-milestones)"
fge_phase action
fge_run_timeout 600 MILESTONE-LIFECYCLE python3 "$E2E_ROOT/helpers/milestones.py" --fg "$FG_BIN" --work "$WORK" || true
fge_assert_exit MILESTONE-EXIT 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_assert_file MILESTONE-RESULTS "$WORK/results.json"
if [[ -f "$WORK/results.json" ]]; then
    fge_artifact "$WORK/results.json" native_milestone_results
fi
