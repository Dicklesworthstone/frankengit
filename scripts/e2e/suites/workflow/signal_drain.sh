#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'workflow signal drain requires a prebuilt native FG_BIN' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-signal-drain
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.38
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted foreground cancellation; retained workspaces remain explicit containment failures, not hostile isolation or universal process-tree reaping.'
WORK="$(fge_tempdir workflow-signal-drain)"
fge_phase action
fge_run_timeout 300 SIGNAL-DRAIN-001 python3 "$E2E_ROOT/helpers/workflow_signal_drain.py" "$FG_BIN" "$WORK"
fge_assert_exit SIGNAL-DRAIN-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" signal_drain
fge_note SIGNAL-DRAIN-003 'SHA-1/SHA-256 run and dispatch: SIGTERM/SIGINT and repeated signals, live descendants, no-signal twins, no later jobs, exact journal recovery, no replay and unchanged repository authority.'
