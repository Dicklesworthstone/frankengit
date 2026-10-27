#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-workflow-watch-continuous
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name the prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Real trusted-host foreground service, canonical check publication and process drain; not hostile-code isolation, an all-events queue or a full release gate.'
WORK="$(fge_tempdir native-workflow-watch-continuous)"
fge_phase action
fge_run_timeout 300 WATCH-CONTINUOUS-001 python3 "$E2E_ROOT/helpers/workflow_watch_continuous.py" "$FG_BIN" "$WORK"
fge_assert_exit WATCH-CONTINUOUS-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" native_continuous_workflow_results
