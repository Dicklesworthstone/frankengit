#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-http-workflow-service
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name the prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Actual HTTP listener and trusted-host workflow sibling with canonical checks and owned drain; not hostile-runner isolation or an all-events queue.'
WORK="$(fge_tempdir native-http-workflow-service)"
fge_phase action
fge_run_timeout 360 HTTP-WORKFLOW-001 python3 "$E2E_ROOT/helpers/workflow_http_service.py" "$FG_BIN" "$WORK"
fge_assert_exit HTTP-WORKFLOW-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" native_http_workflow_results
