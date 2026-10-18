#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'supervisor loop requires a prebuilt native FG_BIN' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-supervisor-loop
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Real native trusted-local execution/publication and local custody recovery; not hostile isolation, power loss or merge authorization.'
WORK="$(fge_tempdir workflow-supervisor-loop)"
fge_phase action
fge_run_timeout 600 SUPERVISOR-LOOP-001 python3 "$E2E_ROOT/helpers/workflow_supervisor_loop.py" "$FG_BIN" "$WORK"
fge_assert_exit SUPERVISOR-LOOP-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" supervisor_loop
fge_note SUPERVISOR-LOOP-003 'Both hash domains execute matrices, automatically publish, enforce backpressure and reconcile SIGKILL-retained native reports without source/binary access or execution replay.'
