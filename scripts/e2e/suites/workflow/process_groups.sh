#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'process group execution requires a prebuilt native FG_BIN' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-process-groups
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted host process-group cleanup. No hostile isolation or descendant-reaping claim.'
WORK="$(fge_tempdir workflow-process-groups)"
fge_phase action
fge_run_timeout 300 PROCESS-GROUP-001 python3 "$E2E_ROOT/helpers/workflow_process_groups.py" "$FG_BIN" "$WORK"
fge_assert_exit PROCESS-GROUP-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" process_groups
fge_note PROCESS-GROUP-003 'Both native hash formats exercise joined children, orphaned shell success, termination, deadline cancellation, retained evidence, distinct canonical non-pass checks, exact publication retries and source-free recovery.'
