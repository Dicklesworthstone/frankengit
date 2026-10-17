#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'matrix execution requires a prebuilt native FG_BIN' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-matrix-execution
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted local matrix execution and persisted observations, not hostile isolation or a required-check grant.'
WORK="$(fge_tempdir workflow-matrix-execution)"
fge_phase action
fge_run_timeout 600 MATRIX-EXECUTION-001 python3 "$E2E_ROOT/helpers/workflow_matrix.py" "$FG_BIN" "$WORK"
fge_assert_exit MATRIX-EXECUTION-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" matrix_execution
fge_note MATRIX-EXECUTION-003 'Both native hash formats exercise matrix dependency joins, legitimate skips, persisted distinct job results, exact publication retry and source-free recovery.'
