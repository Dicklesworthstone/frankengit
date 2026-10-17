#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'step context requires FG_BIN naming the prebuilt native fg' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-step-context
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted local process inputs, not a hostile-host filesystem or namespace isolation claim.'
WORK="$(fge_tempdir workflow-step-context)"
fge_phase action
fge_run_timeout 600 WORKFLOW-CONTEXT-001 python3 "$E2E_ROOT/helpers/workflow_step_context.py" "$FG_BIN" "$WORK"
fge_assert_exit WORKFLOW-CONTEXT-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" native_step_context
fge_note WORKFLOW-CONTEXT-003 'Both native hash domains exercised explicit literal inputs, directory selection, restored defaults, unsupported-input preflight and failed directory selection.'
