#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'continue-on-error requires FG_BIN naming the prebuilt native fg' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-continue-on-error
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted-local step policy and exact saved evidence; not hostile isolation, job-level failure tolerance or a release-readiness claim.'
WORK="$(fge_tempdir workflow-continue-on-error)"
fge_phase action
fge_run_timeout 600 WORKFLOW-OPTIONAL-001 python3 "$E2E_ROOT/helpers/workflow_continue_on_error.py" "$FG_BIN" "$WORK" || true
fge_assert_exit WORKFLOW-OPTIONAL-002 0 "$FGE_LAST_EXIT"
if [[ -f "$WORK/results.json" ]]; then
    fge_phase assert
    fge_artifact "$WORK/results.json" native_step_continue_on_error
    fge_note WORKFLOW-OPTIONAL-003 'Both native hash formats exercise tolerated exit 7 and its required-failure twin, non-tolerated deadline/output/containment stops, exact saved raw outcomes, canonical check publication, and offline recovery without reexecution.'
fi
