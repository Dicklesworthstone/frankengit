#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init stock-push-workflow-landing
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
fge_assert_cmd WORKFLOW-PUSH-BIN 'a prebuilt native fg is supplied' test -x "${FG_BIN:-}"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_phase setup
fge_run verify-stock-client "$E2E_ROOT/oracle/oracle.sh" verify git-2.54.0 || true
if [[ "$FGE_LAST_EXIT" == 69 ]]; then
    fge_unsupported WORKFLOW-PUSH-LANDING 'the pinned Git 2.54.0 oracle is unavailable'
    exit 0
fi
fge_assert_exit WORKFLOW-PUSH-ORACLE 0 "$FGE_LAST_EXIT"
WORK="$(fge_tempdir stock-push-workflow-landing)"
fge_phase action
fge_run_timeout 360 push-workflow-landing python3 "$E2E_ROOT/helpers/stock_push_workflow_landing.py" "$FG_BIN" "$WORK"
fge_assert_exit WORKFLOW-PUSH-LANDING 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" stock_push_workflow_landing
