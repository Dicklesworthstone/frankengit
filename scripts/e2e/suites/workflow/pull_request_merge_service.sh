#!/usr/bin/env bash
# e2e: HTTP-owned exact PR candidate CI, canonical checks, restart and drain.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-pull-request-merge-service
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name a prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Actual HTTP service and trusted-host exact PR candidate execution with canonical checks; not hostile-runner isolation, an upstream-Git differential lane, or a release gate.'
WORK="$(fge_tempdir pull-request-merge-service)"
fge_phase action
fge_run_timeout 900 PR-MERGE-SERVICE-001 python3 "$E2E_ROOT/helpers/workflow_pull_request_merge_service.py" "$FG_BIN" "$WORK" || true
fge_assert_exit PR-MERGE-SERVICE-002 0 "$FGE_LAST_EXIT"
fge_phase assert
if [[ -f "$WORK/results.json" ]]; then
    fge_artifact "$WORK/results.json" native_pr_merge_service_results
else
    fge_fail PR-MERGE-SERVICE-003 'native service campaign did not complete; command transcripts and fixture state retained'
fi
