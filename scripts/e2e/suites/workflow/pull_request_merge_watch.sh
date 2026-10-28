#!/usr/bin/env bash
# e2e: Native PR merged-tree CI, retained canonical checks, and exact protected merge.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-pull-request-merge-watch
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name a prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted local native PR merge/squash execution and ordinary protected admission; not hostile isolation, upstream-Git differential parity, or a whole-workspace gate.'
WORK="$(fge_tempdir pull-request-merge-watch)"
fge_phase action
fge_run_timeout 900 PR-MERGE-WATCH-001 python3 "$E2E_ROOT/helpers/workflow_pull_request_merge_watch.py" "$FG_BIN" "$WORK" || true
fge_assert_exit PR-MERGE-WATCH-002 0 "$FGE_LAST_EXIT"
fge_phase assert
if [[ -f "$WORK/results.json" ]]; then
    fge_artifact "$WORK/results.json" native_pr_merge_watch_results
else
    fge_fail PR-MERGE-WATCH-003 'native campaign did not complete; command transcripts and fixture state retained'
fi
