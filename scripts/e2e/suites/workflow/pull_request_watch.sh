#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-pull-request-watch
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name a prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted native same-repository PR source-head execution; not synthetic merge testing, hostile isolation, physical power-loss or a GitHub PR.'
WORK="$(fge_tempdir pull-request-watch)"
fge_phase action
fge_run_timeout 420 PR-WATCH-001 python3 "$E2E_ROOT/helpers/workflow_pull_request_watch.py" "$FG_BIN" "$WORK"
fge_assert_exit PR-WATCH-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" native_pr_results
