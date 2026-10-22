#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'workspace lifecycle requires a prebuilt native FG_BIN' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workspace-lifecycle
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.38
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted Linux process-group cleanup, not hostile isolation, universal descendant reaping or exactly-once effects.'
WORK="$(fge_tempdir workspace-lifecycle)"
fge_phase action
fge_run_timeout 180 WORKSPACE-LIFECYCLE-001 python3 "$E2E_ROOT/helpers/workspace_lifecycle.py" "$FG_BIN" "$WORK"
fge_assert_exit WORKSPACE-LIFECYCLE-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" workspace_lifecycle
fge_note WORKSPACE-LIFECYCLE-003 'Both native hash formats: stale pins refuse before host effects; joined children produce exact bundles; orphans, SIGTERM, SIGINT and deadlines retain workspace and refuse export/replay; refs stay unchanged.'
