#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-merge-dispatch
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Exact candidate batch execution and custody, not automatic merge watching, canonical check admission or hostile isolation.'
WORK="$(fge_tempdir workflow-merge-dispatch)"
fge_phase action
fge_run_timeout 600 MERGE-DISPATCH-001 python3 "$E2E_ROOT/helpers/workflow_merge_dispatch.py" "$FG_BIN" "$WORK"
fge_assert_exit MERGE-DISPATCH-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" merge_dispatch_results
