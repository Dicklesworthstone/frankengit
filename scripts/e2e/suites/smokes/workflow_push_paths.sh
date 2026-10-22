#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-push-paths
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Native canonical ref-change selection, not wire-client conformance, hostile isolation or blanket Actions compatibility.'
WORK="$(fge_tempdir workflow-push-paths)"
fge_phase action
fge_run_timeout 900 PUSH-PATHS-001 python3 "$E2E_ROOT/helpers/workflow_push_paths.py" "$FG_BIN" "$WORK"
fge_assert_exit PUSH-PATHS-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" native_push_paths_results
