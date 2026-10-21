#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-index-deadlines
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.54
fge_assert_cmd INDEX-DEADLINE-001 'prebuilt native fg supplied' test -x "${FG_BIN:-}"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Native foreground operator deadlines, not hard preemption of OS calls or physical power-loss verification.'
WORK="$(fge_tempdir index-deadlines)"
fge_phase action
fge_run_timeout 180 INDEX-DEADLINE-002 python3 "$E2E_ROOT/helpers/operator_index_deadlines.py" "$FG_BIN" "$WORK"
fge_assert_exit INDEX-DEADLINE-003 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" native_deadline_results
