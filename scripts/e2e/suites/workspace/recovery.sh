#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workspace-recovery
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.38
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name the prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted local exact-byte recovery, not exactly-once effects, hostile isolation or physical power-loss simulation. SIGKILL fixture children are cleaned by the test.'
WORK="$(fge_tempdir workspace-recovery)"
fge_phase action
fge_run_timeout 240 WORKSPACE-RECOVERY-001 python3 "$E2E_ROOT/helpers/workspace_recovery.py" "$FG_BIN" "$WORK"
fge_assert_exit WORKSPACE-RECOVERY-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" recovery_results
