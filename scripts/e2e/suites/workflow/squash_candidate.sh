#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-squash-candidate
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name a prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted native squash-candidate CI; not hostile-code isolation, merge authorization or physical power-loss evidence.'
WORK="$(fge_tempdir squash-candidate)"
fge_phase action
fge_run_timeout 240 SQUASH-CI-001 python3 "$E2E_ROOT/helpers/workflow_squash.py" "$FG_BIN" "$WORK"
fge_assert_exit SQUASH-CI-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" native_squash_results
