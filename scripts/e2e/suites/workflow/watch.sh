#!/usr/bin/env bash
set -euo pipefail
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-workflow-watch
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Native latest-state trusted-host polling, not an all-push queue, hostile isolation or automatic check publisher.'
WORK="$(fge_tempdir native-workflow-watch)"
fge_phase action
fge_run_timeout 240 WATCH-001 python3 "$E2E_ROOT/helpers/workflow_watch.py" "$FG_BIN" "$WORK"
fge_assert_exit WATCH-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" native_watch
