#!/usr/bin/env bash
# e2e: Native PR reopen across CLI, HTTP, review protection, races and restart.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "$E2E_ROOT/lib.sh"
fge_init pull-request-reopen
fge_phase setup
[ -n "${FG_BIN:-}" ] || fge_die 'FG_BIN must select an already-built fg'
[ -x "$FG_BIN" ] || fge_die 'FG_BIN is not executable'
fge_phase action
fge_run_timeout 900 reopen-native python3 "$E2E_ROOT/pull_request_reopen_smoke.py" --fg "$FG_BIN" || true
fge_assert_exit FG-PR-REOPEN-001 0 "$FGE_LAST_EXIT" 'both native hash formats preserve reopen/review/retry semantics'
