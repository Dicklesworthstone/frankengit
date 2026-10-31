#!/usr/bin/env bash
# e2e: Canonical queue-head CI and exact retained-bundle guarded landing.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-queue-merge-watch
fge_kind e2e-binary
fge_context bead frankengit-fg083-merge-queue-3hz1
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name a prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted local canonical queue-head candidate CI and guarded landing; not autonomous landing, speculative multi-PR trains, hostile isolation, upstream-Git differential parity, or a workspace gate.'
WORK="$(fge_tempdir queue-merge-watch)"
fge_phase action
fge_run_timeout 900 QUEUE-MERGE-WATCH-001 python3 "$E2E_ROOT/helpers/workflow_queue_merge_watch.py" "$FG_BIN" "$WORK" || true
fge_assert_exit QUEUE-MERGE-WATCH-002 0 "$FGE_LAST_EXIT"
fge_phase assert
if [[ -f "$WORK/results.json" ]]; then
    fge_artifact "$WORK/results.json" native_queue_merge_watch_results
else
    fge_fail QUEUE-MERGE-WATCH-003 'native campaign did not complete; command transcripts and fixture state retained'
fi
