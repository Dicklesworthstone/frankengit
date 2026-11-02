#!/usr/bin/env bash
# e2e: Automatic native PR discovery, original check recovery and retained capacity.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-pull-request-collection
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name the prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Actual trusted-host source-head CI for bounded same-repository PR collections; no hostile isolation, synthetic merge evidence, all-events queue or unbounded membership.'
WORK="$(fge_tempdir native-pull-request-collection)"
fge_phase action
fge_run_timeout 900 PR-COLLECTION-RUN python3 "$E2E_ROOT/helpers/workflow_pull_request_collection.py" "$FG_BIN" "$WORK" || true
fge_assert_exit PR-COLLECTION-EXIT 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_assert_file PR-COLLECTION-RESULTS "$WORK/results.json"
if [[ -f "$WORK/results.json" ]]; then
    fge_artifact "$WORK/results.json" native_pull_request_collection_results
fi
