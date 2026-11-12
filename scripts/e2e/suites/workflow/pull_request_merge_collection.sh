#!/usr/bin/env bash
# e2e: Automatically discovered PRs execute distinct exact merged candidates.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-pull-request-merge-collection
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name the prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted-host bounded PR collection with exact merge/squash candidate CI; no hostile isolation, member retirement, or automatic target-branch merge.'
WORK="$(fge_tempdir native-pull-request-merge-collection)"
fge_phase action
fge_run_timeout 900 PR-MERGE-COLLECTION-RUN python3 "$E2E_ROOT/helpers/workflow_pull_request_merge_collection.py" "$FG_BIN" "$WORK" || true
fge_assert_exit PR-MERGE-COLLECTION-EXIT 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_assert_file PR-MERGE-COLLECTION-RESULTS "$WORK/results.json"
if [[ -f "$WORK/results.json" ]]; then
    fge_artifact "$WORK/results.json" native_pull_request_merge_collection_results
fi
