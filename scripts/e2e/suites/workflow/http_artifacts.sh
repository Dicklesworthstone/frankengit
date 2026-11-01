#!/usr/bin/env bash
# e2e: Native HTTP CI producer/consumer artifacts, original checks and restart reads.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-http-workflow-artifacts
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name the prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Actual trusted-host jobs and verified artifact custody; no hostile isolation, deterministic cache reuse or new authority.'
WORK="$(fge_tempdir native-http-workflow-artifacts)"
fge_phase action
fge_run_timeout 600 HTTP-ARTIFACT-RUN python3 "$E2E_ROOT/helpers/workflow_http_artifacts.py" "$FG_BIN" "$WORK" || true
fge_assert_exit HTTP-ARTIFACT-EXIT 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_assert_file HTTP-ARTIFACT-RESULTS "$WORK/results.json"
if [[ -f "$WORK/results.json" ]]; then
    fge_artifact "$WORK/results.json" native_http_workflow_artifact_results
fi
