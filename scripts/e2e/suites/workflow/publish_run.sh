#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-publish-run
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name the prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted saved checks and canonical admission; not whole-run atomicity, hostile isolation, exactly-once external execution or physical power-loss simulation.'
WORK="$(fge_tempdir workflow-publish-run)"
fge_phase action
fge_run_timeout 900 WORKFLOW-PUBLISH-RUN-001 python3 "$E2E_ROOT/helpers/workflow_publish_run.py" "$FG_BIN" "$WORK"
fge_assert_exit WORKFLOW-PUBLISH-RUN-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" check_publication_results
