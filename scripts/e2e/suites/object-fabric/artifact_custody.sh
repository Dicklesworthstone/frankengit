#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'artifact custody requires a prebuilt native FG_BIN' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-artifact-custody
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Verified local payload custody, real workflow output/log/manifest HTTP retrieval and evidence archival; no canonical publication, authenticated provenance or retention enforcement.'
WORK="$(fge_tempdir native-artifact-custody)"
fge_phase action
fge_run_timeout 600 ARTIFACT-CUSTODY-001 python3 "$E2E_ROOT/helpers/artifact_custody.py" "$FG_BIN" "$WORK"
fge_assert_exit ARTIFACT-CUSTODY-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" artifact_custody
fge_note ARTIFACT-CUSTODY-003 'Real fg covers immutable custody and workflow-produced output, binary stdout/stderr and manifest IDs through HTTP metadata/download; failed jobs retain diagnostics without a successful check proposal. Independent grants, live revocation, corruption refusal/restoration and restart run in both object formats; refs remain unchanged.'
