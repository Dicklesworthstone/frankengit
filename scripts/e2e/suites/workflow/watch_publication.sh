#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-watch-publication
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'FG_BIN must name the prebuilt native fg' >&2
    exit 2
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted native reporting, not hostile-code isolation, whole-event atomicity or a passing-check claim from local settlement.'
WORK="$(fge_tempdir workflow-watch-publication)"
fge_phase action
fge_run_timeout 300 WATCH-PUBLICATION-001 python3 "$E2E_ROOT/helpers/workflow_watch_publication.py" "$FG_BIN" "$WORK"
fge_assert_exit WATCH-PUBLICATION-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" native_watch_publication_results
