#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-path-filters
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native FG_BIN required' >&2; exit 2; }
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted native changed-path selection; not hostile isolation, synthetic merge testing or blanket Actions compatibility.'
WORK="$(fge_tempdir workflow-path-filters)"
fge_phase action
fge_run_timeout 600 PATH-FILTER-001 python3 "$E2E_ROOT/helpers/workflow_path_filters.py" "$FG_BIN" "$WORK"
fge_assert_exit PATH-FILTER-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" native_path_filter_results
