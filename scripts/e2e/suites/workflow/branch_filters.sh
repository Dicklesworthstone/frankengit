#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init workflow-branch-filters
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.12
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Trusted-local branch-filter selection and canonical publication, not hostile isolation, all-events delivery, or full Actions compatibility.'
WORK="$(fge_tempdir workflow-branch-filters)"
fge_phase action
fge_run_timeout 360 BRANCH-FILTER-001 python3 "$E2E_ROOT/helpers/workflow_branch_filters.py" "$FG_BIN" "$WORK"
fge_assert_exit BRANCH-FILTER-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" native_branch_filters
