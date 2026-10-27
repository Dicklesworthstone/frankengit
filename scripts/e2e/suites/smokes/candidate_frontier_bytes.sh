#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init candidate-frontier-bytes
fge_kind e2e-binary
fge_context bead frankengit-t0iw
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Actual native loopback HTTP and admission; not a full object scrub, hostile isolation, whole-workspace or release qualification.'
WORK="$(fge_tempdir candidate-frontier-bytes)"
fge_phase action
fge_run_timeout 900 CANDIDATE-FRONTIER-001 python3 "$E2E_ROOT/helpers/candidate_frontier_bytes.py" "$FG_BIN" "$WORK"
fge_assert_exit CANDIDATE-FRONTIER-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" candidate_frontier_results
