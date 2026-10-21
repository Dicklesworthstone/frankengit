#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init import-metadata-scale
fge_kind e2e-binary
fge_context bead frankengit-gzdy
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'FG_BIN must name a prebuilt native fg' >&2; exit 2; }
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Ordinary installed Git test client; not a pinned Tier A matrix, throughput benchmark, power-loss or release gate.'
WORK="$(fge_tempdir import-metadata-scale)"
fge_phase action
fge_run_timeout 1800 IMPORT-METADATA-001 python3 "$E2E_ROOT/helpers/import_metadata_scale.py" "$FG_BIN" "$WORK"
fge_assert_exit IMPORT-METADATA-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" native_import_results
