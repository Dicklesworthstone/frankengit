#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init source-splice-native
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Actual Node CLI and native Rust preparation/admission, not complete operator qualification or hostile isolation.'
WORK="$(fge_tempdir source-splice-native)"
fge_phase action
fge_run_timeout 360 SPLICE-NATIVE-001 python3 "$E2E_ROOT/helpers/source_splice_native.py" "$FG_BIN" "$WORK"
fge_assert_exit SPLICE-NATIVE-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" native_splice_results
