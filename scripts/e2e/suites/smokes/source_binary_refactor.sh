#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init source-binary-refactor
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
[[ -n "${FG_BIN:-}" && -x "$FG_BIN" ]] || { echo 'native prebuilt FG_BIN required' >&2; exit 2; }
NODE_BIN="$(command -v node)"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context node_version "$("$NODE_BIN" --version)"
fge_context node_digest "$(fge_digest_file "$NODE_BIN")"
fge_context non_claim 'Actual Node author and native Rust admission; not remote HTTP, hostile isolation, whole operator qualification or release gates.'
WORK="$(fge_tempdir source-binary-refactor)"
fge_phase action
fge_run_timeout 900 BINARY-REFACTOR-001 python3 "$E2E_ROOT/helpers/source_binary_refactor.py" "$FG_BIN" "$NODE_BIN" "$WORK"
fge_assert_exit BINARY-REFACTOR-002 0 "$FGE_LAST_EXIT"
fge_artifact "$WORK/results.json" source_binary_refactor_results
