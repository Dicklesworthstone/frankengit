#!/usr/bin/env bash
# Real native prepare/inspect/review/publication above 100,000 inherited files.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init mcp-reviewed-merge-scale
fge_kind e2e-binary
fge_context bead frankengit-t0iw
fge_context inherited_files 100000
fge_context non_claim 'Bounded local MCP lifecycle; not remote IAM, hostile execution, unbounded repositories or a release gate.'
: "${FG_BIN:?Supply the compiled native fg binary}"
: "${FG_MCP_BIN:?Supply the compiled native fg-mcp binary}"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context fg_mcp_digest "$(fge_digest_file "$FG_MCP_BIN")"
work="$(fge_tempdir mcp-reviewed-merge-scale)"
fge_phase action
fge_run_timeout 30 MCP-REVIEWED-SCALE-CAPTURE-001 python3 "$E2E_ROOT/selftests/test_recorded_command.py"
fge_assert_exit MCP-REVIEWED-SCALE-CAPTURE-002 0 "$FGE_LAST_EXIT"
fge_run_timeout 1800 MCP-REVIEWED-SCALE-001 python3 "$E2E_ROOT/helpers/mcp_reviewed_merges.py" "$FG_BIN" "$FG_MCP_BIN" "$work" 100000
fge_assert_exit MCP-REVIEWED-SCALE-002 0 "$FGE_LAST_EXIT"
fge_phase assert
cp "$work/results.json" "$(fge_artifact_path results.json)"
fge_artifact results.json json
