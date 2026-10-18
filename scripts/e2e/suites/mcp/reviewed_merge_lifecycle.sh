#!/usr/bin/env bash
# Real MCP processes and native repository authority, not stand-in tool peers.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init mcp-reviewed-merge-lifecycle
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.58
fge_context non_claim 'Local operator grants, exact native merges and durable retries; not remote IAM, rebase or a merge queue.'
: "${FG_BIN:?Supply the compiled native fg binary}"
: "${FG_MCP_BIN:?Supply the compiled native fg-mcp binary}"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context fg_mcp_digest "$(fge_digest_file "$FG_MCP_BIN")"
work="$(fge_tempdir mcp-reviewed-merges)"
fge_phase action
fge_run_timeout 600 MCP-REVIEWED-MERGES-001 python3 "$E2E_ROOT/helpers/mcp_reviewed_merges.py" "$FG_BIN" "$FG_MCP_BIN" "$work"
fge_assert_exit MCP-REVIEWED-MERGES-002 0 "$FGE_LAST_EXIT"
fge_phase assert
cp "$work/results.json" "$(fge_artifact_path results.json)"
fge_artifact results.json json
