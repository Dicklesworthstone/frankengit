#!/usr/bin/env bash
# Exact entrypoint for x2mv.4.17 MCP stdio live-client evidence suite
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/suites/mcp/mcp_stdio_live_client.sh" "$@"
