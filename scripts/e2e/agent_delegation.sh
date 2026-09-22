#!/usr/bin/env bash
# FrankenGit agent delegation e2e suite driver (FG-074)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/suites/agent/agent_delegation.sh" "$@"
