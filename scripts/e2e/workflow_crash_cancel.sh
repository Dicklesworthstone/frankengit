#!/usr/bin/env bash
# Forwarding entrypoint for FG-095c Workflow Crash and Cancellation suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/suites/workflow/workflow_crash_cancel.sh" "$@"
