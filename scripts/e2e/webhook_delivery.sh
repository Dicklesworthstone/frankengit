#!/usr/bin/env bash
# Exact entrypoint for FG-046 webhook delivery evidence suite
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/suites/forge/webhook_delivery.sh" "$@"
