#!/usr/bin/env bash
# Stable FG-028b entrypoint.  The actual campaign remains discoverable under
# suites/node/; passing it explicitly keeps this root-level contract from
# becoming silently undiscoverable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "${SCRIPT_DIR}/run_all.sh" "${SCRIPT_DIR}/suites/node/incremental_fetch.sh"
