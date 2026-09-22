#!/usr/bin/env bash
# Forwarding entrypoint for FG-063 Federation Bundles suite.
# The discovered suite lives under scripts/e2e/suites/federation/federation_bundles.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/suites/federation/federation_bundles.sh" "$@"
