#!/usr/bin/env bash
# Local filesystem discovery and capture composition; not native fg/E2E evidence.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --version
node --check scripts/operator/source_workspace_scan.mjs
node --check scripts/operator/source_workspace_changes.mjs
node --check scripts/fg_source_workspace_scan.mjs
node --test tests/operator/source_workspace_scan.test.mjs
# The actual capture/inspection module runs with explicit pre-existing service
# fixtures. No replacement kernel is linked into production.
node --experimental-vm-modules --test tests/operator/source_workspace_scan_capture.spec.mjs
