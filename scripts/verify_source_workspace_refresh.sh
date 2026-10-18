#!/usr/bin/env bash
# Trusted-local workspace refresh, with explicit source-service contract fixtures.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --version
node --check scripts/operator/source_workspace_merge.mjs
node --check scripts/operator/source_workspace.mjs
node --check scripts/fg_source_workspace.mjs
node --test tests/operator/source_workspace_refresh.test.mjs \
  tests/operator/source_workspace_refresh_command.test.mjs \
  tests/operator/source_workspace_refresh_resolution.test.mjs \
  tests/operator/source_workspace_merge.test.mjs \
  tests/operator/source_workspace_refresh_merge.test.mjs
