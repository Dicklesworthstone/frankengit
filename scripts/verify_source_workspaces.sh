#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# External trusted-local adapter; not native Rust TreeFS or confinement evidence.
node --version
node --test scripts/tests/source_workspace.test.mjs scripts/tests/source_workspace_changes.test.mjs \
  scripts/tests/source_binary_pipeline.test.mjs \
  scripts/tests/source_workspace_profiles.test.mjs
bash scripts/verify_source_changes.sh
