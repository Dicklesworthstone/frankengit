#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Private sparse editing expansion; not native authority or a running Rust node.
node --version
node --test scripts/tests/source_workspace_expansion.test.mjs \
  scripts/tests/source_workspace_expansion_cli.test.mjs
bash scripts/verify_packed_source_flow.sh
