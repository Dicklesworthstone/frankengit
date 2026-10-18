#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# External reviewed source composition, not native agent execution or authority.
node --version
git --version
node --test scripts/tests/source_assembly.test.mjs \
  scripts/tests/source_assembly_capture.test.mjs \
  scripts/tests/source_assembly_cli.test.mjs
bash scripts/verify_source_expansion.sh
