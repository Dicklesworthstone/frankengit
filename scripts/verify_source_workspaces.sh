#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# External trusted-local adapter; not native Rust TreeFS or confinement evidence.
node --version
node --test scripts/tests/source_workspace.test.mjs
