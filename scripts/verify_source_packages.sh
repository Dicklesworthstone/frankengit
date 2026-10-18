#!/usr/bin/env bash
# Runnable operator/package integration lane; not a Cargo or native-server gate.
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for file in scripts/fg_source_package.mjs scripts/operator/source_package.mjs \
  scripts/tests/source_package_fixture.mjs scripts/tests/source_package_operator.test.mjs \
  scripts/tests/source_package_cli.test.mjs; do
  node --check "$file"
done
node --test scripts/tests/source_package_operator.test.mjs scripts/tests/source_package_cli.test.mjs
