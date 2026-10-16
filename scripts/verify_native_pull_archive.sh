#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
node --check scripts/lib/forge-pull-archive-protocol.mjs
node --check scripts/lib/forge-pull-archive-store.mjs
node --check scripts/lib/forge-pull-archive.mjs
node --check scripts/lib/forge-pull-capture.mjs
node --check scripts/archive_native_pulls.mjs
node --test tests/operator/pull_archive.test.mjs tests/operator/pull_archive_complete.test.mjs \
  tests/operator/pull_archive_capacity.test.mjs tests/operator/pull_capture.test.mjs \
  tests/operator/pull_capture_cli.test.mjs
