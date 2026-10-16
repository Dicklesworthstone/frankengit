#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
node --check scripts/lib/forge-pull-archive.mjs
node --check scripts/archive_native_pulls.mjs
node --test tests/operator/pull_archive.test.mjs
