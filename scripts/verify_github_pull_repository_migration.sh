#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
node --check scripts/lib/github-pull-migration.mjs
node --test tests/operator/github_pull_migration.test.mjs
