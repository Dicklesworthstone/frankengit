#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
node --check scripts/lib/github-pull-migration.mjs
node --check scripts/migrate_github_pull_collection.mjs
node --test tests/operator/github_pull_migration.test.mjs \
  tests/operator/github_pull_migration_cli.test.mjs tests/operator/github_pull_migration_capacity.test.mjs
