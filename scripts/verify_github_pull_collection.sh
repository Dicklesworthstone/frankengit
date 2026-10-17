#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
node --check scripts/lib/github-pull-source.mjs
node --check scripts/lib/github-pull-inventory.mjs
node --check scripts/lib/github-pull-collection-store.mjs
node --check scripts/lib/github-pull-collection.mjs
node --check scripts/discover_github_pulls.mjs
node --check scripts/collect_github_pulls.mjs
node --test tests/operator/github_pull_source.test.mjs tests/operator/github_pull_inventory.test.mjs \
  tests/operator/github_pull_inventory_cli.test.mjs tests/operator/github_pull_collection.test.mjs \
  tests/operator/github_pull_collection_cli.test.mjs tests/operator/github_pull_collection_import.test.mjs
