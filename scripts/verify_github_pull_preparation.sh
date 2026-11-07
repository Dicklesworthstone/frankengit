#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
node --check scripts/operator/pull_command.mjs
node --check scripts/lib/github-pull-preparation.mjs
node --check scripts/migrate_github_pulls.mjs
node --test tests/operator/pull_preparation_identity.test.mjs tests/operator/github_pull_preparation.test.mjs tests/operator/github_pull_import_cli.test.mjs
