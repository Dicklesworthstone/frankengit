#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
node --check scripts/lib/github-pull-source.mjs
node --check scripts/migrate_github_pulls.mjs
node --test tests/operator/github_pull_source.test.mjs tests/operator/github_pull_capture_cli.test.mjs
