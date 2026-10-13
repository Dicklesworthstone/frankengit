#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for file in scripts/operator/transaction_outcome.mjs scripts/operator/pull_command.mjs \
  scripts/operator/remote_pull.mjs scripts/operator/pull_files.mjs scripts/remote_pull.mjs \
  tests/operator/remote_pull_fixture.mjs tests/operator/remote_pull.test.mjs \
  tests/operator/remote_pull_cli.test.mjs tests/operator/remote_pull_review_fixture.mjs \
  tests/operator/remote_pull_review.test.mjs tests/operator/remote_pull_review_cli.test.mjs; do
  node --check "$file"
done
node --test tests/operator/remote_pull.test.mjs tests/operator/remote_pull_cli.test.mjs \
  tests/operator/remote_pull_review.test.mjs tests/operator/remote_pull_review_cli.test.mjs
