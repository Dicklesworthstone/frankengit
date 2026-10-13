#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for file in scripts/operator/pull_review_snapshot.mjs scripts/operator/pull_review_draft.mjs \
  scripts/operator/pull_review_files.mjs scripts/fg_pull_review.mjs \
  tests/operator/pull_review_snapshot_fixture.mjs tests/operator/pull_review_snapshot.test.mjs \
  tests/operator/pull_review_cli.test.mjs tests/operator/pull_review_lifecycle.test.mjs \
  scripts/operator/pull_command.mjs scripts/operator/remote_pull.mjs scripts/operator/transaction_outcome.mjs; do
  node --check "$file"
done
node --test tests/operator/pull_review_snapshot.test.mjs tests/operator/pull_review_cli.test.mjs \
  tests/operator/pull_review_lifecycle.test.mjs
