#!/usr/bin/env bash
# Operator client contracts: real Node processes/sockets, explicit HTTP peers.
# Not a Rust-native or live-fg end-to-end lane.
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for module in scripts/remote_issue.mjs scripts/operator/remote_issue.mjs \
  scripts/operator/issue_files.mjs scripts/operator/transaction_outcome.mjs \
  tests/operator/remote_issue.test.mjs tests/operator/remote_issue_cli.test.mjs; do
  node --check "$module"
done
node --test tests/operator/remote_issue.test.mjs tests/operator/remote_issue_cli.test.mjs
