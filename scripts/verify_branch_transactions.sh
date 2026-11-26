#!/usr/bin/env bash
# Client protocol/custody coverage; native admission remains a separate gate.
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for file in scripts/fg_branch_transaction.mjs \
  scripts/operator/branch_transaction{,_files,_transport}.mjs \
  tests/operator/fixtures/branch_transaction_peer.mjs \
  tests/operator/branch_transaction{,_cli}.test.mjs; do
  node --check "$file"
done
node --test --test-concurrency=1 tests/operator/branch_transaction{,_cli}.test.mjs
