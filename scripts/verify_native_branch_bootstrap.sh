#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --version
node --check scripts/lib/branch-bootstrap-protocol.mjs
node --check scripts/lib/branch-bootstrap-store.mjs
node --check scripts/lib/branch-bootstrap.mjs
node --check scripts/lib/branch-bootstrap-pulls.mjs
node --check scripts/bootstrap_native_branches.mjs
node --test tests/operator/branch_bootstrap.test.mjs tests/operator/branch_bootstrap_pulls.test.mjs \
  tests/operator/branch_bootstrap_cli.test.mjs tests/operator/branch_bootstrap_lifecycle.test.mjs
