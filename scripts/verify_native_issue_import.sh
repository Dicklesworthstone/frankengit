#!/usr/bin/env bash
# Native issue data migration: complete production JS paths, loopback API peers.
# No Rust fg/native authority or canonical restore claim.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --version
node --test tests/operator/native_issue_import.test.mjs \
  tests/operator/native_issue_import_capacity.test.mjs \
  tests/operator/native_issue_migration.test.mjs \
  tests/operator/native_issue_migration_cli.test.mjs \
  tests/operator/issue_import_compatibility.test.mjs
