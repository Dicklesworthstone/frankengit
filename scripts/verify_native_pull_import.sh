#!/usr/bin/env bash
# FG-049 operator modules + real HTTP response-schema peers, not a native fg gate.
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for file in scripts/lib/native-pull-import-source.mjs scripts/lib/native-pull-import-plan.mjs \
  scripts/lib/native-pull-import.mjs scripts/lib/native-pull-import-journal.mjs \
  scripts/lib/native-pull-import-execute.mjs scripts/migrate_native_pulls.mjs; do node --check "$file"; done
node --test tests/operator/native_pull_import_prepare.test.mjs tests/operator/native_pull_import_cli.test.mjs \
  tests/operator/native_pull_import_execute.test.mjs tests/operator/native_pull_import_lifecycle.test.mjs
