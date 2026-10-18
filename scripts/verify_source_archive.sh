#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
for tool in node git python3 openssl; do
  command -v "$tool" >/dev/null || { printf 'Source archive verification requires %s\n' "$tool" >&2; exit 2; }
done
for file in scripts/fg_source_archive.mjs scripts/operator/source_archive*.mjs \
  scripts/operator/transaction_outcome.mjs scripts/operator/workflow_watch_io.mjs \
  tests/operator/source_archive*.test.mjs tests/operator/fixtures/source_archive_native.mjs; do
  node --check "$file"
done
node --test tests/operator/source_archive*.test.mjs
