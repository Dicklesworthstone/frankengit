#!/usr/bin/env bash
# External operator lifecycle; peers are explicit schemas, not native Rust fg.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --version
git rev-parse HEAD
for file in scripts/operator/source_edit_*.mjs scripts/fg_source_edit.mjs; do
  node --check "$file"
done
node --test tests/operator/source_edit_candidate.test.mjs \
  tests/operator/source_edit_publish.test.mjs tests/operator/source_edit_cli.test.mjs
