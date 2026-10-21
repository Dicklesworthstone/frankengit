#!/usr/bin/env bash
# External operator lifecycle; peers are explicit schemas, not native Rust fg.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --version
git rev-parse HEAD
for file in scripts/operator/source_edit_*.mjs scripts/fg_source_edit.mjs scripts/fg_source_patch.mjs; do
  node --check "$file"
done
node --test tests/operator/source_edit_candidate.test.mjs \
  tests/operator/source_edit_from_package.test.mjs \
  tests/operator/source_edit_publish.test.mjs tests/operator/source_edit_cli.test.mjs \
  tests/operator/source_edit_evidence.test.mjs \
  tests/operator/source_edit_evidence_publish.test.mjs tests/operator/source_edit_evidence_cli.test.mjs \
  tests/operator/source_edit_creations.test.mjs tests/operator/source_edit_creations_publish.test.mjs \
  tests/operator/source_edit_results.test.mjs tests/operator/source_edit_results_custody.test.mjs \
  tests/operator/source_edit_result_tree.test.mjs \
  tests/operator/source_edit_replacements.test.mjs tests/operator/source_edit_replacements_cli.test.mjs \
  tests/operator/source_edit_binary.test.mjs tests/operator/source_edit_binary_cli.test.mjs \
  tests/operator/source_edit_delta.test.mjs tests/operator/source_edit_delta_cli.test.mjs \
  tests/operator/source_edit_delta_runs.test.mjs \
  tests/operator/source_edit_splices.test.mjs tests/operator/source_edit_splices_cli.test.mjs \
  tests/operator/source_edit_compact_splices.test.mjs tests/operator/source_edit_compact_splices_cli.test.mjs
