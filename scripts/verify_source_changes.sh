#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Focused external-client tests. Native-schema peers are not the Rust fg server;
# installed Git is a test oracle, not the pinned native conformance lane.
node --version
git --version
openssl version
node --test scripts/tests/source_changes.test.mjs \
  scripts/tests/source_changes_prepare.test.mjs \
  scripts/tests/source_changes_cli.test.mjs \
  scripts/tests/source_creation.test.mjs \
  scripts/tests/source_creation_pipeline.test.mjs \
  scripts/tests/source_tree_transition.test.mjs \
  scripts/tests/source_tree_binding.test.mjs \
  scripts/tests/source_relocation.test.mjs \
  scripts/tests/source_verified_stage.test.mjs \
  scripts/tests/source_binary_changes.test.mjs \
  scripts/tests/source_compact_patch.test.mjs \
  scripts/tests/source_line_hunks.test.mjs \
  scripts/tests/source_line_hunks_pipeline.test.mjs
