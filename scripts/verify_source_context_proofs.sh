#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
node --check scripts/operator/source_archive.mjs
node --check scripts/operator/source_context_proof.mjs
node --check scripts/fg_context_proof.mjs
node --test tests/operator/source_archive.test.mjs \
  tests/operator/source_path_capture.test.mjs \
  tests/operator/source_context_proof.test.mjs \
  tests/operator/source_context_proof_cli.test.mjs
