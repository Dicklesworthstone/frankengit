#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Complete external pack-verification consumers, then the unchanged source lanes.
# Test peers model native schemas; this is not Rust authority/admission evidence.
node --version
node --test scripts/tests/source_candidate_pack_flow.test.mjs \
  scripts/tests/source_candidate_pack_cli.test.mjs
bash scripts/verify_source_candidate_packs.sh
