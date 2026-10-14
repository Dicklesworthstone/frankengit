#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Existing decoder + real Git-shaped candidate objects; not Rust fg admission.
node --version
git --version
node --test scripts/tests/source_candidate_pack.test.mjs
bash scripts/verify_source_replay.sh
