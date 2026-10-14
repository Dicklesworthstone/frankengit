#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# External exact-preimage replay, not native Git rebase or semantic merge proof.
node --version
node --test scripts/tests/source_replay.test.mjs \
  scripts/tests/source_replay_capture.test.mjs \
  scripts/tests/source_replay_cli.test.mjs
bash scripts/verify_source_workspaces.sh
