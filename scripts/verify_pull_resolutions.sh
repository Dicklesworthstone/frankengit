#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for file in crates/fgit-node/src/smart_http/server/browser/pulls-{core,candidate,resolution}.mjs \
  scripts/operator/pull_candidate_{io,capture,files,draft,stage}.mjs \
  scripts/operator/{pull_command,pull_files,remote_pull,transaction_outcome}.mjs scripts/fg_pull_candidate.mjs \
  tests/operator/pull_candidate_fixture.mjs tests/operator/pull_resolution_fixture.mjs \
  tests/operator/pull_resolution{,_cli}.test.mjs tests/operator/pull_candidate_stage.test.mjs; do
  node --check "$file"
done
node --test tests/operator/pull_resolution.test.mjs tests/operator/pull_resolution_cli.test.mjs tests/operator/pull_candidate_stage.test.mjs
