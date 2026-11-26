#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for file in scripts/operator/pull_candidate_{capture,commit,io,files,draft}.mjs scripts/fg_pull_candidate.mjs \
  scripts/operator/{pull_command,remote_pull,transaction_outcome}.mjs \
  crates/fgit-node/src/smart_http/server/browser/{pulls-core,pulls-candidate,pulls-rebase}.mjs \
  tests/operator/pull_candidate_{fixture,package_fixture,rebase_fixture,files.test,draft.test,cli.test,workflow.test,rebase.test}.mjs; do
  node --check "$file"
done
node --test tests/operator/pull_candidate_{files,draft,cli,workflow,rebase}.test.mjs
