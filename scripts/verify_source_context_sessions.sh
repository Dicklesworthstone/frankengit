#!/usr/bin/env bash
# Execute complete normal production modules and unchanged continuation peers.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
node --version
git rev-parse HEAD
for file in scripts/fg_context_session.mjs scripts/operator/source_context{,_continue,_export,_session}.mjs \
  tests/operator/source_context{_fixtures,_symbols_fixtures,_continue_fixtures}.mjs \
  tests/operator/source_context{_session,_session_cli,_continue}.test.mjs; do
  node --check "$file"
done
node --test tests/operator/source_context_session.test.mjs \
  tests/operator/source_context_session_cli.test.mjs tests/operator/source_context_continue.test.mjs
