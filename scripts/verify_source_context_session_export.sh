#!/usr/bin/env bash
# Complete operator modules and actual local session/export consumers.
# HTTP peers in these tests are explicit schema fixtures, not Rust fg.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
node --version
for path in scripts/fg_context_session.mjs scripts/operator/source_context{,_export,_continue,_session,_merge,_session_export}.mjs \
  tests/operator/source_context_{merge,session_export,continue}.test.mjs; do
  node --check "$path"
done
node --test tests/operator/source_context_merge.test.mjs \
  tests/operator/source_context_session_export.test.mjs \
  tests/operator/source_context_continue.test.mjs
