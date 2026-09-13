#!/usr/bin/env bash
# Native publication/rebase integration. No source edits, golden regeneration,
# dependency updates or publication. Run identically locally or on a runner.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${1:-check}" in
  check)
    cargo check --locked -p fgit-forge -p fgit-node -p fgit-cli --all-targets
    ;;
  test)
    status=0
    cargo test --locked -p fgit-forge --lib preparation::rebase -- --nocapture || status=1
    cargo test --locked -p fgit-node --test workspace_publication -- --nocapture || status=1
    cargo test --locked -p fgit-node --lib treefs_workspace::merge_prepare::rebase -- --nocapture || status=1
    cargo test --locked -p fgit-node --lib treefs_workspace::branches::tests -- --nocapture || status=1
    cargo test --locked -p fgit-cli --bin fg rebase -- --nocapture || status=1
    cargo test --locked -p fgit-cli --test native_rebase_smoke -- --nocapture || status=1
    exit "$status"
    ;;
  *) printf 'usage: %s [check|test]\n' "$0" >&2; exit 2 ;;
esac
