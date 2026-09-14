#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fg-source-browse-${USER:-local}}"
case "${1:-test}" in
  check) cargo check --locked -p fgit-node -p fgit-cli --all-targets ;;
  test)
    cargo test --locked -p fgit-node --lib treefs_workspace::source_browse::tests -- --nocapture
    cargo test --locked -p fgit-node --test source_browse -- --nocapture
    cargo test --locked -p fgit-cli --bin fg source_browse:: -- --nocapture
    cargo test --locked -p fgit-cli --test native_source_browse_smoke -- --nocapture
    ;;
  *) echo 'usage: bash scripts/verify_source_browse.sh [check|test]' >&2; exit 2 ;;
esac
