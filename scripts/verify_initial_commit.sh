#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fgit-initial-commit-target}"
case "${1:-check}" in
  check) cargo check --locked -p fgit-node -p fgit-cli --all-targets ;;
  test)
    cargo test --locked -p fgit-forge --lib initial_commit -- --nocapture
    cargo test --locked -p fgit-node --lib treefs_workspace::initial_commit -- --nocapture
    cargo test --locked -p fgit-cli --bin fg patch_command::initial -- --nocapture
    cargo test --locked -p fgit-cli --test native_initial_commit_smoke -- --nocapture
    ;;
  *) echo "usage: $0 check|test" >&2; exit 2 ;;
esac
