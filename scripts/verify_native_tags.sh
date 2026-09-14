#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export RCH_CARGO_WRAPPER_BYPASS=1
: "${CARGO_TARGET_DIR:?use a private target directory}"
case "${1:-check}" in
  check) cargo check --locked -p fgit-node -p fgit-cli --all-targets ;;
  test)
    cargo test --locked -p fgit-forge --lib tags::tests -- --nocapture
    cargo test --locked -p fgit-node --lib treefs_workspace::tags::tests -- --nocapture
    cargo test --locked -p fgit-cli --bin fg tags::tests -- --nocapture
    cargo test --locked -p fgit-cli --test native_tag_smoke -- --nocapture ;;
  *) echo 'usage: verify_native_tags.sh check|test' >&2; exit 2 ;;
esac
