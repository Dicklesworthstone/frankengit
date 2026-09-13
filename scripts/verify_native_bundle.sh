#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fg-native-bundle-${USER:-local}}"
case "${1:-test}" in
  check) cargo check --locked -p fgit-node -p fgit-cli --all-targets ;;
  test)
    status=0
    run() { "$@" || status=1; }
    run cargo test --locked -p fgit-pack --test full_bundle -- --nocapture
    run cargo test --locked -p fgit-node --lib treefs_workspace::full_bundle::tests -- --nocapture
    run cargo test --locked -p fgit-node --lib quarantine_validator::typed_closure::tests -- --nocapture
    run cargo test --locked -p fgit-cli --bin fg bundle::tests -- --nocapture
    run cargo test --locked -p fgit-cli --test native_full_bundle_smoke -- --nocapture
    exit "$status" ;;
  *) echo 'usage: bash scripts/verify_native_bundle.sh [check|test]' >&2; exit 2 ;;
esac
