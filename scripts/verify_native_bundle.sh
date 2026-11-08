#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# The caller owns its pane target; preserve normal RCH dispatch.
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to your private /data/frankengit-targets/<pane-label> directory}"
export CARGO_TARGET_DIR
case "${1:-test}" in
  check) cargo check --locked -p fgit-node -p fgit-cli --all-targets ;;
  test)
    status=0
    run() { "$@" || status=1; }
    run cargo test --locked -p fgit-pack --test full_bundle -- --nocapture
    run cargo test --locked -p fgit-node --lib treefs_workspace::full_bundle:: -- --nocapture
    run cargo test --locked -p fgit-node --lib quarantine_validator::typed_closure::tests -- --nocapture
    run cargo test --locked -p fgit-cli --bin fg bundle:: -- --nocapture
    run cargo test --locked -p fgit-cli --bin fg branches:: -- --nocapture
    run cargo test --locked -p fgit-cli --test native_full_bundle_smoke -- --nocapture
    run cargo test --locked -p fgit-cli --test native_bundle_fetch_smoke -- --nocapture
    run cargo test --locked -p fgit-node --lib bundle_fetch_cannot_bypass -- --nocapture
    exit "$status" ;;
  *) echo 'usage: bash scripts/verify_native_bundle.sh [check|test]' >&2; exit 2 ;;
esac
