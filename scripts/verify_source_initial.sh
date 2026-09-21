#!/usr/bin/env bash
# Actual model-free Initial readers and credentialed source gateway. No fake
# authority, transformed Rust, skipped assertions, or dependency changes.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
rustc --version --verbose
git rev-parse HEAD
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/initial-retrieval}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_PROFILE_TEST_DEBUG=0
cargo check --locked --offline -p fgit-node --all-targets
cargo test --locked --offline -p fgit-node --lib source_retrieval -- --test-threads=1
cargo test --locked --offline -p fgit-node --test source_initial_retrieval -- --test-threads=1
# Retain the gateway's prior protocol tests as well as the new route tests.
cargo test --locked --offline -p fgit-node --lib smart_http::server::source -- --test-threads=1
