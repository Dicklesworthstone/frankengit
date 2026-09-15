#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo test --locked -p fgit-pack --test incremental_bundle --test full_bundle
cargo check --locked -p fgit-cli --all-targets
cargo test --locked -p fgit-node --lib treefs_workspace::full_bundle -- --nocapture
cargo test --locked -p fgit-cli --bin fg bundle:: -- --nocapture
cargo test --locked -p fgit-cli --test native_incremental_bundle_smoke --test native_full_bundle_smoke --test native_bundle_fetch_smoke -- --nocapture
