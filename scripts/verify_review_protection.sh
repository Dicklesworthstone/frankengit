#!/usr/bin/env bash
# Native production protection checks; no external Git or hosted runner is required.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo test --locked -p fgit-admission --lib merge::staging::epoch_tests -- --nocapture
cargo test --locked -p fgit-node --lib mandatory_protection -- --nocapture --test-threads=1
cargo test --locked -p fgit-cli --test native_protection_smoke -- --nocapture
