#!/usr/bin/env bash
# Execute the real std-only progress codec/state/file tests, not a rewritten model.
# Native node, runtime, and end-to-end indexing tests are separate gates.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
rustc --version --verbose
git rev-parse HEAD
sha256sum crates/fgit-node/src/bin/index_maintenance/state.rs \
  crates/fgit-node/src/bin/index_maintenance/state_tests.rs
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
rustc --edition=2024 --test -F unsafe_code \
  crates/fgit-node/src/bin/index_maintenance/state.rs -o "$out/progress-tests"
"$out/progress-tests" --nocapture
