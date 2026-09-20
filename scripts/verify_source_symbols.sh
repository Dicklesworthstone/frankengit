#!/usr/bin/env bash
# Compile/test the exact std-only production declaration scanner. This does not
# replace the native TreeFS, node, HTTP, full-workspace or release lanes.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
rustc --version --verbose
git rev-parse HEAD
sha256sum crates/fgit-forge/src/source_symbols/{engine.rs,engine_tests.rs}
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
rustc --edition=2024 --test -F unsafe_code crates/fgit-forge/src/source_symbols/engine.rs -o "$out/symbol-tests"
"$out/symbol-tests" --nocapture
