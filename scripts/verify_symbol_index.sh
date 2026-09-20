#!/usr/bin/env bash
# Actual production scanner/table implementation; no transformed Rust sources.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
rustc --version --verbose
git rev-parse HEAD
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
if [[ "${1:-tables}" == native && $# -eq 1 ]]; then
  # Check the real cross-crate composition, including binary/HTTP test targets.
  # The normal rch wrapper is not bypassed; each invocation owns its target.
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$out/native-target}" CARGO_BUILD_JOBS=2
  cargo check --locked -p fgit-forge -p fgit-node --all-targets
  # Execute the actual codec, native node, operator and HTTP implementations.
  # Omit test debug symbols to bound linking memory; no assertions are removed.
  export CARGO_PROFILE_TEST_DEBUG=0
  cargo test --locked -p fgit-forge --lib source_symbols -- --test-threads=1
  cargo test --locked -p fgit-node --test source_symbol_index --bin fg-symbol-index -- --test-threads=1
  cargo test --locked -p fgit-node --lib smart_http::server::source::symbols -- --test-threads=1
  exit 0
fi
[[ "${1:-tables}" == tables && $# -le 1 ]] || { echo "Usage: $0 [tables|native]" >&2; exit 2; }
for file in engine.rs engine_tests.rs table.rs table_tests.rs; do
  sha256sum "crates/fgit-forge/src/source_symbols/$file"
  cp "crates/fgit-forge/src/source_symbols/$file" "$out/$file"
done
printf '#![forbid(unsafe_code)]\nmod engine;\nmod table;\n' > "$out/lib.rs"
rustc --edition=2024 --test -F unsafe_code "$out/lib.rs" -o "$out/tables"
"$out/tables" --nocapture
