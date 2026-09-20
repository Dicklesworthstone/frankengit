#!/usr/bin/env bash
# Actual production scanner/table implementation; no transformed Rust sources.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
rustc --version --verbose
git rev-parse HEAD
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
for file in engine.rs engine_tests.rs table.rs table_tests.rs; do
  sha256sum "crates/fgit-forge/src/source_symbols/$file"
  cp "crates/fgit-forge/src/source_symbols/$file" "$out/$file"
done
printf '#![forbid(unsafe_code)]\nmod engine;\nmod table;\n' > "$out/lib.rs"
rustc --edition=2024 --test -F unsafe_code "$out/lib.rs" -o "$out/tables"
"$out/tables" --nocapture
