#!/usr/bin/env bash
# Dependency-free adapter over the production patch module and its unit tests.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# Compile a wrapper so Rust resolves patch's child modules exactly as in the crate.
python3 - "$root" "$work" <<'PY'
import json, pathlib, sys
root, work = map(pathlib.Path, sys.argv[1:])
(work / 'tests.rs').write_text('#![forbid(unsafe_code)]\n#[path = ' +
    json.dumps(str(root / 'crates/fgit-diff/src/patch.rs')) + ']\nmod patch;\n')
PY
"${RUSTC:-rustc}" --version
"${RUSTC:-rustc}" --edition=2024 --test "$work/tests.rs" -o "$work/tests"
"$work/tests" "$@"
