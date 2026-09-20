#!/usr/bin/env bash
# Dependency-free adapter over the unmodified production patch module/tests.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# An absolute #[path] attribute changes child-module lookup. Keep the normal
# patch.rs + patch/ layout in an isolated copy; never rewrite production bytes.
python3 - "$root" "$work" <<'PYTHON'
import pathlib, shutil, sys
root, work = map(pathlib.Path, sys.argv[1:])
source = root / 'crates/fgit-diff/src'
shutil.copyfile(source / 'patch.rs', work / 'patch.rs')
shutil.copytree(source / 'patch', work / 'patch')
(work / 'tests.rs').write_text('#![forbid(unsafe_code)]\nmod patch;\n')
PYTHON
"${RUSTC:-rustc}" --version
"${RUSTC:-rustc}" --edition=2024 --test "$work/tests.rs" -o "$work/tests"
"$work/tests" "$@"
