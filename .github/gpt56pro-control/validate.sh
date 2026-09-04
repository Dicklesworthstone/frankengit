#!/usr/bin/env bash
set -euo pipefail
cargo fmt --all --check
cargo test -p fgit-crypto --all-targets --no-fail-fast
