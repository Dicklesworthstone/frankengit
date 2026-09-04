#!/usr/bin/env bash
set -euo pipefail
cargo fmt --all
git add -A
git diff --cached --check
changed="$(git diff --cached --name-only)"
expected=$'crates/fgit-node/src/lib.rs\ncrates/fgit-node/tests/git_daemon_deadline.rs\ncrates/fgit-node/tests/git_daemon_receive_transport.rs'
test "$changed" = "$expected"
cargo test -p fgit-node --test git_daemon_deadline --test git_daemon_receive_transport --no-fail-fast
cargo clippy -p fgit-node --all-targets -- -D warnings
