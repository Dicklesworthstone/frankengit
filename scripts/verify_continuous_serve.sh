#!/usr/bin/env bash
# Continuous `fg serve` and `fg serve-ssh` (frankengit-root-doctrine-x2mv.4.32):
# lifetime and deadline unit tests, then stock git and OpenSSH against a
# freshly built fg in both native hash domains, and the SSH compatibility
# suite with its quiet-command regression. Repository-owned so a dispatch
# manifest delegates here (AGENTS.md section 12).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
git rev-parse HEAD
rustc -Vv
cargo test --locked -p fgit-cli --bin fg guarded_git_server::tests
cargo test --locked -p fgit-cli --bin fg ssh_server::tests
cargo test --locked -p fgit-cli --bin fg service_stop::tests
cargo test --locked -p fgit-node --lib daemon::supervisor::tests
cargo test --locked -p fgit-node --lib ssh::
cargo test --locked -p fgit-node --test guarded_git_daemon continuous
cargo build --locked -p fgit-cli --bin fg
target="$(cargo metadata --locked --format-version 1 --no-deps |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
fg="$target/debug/fg"
python3 scripts/e2e/continuous_git_transports_smoke.py --fg "$fg" --format sha1 --format sha256
FG_BIN="$fg" ./scripts/e2e/run_all.sh scripts/e2e/suites/transport/ssh_git_compat.sh
