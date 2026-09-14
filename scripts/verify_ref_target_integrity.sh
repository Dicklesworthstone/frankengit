#!/usr/bin/env bash
# Native branch-kind gates; source preparation, disclosure and publication remain separate.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${1:-test}" in
  check)
    cargo check --locked -p fgit-node --all-targets
    ;;
  test)
    cargo test --locked -p fgit-git-object --all-targets
    cargo test --locked -p fgit-node --lib ref_roots -- --nocapture
    cargo test --locked -p fgit-node \
      --test git_daemon_receive_transport \
      --test production_receive_handoff \
      --test staging_only_receive \
      --test hidden_ref_policy_end_to_end --no-fail-fast
    ;;
  *) printf '%s\n' 'usage: bash scripts/verify_ref_target_integrity.sh [check|test]' >&2; exit 2 ;;
esac
