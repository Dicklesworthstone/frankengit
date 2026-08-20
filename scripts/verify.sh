#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

lane="${1:-}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

echo_step() { printf '\033[1;36m==> %s\033[0m\n' "$*" >&2; }
refuse_dormant() {
  printf '\033[1;33m==> %s\033[0m\n' "$1" >&2
  printf 'This is a typed pre-implementation refusal, not a passing gate.\n' >&2
  exit 3
}

run_docs() {
  echo_step "Checking FrankenGit documentation and registries"
  cargo run --locked -p fgit-registry-check -- docs
}

run_constitution() {
  echo_step "Checking dependency and memory-safety constitution"
  cargo run --locked -p fgit-registry-check -- constitution
  cargo metadata --locked --no-deps --format-version 1 >/dev/null
}

run_fast() {
  run_docs
  run_constitution
  echo_step "Checking formatting"
  cargo fmt --all -- --check
  echo_step "Checking workspace"
  cargo check --workspace --all-targets --locked
  echo_step "Running workspace tests"
  cargo test --workspace --all-targets --locked
  echo_step "Running Clippy"
  cargo clippy --workspace --all-targets --locked -- -D warnings
}

run_full() {
  run_fast
  refuse_dormant "Full conformance/lab/fault/fuzz/corpus lane is not implemented yet"
}

run_release() {
  run_fast
  refuse_dormant "No releasable FrankenGit binary or complete native target matrix exists yet"
}

if [ -z "$lane" ]; then
  printf 'usage: %s {docs|constitution|fast|full|release}\n' "$0" >&2
  exit 2
fi

case "$lane" in
  docs) run_docs ;;
  constitution) run_constitution ;;
  fast) run_fast ;;
  full) run_full ;;
  release) run_release ;;
  *)
    printf 'usage: %s {docs|constitution|fast|full|release}\n' "$0" >&2
    exit 2
    ;;
esac
