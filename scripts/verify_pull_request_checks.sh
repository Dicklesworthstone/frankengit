#!/usr/bin/env bash
# Canonical workflow observations on pull requests (frankengit-root-doctrine-x2mv.4.12):
# selection, persistence, publication, and HTTP, CLI, MCP and browser reads.
# Repository-owned so a dispatch manifest delegates here (AGENTS.md section 12).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
git rev-parse HEAD
rustc -Vv
cargo check --locked -p fgit-cli --all-targets
cargo test --locked -p fgit-admission --lib workflow_checks::read::tests
cargo test --locked -p fgit-node --lib pull_request_checks
cargo test --locked -p fgit-node --lib saved_check_record
cargo test --locked -p fgit-cli --bin fg workflow_command::publish::tests
cargo test --locked -p fgit-cli --test workflow_publication
cargo test --locked -p fgit-node --lib smart_http::server::pulls::checks
cargo test --locked -p fgit-node --test pull_request_checks_http
cargo test --locked -p fgit-cli --bin fg checks
cargo test --locked -p fgit-cli --bin fg mcp::backend::integration_tests
cargo test --locked -p fgit-cli --test native_pull_request_smoke
node --test tests/browser/pulls-checks*.test.mjs
