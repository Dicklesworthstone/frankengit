#!/usr/bin/env bash
# Production storage/authentication regressions; no publication credentials.
set -euo pipefail

git rev-parse HEAD
node --version
node --test tests/operator/review_protection.test.mjs tests/browser/protection.test.mjs tests/browser/protection-view.test.mjs tests/browser/protection-standalone.test.mjs
rustc -Vv
cargo check --locked -p fgit-node -p fgit-admission -p fgit-object-fabric --all-targets
cargo test --locked -p fgit-policy --all-targets
cargo test --locked -p fgit-object-fabric --lib --test local_batch --test local_immutable_durability
cargo test --locked -p fgit-forge --lib
cargo test --locked -p fgit-admission --lib --test native_merge_delivery_faults
cargo test --locked -p fgit-node --lib authentication
cargo test --locked -p fgit-node --test branch_http --test review_merge_http --test source_change_http --test source_rebase_http --test sealed_merge_publication --test sealed_native_merge_publication
