#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Focused external-client tests. Native-schema peers are not the Rust fg server;
# installed Git is a test oracle, not the pinned native conformance lane.
node --version
git --version
openssl version
node --test scripts/tests/source_changes.test.mjs \
  scripts/tests/source_changes_prepare.test.mjs \
  scripts/tests/source_changes_cli.test.mjs
