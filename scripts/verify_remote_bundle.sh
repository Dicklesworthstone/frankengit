#!/usr/bin/env bash
# Operator/HTTP schema and custody tests, not a Rust fg/admission/CAS gate.
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for module in scripts/operator/remote_bundle{,_protocol,_http,_files,_export}.mjs scripts/remote_bundle.mjs; do
  node --check "$module"
done
node --test tests/operator/remote_bundle.test.mjs tests/operator/remote_bundle_export.test.mjs \
  tests/operator/remote_bundle_cli.test.mjs
