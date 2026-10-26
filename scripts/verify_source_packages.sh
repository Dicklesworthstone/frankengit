#!/usr/bin/env bash
# Operator/package lane. Native cases require an explicitly supplied FG_NATIVE_BIN.
set -euo pipefail
cd "$(dirname "$0")/.."
node --version
for file in scripts/fg_source_package.mjs scripts/operator/source_package.mjs scripts/operator/source_package_native.mjs \
  scripts/tests/source_package_fixture.mjs scripts/tests/source_package_operator.test.mjs \
  scripts/tests/source_package_cli.test.mjs scripts/tests/source_package_native.test.mjs; do
  node --check "$file"
done
# Preserve the existing client group. Native server/process campaigns run after
# it so they do not starve the client's short, whole-operation deadline controls.
client_status=0
native_status=0
node --test scripts/tests/source_package_operator.test.mjs scripts/tests/source_package_cli.test.mjs || client_status=$?
node --test scripts/tests/source_package_native.test.mjs || native_status=$?
if ((client_status != 0)); then exit "$client_status"; fi
exit "$native_status"
