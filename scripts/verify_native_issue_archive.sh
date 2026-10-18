#!/usr/bin/env bash
# Local issue export/inspection lane. No hosted workflow or native-server claim.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --version
node --check scripts/lib/forge-issue-archive.mjs
node --check scripts/archive_native_issues.mjs
node --test tests/operator/forge_issue_archive.test.mjs \
  tests/operator/forge_issue_archive_cli.test.mjs \
  tests/operator/forge_issue_archive_capacity.test.mjs
