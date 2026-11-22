#!/usr/bin/env bash
# FG-049 source capture/library/command checks. HTTP peers are fixtures, not GitHub.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
node --version
node --check scripts/capture_github_issue_migration.mjs
node --check scripts/lib/github-issue-capture-migration.mjs
node --check scripts/lib/github-issue-source.mjs
node --check scripts/lib/github-source-http.mjs
node --check scripts/import_github_issues.mjs
node --test --test-concurrency=1 tests/operator/github_issue_capture_migration.test.mjs \
  tests/operator/github_issue_capture_command.test.mjs \
  tests/operator/github_issue_capture_compatibility.test.mjs \
  tests/operator/github_issue_lock_capture.test.mjs \
  tests/operator/github_issue_lock_migration.test.mjs \
  tests/operator/github_issue_assignee_mapping.test.mjs \
  tests/operator/github_issue_assignee_migration.test.mjs
