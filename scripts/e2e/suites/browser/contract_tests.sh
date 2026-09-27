#!/usr/bin/env bash
# e2e lane entry for the node:test browser contract tests (tests/browser/*.test.mjs).
#
# These run module logic against hand-written fake DOMs and fetch doubles. They
# are contract tests of the modules, NOT evidence that a page works in a
# browser: from 2026-09-18 to 2026-09-27, 1,731 of them passed while no
# API-calling page could make a request in Chrome (x2mv.4.45). The real-browser
# suites beside this one are that evidence. Registered by
# frankengit-root-doctrine-x2mv.4.18 so the contract tests run somewhere.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init
fge_kind js-unit
fge_context bead frankengit-root-doctrine-x2mv.4.18
fge_context non_claim 'Module contract tests on fake DOMs; says nothing about a real browser, the served CSP or the product binary.'

fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ]; then
  fge_skip JS-CONTRACT-001 'no Node: the browser contract tests cannot run here'
  exit 0
fi
fge_context node "$("$NODE" --version 2>&1)"
REPO_ROOT="$(cd "$E2E_ROOT/../.." && pwd)"
shopt -s nullglob
tests=("$REPO_ROOT"/tests/browser/*.test.mjs)
shopt -u nullglob
fge_assert_ne JS-CONTRACT-002 0 "${#tests[@]}" 'the browser contract test files are present'

fge_phase action
test_exit=0
fge_capture node-test "$NODE" --test "${tests[@]}" || test_exit=$?
summary=''
if [ -n "${FGE_LAST_STDOUT_FILE:-}" ] && [ -f "$FGE_LAST_STDOUT_FILE" ]; then
  summary=$(grep -E '^# (tests|pass|fail|cancelled|skipped|todo) ' "$FGE_LAST_STDOUT_FILE" | tr '\n' ' ')
  failing=$(grep -E '^not ok ' "$FGE_LAST_STDOUT_FILE" | head -40 | tr '\n' ';')
  fge_context tap_summary "$summary"
  fge_context failing_tests "$failing"
fi

fge_phase assert
fge_assert_contains JS-CONTRACT-003 "$summary" '# tests ' 'node:test produced a TAP summary'
fge_assert_exit JS-CONTRACT-001 0 "$test_exit" 'every browser contract test passes'
fge_phase teardown
