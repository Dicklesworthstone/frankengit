#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- a step command fails.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-command-failure
fge_phase action
fge_run failing-step bash -c 'printf "boom\n" >&2; exit 7' || true
fge_phase assert
fge_assert_exit FG-000A-CMDFAIL-001 0 "$FGE_LAST_EXIT" 'the failing command was expected to succeed'
