#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- a spawned child ignores SIGTERM and must be
# killed at teardown, which is a containment failure rather than a tidy exit.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-orphan-child
fge_phase action
fge_spawn stubborn bash -c 'trap "" TERM; sleep 30'
fge_phase assert
fge_assert_eq FG-000A-ORPHAN-001 ok ok 'the assertions themselves are healthy'
