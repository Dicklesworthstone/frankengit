#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- outlives the runner's wall budget.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-timeout
fge_phase assert
fge_assert_eq FG-000A-TIMEOUT-001 ok ok 'an assertion lands before the stall'
fge_phase action
sleep 30
