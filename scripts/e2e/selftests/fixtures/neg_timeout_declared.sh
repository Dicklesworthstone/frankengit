#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- outlives the runner's wall budget after
# declaring its evidence kind; the runner must still count it under that kind.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-timeout-declared
fge_kind e2e-binary
fge_phase assert
fge_assert_eq FG-000A-TIMEOUT-DECL-001 ok ok 'an assertion lands before the stall'
fge_phase action
sleep 30
