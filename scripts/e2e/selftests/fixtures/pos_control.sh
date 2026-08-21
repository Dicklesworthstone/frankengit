#!/usr/bin/env bash
# e2e-fixture: PERMITTED control. Every planted negative in this directory has
# this as its near-identical permitted counterpart.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-pos-control
fge_phase action
fge_run true-step true
fge_phase assert
fge_assert_exit FG-000A-CTL-001 0 "$FGE_LAST_EXIT" 'the control command succeeds'
fge_assert_eq   FG-000A-CTL-002 ok ok              'the control assertion holds'
