#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- one assertion mismatches, the rest hold.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-assert-mismatch
fge_phase assert
fge_assert_eq FG-000A-MISMATCH-001 expected expected 'holds'
fge_assert_eq FG-000A-MISMATCH-002 expected actual   'mismatches on purpose'
fge_assert_eq FG-000A-MISMATCH-003 expected expected 'still runs after the failure'
