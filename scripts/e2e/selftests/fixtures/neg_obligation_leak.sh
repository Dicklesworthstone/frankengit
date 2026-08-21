#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- an obligation is opened and never closed.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-obligation-leak
fge_phase action
fge_obligation_open leaked-lease lease
fge_phase assert
fge_assert_eq FG-000A-OBLIG-001 ok ok 'the assertions themselves are healthy'
