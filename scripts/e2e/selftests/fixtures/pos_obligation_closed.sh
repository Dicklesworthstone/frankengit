#!/usr/bin/env bash
# e2e-fixture: PERMITTED counterpart of neg_obligation_leak.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-pos-obligation-closed
fge_phase action
fge_obligation_open honoured-lease lease
fge_obligation_close honoured-lease
fge_phase assert
fge_assert_eq FG-000A-OBLIGOK-001 ok ok 'a balanced obligation keeps the run green'
