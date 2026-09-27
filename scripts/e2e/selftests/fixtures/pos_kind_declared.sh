#!/usr/bin/env bash
# e2e-fixture: PERMITTED control that declares its evidence kind. Its twin,
# pos_control.sh, declares none and must be reported as undeclared.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-pos-kind-declared
fge_kind e2e-binary
fge_phase action
fge_run true-step true || true
fge_phase assert
fge_assert_exit FG-000A-KIND-001 0 "$FGE_LAST_EXIT" 'the declared-kind control command succeeds'
