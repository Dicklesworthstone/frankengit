#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- one acceptance ID emitted twice.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-duplicate-id
fge_phase assert
fge_assert_eq FG-000A-DUP-001 a a 'first use of the id'
fge_assert_eq FG-000A-DUP-001 b b 'second use of the same id'
