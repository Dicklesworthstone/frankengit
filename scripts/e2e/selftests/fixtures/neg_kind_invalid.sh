#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE. An evidence kind outside the closed set is
# refused by the library, so a script cannot invent a kind to be counted as.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-kind-invalid
fge_kind end-to-end
fge_phase assert
fge_assert_eq FG-000A-KIND-NEG-001 ok ok 'unreachable when the kind is refused'
