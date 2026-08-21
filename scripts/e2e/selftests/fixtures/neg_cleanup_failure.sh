#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- every assertion passes but cleanup fails.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-cleanup-failure
fge_phase setup
fge_cleanup_register bash -c 'exit 5'
fge_phase assert
fge_assert_eq FG-000A-CLEANUP-001 ok ok 'the body of the run is entirely healthy'
