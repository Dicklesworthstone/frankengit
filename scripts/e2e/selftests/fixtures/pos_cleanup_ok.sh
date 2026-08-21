#!/usr/bin/env bash
# e2e-fixture: PERMITTED counterpart of neg_cleanup_failure.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-pos-cleanup-ok
fge_phase setup
fge_cleanup_register true
fge_phase assert
fge_assert_eq FG-000A-CLEANUPOK-001 ok ok 'a succeeding cleanup keeps the run green'
