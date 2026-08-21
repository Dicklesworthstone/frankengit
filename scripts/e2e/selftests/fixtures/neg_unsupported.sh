#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- a typed unsupported result is a terminal
# non-pass, not a quiet success.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-unsupported
fge_phase assert
fge_assert_eq   FG-000A-UNSUP-001 ok ok 'a healthy assertion'
fge_unsupported FG-000A-UNSUP-002 'unsupported on purpose'
