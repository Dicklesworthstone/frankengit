#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- fails on the first attempt and passes on the
# second. A retry that goes green must not launder the first attempt away.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-flaky-by-attempt
fge_phase assert
if [ "${FGE_ATTEMPT:-1}" -eq 1 ]; then
  fge_assert_eq FG-000A-FLAKY-001 pass fail 'first attempt fails on purpose'
else
  fge_assert_eq FG-000A-FLAKY-001 pass pass 'later attempts pass'
fi
