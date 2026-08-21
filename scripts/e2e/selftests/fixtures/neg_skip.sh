#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- a skipped assertion is a terminal non-pass.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-skip
fge_phase assert
fge_assert_eq FG-000A-SKIP-001 ok ok 'a healthy assertion'
fge_skip      FG-000A-SKIP-002 'skipped on purpose'
