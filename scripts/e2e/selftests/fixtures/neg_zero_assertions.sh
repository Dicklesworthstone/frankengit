#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- exits 0 having proved nothing.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-zero-assertions
fge_phase action
fge_run looks-busy true
fge_step done 'plenty of activity, zero assertions'
