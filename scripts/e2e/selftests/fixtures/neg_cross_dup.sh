#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- claims an acceptance ID that pos_control.sh
# already owns. One acceptance ID has exactly one owning script; two claimants
# make the aggregate set ambiguous.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-cross-dup
fge_phase assert
fge_assert_eq FG-000A-CTL-001 ok ok 'an id already owned by pos_control.sh'
