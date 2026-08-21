#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- the same artifact name registered twice with
# different bytes, which would otherwise erase the evidence an earlier
# assertion was judged against.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-artifact-collision
fge_phase action
p=$(fge_artifact_path shared/name.txt)
printf 'first content\n' > "$p"
fge_artifact shared/name.txt text
printf 'second content\n' > "$p"
fge_artifact shared/name.txt text || true
fge_phase assert
fge_assert_eq FG-000A-COLLIDE-001 ok ok 'the assertions themselves are healthy'
