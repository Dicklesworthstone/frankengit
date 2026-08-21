#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- a healthy run whose log is then corrupted so
# one line is no longer a complete JSON object.
#
# The corrupting fixtures run pos_control.sh into the SAME run directory and
# then mutate its NDJSON. Producing a realistic log and damaging it is the only
# way to test the validator against the failure it actually has to catch; a
# hand-written stub would test a strawman.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lib=${FGE_LIB:-$(cd "$here/../.." && pwd)/lib.sh}
: "${FGE_RUN_DIR:?corrupting fixtures require FGE_RUN_DIR}"
rc=0
FGE_LIB="$lib" "$here/pos_control.sh" || rc=$?
log=$FGE_RUN_DIR/e2e.ndjson
tmp=$FGE_RUN_DIR/.corrupt.tmp
{ sed -n '1p' "$log"; sed -n '2p' "$log" | sed 's/}$//'; sed -n '3,$p' "$log"; } > "$tmp"
mv "$tmp" "$log"
exit "$rc"
