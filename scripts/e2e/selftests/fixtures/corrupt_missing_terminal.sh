#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- the terminal record is gone, so the run has
# no summary to be judged by.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lib=${FGE_LIB:-$(cd "$here/../.." && pwd)/lib.sh}
: "${FGE_RUN_DIR:?corrupting fixtures require FGE_RUN_DIR}"
rc=0
FGE_LIB="$lib" "$here/pos_control.sh" || rc=$?
log=$FGE_RUN_DIR/e2e.ndjson
tmp=$FGE_RUN_DIR/.corrupt.tmp
sed '$d' "$log" > "$tmp"
mv "$tmp" "$log"
exit "$rc"
