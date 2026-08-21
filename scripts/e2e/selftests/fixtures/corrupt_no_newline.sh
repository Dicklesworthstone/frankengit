#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- the stream is cut mid-write, so the log does
# not end with a newline.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lib=${FGE_LIB:-$(cd "$here/../.." && pwd)/lib.sh}
: "${FGE_RUN_DIR:?corrupting fixtures require FGE_RUN_DIR}"
rc=0
FGE_LIB="$lib" "$here/pos_control.sh" || rc=$?
log=$FGE_RUN_DIR/e2e.ndjson
bytes=$(wc -c < "$log")
tmp=$FGE_RUN_DIR/.corrupt.tmp
head -c "$((bytes - 12))" "$log" > "$tmp"
mv "$tmp" "$log"
exit "$rc"
