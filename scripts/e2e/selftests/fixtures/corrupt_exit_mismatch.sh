#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- the terminal record disagrees with the
# process's real exit status. A script that exits 0 while its own summary says
# otherwise has broken the harness contract and is never credited as a pass.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lib=${FGE_LIB:-$(cd "$here/../.." && pwd)/lib.sh}
: "${FGE_RUN_DIR:?corrupting fixtures require FGE_RUN_DIR}"
rc=0
FGE_LIB="$lib" "$here/pos_control.sh" || rc=$?
log=$FGE_RUN_DIR/e2e.ndjson
tmp=$FGE_RUN_DIR/.corrupt.tmp
sed '$s/"terminal":{"status":"pass","exit_code":0/"terminal":{"status":"pass","exit_code":9/' \
  "$log" > "$tmp"
mv "$tmp" "$log"
exit "$rc"
