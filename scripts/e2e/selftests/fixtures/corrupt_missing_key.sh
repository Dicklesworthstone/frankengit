#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- a record loses a required base key while
# staying perfectly well-formed JSON. This is the case a shape-blind validator
# passes: the line parses, so only an explicit required-key check catches it.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lib=${FGE_LIB:-$(cd "$here/../.." && pwd)/lib.sh}
: "${FGE_RUN_DIR:?corrupting fixtures require FGE_RUN_DIR}"
rc=0
FGE_LIB="$lib" "$here/pos_control.sh" || rc=$?
log=$FGE_RUN_DIR/e2e.ndjson
tmp=$FGE_RUN_DIR/.corrupt.tmp
# Drop the "replay" member from the second record, leaving valid JSON.
sed '2s/,"replay":"[^"]*"//' "$log" > "$tmp"
mv "$tmp" "$log"
exit "$rc"
