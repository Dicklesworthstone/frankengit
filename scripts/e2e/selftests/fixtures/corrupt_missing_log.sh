#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- the script exits 0 without leaving any
# NDJSON evidence at all.
set -uo pipefail
: "${FGE_RUN_DIR:?corrupting fixtures require FGE_RUN_DIR}"
mkdir -p "$FGE_RUN_DIR"
rm -f "$FGE_RUN_DIR/e2e.ndjson"
printf 'this script produced no evidence and still exited 0\n' >&2
exit 0
