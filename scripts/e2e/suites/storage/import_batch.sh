#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'import batch verification requires a prebuilt native FG_BIN' >&2
    exit 2
fi
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init import-batch
fge_kind e2e-binary
fge_context bead frankengit-pc9g
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context non_claim 'Real process death and durable import recovery, not physical power-loss testing or the final throughput target.'
WORK="$(fge_tempdir import-batch)"
fge_phase action
fge_run_timeout 180 IMPORT-BATCH-001 python3 "$E2E_ROOT/helpers/import_batch.py" "$FG_BIN" "$WORK"
fge_assert_exit IMPORT-BATCH-002 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_artifact "$WORK/results.json" import_batch
fge_note IMPORT-BATCH-003 'Both native hash domains cross multiple batches, retain exact payloads after cold reopen, leave refs unchanged after killed partial placement, and recover with unchanged object bytes.'
