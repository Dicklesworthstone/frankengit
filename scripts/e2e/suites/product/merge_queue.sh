#!/usr/bin/env bash
# Fresh native fg processes, real canonical queue admission, both Git hash domains.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init product-merge-queue
fge_kind e2e-binary
fge_context bead frankengit-fg083a-merge-queue-impl-95fm
fge_context non_claim 'Canonical queue management; no speculative batches, required-check execution or merge landing.'
: "${FG_BIN:?Supply the compiled native fg binary}"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
work="$(fge_tempdir merge-queue)"
fge_phase action
for format in sha1 sha256; do
  fge_run_timeout 900 "FG-083A-QUEUE-${format}" python3 "$E2E_ROOT/merge_queue_smoke.py" \
    --fg "$FG_BIN" --root "$work" --format "$format"
  fge_assert_exit "FG-083A-QUEUE-${format}-RESULT" 0 "$FGE_LAST_EXIT"
  if [[ -f "$work/$format/results.json" ]]; then
    cp "$work/$format/results.json" "$(fge_artifact_path "${format}-results.json")"
    fge_artifact "${format}-results.json" json
  fi
done
fge_phase assert
