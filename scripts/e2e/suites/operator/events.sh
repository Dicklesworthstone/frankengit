#!/usr/bin/env bash
# Shipped event archive CLI -> real native HTTP, restart and canonical frames.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-events
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Small SHA1/SHA256 native issue history and local archive; no Git oracle, PR hidden-ref proof, TLS, crash durability, hostile isolation, same-source native or every operator qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-EVENTS-001 'A supplied prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir operator-events)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 300 campaign python3 "$E2E_ROOT/operator_events_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$WORK/campaign" --summary "$SUMMARY" || true
fge_assert_exit OPERATOR-EVENTS-002 0 "$FGE_LAST_EXIT" 'actual event CLI lifecycle and native canonical reads complete'
fge_phase assert
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'event operator summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  for property in local_init_and_partial_capture restart_append_exact_native_frames readonly_inspection_and_tail_twins quiet_watch_and_no_growth credential_and_grant_twins filtered_pages_advance_without_disclosure tamper_refuses_without_mutation saved_records_private_and_opaque disabled_scope_refuses_without_archive_change owned_services_drained; do
    fge_assert_eq "OPERATOR-EVENTS-$format-$property" true "$(fact "${format}_$property")" "native event operator $property"
  done
done
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" operator-events-summary; fi
if [ -f "$WORK/campaign/commands.jsonl" ]; then fge_artifact "$WORK/campaign/commands.jsonl" native-operator-command-journal; fi
fge_phase teardown
