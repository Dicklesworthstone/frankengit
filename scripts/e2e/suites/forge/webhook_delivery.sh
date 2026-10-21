#!/usr/bin/env bash
# FG-046: real prebuilt fg, canonical payloads and owned HTTP receivers.
# Rust unit/integration qualification remains a separate .4.57 acceptance gate.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init fg046-webhook-delivery
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.57
fge_context evidence_class native_cli_loopback_http
fge_context non_claim 'No canonical settlement, exactly-once delivery, HTTPS, Rust unit-test result, automatic backoff timing or power-loss proof.'
fge_phase setup
if [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ]; then
    fge_die 'FG_BIN must name a prebuilt native fg; this suite never runs Cargo'
fi
command -v python3 >/dev/null || fge_die 'Python 3 is required for the independent receiver'
fge_context fg_sha256 "$(fge_digest_file "$FG_BIN")"
work="$(fge_tempdir fg046-webhook)"
summary="$work/summary.json"
fge_phase action
fge_run_timeout 1200 native-webhook python3 "$E2E_ROOT/helpers/webhook_delivery.py" \
    --fg "$FG_BIN" --work "$work/campaign" --summary "$summary" || true
fge_assert_exit FG-046-NATIVE-001 0 "$FGE_LAST_EXIT" 'Native webhook campaign completed and receiver threads drained'
fge_phase assert
fact() {
    python3 - "$summary" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as source:
        result = json.load(source)
    valid = result.get("complete") is True and result.get("facts", {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f"webhook summary unavailable: {error}", file=sys.stderr)
    valid = False
print(str(valid).lower())
PY
}
index=2
for format in sha1 sha256; do
    for axis in ssrf_twins canonical_hmac_rotation refusal_before_send \
                down_retry_dead_letter live_replay fanout_restart_budget canonical_unsettled; do
        printf -v assertion 'FG-046-NATIVE-%03d' "$index"
        fge_assert_eq "$assertion" true "$(fact "${format}_${axis}")" "$format $axis through real fg"
        index=$((index + 1))
    done
done
if [ -f "$summary" ]; then fge_artifact "$summary" native-webhook-summary; fi
if [ -f "$work/campaign/commands.jsonl" ]; then
    fge_artifact "$work/campaign/commands.jsonl" native-command-journal
fi
for format in sha1 sha256; do
    if [ -f "$work/campaign/$format-receiver.jsonl" ]; then
        fge_artifact "$work/campaign/$format-receiver.jsonl" actual-http-requests
    fi
done
fge_note replay "$(fge_replay_command)"
