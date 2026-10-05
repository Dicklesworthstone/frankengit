#!/usr/bin/env bash
# e2e: canonical event frame parity, scoped disclosure and append-stable restart
# through prebuilt fg events, fg mcp, and fg serve-http. Bead: x2mv.4.35.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init scoped-event-feed
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.35
fge_context evidence_class real_binary_http_stdio_cli
fge_context non_claim 'Native issue fixture in SHA-1/SHA-256; PR hidden-ref policy is unit-covered. Not indexed O(limit), full forge history, long-poll, browser or TLS evidence.'
fge_phase setup
if [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ]; then
    fge_skip EVENT-FEED-001 'FG_BIN must identify a prebuilt native fg; no implicit build or substitute is allowed'
    exit 0
fi
if ! command -v python3 >/dev/null; then
    fge_skip EVENT-FEED-001 'Python 3 is absent; the real HTTP/MCP client cannot run'
    exit 0
fi
fge_context python "$(python3 --version 2>&1)"
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir scoped-event-feed)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 900 campaign python3 "$E2E_ROOT/scoped_events_smoke.py" \
    --fg "$FG_BIN" --work "$WORK/campaign" --summary "$SUMMARY" || true
fge_assert_exit EVENT-FEED-001 0 "$FGE_LAST_EXIT" 'actual fg commands, HTTP and MCP requests completed with owned children drained'
fge_phase assert
fact() {
    python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as source:
        summary = json.load(source)
    result = summary.get("complete") is True and summary.get("facts", {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f"event feed summary unavailable: {error}", file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
fge_assert_eq EVENT-FEED-002 true "$(fact sha1_parity_scopes_bounds)" 'SHA-1 canonical frame parity; independent read scopes; typed refusal and permitted twins'
fge_assert_eq EVENT-FEED-003 true "$(fact sha256_parity_scopes_bounds)" 'SHA-256 canonical frame parity; independent read scopes; typed refusal and permitted twins'
fge_assert_eq EVENT-FEED-004 true "$(fact sha1_restart_append_drain)" 'SHA-1 cursors survive process reopen and append; stale pin refuses; both services drain'
fge_assert_eq EVENT-FEED-005 true "$(fact sha256_restart_append_drain)" 'SHA-256 cursors survive process reopen and append; stale pin refuses; both services drain'
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" event-feed-summary; fi
if [ -f "$WORK/campaign/commands.jsonl" ]; then fge_artifact "$WORK/campaign/commands.jsonl" native-command-journal; fi
fge_note replay "$(fge_replay_command)"
