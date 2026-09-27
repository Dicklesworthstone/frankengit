#!/usr/bin/env bash
# e2e: every browser API client, on its own served page in a real Chrome,
# reaches the API through the platform fetch with its production defaults.
# Bead: frankengit-root-doctrine-x2mv.4.45 (acceptance 4). Drives a prebuilt
# fg serve-http and an installed Chrome; not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init browser-client-fetch
fge_kind real-browser
fge_context bead frankengit-root-doctrine-x2mv.4.45
fge_context evidence_class e2e_binary_real_browser
fge_context non_claim 'One read per client class on its own page (issues, pulls, history) in one Chrome build; not a UI flow test of every page (x2mv.4.46).'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd CLIENT-FETCH-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
CHROME="${FGE_CHROME:-$(command -v google-chrome || command -v google-chrome-stable || command -v chromium || true)}"
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$CHROME" ] || [ -z "$NODE" ]; then
  fge_skip CLIENT-FETCH-002 'no installed Chrome or Node: the platform fetch cannot be observed here'
  exit 0
fi
fge_context browser "$("$CHROME" --version 2>&1 | head -1)"

fge_phase action
WORK="$(fge_tempdir browser-client-fetch)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 900 campaign python3 "$E2E_ROOT/browser_client_fetch_smoke.py" \
  --fg "$FG_BIN" --chrome "$CHROME" --node "$NODE" --summary "$SUMMARY" || true
fge_assert_exit CLIENT-FETCH-003 0 "$FGE_LAST_EXIT" 'the campaign reached the browser and stopped the server'

page() { # client -> JSON of that client's observation, or missing
  python3 -c '
import json, sys
s = json.load(open(sys.argv[1]))
match = [p for p in s.get("browser", {}).get("pages", []) if p.get("client") == sys.argv[2]]
print(json.dumps(match[0] if match else None, sort_keys=True))' "$SUMMARY" "$1" 2>/dev/null || echo missing
}
fact() { # client, predicate over p -> true/false
  python3 -c '
import json, sys
s = json.load(open(sys.argv[1]))
match = [p for p in s.get("browser", {}).get("pages", []) if p.get("client") == sys.argv[2]]
p = match[0] if match else {}
print(str(bool(match) and bool(eval(sys.argv[3]))).lower())' "$SUMMARY" "$1" "$2" 2>/dev/null || echo false
}

fge_phase assert
n=4
for client in IssueClient Transport HistoryClient; do
  fge_context "observed_$client" "$(page "$client")"
  fge_assert_eq "CLIENT-FETCH-$(printf '%03d' "$n")" true \
    "$(fact "$client" 'p["resolved"] is True and p["error"] is None')" \
    "$client resolved one read on its own page with the platform fetch"
  n=$((n + 1))
  fge_assert_eq "CLIENT-FETCH-$(printf '%03d' "$n")" true \
    "$(fact "$client" 'len(p["api"]) >= 1 and all(r["status"] == 200 for r in p["api"])')" \
    "$client's request reached the served API and was answered 200, as the network layer recorded it"
  n=$((n + 1))
done
fge_assert_eq CLIENT-FETCH-010 true \
  "$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(str(s["browser"].get("exceptions") == [] and s.get("server_drained_exit") == 0).lower())' "$SUMMARY" 2>/dev/null || echo false)" \
  'no uncaught page exception, and the continuous server drained on its stop file'

fge_phase teardown
