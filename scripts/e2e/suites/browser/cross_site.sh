#!/usr/bin/env bash
# e2e: a page on another origin cannot make a real Chrome change repository
# state through fg serve-http, while the served pages' own clients still can.
# Bead: frankengit-root-doctrine-x2mv.4.31. Drives a prebuilt fg serve-http and
# an installed Chrome; not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init browser-cross-site
fge_kind real-browser
fge_context bead frankengit-root-doctrine-x2mv.4.31
fge_context evidence_class e2e_binary_real_browser
fge_context non_claim 'One Chrome build over loopback HTTP. The attacker page carries no credential, so it shows the Origin/Sec-Fetch-Site guard firing before authentication; the ambient-Basic refusal is proven by crates/fgit-node/tests/issue_http.rs, not by a browser-cached credential here.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd CROSS-SITE-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
CHROME="${FGE_CHROME:-$(command -v google-chrome || command -v google-chrome-stable || command -v chromium || true)}"
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$CHROME" ] || [ -z "$NODE" ]; then
  fge_skip CROSS-SITE-002 'no installed Chrome or Node: the browser-sent Origin and Sec-Fetch-Site cannot be observed here'
  exit 0
fi
fge_context browser "$("$CHROME" --version 2>&1 | head -1)"

fge_phase action
WORK="$(fge_tempdir browser-cross-site)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 900 campaign python3 "$E2E_ROOT/browser_cross_site_smoke.py" \
  --fg "$FG_BIN" --chrome "$CHROME" --node "$NODE" --summary "$SUMMARY" || true
fge_assert_exit CROSS-SITE-003 0 "$FGE_LAST_EXIT" 'the campaign reached the browser and stopped the server'

fact() { # predicate over the summary s -> true/false
  python3 -c '
import json, sys
s = json.load(open(sys.argv[1]))
attack = {a["relation"]: a for a in s.get("browser", {}).get("attacks", [])}
twin = {t["client"]: t for t in s.get("browser", {}).get("twins", [])}
print(str(bool(eval(sys.argv[2]))).lower())' "$SUMMARY" "$1" 2>/dev/null || echo false
}

fge_phase assert
fge_context observed_attacks "$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["browser"]["attacks"], sort_keys=True))' "$SUMMARY" 2>/dev/null || echo missing)"
fge_context observed_twins "$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["browser"]["twins"], sort_keys=True))' "$SUMMARY" 2>/dev/null || echo missing)"
n=4
for relation in cross-site same-site; do
  fge_assert_eq "CROSS-SITE-$(printf '%03d' "$n")" true \
    "$(fact "[r[\"site\"] for r in attack[\"$relation\"][\"fetch\"][\"api\"]] == [\"$relation\"] and attack[\"$relation\"][\"fetch\"][\"api\"][0][\"origin\"] == attack[\"$relation\"][\"origin\"]")" \
    "Chrome sent the $relation fetch with the attacker's Origin and Sec-Fetch-Site: $relation"
  n=$((n + 1))
  fge_assert_eq "CROSS-SITE-$(printf '%03d' "$n")" true \
    "$(fact "[r[\"status\"] for r in attack[\"$relation\"][\"fetch\"][\"api\"]] == [403]")" \
    "the $relation no-cors fetch was answered 403 before any route ran"
  n=$((n + 1))
  fge_assert_eq "CROSS-SITE-$(printf '%03d' "$n")" true \
    "$(fact "[(r[\"status\"], r[\"site\"]) for r in attack[\"$relation\"][\"form\"][\"api\"]] == [(403, \"$relation\")] and attack[\"$relation\"][\"form\"][\"value\"].startswith(\"cross-site request refused\")")" \
    "the $relation top-level form submission shows the typed 403 refusal body"
  n=$((n + 1))
done
fge_assert_eq CROSS-SITE-010 true \
  "$(fact 'twin["IssueClient"]["value"]["resolved"] is True and [(r["method"], r["status"], r["site"]) for r in twin["IssueClient"]["api"]] == [("POST", 200, "same-origin")]')" \
  "the served issue page's own client opened issue 1: a same-origin POST answered 200"
fge_assert_eq CROSS-SITE-011 true \
  "$(fact 'twin["HistoryClient"]["value"]["resolved"] is True and len(twin["HistoryClient"]["api"]) >= 1 and all(r["method"] == "POST" and r["status"] == 200 and r["site"] == "same-origin" and r["origin"] == "null" for r in twin["HistoryClient"]["api"])')" \
  "the history client's same-origin POSTs, sent with Origin: null under no-referrer, were answered 200"
fge_assert_eq CROSS-SITE-012 true \
  "$(fact 's["issues"] == [{"number": 1, "title": "same-origin twin"}]')" \
  'a non-browser read lists exactly the twin issue; nothing forged was published'
fge_assert_eq CROSS-SITE-013 true \
  "$(fact 's["browser"].get("exceptions") == [] and s.get("server_drained_exit") == 0 and s.get("browser_probe_exit") == 0')" \
  'no uncaught page exception, the probe exited 0, and the continuous server drained on its stop file'

fge_phase teardown
