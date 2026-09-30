#!/usr/bin/env bash
# e2e: every served browser page boots, reads and (where it writes) commits one
# change in a real Chrome against a real fg serve-http, and the same action
# with a token lacking the scope is refused.
# Bead: frankengit-root-doctrine-x2mv.4.46. Drives a prebuilt fg serve-http and
# an installed Chrome through each page's own controls; not a cargo-test
# wrapper. Every write is read back through the HTTP API and a stock git clone.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init browser-pages
fge_kind real-browser
fge_context bead frankengit-root-doctrine-x2mv.4.46
fge_context evidence_class e2e_binary_real_browser
fge_context non_claim 'One headless Chrome build over loopback HTTP, SHA-1 only, one small repository. Each page is driven along one read and one write path; recovery receipts, conflict resolution, uploads other than one bundle, paging and every other control remain covered only by the tests/browser unit suites.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd PAGES-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
CHROME="${FGE_CHROME:-$(command -v google-chrome || command -v google-chrome-stable || command -v chromium || true)}"
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$CHROME" ] || [ -z "$NODE" ]; then
  fge_skip PAGES-002 'no installed Chrome or Node: the served pages cannot be driven here'
  exit 0
fi
fge_context browser "$("$CHROME" --version 2>&1 | head -1)"

fge_phase action
WORK="$(fge_tempdir browser-pages)"
SUMMARY="$WORK/summary.json"
# Inside the e2e lane's default 1800 s per-suite budget (scripts/verify.sh e2e).
fge_run_timeout 1500 campaign python3 "$E2E_ROOT/browser_pages_smoke.py" \
  --fg "$FG_BIN" --chrome "$CHROME" --node "$NODE" --summary "$SUMMARY" || true
fge_assert_exit PAGES-003 0 "$FGE_LAST_EXIT" 'the campaign seeded the node, drove Chrome and stopped the server'

fge_phase assert
fge_context observed_pages "$(python3 -c '
import json, sys
s = json.load(open(sys.argv[1]))
print(json.dumps([{"name": p["name"], "error": p["error"], "steps": {k: (v or {}).get("status") for k, v in p["steps"].items()}}
                  for p in s["browser"]["pages"]], sort_keys=True))' "$SUMMARY" 2>/dev/null || echo missing)"
fge_context observed_canonical "$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["canonical"], sort_keys=True))' "$SUMMARY" 2>/dev/null || echo missing)"
fge_context served_csp "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ui_csp"])' "$SUMMARY" 2>/dev/null || echo missing)"
fge_context driven_browser "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["browser"]["browser"])' "$SUMMARY" 2>/dev/null || echo missing)"

# One row per check: ID, true/false, description. A missing or malformed
# summary makes every row false rather than skipping it.
checks() {
  python3 - "$SUMMARY" <<'PY'
import json, re, sys

rows = []
def check(ident, description, predicate):
    try:
        ok = bool(predicate())
    except Exception:
        ok = False
    rows.append((ident, ok, description))

try:
    summary = json.load(open(sys.argv[1]))
except Exception:
    summary = {}
pages = {p["name"]: p for p in summary.get("browser", {}).get("pages", [])}
tips = summary.get("tips", {})
canonical = summary.get("canonical", {})

def step(name, label):
    return pages[name]["steps"][label]

def api(name, label):
    return [(a["path"].split("/api/v1/", 1)[1], a["status"]) for a in pages[name]["api"] if a["step"] == label]

def clean(name):
    # Allowed: the forbidden step's own 403, and Chrome refusing the page's
    # beforeunload guard (no user gesture) when a step navigates away from
    # unsent work. Anything else is a page defect.
    for error in pages[name]["errors"]:
        if error["kind"] == "log-intervention" and "beforeunload" in error["text"]:
            continue
        if error["step"] == "forbidden" and error["kind"] == "log-network" and "403 (Forbidden)" in error["text"]:
            continue
        return False
    return pages[name]["violations"] == []

# name: (read check, forbidden refusal text, mutation endpoint or None, write check)
REFUSED = "Required independent scope is missing or this endpoint is disabled."
PAGES = {
    "source": (lambda r: r["status"].startswith("Read complete") and "READMEfile" in r["listing"],
               "This token lacks read scope", None, None),
    "history": (lambda r: "Exact path history: README" in r["content"] and tips["main"] in r["content"] and tips["first"] in r["content"],
                "Source read permission is missing or disabled.", None, None),
    "search": (lambda r: r["status"] == "Server scan complete. Open a result to verify its file bytes." and "README : 2:20" in r["results"],
               REFUSED, None, None),
    "export-verify": (lambda r: r["status"].startswith("Every advertised reference, packed object and reachable Git dependency was checked.")
                      and '"pack_checksum_verified": true' in r["report"],
                      REFUSED, None, None),
    "transfers": (lambda r: r["status"].startswith("Complete snapshot-pinned export and reachable Git history verified.")
                  and '"pack_checksum_verified": true' in r["export"],
                  REFUSED, "source/bundle/fetch", lambda w: w["status"].startswith("Canonical committed: ")),
    "issues": (lambda r: "#1 Seeded issueopen · version 1" in r["listing"],
               "Required issue or outcome scope is missing", "issues/2/open", lambda w: w["status"].startswith("Committed · transaction ")),
    "pulls": (lambda r: "#1 · open · Seeded pull request" in r["listing"],
              REFUSED, "pulls/2/open", lambda w: w["status"].startswith("Canonical committed: transaction ")),
    "branches": (lambda r: f'"refs/heads/main" [726566732f68656164732f6d61696e] → {tips["main"]}' in r["listing"],
                 REFUSED, "source/branches/create", lambda w: w["status"].startswith("Canonical committed; transaction ")),
    "tags": (lambda r: "refs/tags/v1 · " in r["tags"] and f"refs/tags/v1-light · {tips['first']}" in r["tags"],
             REFUSED, "source/tags/lightweight", lambda w: w["status"].startswith("Native tag decision: committed; transaction ")),
    "initial": (lambda r: r["status"].startswith("Complete file/tree/commit identity matched native preparation.") and '"parents": []' in r["candidate"],
                REFUSED, "source/initial/apply", lambda w: w["status"].startswith("Canonical committed: ")),
    "rebase": (lambda r: r["status"].startswith("Both branches selected at one snapshot.") and tips["feature"] in r["selection"],
               REFUSED, "source/rebase/apply", lambda w: w["status"].startswith("Canonical committed: ")),
    "replay": (lambda r: r["status"].startswith("Both branch tips are pinned.") and tips["topic"] in r["selection"],
               REFUSED, "source/apply", lambda w: w["status"].startswith("Canonical committed: ")),
    # The replay page has already moved main, so the editor's base is the replayed commit.
    "source-edit": (lambda r: r["status"].startswith("Immutable base selected.") and canonical["refs/heads/main~1"]["commit"] in r["base"],
                    REFUSED, "source/apply", lambda w: w["status"].startswith("Canonical committed: ")),
}
number = 10
for name, (read, refusal, mutation, write) in PAGES.items():
    check(f"PAGES-{number:03d}", f"{name}: the page booted and every step ran to an observation",
          lambda: pages[name]["booted"] and pages[name]["error"] is None and all(not (v or {}).get("stopped") for v in pages[name]["steps"].values()))
    check(f"PAGES-{number + 1:03d}", f"{name}: no uncaught exception, console error, unexpected log error or CSP violation in any step",
          lambda: clean(name))
    check(f"PAGES-{number + 2:03d}", f"{name}: the full-scope read shows the seeded repository",
          lambda: read(step(name, "read")))
    if mutation is None:
        check(f"PAGES-{number + 3:03d}", f"{name}: without read scope the same read is answered 403 and the page says so",
              lambda: refusal in step(name, "forbidden")["status"] and api(name, "forbidden")[-1][1] == 403
              and all(status == 200 for _, status in api(name, "read")))
    else:
        check(f"PAGES-{number + 3:03d}", f"{name}: the read-only token's write is refused 403 at {mutation} and the page says so",
              lambda: refusal in step(name, "forbidden")["status"] and (mutation, 403) in api(name, "forbidden")
              and all(status == 200 for path, status in api(name, "forbidden") if path != mutation))
        check(f"PAGES-{number + 4:03d}", f"{name}: the same write with the full token is committed through {mutation}",
              lambda: write(step(name, "write")) and (mutation, 200) in api(name, "write")
              and all(status == 200 for _, status in api(name, "write")))
    number += 10

refs = canonical.get("refs", {})
check("PAGES-200", "the issue opened in the page is canonical, once: issue 2 at version 1 beside the seeded issue",
      lambda: canonical["issues"] == [[1, 1, "Seeded issue"], [2, 1, "Opened in Chrome"]])
check("PAGES-201", "the pull request opened in the page is canonical, once: PR 2 at version 1",
      lambda: canonical["pulls"] == [[1, 1, "Seeded pull request"], [2, 1, "Opened in Chrome"]])
check("PAGES-202", "stock git sees the page-created branch and lightweight tag at the main tip they were made from",
      lambda: refs["refs/heads/created-in-ui"] == tips["main"] and refs["refs/tags/ui-light"] == tips["main"])
check("PAGES-203", "stock git sees the bundle-mapped branch at the bundled commit the node had never held",
      lambda: refs["refs/heads/imported"] == tips["bundled"])
check("PAGES-204", "the initial-commit page made a root commit holding exactly hello.txt",
      lambda: canonical["refs/heads/fresh"]["parents"] == [] and canonical["refs/heads/fresh"]["files"] == ["hello.txt"]
      and canonical["refs/heads/fresh"]["subject"] == "Initial commit from the served page")
check("PAGES-205", "the rebase page rewrote feature onto the main tip it selected, keeping the feature change",
      lambda: canonical["refs/heads/feature"]["parents"] == [tips["main"]] and canonical["refs/heads/feature"]["commit"] != tips["feature"]
      and "src/feature.rs" in canonical["refs/heads/feature"]["files"] and canonical["refs/heads/feature"]["subject"] == "feature work")
check("PAGES-206", "the cherry-pick page replayed the topic commit onto the seeded main tip",
      lambda: canonical["refs/heads/main~1"]["parents"] == [tips["main"]] and "src/topic.rs" in canonical["refs/heads/main~1"]["files"]
      and canonical["refs/heads/main~1"]["subject"] == "Replay the topic commit from the served page")
check("PAGES-207", "the source editor committed notes.txt on top of the replayed commit",
      lambda: canonical["refs/heads/main"]["parents"] == [canonical["refs/heads/main~1"]["commit"]]
      and "notes.txt" in canonical["refs/heads/main"]["files"] and "src/topic.rs" in canonical["refs/heads/main"]["files"]
      and canonical["refs/heads/main"]["subject"] == "Add notes from the served source editor")
check("PAGES-208", "git fsck --strict accepts the clone of everything the pages wrote",
      lambda: canonical["fsck"]["exit"] == 0)
check("PAGES-209", "the probe exited 0 and the continuous server drained on its stop file",
      lambda: summary["browser_probe_exit"] == 0 and summary["server_drained_exit"] == 0)
check("PAGES-210", "the served UI carries the strict same-origin CSP",
      lambda: summary["ui_status"] == 200 and "script-src 'self'" in summary["ui_csp"] and "connect-src 'self'" in summary["ui_csp"])
for ident, ok, description in rows:
    print(f"{ident}\t{str(ok).lower()}\t{description}")
PY
}

rows=0
while IFS=$'\t' read -r ident observed description; do
  fge_assert_eq "$ident" true "$observed" "$description"
  rows=$((rows + 1))
done < <(checks)
# 4 read-only pages x 4 checks + 9 writing pages x 5 checks + 11 canonical checks.
fge_assert_eq PAGES-299 72 "$rows" 'every planned check produced a row'

fge_phase teardown
