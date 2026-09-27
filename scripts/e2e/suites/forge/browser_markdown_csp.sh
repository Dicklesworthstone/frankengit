#!/usr/bin/env bash
# e2e: issue Markdown rendered by fgit-doc and displayed by the browser shell,
# in a real Chrome, under the Content-Security-Policy the server actually sends.
# Bead: frankengit-root-doctrine-x2mv.4.11 (acceptance 1 and 4). Drives a
# prebuilt fg serve-http and an installed Chrome; not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init browser-markdown-csp
fge_context bead frankengit-root-doctrine-x2mv.4.11
fge_context evidence_class e2e_binary_real_browser
fge_context non_claim 'One issue body on the issues page in one Chrome build on Linux; not PR, comment or review rendering, not other browsers, and not a sanitizer proof.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd MD-CSP-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
CHROME="${FGE_CHROME:-$(command -v google-chrome || command -v google-chrome-stable || command -v chromium || true)}"
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$CHROME" ] || [ -z "$NODE" ]; then
  fge_skip MD-CSP-002 'no installed Chrome or Node: the real-browser rendering cannot be observed here'
  exit 0
fi
fge_context browser "$("$CHROME" --version 2>&1 | head -1)"
fge_context node "$("$NODE" --version 2>&1)"

fge_phase action
WORK="$(fge_tempdir browser-markdown-csp)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 900 campaign python3 "$E2E_ROOT/browser_markdown_smoke.py" \
  --fg "$FG_BIN" --chrome "$CHROME" --node "$NODE" --summary "$SUMMARY" || true
fge_assert_exit MD-CSP-003 0 "$FGE_LAST_EXIT" 'the campaign reached the browser and stopped the server'

# One predicate over the recorded facts; prints true or false, never hides a
# missing summary (a missing file is false).
fact() {
  python3 - "$SUMMARY" "$1" <<'PY' 2>/dev/null || echo false
import json, sys
from html.parser import HTMLParser
s = json.load(open(sys.argv[1]))
b = s.get("browser", {})
html = (s.get("http_rendered_html") or "")
csp = s.get("http_ui_csp") or ""
class Elements(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found = []
    def handle_starttag(self, tag, attrs):
        self.found.append((tag, dict(attrs)))
parsed = Elements()
parsed.feed(html)
tags = [tag for tag, _ in parsed.found]
attrs = [(name.lower(), (value or "").strip().lower()) for _, a in parsed.found for name, value in a.items()]
print(str(bool(eval(sys.argv[2]))).lower())
PY
}
context() {
  python3 -c 'import json, sys; s = json.load(open(sys.argv[1])); print(json.dumps(eval(sys.argv[2]), sort_keys=True))' \
    "$SUMMARY" "$1" 2>/dev/null || echo missing
}
fge_context campaign_artifacts "$(context 's.get("artifacts")')"
fge_context http_ui_csp "$(context 's.get("http_ui_csp")')"
fge_context browser_version "$(context 's.get("browser", {}).get("browser")')"

fge_phase assert
fge_assert_eq MD-CSP-004 true "$(fact 's.get("http_plain_status") == 200 and s.get("http_rendered_status") == 200')" \
  'the issue reads back over HTTP both as stored text and with render=html_safe'
fge_assert_eq MD-CSP-005 true "$(fact 's.get("http_canonical_body_unchanged") is True and s.get("http_source_sha256_matches") is True')" \
  'rendering is derived: the canonical body is byte-identical and the presentation names its source digest'
fge_assert_eq MD-CSP-006 true "$(fact 'all(m in html for m in ["heading-marker", "bold-marker", "em-marker", "list-marker", "https://example.com/ok"])')" \
  'permitted twin: benign Markdown structure survives server rendering'
fge_assert_eq MD-CSP-007 true "$(fact 'not set(tags) & {"script", "svg", "iframe", "object", "embed", "img", "style", "form"} and not any(n.startswith("on") for n, _ in attrs) and not any(n in ("href", "src") and v.startswith(("javascript:", "data:", "vbscript:")) for n, v in attrs)')" \
  'the server-rendered HTML contains no script, SVG, frame, image, style or form element, no event-handler attribute and no dangerous URL'
fge_assert_eq MD-CSP-020 true "$(fact 'html.count("data-fgit-doc-rejected") == 5 and "&lt;script&gt;" in html')" \
  'each of the five hostile constructs is kept visible as rejected, escaped source rather than dropped silently'
fge_assert_eq MD-CSP-008 true "$(fact 's.get("http_ui_status") == 200 and "script-src '"'"'self'"'"'" in csp and "unsafe-inline" not in csp and "default-src '"'"'none'"'"'" in csp')" \
  'the served issues document carries a CSP with script-src self, default-src none and no unsafe-inline'
fge_assert_eq MD-CSP-009 true "$(fact 'b.get("document_headers_observed") is True and b.get("csp_header") == csp')" \
  'the browser observed the same CSP header on the document it rendered'
fge_assert_eq MD-CSP-010 true "$(fact 'b.get("outcome") == "rendered"')" \
  'the browser shell displayed the derived Markdown presentation, not the refusal fallback'
fge_assert_eq MD-CSP-011 true "$(fact 'any("heading-marker" in h for h in b.get("headings", [])) and any("bold-marker" in x for x in b.get("strong", [])) and any("em-marker" in x for x in b.get("emphasis", [])) and any("list-marker" in x for x in b.get("list_items", []))')" \
  'permitted twin in the browser: heading, strong, emphasis and list elements are real DOM elements'
fge_assert_eq MD-CSP-012 true "$(fact 'any(l.get("href") == "https://example.com/ok" for l in b.get("links", [])) and b.get("javascript_links") == 0')" \
  'the safe link is a link; no element carries a javascript: URL'
fge_assert_eq MD-CSP-013 true "$(fact 'b.get("pwned") is None')" \
  'no hostile construct executed (window.__fgitPwned unset)'
fge_assert_eq MD-CSP-014 true "$(fact 'b.get("event_handler_attributes") == [] and b.get("iframes") == 0 and b.get("svg_elements") == 0')" \
  'no event-handler attribute, frame, object, embed or SVG element exists anywhere in the page'
fge_assert_eq MD-CSP-015 true "$(fact 'not any(str(i).startswith(("data:", "javascript:")) for i in b.get("images", []))')" \
  'no image source uses a data: or javascript: URL'
fge_assert_eq MD-CSP-016 true "$(fact '"inline" not in b.get("scripts", []) and len(b.get("scripts", [])) > 0')" \
  'every script in the page is an external same-origin module; none is inline'
fge_assert_eq MD-CSP-017 true "$(fact 'b.get("violations") == [] and b.get("csp_log_entries") == []')" \
  'no CSP violation occurred: nothing hostile reached the DOM for the policy to block'
fge_assert_eq MD-CSP-018 true "$(fact 'b.get("exceptions") == [] and b.get("console_errors") == []')" \
  'the page raised no uncaught exception and logged no console error'
fge_assert_eq MD-CSP-019 true "$(fact 's.get("browser_probe_exit") == 0 and s.get("server_drained_exit") == 0')" \
  'the probe exited cleanly and the continuous server drained on its stop file'

fge_phase teardown
