#!/usr/bin/env bash
# e2e: stock git exercises partial clone (every served filter, lazy fetch, the
# sparse refusal twins), refs/notes/*, superproject gitlinks, atomic push and
# absent-ref deletion and push options through fg serve-http, fg serve (git://) and fg serve-ssh, in
# SHA-1 and SHA-256 repositories.
# Beads: frankengit-root-doctrine-x2mv.4.33; push options frankengit-321s
# Conditional absent-ref deletion: frankengit-l6mb
#
# scripts/e2e/helpers/stock_transport_capabilities.py imports one source into
# a fresh node per transport and records one check per capability; this suite
# asserts every check id. It runs once with the host git and, when the pinned
# oracle is installed, again with that git (the oracle is relocated out of its
# build prefix, so its exec path is passed explicitly).
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init stock-transport-capabilities
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.33
fge_context evidence_class e2e_binary_stock_client
fge_context git_version "$(git --version)"
fge_context ssh_version "$(ssh -V 2>&1)"
fge_context non_claim 'One node per transport, loopback, stock git and OpenSSH; filters are checked by omission and lazy-fetch content, not by pack bytes; fg serves no sparse filter, and its refusal is the claim.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd TCAP-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
ORACLE_ROOT=${FGIT_ORACLE_ROOT:-$HOME/.cache/frankengit/git-oracle}
PIN=git-2.54.0
PINNED="$ORACLE_ROOT/installs/$PIN"

WORK="$(fge_tempdir stock-transport-capabilities)"
# campaign LABEL SUMMARY [helper args...]: run the helper, then assert every check id it recorded.
campaign() {
  local label=$1 summary=$2
  shift 2
  fge_phase action
  fge_run_timeout 3600 "campaign-$label" python3 "$E2E_ROOT/helpers/stock_transport_capabilities.py" \
    --fg "$FG_BIN" --summary "$summary" "$@" || true
  fge_assert_exit "TCAP-$label-campaign" 0 "$FGE_LAST_EXIT" "the $label campaign completed and wrote its summary"
  fge_phase assert
  local rows
  rows=$(python3 -c '
import json, sys
summary = json.load(open(sys.argv[1]))
print("git\t" + summary.get("git", "unknown"))
for check, row in sorted(summary.get("checks", {}).items()):
    print(check + "\t" + ("true" if row["ok"] else "false") + "\t" + row["detail"].replace("\t", " ").replace("\n", " / ")[:300])
' "$summary" 2>/dev/null || true)
  [ -n "$rows" ] || fge_assert_eq "TCAP-$label-summary" present absent "the $label summary is readable"
  local check ok detail
  while IFS=$'\t' read -r check ok detail; do
    if [ "$check" = git ]; then
      fge_context "git_version_$label" "$ok"
      continue
    fi
    fge_assert_eq "TCAP-$label-$check" true "$ok" "$check ($detail)"
  done <<< "$rows"
}

campaign host "$WORK/host.json"
if [ -x "$PINNED/bin/git" ]; then
  campaign pinned "$WORK/pinned.json" --git-bin "$PINNED/bin" --git-exec-path "$PINNED/libexec/git-core"
else
  fge_note TCAP-pinned "pinned oracle $PIN not installed at $PINNED; only the host git ran"
fi
fge_artifact "$WORK/host.json" json

fge_phase teardown
