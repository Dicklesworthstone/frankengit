#!/usr/bin/env bash
# e2e: fg serve-http, fg serve (git://) and fg serve-ssh advertise identical
# capabilities for one node.
# Bead: frankengit-root-doctrine-x2mv.4.8 (acceptance 4)
#
# scripts/e2e/transport_capability_parity.py serves one persisted node with
# each transport in turn and reads stock git's packet trace: the protocol-v2
# capability block, the v0 upload-pack capability list and the v0
# receive-pack capability list (git push --dry-run). Any capability one
# transport advertises and another does not fails its assertion by name.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init capability-parity
fge_context bead frankengit-root-doctrine-x2mv.4.8
fge_context evidence_class e2e_binary_stock_client
fge_context git_version "$(git --version)"
fge_context ssh_version "$(ssh -V 2>&1)"
fge_context non_claim 'One SHA-1 node, loopback, stock git and OpenSSH; compares advertised capability sets only, not the behaviour behind each capability.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd CAP-PARITY-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

fge_phase action
WORK="$(fge_tempdir capability-parity)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 900 campaign python3 "$E2E_ROOT/transport_capability_parity.py" \
  --fg "$FG_BIN" --summary "$SUMMARY" || true
fge_assert_exit CAP-PARITY-002 0 "$FGE_LAST_EXIT" \
  'every transport served its advertisements to stock git, including a dry-run push'
field() {
  python3 -c 'import json, sys; print(json.dumps(json.load(open(sys.argv[1]))[sys.argv[2]], sort_keys=True))' \
    "$SUMMARY" "$1" 2>/dev/null || echo missing
}
fge_context campaign_artifacts "$(field artifacts)"
fge_context capabilities "$(field capabilities)"

fge_phase assert
fge_assert_eq CAP-PARITY-010 '{}' "$(field upload_v2_differences)" \
  'the protocol-v2 capability block is identical over HTTP, git:// and SSH'
fge_assert_eq CAP-PARITY-011 '{}' "$(field upload_v0_differences)" \
  'the v0 upload-pack capability list is identical over HTTP, git:// and SSH'
fge_assert_eq CAP-PARITY-012 '{}' "$(field receive_v0_differences)" \
  'the v0 receive-pack capability list is identical over HTTP, git:// and SSH'

fge_phase teardown
