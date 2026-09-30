#!/usr/bin/env bash
# e2e: a stock `git fetch` of a changed large file receives a thin pack over
# fg serve (git://) and fg serve-http, on protocol 0, 1 and 2. Stock git
# completes it (fsck --strict) at the source head. A fetch-pack without --thin
# gets a self-contained pack. Bead: frankengit-pazc (acceptance 2; served half
# of 3). Not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init thin-fetch
fge_kind e2e-binary
fge_context bead frankengit-pazc
fge_context evidence_class e2e_binary_stock_client
fge_context git_version "$(git --version)"
fge_context non_claim 'One synthetic SHA-1 corpus (a 60,000-line file shifted by a few lines) per transport and protocol, over loopback; not the FG-028c performance harness, not SSH, not a claim of upstream byte parity.'
# The thin fetch must receive at most this share of the clone pack's bytes.
# Declared here, not in prose: a thin fetch of a small shift carries a delta,
# while a self-contained fetch carries the whole new file version.
THIN_FETCH_MAX_PERCENT=5
fge_context thin_fetch_max_percent "$THIN_FETCH_MAX_PERCENT"

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd THIN-FETCH-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

fge_phase action
WORK="$(fge_tempdir thin-fetch)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 1200 campaign python3 "$E2E_ROOT/thin_fetch_smoke.py" \
  --fg "$FG_BIN" --git "${GIT_ORACLE_BIN:-git}" --summary "$SUMMARY" || true
fge_assert_exit THIN-FETCH-002 0 "$FGE_LAST_EXIT" 'the campaign ran to completion'
field() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "$SUMMARY" "$1" 2>/dev/null || echo missing
}
percent_within() { # received clone limit -> true/false
  python3 -c 'import sys; r, c, l = (int(a) for a in sys.argv[1:]); print(str(r * 100 <= c * l).lower())' \
    "$1" "$2" "$3" 2>/dev/null || echo false
}
fge_context campaign_artifacts "$(field artifacts)"

fge_phase assert
id() { printf 'THIN-FETCH-%03d' "$1"; }
n=10
for transport in git http; do
  for protocol in v0 v1 v2; do
    received=$(field "${transport}_${protocol}_received_pack_bytes")
    clone=$(field "${transport}_${protocol}_clone_pack_bytes")
    fge_context "${transport}_${protocol}_bytes" "received=$received clone=$clone"
    fge_assert_eq "$(id "$n")" 0 "$(field "${transport}_${protocol}_fetch_exit")" "$transport $protocol: the stock fetch succeeds"
    fge_assert_eq "$(id $((n + 1)))" True "$(field "${transport}_${protocol}_head_matches")" "$transport $protocol: the fetched head equals the source head"
    fge_assert_eq "$(id $((n + 2)))" 0 "$(field "${transport}_${protocol}_fsck_exit")" "$transport $protocol: git fsck --strict passes after stock git completed the thin pack"
    fge_assert_eq "$(id $((n + 3)))" true "$(percent_within "$received" "$clone" "$THIN_FETCH_MAX_PERCENT")" "$transport $protocol: the fetch received at most $THIN_FETCH_MAX_PERCENT% of the clone pack's bytes"
    n=$((n + 4))
  done
done
twin=$(field git_twin_received_pack_bytes)
twin_clone=$(field git_v0_clone_pack_bytes)
fge_context twin_bytes "received=$twin clone=$twin_clone"
fge_assert_eq THIN-FETCH-040 0 "$(field git_twin_fetch_pack_exit)" 'fetch-pack without --thin succeeds'
fge_assert_eq THIN-FETCH-041 True "$(field git_twin_self_contained)" 'its pack is self-contained: index-pack accepts it without --fix-thin'
fge_assert_eq THIN-FETCH-042 false "$(percent_within "$twin" "$twin_clone" 50)" 'and it carries the whole new version (over half the clone pack), not a thin delta'
fge_assert_eq THIN-FETCH-043 0 "$(field git_server_drained_exit)" 'the git:// service drains and exits cleanly'
fge_assert_eq THIN-FETCH-044 0 "$(field http_server_drained_exit)" 'the HTTP service drains and exits cleanly'

fge_phase teardown
