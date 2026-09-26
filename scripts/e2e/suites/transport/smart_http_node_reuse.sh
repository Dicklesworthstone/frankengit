#!/usr/bin/env bash
# e2e: sequential stock fetches against one fg serve-http process reuse its
# opened repository nodes instead of reopening one per request.
# Bead: frankengit-root-doctrine-x2mv.4.8 (acceptance 2)
#
# scripts/e2e/smart_http_node_reuse_smoke.py serves one persisted node with the
# real fg binary: N timed stock `git fetch` runs and N timed raw discovery
# round trips (raw samples kept in the summary), then M fetches with the server
# under `strace -f`, counting opens of the authority database. A per-request
# node opens that database at least once per HTTP connection.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init smart-http-node-reuse
fge_context bead frankengit-root-doctrine-x2mv.4.8
fge_context evidence_class e2e_binary_stock_client
fge_context git_version "$(git --version)"
fge_context non_claim 'One node, one host, sequential loopback fetches; latency is recorded, not asserted, and is not a throughput or remote-network claim.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd HTTP-REUSE-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
FETCHES="${FG_E2E_REUSE_FETCHES:-1000}"
TRACED="${FG_E2E_REUSE_TRACED_FETCHES:-200}"
fge_context fetches "$FETCHES"
fge_context traced_fetches "$TRACED"

fge_phase action
WORK="$(fge_tempdir smart-http-node-reuse)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 3600 campaign python3 "$E2E_ROOT/smart_http_node_reuse_smoke.py" \
  --fg "$FG_BIN" --fetches "$FETCHES" --traced-fetches "$TRACED" --summary "$SUMMARY" || true
fge_assert_exit HTTP-REUSE-002 0 "$FGE_LAST_EXIT" 'every sequential fetch and discovery succeeded'
field() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "$SUMMARY" "$1" 2>/dev/null || echo missing
}
fge_context campaign_artifacts "$(field artifacts)"
fge_context fetch_p50_s "$(field fetch_p50_s)"
fge_context fetch_p99_s "$(field fetch_p99_s)"
fge_context discovery_p50_s "$(field discovery_p50_s)"
fge_context discovery_p99_s "$(field discovery_p99_s)"

fge_phase assert
EVIDENCE="$(field reopen_evidence)"
if [ "$EVIDENCE" != strace ]; then
  fge_unsupported HTTP-REUSE-010 "reopen count needs strace: $EVIDENCE"
else
  OPENS="$(field database_opens)"
  CONNECTIONS="$(field traced_connections)"
  fge_context database_opens "$OPENS"
  fge_context traced_connections "$CONNECTIONS"
  # The parent's own open, at most one node per in-flight slot (4), and a
  # few retire/reopen cycles are allowed; a per-request node would open the
  # database at least once for each of the traced connections.
  fge_assert_cmd HTTP-REUSE-010 \
    "the authority database is opened at most 8 times across $CONNECTIONS sequential connections" \
    test "$OPENS" -le 8
fi

fge_phase teardown
