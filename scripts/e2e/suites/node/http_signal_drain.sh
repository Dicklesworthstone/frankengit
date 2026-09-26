#!/usr/bin/env bash
# e2e: SIGTERM and SIGINT drain a continuous fg serve-http instead of ending it.
# Bead: frankengit-root-doctrine-x2mv.4.8 (acceptance 3). Not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init http-signal-drain
fge_context bead frankengit-root-doctrine-x2mv.4.8
fge_context evidence_class e2e_binary_stock_client
fge_context non_claim 'One loopback service per signal on Linux; one admitted read held open across SIGTERM, not a load or multi-signal-storm claim.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd HTTP-SIGNAL-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

fge_phase action
WORK="$(fge_tempdir http-signal-drain)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 600 campaign python3 "$E2E_ROOT/http_signal_drain_smoke.py" \
  --fg "$FG_BIN" --git "${GIT_ORACLE_BIN:-git}" --summary "$SUMMARY" || true
field() {
  python3 -c 'import json, sys; print(json.dumps(json.load(open(sys.argv[1]))[sys.argv[2]], sort_keys=True))' \
    "$SUMMARY" "$1" 2>/dev/null || echo missing
}
fge_context campaign_artifacts "$(field artifacts)"

fge_phase assert
fge_assert_exit HTTP-SIGNAL-002 0 "$FGE_LAST_EXIT" \
  'SIGTERM drained an admitted read and SIGINT stopped an idle service, both exiting 0'
fge_assert_eq HTTP-SIGNAL-003 true "$(field sigterm_drained_admitted_read)" \
  'the read admitted before SIGTERM completed with the advertised refs'
fge_context sigterm_receipt "$(field sigterm_receipt)"
fge_context sigint_receipt "$(field sigint_receipt)"

fge_phase teardown
