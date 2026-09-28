#!/usr/bin/env bash
# e2e: continuous raw Git and SSH stock-client sessions and owned native drain.
# Bead: frankengit-root-doctrine-x2mv.4.32, acceptance 1..4.
# Acceptance 4 here is the real permitted twin; owning-crate unit tests cover
# the lifetime state machine. This suite drives FG_BIN and never builds Rust.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init continuous-git-transports
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.32
fge_context evidence_class e2e_binary_stock_client_native_signals
fge_context non_claim 'SHA-1 loopback raw Git and authenticated SSH; 210 stock sessions per transport. Native crate tests separately cover lifetime state-machine transitions. Optional SHA-256 is available in the Python driver.'

fge_phase setup
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
  fge_unsupported FG-GIT-CONTINUOUS-032-SETUP 'an explicitly supplied, already-built FG_BIN is required'
  exit 1
fi
WORK="$(fge_tempdir continuous-git-transports)"
SUMMARY="$WORK/summary.json"
fge_preserve "$WORK" 'stock-client transcripts, packet barriers, canonical restart and lifecycle evidence'

fge_phase action
fge_run_timeout 2400 campaign python3 "$E2E_ROOT/continuous_git_transports_smoke.py" \
  --fg "$FG_BIN" --git "${GIT_ORACLE_BIN:-git}" --artifacts "$WORK" \
  --summary "$SUMMARY" || true
campaign_rc=$FGE_LAST_EXIT

fge_phase assert
fge_assert_exit FG-GIT-CONTINUOUS-032-CAMPAIGN 0 "$campaign_rc" \
  'stock Git exercises both continuous services and actual held-push native shutdown'
fge_assert_file FG-GIT-CONTINUOUS-032-SUMMARY "$SUMMARY" 'campaign records complete lifecycle evidence'
fge_assert_ndjson FG-GIT-CONTINUOUS-032-NDJSON "$WORK/evidence.ndjson" \
  'acceptance-mapped native evidence is well-formed NDJSON'
if [[ -f "$SUMMARY" ]]; then
  for transport in git ssh; do
    for acceptance in 1 2 3 4; do
      fge_assert_cmd "FG-GIT-CONTINUOUS-032-${acceptance}-${transport}" \
        "acceptance $acceptance for $transport: sessions, atomic SIGTERM drain, listener refusal, permitted twin" \
        python3 -c '
import json, sys
summary = json.load(open(sys.argv[1]))
rows = [r for r in summary["results"] if r["transport"] == sys.argv[2] and r["format"] == "sha1"]
field = "acceptance_4_permitted_twin" if sys.argv[3] == "4" else "acceptance_" + sys.argv[3]
assert len(rows) == 1 and rows[0][field] is True
assert rows[0]["sequential"]["stock_sessions"] >= 200
' "$SUMMARY" "$transport" "$acceptance"
    done
  done
  fge_artifact "$SUMMARY" json
fi
if [[ -f "$WORK/evidence.ndjson" ]]; then
  fge_artifact "$WORK/evidence.ndjson" ndjson
fi
fge_context campaign_artifacts "$WORK"
fge_phase teardown
