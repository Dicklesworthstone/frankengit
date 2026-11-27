#!/usr/bin/env bash
# e2e: stock `git push` over fg serve-http survives dropped connections and
# native process restarts without duplication. Protection uses report-status.
# Bead: frankengit-root-doctrine-x2mv.4.8 (acceptance 1). Not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init stock-http-push-faults
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.8
fge_context evidence_class e2e_binary_stock_client
fge_context non_claim 'Local nodes over loopback, two HTTP request boundaries, and native process loss with intact storage.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd PUSH-FAULT-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_run_timeout 30 relay-preflight python3 "$E2E_ROOT/selftests/test_stock_http_push_faults.py" || true
fge_assert_exit PUSH-FAULT-003 0 "$FGE_LAST_EXIT" 'real socket relay regression tests pass'

field() {
  if [[ ! -f "$1" ]]; then printf '%s\n' missing; return; fi
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "$1" "$2" || echo missing
}

run_case() {
  local label="$1" format="$2" suffix="$3" work summary
  shift 3
  work="$(fge_tempdir "$label")"
  summary="$work/summary.json"
  fge_context object_format "$format"
  fge_context fault_profile "$label"
  fge_phase action
  fge_run_timeout 900 "$label" python3 "$E2E_ROOT/stock_http_push_faults.py" \
    --fg "$FG_BIN" --git "${GIT_ORACLE_BIN:-git}" --summary "$summary" \
    --object-format "$format" "$@" || true
  fge_assert_exit "PUSH-FAULT-002$suffix" 0 "$FGE_LAST_EXIT" 'the campaign ran to completion'
  fge_context campaign_artifacts "$(field "$summary" artifacts)"
  fge_context git_version "$(field "$summary" git)"
  fge_phase assert
  fge_assert_eq "PUSH-FAULT-004$suffix" "$format" "$(field "$summary" object_format)" 'the selected object format ran'
  fge_assert_eq "PUSH-FAULT-010$suffix" 0 "$(field "$summary" initial_push_exit)" 'a stock push with only URL credentials succeeds'
  fge_assert_eq "PUSH-FAULT-011$suffix" True "$(field "$summary" initial_published)" 'the pushed commit is published'
  fge_assert_eq "PUSH-FAULT-020$suffix" True "$(field "$summary" drop_after_dropped_one_request)" 'the relay cut exactly one delivered receive request'
  fge_assert_eq "PUSH-FAULT-021$suffix" True "$(field "$summary" drop_after_client_failed)" 'git reports the dropped connection as a failure'
  fge_assert_eq "PUSH-FAULT-022$suffix" True "$(field "$summary" drop_after_committed_once)" 'the delivered push committed exactly once'
  fge_assert_eq "PUSH-FAULT-023$suffix" 0 "$(field "$summary" drop_after_retry_exit)" 'the retried push succeeds'
  fge_assert_eq "PUSH-FAULT-024$suffix" True "$(field "$summary" drop_after_retry_up_to_date)" 'the retry finds the ref already published'
  fge_assert_eq "PUSH-FAULT-025$suffix" True "$(field "$summary" drop_after_retry_not_duplicated)" 'the retry publishes nothing: the generation is unchanged'
  fge_assert_eq "PUSH-FAULT-026$suffix" True "$(field "$summary" drop_after_reply_cut)" 'the relay saw a native reply before cutting it'
  fge_assert_eq "PUSH-FAULT-030$suffix" True "$(field "$summary" drop_before_dropped_one_request)" 'the relay cut exactly one undelivered receive request'
  fge_assert_eq "PUSH-FAULT-031$suffix" True "$(field "$summary" drop_before_client_failed)" 'git reports that failure'
  fge_assert_eq "PUSH-FAULT-032$suffix" True "$(field "$summary" drop_before_nothing_committed)" 'an undelivered push commits nothing'
  fge_assert_eq "PUSH-FAULT-033$suffix" 0 "$(field "$summary" drop_before_retry_exit)" 'its retry succeeds'
  fge_assert_eq "PUSH-FAULT-034$suffix" True "$(field "$summary" drop_before_retry_committed_once)" 'and commits exactly once'
  fge_assert_eq "PUSH-FAULT-040$suffix" 1 "$(field "$summary" protected_push_exit)" 'a direct push to a protected branch fails'
  fge_assert_eq "PUSH-FAULT-041$suffix" True "$(field "$summary" protected_report_status_refusal)" 'git shows the refusal as a report-status [remote rejected] line'
  fge_assert_eq "PUSH-FAULT-042$suffix" True "$(field "$summary" protected_ref_absent)" 'the protected branch is not created'
  fge_assert_eq "PUSH-FAULT-050$suffix" 0 "$(field "$summary" server_drained_exit)" 'the service drains and exits cleanly'
  if [[ -z "$suffix" ]]; then
    fge_assert_eq PUSH-FAULT-060 '[]' "$(field "$summary" restarts)" 'the original twin uses the same native process'
  else
    fge_capture "$label-restarts" python3 - "$summary" <<'PY' || true
import json
import signal
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    restarts = json.load(source)["restarts"]
events = [(entry["after"], entry["exit"]) for entry in restarts]
if events != [("reply-cut", -signal.SIGKILL), ("undelivered", -signal.SIGKILL)]:
    raise SystemExit(f"unexpected restart events: {events!r}")
if restarts[0]["reopened_pid"] != restarts[1]["original_pid"]:
    raise SystemExit("second cut did not stop the reopened server")
PY
    fge_assert_exit "PUSH-FAULT-060$suffix" 0 "$FGE_LAST_EXIT" 'both cuts kill and reopen their original native process before readback'
  fi
  if [[ -f "$summary" ]]; then fge_artifact "$summary" json; fi
}

run_case stock-http-push-faults sha1 ''
run_case restart-sha1 sha1 -RESTART-SHA1 --restart-after-drop
run_case restart-sha256 sha256 -RESTART-SHA256 --restart-after-drop

fge_phase teardown
