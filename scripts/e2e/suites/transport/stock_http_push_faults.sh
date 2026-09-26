#!/usr/bin/env bash
# e2e: stock `git push` over fg serve-http survives dropped connections without
# duplication, and a protected branch refuses through report-status.
# Bead: frankengit-root-doctrine-x2mv.4.8 (acceptance 1). Not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init stock-http-push-faults
fge_context bead frankengit-root-doctrine-x2mv.4.8
fge_context evidence_class e2e_binary_stock_client
fge_context git_version "$(git --version)"
fge_context non_claim 'One SHA-1 node over loopback; the drops are made by a local relay at two request boundaries, not arbitrary network faults.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd PUSH-FAULT-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

fge_phase action
WORK="$(fge_tempdir stock-http-push-faults)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 900 campaign python3 "$E2E_ROOT/stock_http_push_faults.py" \
  --fg "$FG_BIN" --git "${GIT_ORACLE_BIN:-git}" --summary "$SUMMARY" || true
fge_assert_exit PUSH-FAULT-002 0 "$FGE_LAST_EXIT" 'the campaign ran to completion'
field() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "$SUMMARY" "$1" 2>/dev/null || echo missing
}
fge_context campaign_artifacts "$(field artifacts)"

fge_phase assert
fge_assert_eq PUSH-FAULT-010 0 "$(field initial_push_exit)" 'a stock push with only URL credentials succeeds'
fge_assert_eq PUSH-FAULT-011 True "$(field initial_published)" 'the pushed commit is published'
fge_assert_eq PUSH-FAULT-020 True "$(field drop_after_dropped_one_request)" 'the relay cut exactly one delivered receive request'
fge_assert_eq PUSH-FAULT-021 True "$(field drop_after_client_failed)" 'git reports the dropped connection as a failure'
fge_assert_eq PUSH-FAULT-022 True "$(field drop_after_committed_once)" 'the delivered push committed exactly once'
fge_assert_eq PUSH-FAULT-023 0 "$(field drop_after_retry_exit)" 'the retried push succeeds'
fge_assert_eq PUSH-FAULT-024 True "$(field drop_after_retry_up_to_date)" 'the retry finds the ref already published'
fge_assert_eq PUSH-FAULT-025 True "$(field drop_after_retry_not_duplicated)" 'the retry publishes nothing: the generation is unchanged'
fge_assert_eq PUSH-FAULT-030 True "$(field drop_before_dropped_one_request)" 'the relay cut exactly one undelivered receive request'
fge_assert_eq PUSH-FAULT-031 True "$(field drop_before_client_failed)" 'git reports that failure'
fge_assert_eq PUSH-FAULT-032 True "$(field drop_before_nothing_committed)" 'an undelivered push commits nothing'
fge_assert_eq PUSH-FAULT-033 0 "$(field drop_before_retry_exit)" 'its retry succeeds'
fge_assert_eq PUSH-FAULT-034 True "$(field drop_before_retry_committed_once)" 'and commits exactly once'
fge_assert_eq PUSH-FAULT-040 1 "$(field protected_push_exit)" 'a direct push to a protected branch fails'
fge_assert_eq PUSH-FAULT-041 True "$(field protected_report_status_refusal)" 'git shows the refusal as a report-status [remote rejected] line'
fge_assert_eq PUSH-FAULT-042 True "$(field protected_ref_absent)" 'the protected branch is not created'
fge_assert_eq PUSH-FAULT-050 0 "$(field server_drained_exit)" 'the service drains and exits cleanly'

fge_phase teardown
