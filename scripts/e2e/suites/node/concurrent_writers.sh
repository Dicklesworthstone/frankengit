#!/usr/bin/env bash
# e2e: sixteen concurrent writers against one persisted fg serve-http node.
# Bead: frankengit-root-doctrine-x2mv.4.27 (acceptance 2 and 3)
#
# Eight stock git clients push distinct children of one base to
# refs/heads/main while eight HTTP clients edit issue #1 at the same expected
# version, all released by one barrier (scripts/e2e/concurrent_writers_smoke.py).
# Every client then repeats its exact command before and after a server
# restart. Proves exactly one winner per contested target, typed refusals for
# the losers, no unknown outcomes, no duplicate publication, idempotent exact
# retries on a persisted node, and (acceptance 2) that a reply lost after a
# successful CAS is recovered by `fg outcome` from its key alone.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init concurrent-writers
fge_context bead frankengit-root-doctrine-x2mv.4.27
fge_context evidence_class e2e_binary_stock_client
fge_context git_version "$(git --version)"
fge_context non_claim 'One node, one host, 16 writers on two contested targets (one branch, one issue); not a throughput, multi-node or hostile-network claim.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd CW-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

fge_phase action
WORK="$(fge_tempdir concurrent-writers)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 1800 campaign python3 "$E2E_ROOT/concurrent_writers_smoke.py" \
  --fg "$FG_BIN" --summary "$SUMMARY" || true
fge_assert_exit CW-002 0 "$FGE_LAST_EXIT" 'the 16-writer campaign ran to completion'
field() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "$SUMMARY" "$1" 2>/dev/null || echo missing
}
fge_context campaign_artifacts "$(field artifacts)"
fge_context slowest_writer_s "$(field slowest_writer_s)"

fge_assert_eq CW-010 1 "$(field push_winners)" 'exactly one of 8 concurrent pushes to refs/heads/main wins'
fge_assert_eq CW-011 7 "$(field push_typed_refusals)" 'the other 7 pushes receive a typed report-status refusal'
fge_assert_eq CW-012 0 "$(field push_unknown)" 'no push ends as an unknown outcome (503 or hang-up)'
fge_assert_eq CW-013 True "$(field main_is_the_winner)" 'refs/heads/main is exactly the winning client commit'
fge_assert_eq CW-014 0 "$(field committed_push_reported_refused)" 'no committed push was reported as refused'
fge_assert_eq CW-020 1 "$(field edit_winners)" 'exactly one of 8 concurrent issue edits wins'
fge_assert_eq CW-021 7 "$(field edit_typed_refusals)" 'the other 7 edits receive a typed 409 refused outcome'
fge_assert_eq CW-022 0 "$(field edit_unknown)" 'no edit ends as an unknown outcome'
fge_assert_eq CW-023 True "$(field issue_title_is_the_winner)" 'issue #1 carries exactly the winning edit'
fge_assert_eq CW-024 2 "$(field issue_version)" 'one winning edit: the issue is at version 2, no duplicate publication'
fge_assert_eq CW-025 2 "$(field issue_events)" 'the issue history holds exactly the open and one edit'
fge_assert_eq CW-030 True "$(field edit_retries_identical)" 'each exact edit retry returns its original terminal reply'
fge_assert_eq CW-031 True "$(field push_retry_outcomes_stable)" 'each exact push retry keeps its original outcome'
fge_assert_eq CW-032 True "$(field main_unchanged_by_retries)" 'retries publish nothing'
fge_assert_eq CW-033 True "$(field unknown_edits_resolved_by_retry)" 'an edit that got no outcome resolves to a terminal one on exact retry'
fge_assert_eq CW-034 True "$(field unknown_pushes_resolved_by_retry)" 'a push that got no outcome resolves to a terminal one on exact retry'
fge_assert_eq CW-040 True "$(field main_survives_restart)" 'refs/heads/main is unchanged after a server restart'
fge_assert_eq CW-041 True "$(field issue_survives_restart)" 'issue #1 is unchanged after a server restart'
fge_assert_eq CW-042 True "$(field edit_retries_identical_after_restart)" 'exact edit retries after restart return the original replies'
# Acceptance 2: a lost response after a successful CAS is recovered by key.
fge_assert_eq CW-050 True "$(field planted_lost_reply_committed)" 'an edit whose client closed before reading its reply still commits'
fge_assert_eq CW-051 True "$(field planted_lost_reply_logged)" 'the server records that the reply was lost after the canonical outcome'
fge_assert_eq CW-052 0 "$(field planted_lost_outcome_exit)" 'fg outcome resolves the lost reply from its key alone (exit 0)'
fge_assert_eq CW-053 committed "$(field planted_lost_outcome_kind)" 'fg outcome reports the committed decision'

fge_phase teardown
