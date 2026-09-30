#!/usr/bin/env bash
# e2e: a stock `git push` whose graph the node refuses gets a per-ref
# report-status rejection, not a transport error, over Smart HTTP and git://;
# the permitted twin publishes. Beads: frankengit-87c7 (acceptance 1, HTTP) and
# frankengit-root-doctrine-x2mv.4.49 (acceptance 3, git daemon).
# Not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init stock-push-verdicts
fge_kind e2e-binary
fge_context bead 'frankengit-87c7 frankengit-root-doctrine-x2mv.4.49'
fge_context evidence_class e2e_binary_stock_client
fge_context git_version "$(git --version)"
fge_context non_claim 'One SHA-1 node per transport over loopback and one refused graph class (a file-mode entry naming a tree, EvidenceInvalid). Stock git cannot push a ref at a missing object; the other verdict codes share the same classification and are covered by unit and in-process HTTP tests, not pushed here.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd PUSH-VERDICT-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

fge_phase action
WORK="$(fge_tempdir stock-push-verdicts)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 900 campaign python3 "$E2E_ROOT/stock_push_verdicts.py" \
  --fg "$FG_BIN" --git "${GIT_ORACLE_BIN:-git}" --summary "$SUMMARY" || true
fge_assert_exit PUSH-VERDICT-002 0 "$FGE_LAST_EXIT" 'the campaign ran to completion'
field() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "$SUMMARY" "$1" 2>/dev/null || echo missing
}
fge_context campaign_artifacts "$(field artifacts)"

fge_phase assert
id() { printf 'PUSH-VERDICT-%03d' "$1"; }
n=10
for transport in http git; do
  fge_context "${transport}_refused_push_stderr" "$(field "${transport}_refused_push_stderr")"
  fge_assert_eq "$(id "$n")" 0 "$(field "${transport}_base_push_exit")" "$transport: a stock push of an ordinary branch succeeds"
  fge_assert_eq "$(id $((n + 1)))" 1 "$(field "${transport}_refused_push_exit")" "$transport: a push of a refused graph exits 1"
  fge_assert_eq "$(id $((n + 2)))" True "$(field "${transport}_refused_per_ref")" "$transport: git prints '[remote rejected] ... -> bad (object graph failed validation ...)'"
  fge_assert_eq "$(id $((n + 3)))" True "$(field "${transport}_refused_not_transport_error")" "$transport: no remote error, RPC failure or hang-up is reported"
  fge_assert_eq "$(id $((n + 4)))" True "$(field "${transport}_refused_ref_absent")" "$transport: the refused ref is not created"
  fge_assert_eq "$(id $((n + 5)))" True "$(field "${transport}_refused_generation_unchanged")" "$transport: the refusal publishes nothing"
  fge_assert_eq "$(id $((n + 6)))" 0 "$(field "${transport}_permitted_push_exit")" "$transport: the permitted twin push succeeds"
  fge_assert_eq "$(id $((n + 7)))" True "$(field "${transport}_permitted_published")" "$transport: the twin branch is published at the pushed commit"
  fge_assert_eq "$(id $((n + 8)))" True "$(field "${transport}_permitted_generation_advanced")" "$transport: the twin publishes exactly one generation"
  fge_assert_eq "$(id $((n + 9)))" 0 "$(field "${transport}_server_drained_exit")" "$transport: the service drains and exits cleanly"
  n=$((n + 10))
done
fge_assert_eq PUSH-VERDICT-030 True "$(field http_server_log_reports_per_ref_refusal)" 'the HTTP operator log records the refusal as reported per ref'

fge_phase teardown
