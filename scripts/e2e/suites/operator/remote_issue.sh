#!/usr/bin/env bash
# Actual JS issue CLI -> native HTTP -> canonical Rust readback, both hash domains.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-remote-issue
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context evidence_class real_js_cli_native_http_and_canonical_reads
fge_context non_claim 'Two issue operator entrypoints in SHA-1/SHA-256; not the complete operator matrix, browser UI, TLS, D10 or same-revision native build qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-ISSUE-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir operator-remote-issue)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_issue_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$WORK/campaign" --summary "$SUMMARY" || true
fge_assert_exit OPERATOR-ISSUE-001 0 "$FGE_LAST_EXIT" 'actual operator requests and native canonical reads completed'
fge_phase assert
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'operator issue summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  fge_assert_eq "OPERATOR-ISSUE-$format-002" true "$(fact "${format}_stale_refusal_and_current_twin")" 'stale comment refuses without issue/event mutation; current twin commits'
  fge_assert_eq "OPERATOR-ISSUE-$format-003" true "$(fact "${format}_all_actions_and_original_key_recovery")" 'all eight actions have canonical Rust readback and original-key recovery'
  fge_assert_eq "OPERATOR-ISSUE-$format-004" true "$(fact "${format}_independent_outcome_grant")" 'unavailable outcome read preserves uncertainty; recovery never resubmits'
  fge_assert_eq "OPERATOR-ISSUE-$format-005" true "$(fact "${format}_owned_service_drained")" 'native listener drains every accepted transport'
  fge_assert_eq "OPERATOR-ISSUE-$format-006" true "$(fact "${format}_forge_all_actions_and_recovery")" 'shipped IssueClient performs every forge mutation with canonical readback and original-key recovery'
  fge_assert_eq "OPERATOR-ISSUE-$format-007" true "$(fact "${format}_forge_stale_and_grant_twins")" 'forge stale preflight and denied write preserve state; exact retry commits after restored grant'
  fge_assert_eq "OPERATOR-ISSUE-$format-008" true "$(fact "${format}_forge_reads_and_snapshot_refusal")" 'forge list/history/search preserve native pages and reject a moved snapshot'
done
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" operator-issue-summary; fi
if [ -f "$WORK/campaign/commands.jsonl" ]; then fge_artifact "$WORK/campaign/commands.jsonl" native-and-operator-command-journal; fi
fge_phase teardown
